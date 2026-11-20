/**
 * shield360/defend: decide in the app whether a request may go on.
 *
 *   import { createDefend } from 'shield360/defend';
 *   const shield = createDefend({ app: 'checkout', url, apiKey, configPublicKey });
 *   app.use(shield.express());                       // Express / Connect
 *   const result = await shield.defend(request);      // any request, by hand
 *
 * The decision is made locally from a signed policy the SDK fetches and caches
 * the way the RASP config is (same key pinning, same refresh): no network call
 * on the request path unless `sharedRateLimits` is on. Fail open by default.
 * Kept apart from tracing: importing this subpath loads no OpenTelemetry code.
 */
import { tmpdir } from 'os';
import { join } from 'path';
import type { IncomingMessage, ServerResponse } from 'http';
import { parsePublicKeys, RaspConfigClient, type RaspClaims } from '../rasp/config-client';
import { SuspiciousTable, suspiciousTable } from '../rasp/deception';
import { checkContent, decide, failResult, RateTable, rateRulesFor } from './engine';
import { DEFEND_JWS_TYPE, DEFEND_POLICY_PATH, parseDefendPolicy } from './policy';
import { carriesAgentProof, factsOf } from './request';
import { BreadthCounter, classifyClient } from '../client-type';
import { CONTEXT_HEADER, REQUEST_ID_HEADER, verifyEdgeContext } from '../rasp/edge-context';
import { DefendReporter } from './reporter';
import type { ClientClassification, DefendCallOptions, DefendFacts, DefendMode, DefendOptions, DefendPolicy, DefendResult } from './types';

export * from './types';
export { parseDefendPolicy, DEFEND_JWS_TYPE, DEFEND_POLICY_PATH } from './policy';
export { decide, checkContent, RateTable, pathUnder } from './engine';
export { factsOf, pathOf, forwardedIp } from './request';
export { DefendReporter, DEFEND_REPORT_PATH } from './reporter';

export const DEFEND_DECIDE_PATH = '/api/defend/decide';
export const DEFEND_DECISIONS_PATH = '/api/defend/decisions';
/** How often the decisions feed is checked: a block made anywhere reaches this instance within about this long. */
export const DECISIONS_EVERY_MS = 5000;
export const BLOCK_BODY = JSON.stringify({ error: 'Forbidden' });
const PRODUCTION = /^prod(uction)?$/i;
const SDK_VERSION: string = (() => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return String(require('../../package.json').version || '');
  } catch {
    return '';
  }
})();

type Next = (err?: unknown) => void;
type Handler<C> = (request: Request, context: C) => Response | Promise<Response>;

export type ExpressDefendOptions = {
  /** Text in the request to check for prompt injection and sensitive data (e.g. `req => req.body?.prompt`). */
  content?: (req: IncomingMessage & Record<string, unknown>) => string | string[] | undefined;
  /** Answer a decision yourself; return true when you sent the response. */
  onDecision?: (req: IncomingMessage, res: ServerResponse, result: DefendResult) => boolean;
};

export type Defend = {
  /** The decision for a request (Node IncomingMessage, fetch Request, or { method, url, headers }). Never throws. */
  defend(request: unknown, call?: DefendCallOptions): Promise<DefendResult>;
  /** Express / Connect middleware: sets `req.shield360Defend`, answers 403 (deny, challenge) or 401 (require sign-in). */
  express(options?: ExpressDefendOptions): (req: IncomingMessage & Record<string, unknown>, res: ServerResponse, next: Next) => void;
  /** Wraps a Node http handler. */
  http<H extends (req: IncomingMessage, res: ServerResponse) => unknown>(handler: H): H;
  /** Wraps a fetch-style handler (Next.js route handlers, Hono, …). */
  withDefend<C = unknown>(handler: Handler<C>, options?: { content?: (request: Request) => Promise<string | string[] | undefined> | string | string[] | undefined }): Handler<C>;
  /** For Next.js middleware: the Response to answer with, or null to go on (return NextResponse.next()). */
  respond(request: Request, call?: DefendCallOptions): Promise<Response | null>;
  /** The app saw a trap hit by this request's client: it is marked suspected for the policy's trap TTL and the hit is reported. */
  trapHit(request: unknown, trap: string, call?: DefendCallOptions): void;
  /** The app saw a failed sign-in from this request's client: reported (never the user name or password). */
  failedLogin(request: unknown, call?: DefendCallOptions): void;
  /** The policy in force, or null. */
  policy(): DefendPolicy | null;
  /** Resolves once the first policy fetch finished (or immediately without a URL). */
  ready(): Promise<void>;
  /** Stops polling and sends queued events. */
  close(): Promise<void>;
};

function tofuAllowed(option: boolean | undefined, env: NodeJS.ProcessEnv): boolean {
  const asked = option === true || (env.SHIELD360_CONFIG_TOFU || '').trim().toLowerCase() === 'dev';
  return asked && ![env.NODE_ENV, env.ENVIRONMENT].some((v) => PRODUCTION.test((v || '').trim()));
}

/** SHIELD360_DEFEND: off (allow everything), monitor (never deny), enforce; anything else: the option decides. */
export function envMode(env: NodeJS.ProcessEnv): 'off' | DefendMode | undefined {
  const v = (env.SHIELD360_DEFEND || '').trim().toLowerCase();
  return v === 'off' || v === 'monitor' || v === 'enforce' ? v : undefined;
}

function statusOf(result: DefendResult): number {
  return result.decision === 'require_sign_in' ? 401 : 403;
}

function answerNode(res: ServerResponse, result: DefendResult): void {
  if (res.headersSent) return;
  res.statusCode = statusOf(result);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Shield360-Defend', result.decision);
  res.setHeader('Cache-Control', 'no-store');
  res.end(BLOCK_BODY);
}

function answerFetch(result: DefendResult): Response {
  return new Response(BLOCK_BODY, { status: statusOf(result), headers: { 'Content-Type': 'application/json', 'Shield360-Defend': result.decision, 'Cache-Control': 'no-store' } });
}

export function createDefend(options: DefendOptions): Defend {
  if (!options || typeof options.app !== 'string' || !options.app.trim()) throw new TypeError('createDefend: `app` (the app name in Shield360) is required');
  const env = options.env ?? process.env;
  const now = options.now ?? Date.now;
  const app = options.app.trim();
  const failMode = options.failMode === 'closed' ? 'closed' : 'open';
  const sensitiveData = options.sensitiveData ?? 'monitor';
  const rates = new RateTable();
  const breadth = new BreadthCounter();
  const marks = new SuspiciousTable(10_000, now);
  const factsOpts = { trustProxy: options.trustProxy, geoHeaders: options.geoHeaders };
  let current: DefendPolicy | null = null;
  let firstPoll: Promise<unknown> = Promise.resolve();
  let warned = false;
  let stopFeed: () => void = () => undefined;
  let feedEtag: string | undefined;
  let feedBusy = false;

  async function checkFeed(c: RaspConfigClient): Promise<void> {
    if (feedBusy || c.stopped || !current) return;
    feedBusy = true;
    try {
      const send = options.fetchImpl ?? globalThis.fetch;
      const headers: Record<string, string> = { Authorization: `Bearer ${options.apiKey}`, Accept: 'application/json' };
      if (feedEtag) headers['If-None-Match'] = feedEtag;
      const init: RequestInit = { headers };
      if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') init.signal = AbortSignal.timeout(3000);
      const res = await send(`${(options.url as string).replace(/\/+$/, '')}${DEFEND_DECISIONS_PATH}?app=${encodeURIComponent(app)}`, init);
      if (res.status === 304 || !res.ok) return;
      feedEtag = res.headers.get('etag') ?? undefined;
      const body = (await res.json()) as { version?: unknown };
      if (typeof body?.version === 'string' && body.version !== current.listsVersion) await c.poll();
    } catch {
      // the next check, or the regular policy poll, catches up
    } finally {
      feedBusy = false;
    }
  }

  const remote = Boolean(options.url && options.apiKey);
  const pinned = parsePublicKeys((options.configPublicKey as never) ?? env.SHIELD360_CONFIG_PUBLIC_KEY);
  const tofu = !pinned.length && tofuAllowed(options.allowUnpinnedConfig, env);
  let client: RaspConfigClient | undefined;
  if (remote && (pinned.length || tofu)) {
    client = new RaspConfigClient({
      url: options.url as string,
      apiKey: options.apiKey as string,
      app,
      pinned,
      allowUnpinned: tofu,
      cacheDir: options.cacheDir || join(tmpdir(), 'shield360-defend'),
      path: DEFEND_POLICY_PATH,
      jwsType: DEFEND_JWS_TYPE,
      onConfig: (claims: RaspClaims | undefined) => {
        current = claims ? parseDefendPolicy(claims) : null;
      },
      onWarning: (reason) => {
        if (reason !== 'trust_on_first_use') console.warn(`Shield360 Defend: a signed policy was refused (${reason}); the last verified policy stays in force.`);
      },
      fetchImpl: options.fetchImpl,
      now,
    });
    client.loadCache();
    const c = client;
    // The first fetch now (so ready() means something); the regular ETag polling after it.
    firstPoll = c
      .poll()
      .catch(() => undefined)
      .finally(() => {
        if (!c.stopped) c.start();
      });
    // The decisions feed: a cheap version check every few seconds; the signed policy is read again only when its lists changed
    // (a trap hit on another instance, a response-rule block, "Block this IP").
    const feed = setInterval(() => void checkFeed(c), DECISIONS_EVERY_MS);
    feed.unref?.();
    stopFeed = () => clearInterval(feed);
  } else if (remote && !warned) {
    warned = true;
    console.warn('Shield360 Defend: the signed policy key is not pinned, so no policy is used and the fail mode applies. Set configPublicKey (or SHIELD360_CONFIG_PUBLIC_KEY).');
  }
  const reporter = remote && options.report !== false ? new DefendReporter({ url: options.url as string, apiKey: options.apiKey as string, app, sdkVersion: SDK_VERSION, fetchImpl: options.fetchImpl, now }) : undefined;
  reporter?.start();

  const mode = (): DefendMode | 'off' => envMode(env) ?? options.mode ?? 'enforce';

  function trapHitFor(ip: string | undefined): boolean {
    if (!ip) return false;
    if (marks.isMarked(ip)) return true;
    try {
      // RASP deception's own marks: a client that touched a decoy this process served.
      return suspiciousTable().isMarked(ip);
    } catch {
      return false;
    }
  }

  async function sharedOver(policy: DefendPolicy, facts: DefendFacts, base: Parameters<typeof rateRulesFor>[0]): Promise<Record<string, boolean> | undefined> {
    if (!options.sharedRateLimits || !remote || !facts.ip) return undefined;
    const ids = rateRulesFor(base).map((r) => r.id);
    if (!ids.length) return undefined;
    const timeoutMs = typeof options.sharedRateLimits === 'object' && options.sharedRateLimits.timeoutMs ? options.sharedRateLimits.timeoutMs : 150;
    try {
      const send = options.fetchImpl ?? globalThis.fetch;
      const init: RequestInit = {
        method: 'POST',
        headers: { Authorization: `Bearer ${options.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ app, ip: facts.ip, ruleIds: ids, version: policy.version }),
      };
      if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') init.signal = AbortSignal.timeout(timeoutMs);
      const res = await send(`${(options.url as string).replace(/\/+$/, '')}${DEFEND_DECIDE_PATH}`, init);
      if (!res.ok) return undefined;
      const body = (await res.json()) as { over?: unknown };
      if (!body || typeof body.over !== 'object' || body.over === null) return undefined;
      const out: Record<string, boolean> = {};
      for (const id of ids) if (typeof (body.over as Record<string, unknown>)[id] === 'boolean') out[id] = (body.over as Record<string, boolean>)[id];
      return out;
    } catch {
      return undefined;
    }
  }

  function report(result: DefendResult, facts: DefendFacts): void {
    if (!reporter) return;
    const decision = result.wouldBe ?? result.decision;
    const trap = result.reasons.includes('trap_hit');
    if (decision === 'allow' && !trap && !result.reasons.includes('rule:monitor')) return;
    reporter.add({
      kind: 'decision',
      decision,
      ...(result.wouldBe ? { monitored: true } : {}),
      ...(result.clientType ? { clientType: result.clientType } : {}),
      ...(facts.ip ? { ip: facts.ip } : {}),
      path: facts.path.slice(0, 256),
      method: facts.method,
      reasons: result.reasons,
      ruleIds: result.ruleIds,
    });
  }

  async function defendOne(request: unknown, call: DefendCallOptions = {}): Promise<DefendResult> {
    const m = mode();
    if (m === 'off') return { decision: 'allow', reasons: ['off'], ruleIds: [], ttl: 0 };
    let facts: DefendFacts = { method: 'GET', path: '/', headers: {} };
    try {
      facts = factsOf(request, call, factsOpts);
      const policy = current && current.exp + 60 > now() / 1000 ? current : null;
      let agent: { verified: boolean; blocked: boolean; reason?: string } | undefined;
      if (options.agents && carriesAgentProof(facts.headers)) {
        try {
          const check = await options.agents.check(request, { route: facts.path, method: facts.method });
          agent = { verified: check.status === 'verified', blocked: check.blocked === true, reason: check.status === 'verified' ? undefined : check.reason };
        } catch {
          agent = undefined;
        }
      }
      // Protection triangle: what Edge, in front, says about this client (verified, never trusted unverified).
      const ctxValue = facts.headers[CONTEXT_HEADER];
      if (ctxValue && policy?.edgeKeys.length) {
        const edge = verifyEdgeContext(policy.edgeKeys, ctxValue, { method: facts.method, path: facts.rawPath ?? facts.path, requestId: facts.headers[REQUEST_ID_HEADER] || undefined }, now());
        if (edge) facts.edge = { ct: edge.ct, trap: edge.trap, fl: edge.fl, risk: edge.risk };
      }
      // A client Edge's honeypots already caught following a trail (level 2+) is a trap hit here too: blocked at once.
      const edgeVerified = facts.edge?.ct === 'verified_agent' || facts.edge?.ct === 'verified_crawler';
      const trapHit = !edgeVerified && (trapHitFor(facts.ip) || (facts.edge?.trap ?? 0) >= 2);
      let classification: ClientClassification | null | undefined;
      if (options.classify !== false && !agent?.verified && !trapHit) {
        try {
          classification = options.classify
            ? options.classify(facts, { verifiedAgent: false, trapHit: false })
            : classifyClient(facts.headers, { edge: facts.edge, breadth: facts.ip ? breadth.see(facts.ip, facts.path, now()) : undefined });
        } catch {
          classification = undefined;
        }
      }
      const content = checkContent(facts.content, sensitiveData);
      const base = { policy: policy as DefendPolicy, facts, mode: m, failMode, agent, trapHit, classification, content, sensitiveData } as const;
      const shared = policy ? await sharedOver(policy, facts, base) : undefined;
      const result = decide({ ...base, policy, rates, nowMs: now(), sharedOver: shared });
      report(result, facts);
      return result;
    } catch {
      const r = failResult(failMode, 'error', m);
      report(r, facts);
      return r;
    }
  }

  const self: Defend = {
    defend: defendOne,
    express(o: ExpressDefendOptions = {}) {
      return function shield360Defend(req, res, next) {
        let content: string | string[] | undefined;
        try {
          content = o.content?.(req);
        } catch {
          content = undefined;
        }
        defendOne(req, { content })
          .then((result) => {
            req.shield360Defend = result;
            if (result.decision === 'allow') return next();
            if (o.onDecision?.(req, res, result)) return;
            answerNode(res, result);
          })
          .catch(() => next());
      };
    },
    http<H extends (req: IncomingMessage, res: ServerResponse) => unknown>(handler: H): H {
      const wrapped = function (this: unknown, req: IncomingMessage, res: ServerResponse) {
        void defendOne(req).then(
          (result) => (result.decision === 'allow' ? handler.call(this, req, res) : answerNode(res, result)),
          () => handler.call(this, req, res),
        );
      };
      return wrapped as unknown as H;
    },
    withDefend<C>(handler: Handler<C>, o: { content?: (request: Request) => Promise<string | string[] | undefined> | string | string[] | undefined } = {}): Handler<C> {
      return async function shield360Defend(request: Request, context: C): Promise<Response> {
        let content: string | string[] | undefined;
        try {
          content = await o.content?.(request.clone());
        } catch {
          content = undefined;
        }
        const result = await defendOne(request, { content });
        return result.decision === 'allow' ? handler(request, context) : answerFetch(result);
      };
    },
    async respond(request: Request, call?: DefendCallOptions) {
      const result = await defendOne(request, call);
      return result.decision === 'allow' ? null : answerFetch(result);
    },
    trapHit(request: unknown, trap: string, call: DefendCallOptions = {}) {
      try {
        const facts = factsOf(request, call, factsOpts);
        const ttl = current?.traps.ttlSeconds ?? 900;
        if (facts.ip) marks.mark(facts.ip, ttl);
        const code = /^[a-z0-9_.-]{1,48}$/.test(trap) ? trap : 'trap';
        reporter?.add({ kind: 'trap_hit', ...(facts.ip ? { ip: facts.ip } : {}), path: facts.path.slice(0, 256), method: facts.method, clientType: 'suspected_ai_agent', reasons: [`trap:${code}`], ruleIds: [] });
      } catch {
        // never
      }
    },
    failedLogin(request: unknown, call: DefendCallOptions = {}) {
      try {
        const facts = factsOf(request, call, factsOpts);
        reporter?.add({ kind: 'failed_login', ...(facts.ip ? { ip: facts.ip } : {}), path: facts.path.slice(0, 256), method: facts.method, reasons: ['failed_login'], ruleIds: [] });
      } catch {
        // never
      }
    },
    policy: () => current,
    ready: () => firstPoll.then(() => undefined),
    async close() {
      stopFeed();
      client?.stop();
      await reporter?.stop();
    },
  };
  return self;
}
