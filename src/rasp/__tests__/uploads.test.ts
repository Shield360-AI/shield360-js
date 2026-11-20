/**
 * Uploads (README "Uploads"): the conformance corpus, inspection of fixture
 * files built here (never real malware: the shells are inert text and EICAR is
 * the industry's harmless test string), the policy, the deep scan against a
 * fake clamd on a Unix socket, and the backdoor checks through the real fs,
 * child_process and require hooks.
 */
import cp = require('child_process');
import fs = require('fs');
import { createServer, type Server } from 'net';
import { tmpdir } from 'os';
import { join } from 'path';
import { captureBody, captureRequest } from '../capture';
import { storage } from '../context';
import { configureEngine, setEventSink } from '../engine';
import { installFsHooks, uninstallFsHooks } from '../hooks/fs';
import { installIncludeHooks, uninstallIncludeHooks } from '../hooks/include';
import { installProcessHooks, uninstallProcessHooks } from '../hooks/process';
import { RaspBlockedError, type AttackType, type RaspMode } from '../types';
import { inspectUpload, multipartFiles, verdictOfFile } from '../upload';
import { resetScannerStatus, SCANNER_EVENT } from '../upload-deep';
import { hasDoubleExtension, inspectBytes, isServerConfigName, sniffType, typeMismatch, UPLOAD_RULE_ORDER, zipEntries } from '../upload-inspect';
import { configureUploads, effectivePolicy, parseUploadsBlock, setRemoteUploads, type UploadOptions } from '../upload-policy';
import { compileSignature, compileSignatures, matchSample } from '../upload-signatures';
import { rememberLocation, resetLocations, uploadAt } from '../upload-taint';

const REPO = join(__dirname, '..', '..', '..', '..', '..');
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const corpus: any = JSON.parse(fs.readFileSync(join(REPO, 'sdk/rasp/testdata/uploads.json'), 'utf8'));

// ---- fixtures -------------------------------------------------------------------

const EICAR = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10]), Buffer.from('JFIF\u0000'), Buffer.alloc(200, 7)]);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(300, 1)]);
const PDF = Buffer.from('%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n');
const CSV = Buffer.from('name,amount,note\nalice,3,"on time"\nbob,5,late\n');
const SHELL = '<?php @eval($_POST["x"]); ?>';

type Entry = { name: string; data?: Buffer; symlink?: boolean; encrypted?: boolean; declaredSize?: number };

/** A stored (uncompressed) zip, written by hand, with optional link, encryption and declared-size tricks. */
function zip(entries: Entry[]): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const data = e.data ?? Buffer.alloc(0);
    const name = Buffer.from(e.name);
    const flags = e.encrypted ? 1 : 0;
    const size = e.declaredSize ?? data.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(e.symlink ? (3 << 8) | 20 : 20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(flags, 8);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(size, 24);
    cd.writeUInt16LE(name.length, 28);
    cd.writeUInt32LE(e.symlink ? (0o120777 << 16) >>> 0 : 0, 38);
    cd.writeUInt32LE(offset, 42);
    locals.push(local, name, data);
    central.push(cd, name);
    offset += 30 + name.length + data.length;
  }
  const cdBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cdBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cdBuf, end]);
}

/** A ustar archive with one entry of the given type flag. */
function tar(name: string, type = '0', data = Buffer.from('x')): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 'latin1');
  h.write('0000644\u0000', 100);
  h.write(data.length.toString(8).padStart(11, '0') + '\u0000', 124);
  h.write(type, 156);
  h.write('ustar\u000000', 257);
  const body = Buffer.alloc(Math.ceil(data.length / 512) * 512);
  data.copy(body);
  return Buffer.concat([h, body, Buffer.alloc(1024)]);
}

const rule = (data: Buffer, name?: string, contentType?: string) => inspectBytes(data, { name, contentType }).findings[0]?.rule;

// ---- the corpus -------------------------------------------------------------------

describe('conformance (testdata/uploads.json)', () => {
  it('signatures file is byte-identical to sdk/rasp/rules', () => {
    expect(fs.readFileSync(join(__dirname, '..', 'data', 'upload-signatures.json')).equals(fs.readFileSync(join(REPO, 'sdk/rasp/rules/upload-signatures.json')))).toBe(true);
  });

  it('every built-in signature compiles', () => {
    const raw = JSON.parse(fs.readFileSync(join(REPO, 'sdk/rasp/rules/upload-signatures.json'), 'utf8')).rules;
    for (const [i, r] of raw.entries()) expect([r.id, compileSignature(r, i).ok]).toEqual([r.id, true]);
  });

  it.each(corpus.types.map((t: { hex: string; type: string }) => [t.type, t.hex]))('sniffs %s', (...[type, hex]: any[]) => {
    expect(sniffType(Buffer.from(hex as string, 'hex'))).toBe(type);
  });

  it.each(corpus.names.map((n: { name: string; rules: string[] }) => [n.name, n.rules]))('name %j raises %j', (...[name, rules]: any[]) => {
    const got = [isServerConfigName(name as string) && 'upload.server_config', hasDoubleExtension(name as string) && 'upload.double_extension'].filter(Boolean);
    expect(got.sort()).toEqual([...(rules as string[])].sort());
  });

  it.each(corpus.mismatch.map((m: { type: string; name?: string; contentType?: string; mismatch: boolean }) => [m.type, m.name, m.contentType, m.mismatch]))(
    'type %s named %s declared %s: mismatch %s',
    (...[type, name, contentType, expected]: any[]) => {
      expect(typeMismatch(type as string, { name: name as string | undefined, contentType: contentType as string | undefined })).toBe(expected);
    },
  );

  it.each(corpus.signatures.map((s: { rule: { id: string }; sample: string; match: boolean }) => [s.rule.id, s]))('signature %s', (...[, s]: any[]) => {
    const c = s as { rule: unknown; sample: string; match: boolean };
    const compiled = compileSignature(c.rule);
    expect(compiled.ok).toBe(true);
    const sample = c.sample === '@@ACROSS@@' ? Buffer.concat([Buffer.alloc(1048570, 'x'), Buffer.from('MARKERTEXT'), Buffer.alloc(100, 'x')]) : Buffer.from(c.sample, 'utf8');
    expect(matchSample(compiled.ok ? [compiled.signature] : [], sample).length > 0).toBe(c.match);
  });

  it.each(corpus.invalid.map((s: { rule: unknown; code: string }) => [s.code, s.rule]))('refuses (%s)', (...[code, raw]: any[]) => {
    const r = compileSignature(raw);
    expect(r.ok ? null : r.error.code).toBe(code);
  });

  it('caps the organization\'s own rules', () => {
    const one = { id: 'r', title: 't', strings: [{ id: 'a', text: 'abc' }], condition: 'any' };
    expect(compileSignatures(Array.from({ length: 65 }, (_, i) => ({ ...one, id: `r${i}` }))).errors[0].code).toBe('too_many');
    const big = { ...one, title: 'x'.repeat(100), strings: Array.from({ length: 16 }, (_, i) => ({ id: `s${i}`, text: 'y'.repeat(256) })) };
    expect(compileSignatures(Array.from({ length: 20 }, (_, i) => ({ ...big, id: `b${i}` }))).errors[0].code).toBe('too_large');
    expect(compileSignatures([one, one]).errors[0].code).toBe('duplicate_id');
  });

  it('bounds regex work on hostile input (no catastrophic backtracking, fixed step budget)', () => {
    const c = compileSignature({ id: 'r', title: 't', strings: [{ id: 'a', regex: '(a|aa)*b', anchor: 'aaa' }], condition: 'any' });
    expect(c.ok).toBe(true);
    const started = Date.now();
    expect(matchSample(c.ok ? [c.signature] : [], Buffer.alloc(4 * 1024 * 1024, 'a'))).toEqual([]);
    expect(Date.now() - started).toBeLessThan(5000);
  });
});

// ---- inspection ---------------------------------------------------------------------

describe('inspection of fixture files', () => {
  it('flags an image with an embedded PHP web shell', () => {
    const v = inspectBytes(Buffer.concat([JPEG, Buffer.from(SHELL), Buffer.alloc(50, 9)]), { name: 'profile.jpg', contentType: 'image/jpeg' });
    expect(v.type).toBe('jpeg');
    expect(v.findings[0]).toMatchObject({ rule: 'upload.webshell', signature: 'php.eval_request' });
    expect(v.findings.map((f) => f.rule)).toContain('upload.polyglot');
  });

  it('flags a .jpg that is really PHP', () => {
    expect(inspectBytes(Buffer.from('<?php system($_GET["c"]); ?>'), { name: 'avatar.jpg', contentType: 'image/jpeg' }).findings[0]).toMatchObject({ rule: 'upload.webshell', signature: 'php.exec_request' });
    const plain = inspectBytes(Buffer.from('<?php echo "hello"; ?>'), { name: 'avatar.jpg' });
    expect([plain.type, plain.findings[0].rule]).toEqual(['php', 'upload.script']);
  });

  it('flags an SVG with script and with an event handler', () => {
    expect(rule(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), 'logo.svg')).toBe('upload.active_content');
    expect(rule(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="x()"></svg>'), 'logo.svg')).toBe('upload.active_content');
    expect(rule(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>'), 'logo.svg')).toBeUndefined();
  });

  it('flags zip-slip, links, bombs and encrypted archives (declared sizes, nothing inflated)', () => {
    expect(rule(zip([{ name: '../../var/www/html/x.php', data: Buffer.from('a') }]), 'a.zip')).toBe('upload.archive_traversal');
    expect(rule(zip([{ name: 'C:\\Windows\\x.dll', data: Buffer.from('a') }]), 'a.zip')).toBe('upload.archive_traversal');
    expect(rule(zip([{ name: 'link', data: Buffer.from('/etc/passwd'), symlink: true }]), 'a.zip')).toBe('upload.archive_symlink');
    expect(rule(zip([{ name: 'big.bin', data: Buffer.alloc(1000), declaredSize: 4000 * 1024 * 1024 }]), 'a.zip')).toBe('upload.archive_bomb');
    expect(rule(zip([{ name: 'secret.txt', data: Buffer.from('xxxx'), encrypted: true }]), 'a.zip')).toBe('upload.archive_encrypted');
    expect(rule(tar('../etc/cron.d/x'), 'a.tar')).toBe('upload.archive_traversal');
    expect(rule(tar('link', '2'), 'a.tar')).toBe('upload.archive_symlink');
  });

  it('flags a macro document and an OLE macro stub', () => {
    const docm = zip([{ name: '[Content_Types].xml', data: Buffer.from('<Types/>') }, { name: 'word/document.xml', data: Buffer.from('<w/>') }, { name: 'word/vbaProject.bin', data: Buffer.from('stub') }]);
    const v = inspectBytes(docm, { name: 'report.docx' });
    expect([v.type, v.findings[0].rule]).toEqual(['docx', 'upload.office_macro']);
    const ole = Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.alloc(100), Buffer.from('_VBA_PROJECT', 'utf16le')]);
    expect(rule(ole, 'old.doc')).toBe('upload.office_macro');
  });

  it('flags EICAR, executables and server config names', () => {
    expect(rule(EICAR, 'test.txt')).toBe('upload.eicar');
    expect(rule(Buffer.concat([EICAR, Buffer.from('\r\n')]), 'test.txt')).toBe('upload.eicar');
    expect(rule(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0]), 'cat.png')).toBe('upload.executable');
    expect(rule(Buffer.from('AddType application/x-httpd-php .jpg\n'), '.htaccess')).toBe('upload.server_config');
    expect(rule(PNG, 'shell.php.png')).toBe('upload.double_extension');
  });

  it('passes a benign PDF, image and CSV', () => {
    for (const [data, name, ct] of [[PDF, 'invoice.pdf', 'application/pdf'], [PNG, 'photo.png', 'image/png'], [JPEG, 'me.jpg', 'image/jpeg'], [CSV, 'data.csv', 'text/csv']] as const) {
      const v = inspectBytes(data, { name, contentType: ct });
      expect([name, v.findings]).toEqual([name, []]);
      expect(v.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('finds a shell appended after a large image (the tail is read past scanBytes)', () => {
    const dir = fs.mkdtempSync(join(tmpdir(), 'rasp-up-'));
    const p = join(dir, 'big.jpg');
    fs.writeFileSync(p, Buffer.concat([JPEG, Buffer.alloc(10 * 1024 * 1024, 3), Buffer.from(SHELL)]));
    const v = verdictOfFile(p, { name: 'big.jpg' }, effectivePolicy(undefined));
    expect(v?.findings[0]?.rule).toBe('upload.webshell');
    expect(v?.sha256).toBeUndefined();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('reports findings in the contract order', () => {
    expect(UPLOAD_RULE_ORDER[0]).toBe('upload.eicar');
    expect(zipEntries(zip([{ name: 'a.txt', data: Buffer.from('a') }]))?.entries.map((e) => e.name)).toEqual(['a.txt']);
  });

  it('reads multipart bodies', () => {
    const b = '----b';
    const body = Buffer.concat([
      Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n--${b}\r\nContent-Disposition: form-data; name="avatar"; filename="me.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
      JPEG,
      Buffer.from(`\r\n--${b}--\r\n`),
    ]);
    const files = multipartFiles(body, `multipart/form-data; boundary=${b}`);
    expect(files.map((f) => [f.field, f.meta.name, f.meta.contentType, f.bytes.length])).toEqual([['avatar', 'me.jpg', 'image/jpeg', JPEG.length]]);
  });
});

// ---- events, policy, modes -------------------------------------------------------------

const events: { name: string; attrs: Record<string, string> }[] = [];
const engine = (attacks: Partial<Record<AttackType, RaspMode>> = {}, monitorOnly = false) => {
  configureEngine({ enabled: true, applicationName: 'a', mode: 'monitor', attacks, env: {}, monitorOnly });
  setEventSink({ add: (e) => events.push(e) });
};
const last = <T>(xs: T[]): T | undefined => xs[xs.length - 1];
const uploadEvents = () => events.filter((e) => e.name === 'shield360.rasp.event' && /upload/.test(e.attrs['shield360.rasp.attack']));
const multerFile = (originalname: string, buffer: Buffer, mimetype = 'application/octet-stream') => ({ fieldname: 'avatar', originalname, mimetype, buffer, size: buffer.length });
const request = (url = '/api/avatar') => captureRequest({ framework: 'test', method: 'POST', url, headers: { 'content-type': 'multipart/form-data; boundary=x' } });

beforeEach(() => {
  events.length = 0;
  resetLocations();
  resetScannerStatus();
  configureUploads(undefined);
  engine();
});
afterAll(() => {
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

describe('upload events and policy', () => {
  it('reports the first finding with the upload attributes, never the name or content', () => {
    captureBody(request(), { body: {}, files: multerFile('profile.jpg', Buffer.concat([JPEG, Buffer.from(SHELL)]), 'image/jpeg') });
    const e = uploadEvents()[0];
    expect(e.attrs).toMatchObject({
      'shield360.rasp.attack': 'malicious_upload',
      'shield360.rasp.rule': 'upload.webshell',
      'shield360.rasp.decision': 'monitored',
      'shield360.rasp.input_key': 'body.avatar.filename',
      'shield360.rasp.upload.type': 'jpeg',
      'shield360.rasp.upload.ext': 'jpg',
      'shield360.rasp.upload.signature': 'php.eval_request',
      'shield360.rasp.upload.engine': 'builtin',
    });
    expect(e.attrs['shield360.rasp.upload.sha256']).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(e)).not.toMatch(/profile|eval\(/);
  });

  it('blocks when malicious_upload blocks; capped rules never block', () => {
    engine({ malicious_upload: 'block' });
    expect(() => captureBody(request(), { body: {}, files: multerFile('a.jpg', Buffer.from(SHELL)) })).toThrow(RaspBlockedError);
    engine({ malicious_upload: 'block' });
    expect(() => captureBody(request(), { body: {}, files: multerFile('a.jpg', zip([{ name: 'x.txt', data: Buffer.from('a') }])) })).not.toThrow();
    expect(last(uploadEvents())?.attrs['shield360.rasp.rule']).toBe('upload.type_mismatch');
    expect(last(uploadEvents())?.attrs['shield360.rasp.decision']).toBe('monitored');
  });

  it('applies a route policy from the signed config: allowed types, size and its own mode', () => {
    setRemoteUploads({ routes: [{ route: '/api/avatar', allow: ['image'], maxBytes: 100, mode: 'block' }] });
    expect(() => captureBody(request(), { body: {}, files: multerFile('a.pdf', PDF) })).toThrow(expect.objectContaining({ rule: 'upload.type_not_allowed' }));
    expect(() => captureBody(request(), { body: {}, files: multerFile('a.png', PNG) })).toThrow(expect.objectContaining({ rule: 'upload.too_large' }));
    // Another route: the app's (empty) policy, the attack mode (monitor).
    expect(() => captureBody(request('/api/docs'), { body: {}, files: multerFile('a.pdf', PDF) })).not.toThrow();
  });

  it('caps a route mode like an attack mode: no pinned key, local off', () => {
    setRemoteUploads({ routes: [{ route: '/api/*', allow: ['image'], mode: 'block' }] });
    engine({}, true);
    expect(() => captureBody(request(), { body: {}, files: multerFile('a.pdf', PDF) })).not.toThrow();
    expect(last(uploadEvents())?.attrs['shield360.rasp.decision']).toBe('monitored');
    events.length = 0;
    engine({ malicious_upload: 'off' });
    captureBody(request(), { body: {}, files: multerFile('a.pdf', PDF) });
    expect(uploadEvents()).toHaveLength(0);
  });

  it('lets a type the route lists by name past the type checks, and nothing else', () => {
    engine({ malicious_upload: 'block' });
    setRemoteUploads({ routes: [{ route: '/api/avatar', allow: ['executable'] }] });
    expect(() => captureBody(request(), { body: {}, files: multerFile('tool.bin', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0])) })).not.toThrow();
    expect(() => captureBody(request(), { body: {}, files: multerFile('a.jpg', Buffer.from(SHELL)) })).toThrow(expect.objectContaining({ rule: 'upload.webshell' }));
  });

  it('skips a file someone marked safe (trusted hash)', () => {
    const shell = Buffer.from(SHELL);
    const sha = inspectBytes(shell).sha256 as string;
    setRemoteUploads({ trusted: [sha] });
    captureBody(request(), { body: {}, files: multerFile('a.php.txt', shell) });
    expect(uploadEvents().filter((e) => e.attrs['shield360.rasp.rule'] === 'upload.webshell')).toHaveLength(0);
  });

  it('runs own signatures only with the deep scan on, decided by its mode', () => {
    const rules = [{ id: 'acme.marker', title: 'ACME', strings: [{ id: 'a', text: 'ACME-INTERNAL-ONLY' }], condition: 'any' }];
    setRemoteUploads({ rules });
    captureBody(request(), { body: {}, files: multerFile('a.txt', Buffer.from('x ACME-INTERNAL-ONLY y')) });
    expect(uploadEvents()).toHaveLength(0);
    setRemoteUploads({ rules, deepScan: { mode: 'block' } });
    expect(() => captureBody(request(), { body: {}, files: multerFile('a.txt', Buffer.from('x ACME-INTERNAL-ONLY y')) })).toThrow(expect.objectContaining({ rule: 'upload.signature' }));
  });

  it('reads the uploads block with every bound', () => {
    const c = parseUploadsBlock({
      maxBytes: -1,
      allow: ['image', 'nonsense'],
      servedDirs: ['relative/dir', '/srv/public'],
      trusted: ['ABC', 'a'.repeat(64)],
      deepScan: { mode: 'block', scan: 'async', timeoutMs: 999999, failMode: 'closed', clamav: { address: 'tcp:clamav:3310' }, reputation: true, testId: 'abcdefgh1' },
      routes: [{ route: 'no-slash' }, { route: '/x', deepScan: 'monitor', timeoutMs: 1 }],
    });
    expect(c).toMatchObject({ maxBytes: null, allow: ['image'], servedDirs: ['/srv/public'], deepScan: { mode: 'block', scan: 'async', timeoutMs: 60000, failMode: 'closed', clamav: { kind: 'tcp', host: 'clamav', port: 3310 }, reputation: true, testId: 'abcdefgh1' } });
    expect([...(c?.trusted ?? [])]).toEqual(['a'.repeat(64)]);
    expect(c?.routes).toEqual([{ route: '/x', deepScan: 'monitor', timeoutMs: 100 }]);
    expect(parseUploadsBlock({ deepScan: { clamav: { address: 'unix:relative' } } })?.deepScan.clamav).toBeNull();
    expect(parseUploadsBlock(null)).toBeNull();
  });
});

// ---- deep scan --------------------------------------------------------------------------

/** A fake clamd on a Unix socket: `found` names a signature for every stream, else OK. */
function fakeClamd(socket: string, found: string | null): Promise<Server> {
  const server = createServer((s) => {
    let buf = Buffer.alloc(0);
    s.on('data', (d) => {
      buf = Buffer.concat([buf, Buffer.from(d)]);
      if (buf.subarray(0, 6).toString() === 'zPING\u0000') return void s.end('PONG\u0000');
      if (buf.subarray(0, 10).toString() !== 'zINSTREAM\u0000') return;
      let p = 10;
      while (p + 4 <= buf.length) {
        const n = buf.readUInt32BE(p);
        if (n === 0) return void s.end(found ? `stream: ${found} FOUND\u0000` : 'stream: OK\u0000');
        p += 4 + n;
      }
    });
  });
  return new Promise((resolve) => server.listen(socket, () => resolve(server)));
}

describe('deep scan', () => {
  let dir: string;
  let server: Server | undefined;
  beforeEach(() => {
    dir = fs.mkdtempSync(join(tmpdir(), 'rasp-deep-'));
  });
  afterEach(async () => {
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    server = undefined;
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const opts = (deep: UploadOptions['deepScan'], quarantineDir?: string): UploadOptions => ({ deepScan: deep, ...(quarantineDir ? { quarantineDir } : {}) });

  it('blocks synchronously on a ClamAV hit, with the engine and signature', async () => {
    const sock = join(dir, 'clamd.sock');
    server = await fakeClamd(sock, 'Win.Test.EICAR_HDB-1');
    configureUploads(opts({ mode: 'block', clamav: `unix:${sock}` }));
    await expect(inspectUpload(Buffer.from('anything'), { name: 'x.txt' })).rejects.toMatchObject({ rule: 'upload.malware' });
    expect(last(uploadEvents())?.attrs).toMatchObject({ 'shield360.rasp.upload.engine': 'clamav', 'shield360.rasp.upload.signature': 'Win.Test.EICAR_HDB-1', 'shield360.rasp.sink': 'upload.deep_scan' });
  });

  it('lets a clean file through', async () => {
    const sock = join(dir, 'clamd.sock');
    server = await fakeClamd(sock, null);
    configureUploads(opts({ mode: 'block', clamav: `unix:${sock}` }));
    await expect(inspectUpload(PNG, { name: 'a.png' })).resolves.toMatchObject({ type: 'png' });
    expect(events.find((e) => e.name === SCANNER_EVENT)?.attrs['shield360.rasp.scanner.status']).toBe('ok');
  });

  it('scanner down, fail open: the file passes and the status says unreachable', async () => {
    configureUploads(opts({ mode: 'block', clamav: `unix:${join(dir, 'missing.sock')}`, failMode: 'open', timeoutMs: 500 }));
    await expect(inspectUpload(PNG, { name: 'a.png' })).resolves.toBeDefined();
    const status = events.find((e) => e.name === SCANNER_EVENT)?.attrs;
    expect(status).toMatchObject({ 'shield360.rasp.scanner.engine': 'clamav', 'shield360.rasp.scanner.status': 'unreachable', 'shield360.rasp.scanner.fail_mode': 'open' });
    expect(uploadEvents()).toHaveLength(0);
  });

  it('scanner down, fail closed: the file is refused with upload.scan_unavailable', async () => {
    configureUploads(opts({ mode: 'block', clamav: `unix:${join(dir, 'missing.sock')}`, failMode: 'closed', timeoutMs: 500 }));
    await expect(inspectUpload(PNG, { name: 'a.png' })).rejects.toMatchObject({ rule: 'upload.scan_unavailable' });
    configureUploads(opts({ mode: 'monitor', clamav: `unix:${join(dir, 'missing.sock')}`, failMode: 'closed', timeoutMs: 500 }));
    await expect(inspectUpload(PNG, { name: 'a.png' })).resolves.toBeDefined();
    expect(last(uploadEvents())?.attrs['shield360.rasp.decision']).toBe('monitored');
  });

  it('async scan in block mode moves the saved file to quarantine', async () => {
    const sock = join(dir, 'clamd.sock');
    server = await fakeClamd(sock, 'Eicar-Test-Signature');
    const q = join(dir, 'quarantine');
    configureUploads(opts({ mode: 'block', scan: 'async', clamav: `unix:${sock}` }, q));
    const saved = join(dir, 'upload.bin');
    fs.writeFileSync(saved, 'inert fixture');
    await expect(inspectUpload(saved, { name: 'upload.bin' })).resolves.toBeDefined();
    expect(fs.existsSync(saved)).toBe(false);
    const moved = fs.readdirSync(q);
    expect(moved).toHaveLength(1);
    expect(fs.statSync(join(q, moved[0])).mode & 0o777).toBe(0o600);
    expect(last(uploadEvents())?.attrs['shield360.rasp.upload.action']).toBe('quarantined');
  });
});

// ---- backdoor checks ----------------------------------------------------------------------

describe('backdoor checks', () => {
  let dir: string;
  beforeAll(() => {
    installFsHooks();
    installProcessHooks();
  });
  afterAll(() => {
    uninstallFsHooks();
    uninstallProcessHooks();
  });
  beforeEach(() => {
    dir = fs.mkdtempSync(join(tmpdir(), 'rasp-taint-'));
    fs.mkdirSync(join(dir, 'public'));
    fs.mkdirSync(join(dir, 'private'));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  /** Runs fn inside a multipart request that carries one upload (multer memory storage). */
  const withUpload = <T>(name: string, data: Buffer, fn: () => T): T => {
    const ctx = request();
    captureBody(ctx, { body: {}, files: multerFile(name, data) });
    return storage.run(ctx, fn);
  };
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>steal()</script></svg>');

  it('blocks an active upload saved to the web root', () => {
    engine({ upload_backdoor: 'block' });
    const dest = join(dir, 'public', 'avatar.svg');
    expect(() => withUpload('avatar.svg', svg, () => fs.writeFileSync(dest, svg))).toThrow(expect.objectContaining({ rule: 'backdoor.write_served' }));
    expect(fs.existsSync(dest)).toBe(false);
    const e = events.find((x) => x.attrs['shield360.rasp.rule'] === 'backdoor.write_served');
    expect(e?.attrs['shield360.rasp.upload.dest']).toBeTruthy();
    expect(e?.attrs['shield360.rasp.upload.dest']).not.toContain('avatar');
  });

  it('blocks any upload saved under an executable name, even renamed later', () => {
    engine({ upload_backdoor: 'block' });
    const tmp = join(dir, 'private', 'upload.tmp');
    withUpload('notes.txt', Buffer.from('text'), () => fs.writeFileSync(tmp, Buffer.from('text')));
    expect(uploadAt(tmp)).toBeDefined();
    expect(() => fs.renameSync(tmp, join(dir, 'public', 'x.php'))).toThrow(expect.objectContaining({ rule: 'backdoor.write_executable' }));
  });

  it('blocks running an uploaded file', () => {
    const dest = join(dir, 'private', 'tool');
    withUpload('tool', Buffer.from('#!/bin/sh\necho owned\n'), () => fs.writeFileSync(dest, Buffer.from('#!/bin/sh\necho owned\n')));
    engine({ upload_backdoor: 'block' });
    expect(() => cp.execFileSync(dest)).toThrow(expect.objectContaining({ rule: 'backdoor.exec' }));
    expect(() => cp.execFileSync('/bin/sh', [dest])).toThrow(expect.objectContaining({ rule: 'backdoor.exec' }));
    expect(() => cp.execSync(`sh "${dest}"`)).toThrow(expect.objectContaining({ rule: 'backdoor.exec' }));
  });

  it('blocks making an uploaded file executable', () => {
    const dest = join(dir, 'private', 'blob');
    withUpload('blob', Buffer.from('data'), () => fs.writeFileSync(dest, Buffer.from('data')));
    engine({ upload_backdoor: 'block' });
    expect(() => fs.chmodSync(dest, 0o755)).toThrow(expect.objectContaining({ rule: 'backdoor.chmod' }));
    expect(() => fs.chmodSync(dest, 0o644)).not.toThrow();
  });

  it('blocks requiring an uploaded file', () => {
    // Under Jest, Module.prototype is Jest's own: the hook is installed on a stand-in that resolves like Node.
    const target = { require: (id: string) => id };
    const p = join(dir, 'private', 'plugin.js');
    rememberLocation(p, inspectBytes(Buffer.from('module.exports = 1'), { name: 'plugin.js' }));
    installIncludeHooks(target as never);
    try {
      engine({ upload_backdoor: 'block' });
      expect(() => target.require(p)).toThrow(expect.objectContaining({ rule: 'backdoor.include' }));
      expect(target.require(join(dir, 'private', 'other.js'))).toBeDefined();
    } finally {
      uninstallIncludeHooks();
    }
  });

  it('lets a benign upload saved to private storage through without a report', () => {
    engine({ upload_backdoor: 'block', malicious_upload: 'block' });
    const dest = join(dir, 'private', 'photo.png');
    withUpload('photo.png', PNG, () => fs.writeFileSync(dest, PNG));
    expect(fs.existsSync(dest)).toBe(true);
    expect(uploadEvents()).toHaveLength(0);
  });

  it('lets a benign image into the web root (avatars are normal)', () => {
    engine({ upload_backdoor: 'block' });
    const dest = join(dir, 'public', 'avatar.png');
    withUpload('avatar.png', PNG, () => fs.writeFileSync(dest, PNG));
    expect(fs.existsSync(dest)).toBe(true);
  });

  it('inspects a stream a multipart request writes (busboy, multer disk storage) and quarantines in block mode', async () => {
    const q = join(dir, 'q');
    configureUploads({ quarantineDir: q });
    engine({ malicious_upload: 'block' });
    const dest = join(dir, 'private', 'upload-1');
    const ctx = request();
    await new Promise<void>((resolve) => {
      storage.run(ctx, () => {
        const ws = fs.createWriteStream(dest);
        ws.on('finish', () => setImmediate(resolve));
        ws.write(Buffer.from('<?php system($_GET["c"]);'));
        ws.end(Buffer.from(' ?>'));
      });
    });
    expect(fs.existsSync(dest)).toBe(false);
    expect(fs.readdirSync(q)).toHaveLength(1);
    expect(events.find((e) => e.attrs['shield360.rasp.rule'] === 'upload.webshell')?.attrs['shield360.rasp.decision']).toBe('blocked');
  });
});
