/**
 * Uploads (README "Uploads"): turns what the inspector, the policy and the
 * deep scan say about an uploaded file into findings, events and blocks, and
 * remembers where the file was saved for the backdoor checks.
 *
 * Where the SDK sees an upload:
 *   - parser file objects (multer `buffer`/`path`, formidable `filepath`), when
 *     the middleware captures the body (capture.ts);
 *   - a raw multipart body (capture.ts);
 *   - every stream the app writes during a multipart request (hooks/fs.ts):
 *     busboy, multer's disk storage, an app's own pipe;
 *   - `withRasp` (the request's form data), `uploadGuard()` and
 *     `inspectUpload()`, where the deep scan can hold the upload (sync).
 *
 * Fail open: anything that goes wrong lets the upload through; the only error
 * thrown on purpose is the block error.
 */
import * as fs from 'fs';
import { basename } from 'path';
import { currentContext, eventRouteOf, storage, type RaspContext } from './context';
import { handleFinding, isActive, strongest, wouldBlock } from './engine';
import { deepScan, quarantine, type ScanSource } from './upload-deep';
import { kindOf, nameFindings, ruleRank, UploadScanner, type UploadFinding, type UploadMeta, type UploadVerdict } from './upload-inspect';
import { effectivePolicy, uploadConfig, uploadScanBytes, type EffectivePolicy } from './upload-policy';
import { addRequestUpload, checkNewLocation, forgetLocation, locationsOf, rememberLocation, uploadAt } from './upload-taint';
import { RaspBlockedError, type Finding } from './types';

// Captured at load, before the fs hook, so reading an upload never trips RASP itself.
const openSync = fs.openSync.bind(fs);
const readSync = fs.readSync.bind(fs);
const closeSync = fs.closeSync.bind(fs);
const fstatSync = fs.fstatSync.bind(fs);

export const UPLOAD_SINK = 'request.upload';
export const DEEP_SINK = 'upload.deep_scan';
const PIECE = 1024 * 1024;
const TAIL = 1024 * 1024;

const routeOf = (ctx: RaspContext | undefined) => ctx?.route ?? (ctx?.path ? eventRouteOf(ctx.path) : undefined);

/** The scanner for an upload under the policy in force: own signatures only when the deep scan is on. */
function scanner(meta: UploadMeta, policy: EffectivePolicy): UploadScanner {
  const c = uploadConfig();
  return new UploadScanner(meta, { scanBytes: uploadScanBytes(), trusted: c.trusted, custom: policy.deepScan.mode !== 'off' ? c.rules : undefined });
}

/** Inspects bytes in memory. */
export function verdictOfBytes(bytes: Uint8Array, meta: UploadMeta, policy: EffectivePolicy): UploadVerdict {
  const s = scanner(meta, policy);
  for (let i = 0; i < bytes.byteLength; i += PIECE) s.push(bytes.subarray(i, i + PIECE));
  return s.finish(true);
}

/**
 * Inspects a file on disk: the first `scanBytes` and the last 1 MiB (README
 * "Uploads"); the whole file when it is no larger, and only then is it hashed.
 */
export function verdictOfFile(path: string, meta: UploadMeta, policy: EffectivePolicy): UploadVerdict | null {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    const size = fstatSync(fd).size;
    const s = scanner(meta, policy);
    const limit = uploadScanBytes();
    const buf = Buffer.alloc(PIECE);
    const whole = size <= limit + TAIL;
    let pos = 0;
    const readTo = (end: number) => {
      while (pos < end) {
        const n = readSync(fd as number, buf, 0, Math.min(PIECE, end - pos), pos);
        if (n <= 0) break;
        s.push(Buffer.from(buf.subarray(0, n)));
        pos += n;
      }
    };
    if (whole) readTo(size);
    else {
      readTo(limit);
      // The skipped middle counts toward the size; the hash is not reported.
      s.skip(size - TAIL - pos);
      pos = size - TAIL;
      readTo(size);
    }
    return s.finish(whole);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // nothing to do
      }
    }
  }
}

/** The policy's findings for a verdict (README: `upload.type_not_allowed`, `upload.too_large`). */
export function policyFindings(v: UploadVerdict, p: EffectivePolicy): UploadFinding[] {
  const out: UploadFinding[] = [];
  if (p.allow.length && !p.allow.includes(v.type) && !p.allow.includes(v.kind)) out.push({ rule: 'upload.type_not_allowed', engine: 'policy' });
  if (p.maxBytes !== null && v.size > p.maxBytes) out.push({ rule: 'upload.too_large', engine: 'policy' });
  return out;
}

/** The finding as the engine takes it: the deciding mode, the cap, the event's upload attributes. */
export function uploadFinding(f: UploadFinding, v: UploadVerdict, p: EffectivePolicy, key?: string): Finding {
  const deep = f.engine === 'custom' || f.engine === 'clamav' || f.engine === 'reputation' || f.rule === 'upload.scan_unavailable';
  const mode = deep ? p.deepScan.mode : p.mode;
  return {
    attack: 'malicious_upload',
    rule: f.rule,
    // A location, never a value: the name is not sent, even as a snippet.
    ...(key ? { input: { value: '', key, source: 'request' as const } } : {}),
    ...(mode ? { mode } : {}),
    ...(f.capped ? { action: 'monitor' as const } : {}),
    upload: { type: v.type, kind: v.kind, ext: v.ext, size: v.size, sha256: v.sha256, signature: f.signature, engine: f.engine },
  };
}

/** Applies a finding inside the request's context; quarantines `saved` when it blocks. Rethrows the block error. */
function decide(ctx: RaspContext | undefined, finding: Finding, sink: string, saved?: string, sha256?: string): void {
  const run = () => handleFinding(finding, sink, ctx ? { framework: ctx.framework, route: ctx.route, method: ctx.method, path: ctx.path } : {});
  try {
    ctx && currentContext() !== ctx ? storage.run(ctx, run) : run();
  } catch (e) {
    if (e instanceof RaspBlockedError && saved && quarantine(saved, sha256)) forgetLocation(saved);
    throw e;
  }
}

export type SeenUpload = {
  ctx: RaspContext | undefined;
  field: string;
  meta: UploadMeta;
  verdict: UploadVerdict;
  /** Where the file is saved, when known. */
  saved?: string;
  /** Findings already reported for these bytes (a stream inspected before its name was known). */
  reported?: boolean;
};

/**
 * Reports what one upload is (the first finding, README "Inspection rules"),
 * records it on the request and checks its saved location. Throws the block
 * error when one blocks.
 */
export function applyUpload(u: SeenUpload): void {
  const policy = effectivePolicy(routeOf(u.ctx));
  const v = u.verdict;
  const key = `body.${u.field}.filename`;
  const findings = u.reported
    ? nameFindings(u.meta.name ?? '', v.type, u.meta.contentType)
    : [...v.findings.filter((f) => f.engine !== 'custom' || policy.deepScan.mode !== 'off'), ...policyFindings(v, policy)];
  findings.sort((a, b) => ruleRank(a.rule) - ruleRank(b.rule));
  if (u.ctx) addRequestUpload(u.ctx, { field: u.field, name: u.meta.name ?? '', verdict: v });
  // One event a file: the finding with the strongest decision, the contract's order breaking ties
  // (a capped rule never hides a policy finding that blocks).
  const chosen = strongest(...findings.map((f) => uploadFinding(f, v, policy, key)));
  if (chosen) decide(u.ctx, chosen, UPLOAD_SINK, u.saved, v.sha256);
  if (u.saved) {
    const b = checkNewLocation(u.saved, v);
    if (b) decide(u.ctx, b, UPLOAD_SINK, u.saved, v.sha256);
  }
}

/** Whether the deep scan has an engine to run for this policy. */
export const deepScanOn = (p: EffectivePolicy) => p.deepScan.mode !== 'off' && Boolean(p.deepScan.clamav || p.deepScan.reputation);

/**
 * Runs the deep scan and applies what it says. `sync`: the caller holds the
 * upload until this settles and the block error is thrown; otherwise a
 * blocking finding quarantines the saved file(s) and nothing is thrown.
 */
export async function applyDeepScan(u: SeenUpload, src: ScanSource, sync: boolean): Promise<void> {
  const policy = effectivePolicy(routeOf(u.ctx));
  if (!deepScanOn(policy)) return;
  const v = u.verdict;
  if (v.sha256 && uploadConfig().trusted.has(v.sha256)) return;
  const r = await deepScan(policy.deepScan, src, v.sha256);
  let f: UploadFinding | null = r.finding;
  if (!f && r.failed.length && policy.deepScan.failMode === 'closed') f = { rule: 'upload.scan_unavailable', engine: r.failed[0] };
  if (!f) return;
  const key = `body.${u.field}.filename`;
  const finding = uploadFinding(f, v, policy, key);
  if (sync) {
    decide(u.ctx, finding, DEEP_SINK, u.saved, v.sha256);
    return;
  }
  // Async: the app already has the file. Blocking moves every saved copy to quarantine first.
  let moved = false;
  if (wouldBlock(finding)) {
    for (const path of new Set([...(u.saved ? [u.saved] : []), ...locationsOf(v)])) {
      if (quarantine(path, v.sha256)) {
        forgetLocation(path);
        moved = true;
      }
    }
  }
  try {
    decide(u.ctx, moved ? { ...finding, upload: { ...finding.upload, action: 'quarantined' } } : finding, DEEP_SINK);
  } catch {
    // Async: nothing to stop; the event says what happened.
  }
}

// ---- parser file objects ----------------------------------------------------

type FileObject = Record<string, unknown>;

/** Reads a parser's file object: multer (`buffer`, `path`), formidable (`filepath`), the web File. */
export function fileObjectSource(o: FileObject): { meta: UploadMeta; bytes?: Uint8Array; path?: string } {
  const name = [o.originalname, o.originalFilename, o.filename, o.name].find((x) => typeof x === 'string' && x) as string | undefined;
  const contentType = [o.mimetype, o.type, o.contentType].find((x) => typeof x === 'string') as string | undefined;
  const bytes = o.buffer instanceof Uint8Array ? o.buffer : undefined;
  const path = [o.path, o.filepath].find((x) => typeof x === 'string' && x) as string | undefined;
  return { meta: { name, contentType }, bytes, path };
}

/**
 * Inspects one file object a parser set aside, during capture. Throws the
 * block error; the deep scan runs async (capture cannot wait).
 */
export function inspectFileObject(ctx: RaspContext, field: string, o: FileObject): void {
  if (!isActive()) return;
  const src = fileObjectSource(o);
  if (!src.bytes && !src.path) return;
  const policy = effectivePolicy(routeOf(ctx));
  const known = src.path ? uploadAt(src.path) : undefined;
  const verdict = known ?? (src.bytes ? verdictOfBytes(src.bytes, src.meta, policy) : verdictOfFile(src.path as string, src.meta, policy));
  if (!verdict) return;
  const seen: SeenUpload = { ctx, field, meta: src.meta, verdict, saved: src.path, reported: Boolean(known) };
  applyUpload(seen);
  if (deepScanOn(policy)) void applyDeepScan(seen, src.bytes ? { bytes: src.bytes } : { path: src.path as string }, false).catch(() => undefined);
}

// ---- raw multipart bodies -----------------------------------------------------

const MAX_PARTS = 32;

/** The file parts of a raw `multipart/form-data` body: field, name, declared type and bytes. */
export function multipartFiles(body: Uint8Array, contentType: string): { field: string; meta: UploadMeta; bytes: Uint8Array }[] {
  const m = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  const boundary = m?.[1] ?? m?.[2];
  if (!boundary) return [];
  const buf = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  const delim = Buffer.from(`--${boundary}`);
  const out: { field: string; meta: UploadMeta; bytes: Uint8Array }[] = [];
  let at = buf.indexOf(delim);
  while (at >= 0 && out.length < MAX_PARTS) {
    const start = at + delim.length;
    if (buf[start] === 0x2d && buf[start + 1] === 0x2d) break;
    const headEnd = buf.indexOf('\r\n\r\n', start);
    if (headEnd < 0) break;
    const next = buf.indexOf(Buffer.concat([Buffer.from('\r\n'), delim]), headEnd + 4);
    const end = next < 0 ? buf.length : next;
    const head = buf.subarray(start, headEnd).toString('latin1');
    const disp = /content-disposition:[^\r\n]*/i.exec(head)?.[0] ?? '';
    const filename = /\bfilename="([^"\r\n]*)"/i.exec(disp)?.[1] ?? /\bfilename=([^;\s]+)/i.exec(disp)?.[1];
    if (filename !== undefined) {
      const field = /\bname="([^"\r\n]*)"/i.exec(disp)?.[1] || 'file';
      const ct = /content-type:\s*([^\r\n]*)/i.exec(head)?.[1]?.trim();
      out.push({ field, meta: { name: Buffer.from(filename, 'latin1').toString('utf8'), contentType: ct }, bytes: buf.subarray(headEnd + 4, end) });
    }
    if (next < 0) break;
    at = next + 2;
  }
  return out;
}

/** Inspects the files of a raw multipart body during capture. Throws the block error. */
export function inspectMultipartBody(ctx: RaspContext, body: Uint8Array, contentType: string): void {
  if (!isActive()) return;
  const policy = effectivePolicy(routeOf(ctx));
  for (const p of multipartFiles(body, contentType)) {
    const seen: SeenUpload = { ctx, field: p.field, meta: p.meta, verdict: verdictOfBytes(p.bytes, p.meta, policy) };
    applyUpload(seen);
    if (deepScanOn(policy)) void applyDeepScan(seen, { bytes: p.bytes }, false).catch(() => undefined);
  }
}

// ---- streams the app writes ----------------------------------------------------

type Writable = { _write?: (...a: unknown[]) => unknown; _writev?: (...a: unknown[]) => unknown; once(ev: string, fn: () => void): unknown };

/**
 * Inspects a stream the app writes during a multipart request as the bytes
 * pass (README "Where the SDK sees uploads"). At `finish` the file is
 * remembered and judged; a blocking finding moves it to quarantine (the
 * bytes are already written) and is reported.
 */
export function watchUploadStream(ws: unknown, path: string, ctx: RaspContext): void {
  try {
    const w = ws as Writable;
    if (!w || typeof w._write !== 'function') return;
    const policy = effectivePolicy(routeOf(ctx));
    const s = scanner({ name: basename(path) }, policy);
    const write = w._write;
    w._write = function (this: unknown, chunk: unknown, ...rest: unknown[]) {
      try {
        if (chunk instanceof Uint8Array) s.push(chunk);
        else if (typeof chunk === 'string') s.push(Buffer.from(chunk));
      } catch {
        // inspection never breaks the write
      }
      return Reflect.apply(write, this, [chunk, ...rest]);
    };
    const writev = w._writev;
    if (typeof writev === 'function') {
      w._writev = function (this: unknown, ...args: unknown[]) {
        const chunks = (Array.isArray(args[0]) ? args[0] : []) as { chunk: unknown }[];
        try {
          for (const c of chunks) if (c.chunk instanceof Uint8Array) s.push(c.chunk);
        } catch {
          // inspection never breaks the write
        }
        return Reflect.apply(writev, this, args);
      };
    }
    w.once('finish', () => {
      try {
        const verdict = s.finish(true);
        // The file name the client sent is not known here: the bytes are judged, the name later (a parser's file object).
        const seen: SeenUpload = { ctx, field: 'file', meta: {}, verdict, saved: path };
        rememberLocation(path, verdict);
        try {
          applyUpload(seen);
        } catch {
          // Blocked: decide() moved the file to quarantine and the event says so.
        }
        if (deepScanOn(policy)) void applyDeepScan(seen, { path }, false).catch(() => undefined);
      } catch {
        // fail open
      }
    });
  } catch {
    // fail open
  }
}

/** Whether the current request is multipart (the fs hook watches its write streams). */
export const isMultipartRequest = (ctx: RaspContext | undefined) => Boolean(ctx?.inRequest && ctx.multipart);

// ---- sync entry points ------------------------------------------------------------

export type InspectResult = { verdict: UploadVerdict; blocked: boolean; rule?: string };

/**
 * Inspects an upload the app holds (bytes or a path) and runs the deep scan
 * synchronously (README: `inspectUpload`). Resolves with the verdict;
 * rejects with the block error when the upload must be refused.
 */
export async function inspectUpload(data: Uint8Array | string, meta: UploadMeta & { field?: string } = {}): Promise<UploadVerdict> {
  const ctx = currentContext();
  const policy = effectivePolicy(routeOf(ctx));
  const isPath = typeof data === 'string';
  const verdict = isPath ? verdictOfFile(data, meta, policy) : verdictOfBytes(data, meta, policy);
  if (!verdict) throw new TypeError('Shield360: the upload could not be read');
  if (!isActive()) return verdict;
  const seen: SeenUpload = { ctx, field: meta.field ?? 'file', meta, verdict, ...(isPath ? { saved: data } : {}) };
  applyUpload(seen);
  await applyDeepScan(seen, isPath ? { path: data } : { bytes: data }, policy.deepScan.scan === 'sync');
  return verdict;
}

/** The files of a parsed multipart request (`req.file` / `req.files`) as [field, object]. */
export function fileObjects(files: unknown): [string, FileObject][] {
  const out: [string, FileObject][] = [];
  const visit = (f: unknown, field: string) => {
    if (out.length < MAX_PARTS && f && typeof f === 'object' && !Array.isArray(f)) out.push([typeof (f as FileObject).fieldname === 'string' ? ((f as FileObject).fieldname as string) : field, f as FileObject]);
  };
  if (Array.isArray(files)) files.forEach((f) => visit(f, 'file'));
  else if (files && typeof files === 'object') {
    const one = files as FileObject;
    if (typeof one.originalname === 'string' || typeof one.fieldname === 'string' || typeof one.filepath === 'string') visit(files, 'file');
    else for (const [field, v] of Object.entries(one)) (Array.isArray(v) ? v : [v]).forEach((f) => visit(f, field));
  }
  return out;
}

/**
 * Express / Connect middleware placed after the upload parser
 * (`app.post('/avatar', upload.single('f'), uploadGuard(), handler)`): holds
 * the request until the deep scan answered for each file, and answers 403
 * when one is blocked (README `deepScan.scan: sync`).
 */
export function uploadGuard() {
  return function shield360UploadGuard(req: { file?: unknown; files?: unknown }, res: unknown, next: (err?: unknown) => void): void {
    if (!isActive()) return next();
    const ctx = currentContext();
    const policy = effectivePolicy(routeOf(ctx));
    const files = fileObjects(req.files ?? req.file);
    const run = async () => {
      for (const [field, o] of files) {
        const src = fileObjectSource(o);
        const verdict = (src.path ? uploadAt(src.path) : undefined) ?? (src.bytes ? verdictOfBytes(src.bytes, src.meta, policy) : src.path ? verdictOfFile(src.path, src.meta, policy) : null);
        if (!verdict) continue;
        const seen: SeenUpload = { ctx, field, meta: src.meta, verdict, saved: src.path };
        if (!ctx?.uploads?.some((u) => u.verdict === verdict)) applyUpload(seen);
        if (deepScanOn(policy) && policy.deepScan.scan === 'sync') await applyDeepScan(seen, src.bytes ? { bytes: src.bytes } : { path: src.path as string }, true);
        else if (deepScanOn(policy)) void applyDeepScan(seen, src.bytes ? { bytes: src.bytes } : { path: src.path as string }, false).catch(() => undefined);
      }
    };
    run().then(
      () => next(),
      (e) => (e instanceof RaspBlockedError ? next(e) : next()),
    );
  };
}

/**
 * The files of a web `FormData` (Next.js `withRasp`): inspected, and the deep
 * scan held when it is sync. Throws the block error.
 */
export async function inspectFormData(ctx: RaspContext, form: FormData): Promise<void> {
  if (!isActive()) return;
  const policy = effectivePolicy(routeOf(ctx));
  let n = 0;
  for (const [field, value] of form.entries()) {
    if (typeof value === 'string' || n++ >= MAX_PARTS) continue;
    const file = value as File;
    const bytes = new Uint8Array(await file.arrayBuffer());
    const meta = { name: file.name, contentType: file.type };
    const seen: SeenUpload = { ctx, field, meta, verdict: verdictOfBytes(bytes, meta, policy) };
    storage.run(ctx, () => applyUpload(seen));
    if (deepScanOn(policy)) {
      if (policy.deepScan.scan === 'sync') await applyDeepScan(seen, { bytes }, true);
      else void applyDeepScan(seen, { bytes }, false).catch(() => undefined);
    }
  }
}

export { kindOf };
