/**
 * Backdoor checks (README "Uploads", "Backdoor checks"): where uploaded files
 * were saved, per process and in memory only, and the checks that fire when
 * the app writes one somewhere executable or served, loads it as code, runs
 * it or makes it executable.
 *
 * Locations are resolved paths, at most 10,000, each kept 24 hours. Nothing
 * here touches the file system; the hooks call in before the call they guard.
 */
import { createHash } from 'crypto';
import { basename } from 'path';
import { currentContext, type RaspContext } from './context';
import { resolvePath, targetDirectory } from './detect';
import { isActiveContent, isExecutableName, type UploadVerdict } from './upload-inspect';
import { isServed } from './upload-policy';
import type { Finding } from './types';

export const MAX_LOCATIONS = 10_000;
export const LOCATION_TTL_MS = 24 * 60 * 60 * 1000;

/** An upload the current request carries. */
export type RequestUpload = { field: string; name: string; verdict: UploadVerdict };

type Location = { verdict: UploadVerdict; until: number };
const locations = new Map<string, Location>();
let now: () => number = Date.now;

/** Tests only. */
export function resetLocations(clock: () => number = Date.now): void {
  locations.clear();
  now = clock;
}

export const locationCount = () => locations.size;

/** Remembers a saved location of an upload (oldest dropped first when full). */
export function rememberLocation(path: string, verdict: UploadVerdict): string {
  const resolved = resolvePath(path);
  locations.delete(resolved);
  if (locations.size >= MAX_LOCATIONS) {
    const t = now();
    for (const [k, v] of locations) if (v.until <= t) locations.delete(k);
    while (locations.size >= MAX_LOCATIONS) locations.delete(locations.keys().next().value as string);
  }
  locations.set(resolved, { verdict, until: now() + LOCATION_TTL_MS });
  return resolved;
}

/** The verdict of the upload saved at a path, if one was. */
export function uploadAt(path: string): UploadVerdict | undefined {
  if (!locations.size || typeof path !== 'string' || !path) return undefined;
  const resolved = resolvePath(path);
  const l = locations.get(resolved);
  if (!l) return undefined;
  if (l.until <= now()) {
    locations.delete(resolved);
    return undefined;
  }
  return l.verdict;
}

/** The known locations of one upload (the same verdict). */
export function locationsOf(v: UploadVerdict): string[] {
  const out: string[] = [];
  for (const [k, l] of locations) if (l.verdict === v || (v.sha256 && l.verdict.sha256 === v.sha256)) out.push(k);
  return out;
}

/** Forgets a location (the file was moved to quarantine). */
export function forgetLocation(path: string): void {
  locations.delete(resolvePath(path));
}

export function requestUploads(ctx: RaspContext | undefined = currentContext()): RequestUpload[] {
  return ctx?.uploads ?? [];
}

export function addRequestUpload(ctx: RaspContext, u: RequestUpload): void {
  (ctx.uploads ??= []).push(u);
}

/** An upload name as written to disk by a careful app: lower case, `[a-z0-9._-]`, the rest `_`. */
export const sanitizedName = (name: string) => name.toLowerCase().replace(/[^a-z0-9._-]/g, '_');

/**
 * The upload a write in this request stores, if any: same bytes (size, then
 * SHA-256), or a file named after one (README "Backdoor checks").
 */
export function uploadWritten(path: string, data: unknown, ctx: RaspContext | undefined = currentContext()): UploadVerdict | undefined {
  const uploads = requestUploads(ctx);
  if (!uploads.length) return undefined;
  if (data !== undefined && data !== null) {
    const bytes = typeof data === 'string' ? Buffer.from(data) : data instanceof Uint8Array ? data : undefined;
    if (bytes) {
      const same = uploads.filter((u) => u.verdict.sha256 && u.verdict.size === bytes.byteLength);
      if (same.length) {
        const h = createHash('sha256').update(bytes).digest('hex');
        const hit = same.find((u) => u.verdict.sha256 === h);
        if (hit) return hit.verdict;
      }
    }
  }
  const name = basename(path);
  return uploads.find((u) => {
    const n = basename(u.name.replace(/\\/g, '/'));
    return n && (n === name || sanitizedName(n) === name);
  })?.verdict;
}

const finding = (rule: string, verdict: UploadVerdict, dest?: string): Finding => ({
  attack: 'upload_backdoor',
  rule,
  upload: { type: verdict.type, kind: verdict.kind, ext: verdict.ext, size: verdict.size, sha256: verdict.sha256, ...(dest ? { dest } : {}) },
});

/**
 * A new location of an upload: remembers it and checks it
 * (`backdoor.write_executable`, `backdoor.write_served`).
 */
export function checkNewLocation(path: string, verdict: UploadVerdict): Finding | null {
  const resolved = rememberLocation(path, verdict);
  const dest = targetDirectory(resolved);
  if (isExecutableName(resolved)) return finding('backdoor.write_executable', verdict, dest);
  if (isServed(resolved) && isActiveContent(verdict)) return finding('backdoor.write_served', verdict, dest);
  return null;
}

/**
 * A write (or the destination of a rename or copy): when it stores an upload,
 * the new location is remembered and checked. `from` is the source of a
 * rename or copy.
 */
export function detectUploadWrite(path: string | undefined, data?: unknown, from?: string): Finding | null {
  if (!path) return null;
  const verdict = (from !== undefined ? uploadAt(from) : undefined) ?? uploadWritten(path, data);
  return verdict ? checkNewLocation(path, verdict) : null;
}

/** `backdoor.include`: a known location loaded as code. */
export function detectUploadInclude(resolvedFile: string | undefined): Finding | null {
  const v = resolvedFile ? uploadAt(resolvedFile) : undefined;
  return v ? finding('backdoor.include', v, targetDirectory(resolvePath(resolvedFile as string))) : null;
}

const INTERPRETER = /^(sh|bash|zsh|dash|ksh|python[0-9.]*|node|nodejs|perl|php[0-9.]*|ruby|cmd|powershell|pwsh)(\.exe)?$/i;

/** `backdoor.exec`: the program, or the first argument after an interpreter, is a known location. */
export function detectUploadExec(argv: string[]): Finding | null {
  if (!locations.size || !argv.length) return null;
  const candidates = [argv[0]];
  if (INTERPRETER.test(basename(argv[0].replace(/\\/g, '/')))) {
    const script = argv.slice(1).find((a) => !a.startsWith('-'));
    if (script) candidates.push(script);
  }
  for (const c of candidates) {
    const v = uploadAt(c);
    if (v) return finding('backdoor.exec', v, targetDirectory(resolvePath(c)));
  }
  return null;
}

/** A shell command line's words, roughly (quotes removed): enough to find the program and script. */
export function commandWords(command: string): string[] {
  const out: string[] = [];
  for (const m of command.matchAll(/"([^"]*)"|'([^']*)'|([^\s;|&]+)/g)) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

/** `backdoor.chmod`: an execute bit on a known location. */
export function detectUploadChmod(path: unknown, mode: unknown): Finding | null {
  if (typeof path !== 'string' || !locations.size) return null;
  const m = typeof mode === 'number' ? mode : typeof mode === 'string' && /^[0-7]{1,4}$/.test(mode) ? parseInt(mode, 8) : NaN;
  if (!Number.isFinite(m) || (m & 0o111) === 0) return null;
  const v = uploadAt(path);
  return v ? finding('backdoor.chmod', v, targetDirectory(resolvePath(path))) : null;
}
