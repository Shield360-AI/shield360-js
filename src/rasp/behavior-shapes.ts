/**
 * Behavior profiles (README "Behavior profiles"): the shape of what a sink
 * call does. A shape is a short string computed here, never a raw value: an
 * executable's basename, a path template, `host:port` with IP literals cut
 * to their network, a hash of a normalized SQL statement, a deserialized
 * type, a module specifier. Pure functions; small caches keep repeated
 * calls (the same query text, the same path) cheap.
 */
import { createHash } from 'crypto';
import { builtinModules } from 'module';
import { tmpdir } from 'os';
import { exeName, parseV4, parseV6, resolvePath, shellScriptOf } from './detect';
import { sqlTokens, type SqlDialect } from './lexers';
import { isOpaque, maskSecrets } from '../masking';

export type BehaviorCategory = 'process' | 'file' | 'outbound' | 'sql' | 'deser' | 'module';
export const BEHAVIOR_CATEGORIES: readonly BehaviorCategory[] = ['process', 'file', 'outbound', 'sql', 'deser', 'module'];
/** The longest shape: longer ones are cut (README "Shapes"). */
export const MAX_SHAPE = 200;
/** Path segments kept in a file or module template. */
export const MAX_SEGMENTS = 5;

/** A Map that empties itself when full: bounded memory, no bookkeeping on hits. */
class Cache<V> {
  private readonly m = new Map<string, V>();
  constructor(private readonly cap: number) {}
  get(k: string): V | undefined {
    return this.m.get(k);
  }
  set(k: string, v: V): V {
    if (this.m.size >= this.cap) this.m.clear();
    this.m.set(k, v);
    return v;
  }
  clear(): void {
    this.m.clear();
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX8 = /^[0-9a-f]{8,}$/i;
const DIGITS = /^\d+$/;
/** 2026-11-23, 2026_11_23, 2026.11, 2026-11-23T10:00:00Z, 20261123T1000 ... */
const DATE = /^\d{4}[-_.]?\d{2}(?:[-_.]?\d{2})?(?:[T_ -]?\d{2}(?:[:.-]?\d{2}){0,2}(?:\.\d+)?z?)?$/i;
const SAFE_SEGMENT = /^[A-Za-z0-9._@+~-]{1,64}$/;
const UUID_IN = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const PIECE = /[^-_.]+/g;
const STAR_RUN = /\*(?:[-_.]\*)+/g;

/** Whether a whole segment (or label, or piece) names an instance rather than a kind: digits, a UUID, hex of 8+, a date. */
export function idLike(s: string): boolean {
  return DIGITS.test(s) || UUID.test(s) || HEX8.test(s) || DATE.test(s);
}

/**
 * One path segment as a template: `*` when the whole segment is id-like,
 * unusual (characters outside `[A-Za-z0-9._@+~-]`, over 64 characters) or an
 * opaque token; else every id-like piece between `-`, `_` and `.` becomes
 * `*` (`app-2026-11-23` gives `app-*`).
 */
export function segmentTemplate(seg: string): string {
  if (idLike(seg) || !SAFE_SEGMENT.test(seg) || (seg.length >= 20 && isOpaque(seg))) return '*';
  const out = seg.replace(UUID_IN, '*').replace(PIECE, (p) => (p !== '*' && idLike(p) ? '*' : p));
  return out.replace(STAR_RUN, '*');
}

/** The last segment: its name as a template, its extension (1 to 10 letters or digits) kept in lower case. */
function lastTemplate(seg: string): string {
  const dot = seg.lastIndexOf('.');
  if (dot > 0 && dot < seg.length - 1 && seg.length - dot - 1 <= 10 && /^[A-Za-z0-9]+$/.test(seg.slice(dot + 1))) {
    return `${segmentTemplate(seg.slice(0, dot))}.${seg.slice(dot + 1).toLowerCase()}`;
  }
  return segmentTemplate(seg);
}

/** Segments as a template: at most 5 kept; a longer path keeps its first 4, then `**`, then its last. */
export function segmentsTemplate(segs: string[]): string {
  if (!segs.length) return '';
  const last = lastTemplate(segs[segs.length - 1]);
  if (segs.length > MAX_SEGMENTS) return [...segs.slice(0, MAX_SEGMENTS - 1).map(segmentTemplate), '**', last].join('/');
  return [...segs.slice(0, -1).map(segmentTemplate), last].join('/');
}

/** The finished shape: credentials and opaque runs masked (README "Masking"), at most 200 characters. */
function finish(s: string): string {
  const m = maskSecrets(s);
  return m.length > MAX_SHAPE ? m.slice(0, MAX_SHAPE) : m;
}

// ---- process ------------------------------------------------------------------

const PROC_NAME = /^[a-z0-9][a-z0-9._+-]{0,63}$/;
const COMMAND_SPLIT = /;|&&|\|\||\||&|\n|\$\(|`|\(|\)/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const FIRST_WORD = /^([A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s"'])*|"([^"]*)"?|'([^']*)'?|\S+)/;
const MAX_COMMANDS = 16;

/** An executable as a shape: its basename, lower case, without `.exe`; `*` when it is not a plain name. */
export function processName(p: string): string {
  const n = exeName(p.replace(/^['"]|['"]$/g, ''));
  return PROC_NAME.test(n) ? n : '*';
}

/** The programs a shell command line runs: the first word of each command (after `;`, `|`, `&&`, `||`, `&`, `$(`, backticks), assignments skipped. */
export function commandNames(script: string): string[] {
  const out: string[] = [];
  for (const piece of script.split(COMMAND_SPLIT)) {
    let rest = piece.trim();
    let w = '';
    // The first word that is not an assignment; a quoted word is one word.
    for (let k = 0; k < 8 && rest; k++) {
      const m = FIRST_WORD.exec(rest)!;
      w = m[2] ?? m[3] ?? m[1];
      rest = rest.slice(m[0].length).trimStart();
      if (!ASSIGNMENT.test(m[1])) break;
      w = '';
    }
    if (!w || w.startsWith('-') || /^[<>]/.test(w)) continue;
    out.push(processName(w));
    if (out.length >= MAX_COMMANDS) break;
  }
  return out;
}

/**
 * The process shapes of one call: the executable, and for a shell command
 * line (or `sh -c <script>`) the shell and every program the line runs.
 */
export function processShapes(target: { command: string } | { argv: string[] }, platform: string = process.platform): string[] {
  const shapes = new Set<string>();
  if ('command' in target) {
    shapes.add(platform === 'win32' ? 'cmd' : 'sh');
    for (const n of commandNames(target.command)) shapes.add(n);
  } else if (target.argv.length) {
    shapes.add(processName(target.argv[0]));
    const script = shellScriptOf(target.argv);
    if (script) for (const n of commandNames(script)) shapes.add(n);
  }
  return [...shapes];
}

// ---- file ----------------------------------------------------------------------

const fileCache = new Cache<string>(2048);
let tmpRoots: string[] | undefined;

function temps(): string[] {
  if (!tmpRoots) {
    const roots = new Set<string>();
    try {
      roots.add(resolvePath(tmpdir()));
    } catch {
      // no temp dir
    }
    for (const r of ['/tmp', '/var/tmp', '/private/tmp']) roots.add(r);
    // Longest first: /private/tmp before /tmp.
    tmpRoots = [...roots].filter((r) => r && r !== '/').sort((a, b) => b.length - a.length);
  }
  return tmpRoots;
}

/** Tests only: the temp roots are read again (after tmpdir() changes). */
export function resetShapeCaches(): void {
  tmpRoots = undefined;
  fileCache.clear();
  sqlCache.clear();
  moduleCache.clear();
}

/**
 * `read:` or `write:` + the path template of the resolved path; paths under
 * the OS temp dir (or /tmp, /var/tmp) are `read:tmp:/...` / `write:tmp:/...`
 * relative to it.
 */
export function fileShape(path: string, write: boolean): string {
  const key = (write ? 'w' : 'r') + path;
  const hit = fileCache.get(key);
  if (hit !== undefined) return hit;
  let abs = resolvePath(path);
  let tmp = '';
  for (const t of temps()) {
    if (abs === t || abs.startsWith(`${t}/`)) {
      tmp = 'tmp:';
      abs = abs.slice(t.length) || '/';
      break;
    }
  }
  const segs = abs.split('/').filter(Boolean);
  // A Windows drive letter stays as written (C:).
  const lead = /^[A-Za-z]:$/.test(segs[0] ?? '') ? `${segs.shift()!.toUpperCase()}/` : '/';
  return fileCache.set(key, finish(`${write ? 'write' : 'read'}:${tmp}${lead}${segmentsTemplate(segs)}`));
}

// ---- outbound ------------------------------------------------------------------

const DEFAULT_PORTS: Record<string, string> = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443', 'ftp:': '21' };
const HOST_LABEL = /^[a-z0-9_-]{1,63}$/;

/** An IP literal's network: IPv4 /24 (`ip:10.1.2.0/24`), IPv6 /48 (`ip:2001:db8:1::/48`); null when not an IP literal. */
export function ipNetwork(host: string): string | null {
  const h = host.replace(/^\[|\]$/g, '').split('%')[0];
  const v4 = parseV4(h);
  if (v4) return `ip:${v4[0]}.${v4[1]}.${v4[2]}.0/24`;
  const v6 = parseV6(h.toLowerCase());
  if (!v6) return null;
  // An IPv4-mapped address is its IPv4 address.
  if (v6.slice(0, 10).every((b) => b === 0) && v6[10] === 0xff && v6[11] === 0xff) return `ip:${v6[12]}.${v6[13]}.${v6[14]}.0/24`;
  const g = (i: number) => ((v6[i] << 8) | v6[i + 1]).toString(16);
  return `ip:${g(0)}:${g(2)}:${g(4)}::/48`;
}

/** Lower-case `host:port` (the scheme's default port when none is given); an id-like label becomes `*`; IP literals become their network. Null when not a URL. */
export function hostShape(host: string, port: string): string {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const net = ipNetwork(h);
  const suffix = port ? `:${port}` : '';
  if (net) return finish(net + suffix);
  const labels = h.split('.').map((l) => (HOST_LABEL.test(l) ? (idLike(l) ? '*' : l) : '*'));
  // A name too long for a shape keeps its rightmost labels after `*.`.
  while (labels.length > 1 && labels.join('.').length + suffix.length > MAX_SHAPE - 2) labels.shift();
  const name = labels.length < h.split('.').length ? `*.${labels.join('.')}` : labels.join('.');
  return finish(name + suffix);
}

/** The outbound shape of a URL, or null when it is not one. */
export function outboundShape(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (!u.hostname) return null;
  return hostShape(u.hostname, u.port || DEFAULT_PORTS[u.protocol] || '');
}

// ---- sql -----------------------------------------------------------------------

const sqlCache = new Cache<string>(1024);
const MAX_SQL_CACHED = 4096;
const MAX_SQL_LEXED = 64 * 1024;
const VERB = /^[a-z]{1,16}$/;

/**
 * A statement normalized for its shape: comments dropped, literals, numbers
 * and placeholders `?`, words lower case, a parenthesized list of `?` one
 * `(?)`, and repeated `(?)` rows one `(?)`; tokens joined by one space.
 */
export function normalizeSql(text: string, dialect: SqlDialect = 'generic'): { verb: string; normalized: string } {
  const toks = sqlTokens(text.length > MAX_SQL_LEXED ? text.slice(0, MAX_SQL_LEXED) : text, dialect);
  const out: string[] = [];
  let verb = '';
  for (const t of toks) {
    let v: string;
    if (t.kind === 'comment') continue;
    if (t.kind === 'version_comment') v = '/*!*/';
    else if (t.kind === 'string' || t.kind === 'number' || t.kind === 'placeholder') v = '?';
    else if (t.kind === 'word' || t.kind === 'name') v = t.text.toLowerCase();
    else v = t.text;
    if (!verb) verb = t.kind === 'word' ? v : 'other';
    // ( ? , ? , ? ) -> (?)
    if (v === ')') {
      let j = out.length - 1;
      let list = j >= 0 && out[j] === '?';
      while (list && j >= 2 && out[j - 1] === ',' && out[j - 2] === '?') j -= 2;
      if (list && j >= 1 && out[j - 1] === '(') {
        out.length = j - 1;
        v = '(?)';
      } else list = false;
      // (?) , (?) -> (?)
      if (list && out.length >= 2 && out[out.length - 1] === ',' && out[out.length - 2] === '(?)') {
        out.length -= 1;
        continue;
      }
    }
    out.push(v);
  }
  return { verb: VERB.test(verb) ? verb : 'other', normalized: out.join(' ') };
}

/** `verb:` + the first 16 hex of the SHA-256 of the normalized statement (`select:3f2a…`). */
export function sqlShape(text: string, dialect: SqlDialect = 'generic'): string {
  const cacheable = text.length <= MAX_SQL_CACHED;
  const key = cacheable ? `${dialect}\u0000${text}` : '';
  if (cacheable) {
    const hit = sqlCache.get(key);
    if (hit !== undefined) return hit;
  }
  const { verb, normalized } = normalizeSql(text, dialect);
  const shape = `${verb}:${createHash('sha256').update(normalized).digest('hex').slice(0, 16)}`;
  return cacheable ? sqlCache.set(key, shape) : shape;
}

// ---- deser ---------------------------------------------------------------------

const FORMAT = /^[a-z0-9_]{1,32}$/;
const TYPE = /^[A-Za-z_$][A-Za-z0-9_$./:-]{0,99}$/;
const YAML_TAG = /(?:!!|!<tag:yaml\.org,2002:)([A-Za-z_][A-Za-z0-9_$./:-]{0,99})/g;
const YAML_STANDARD = new Set(['str', 'int', 'float', 'bool', 'null', 'map', 'seq', 'set', 'omap', 'pairs', 'binary', 'timestamp', 'merge', 'value']);
const DESER_SCAN = 64 * 1024;

/**
 * The type being deserialized. Node has no class names on the wire, so the
 * shape is the format, plus `:` and the first explicit type the data names:
 * a YAML tag that is not a standard one (`yaml:js/function`), `function` for
 * node-serialize's and funcster's function markers.
 */
export function deserShape(format: string, data?: unknown): string {
  const f = FORMAT.test(format) ? format : '*';
  if (typeof data !== 'string') return f;
  const s = data.length > DESER_SCAN ? data.slice(0, DESER_SCAN) : data;
  let type = '';
  if (f === 'node_serialize' && s.includes('_$$ND_FUNC$$_')) type = 'function';
  else if (f === 'funcster' && s.includes('__js_function')) type = 'function';
  else if (f === 'yaml' && s.includes('!')) {
    YAML_TAG.lastIndex = 0;
    for (let m = YAML_TAG.exec(s); m; m = YAML_TAG.exec(s)) {
      if (!YAML_STANDARD.has(m[1])) {
        type = m[1];
        break;
      }
    }
  }
  if (!type) return f;
  return finish(`${f}:${TYPE.test(type) ? type : '*'}`);
}

// ---- module --------------------------------------------------------------------

const moduleCache = new Cache<string>(1024);
const BUILTINS = new Set(builtinModules);
const PACKAGE = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i;

/**
 * A module specifier as a shape: a built-in module by its name (`node:`
 * dropped); a package by its name and its subpath as a template; a relative
 * or absolute specifier as a path template, `./`, `../` or `/` kept.
 */
export function moduleShape(id: string): string {
  const hit = moduleCache.get(id);
  if (hit !== undefined) return hit;
  let shape: string;
  const bare = id.startsWith('node:') ? id.slice(5) : id;
  if (BUILTINS.has(bare)) {
    shape = bare;
  } else if (/^(\.{1,2}[/\\]|[/\\]|[A-Za-z]:[/\\])/.test(id)) {
    const norm = id.replace(/\\/g, '/');
    const lead = /^(\.\.?\/|\/|[A-Za-z]:\/)/.exec(norm)![1];
    shape = lead + segmentsTemplate(norm.slice(lead.length).split('/').filter((s) => s && s !== '.'));
  } else {
    const parts = bare.split('/');
    const n = parts[0].startsWith('@') ? 2 : 1;
    const name = parts.slice(0, n).join('/');
    const rest = parts.slice(n).filter(Boolean);
    shape = (PACKAGE.test(name) ? name.toLowerCase() : '*') + (rest.length ? `/${segmentsTemplate(rest)}` : '');
  }
  return moduleCache.set(id, finish(shape));
}
