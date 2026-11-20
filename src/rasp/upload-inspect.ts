/**
 * Upload inspection (sdk/rasp/README.md "Uploads"): what an uploaded file
 * really is, from its bytes, read in bounded pieces. Pure: no file system, no
 * network, no events. upload.ts turns a verdict into findings and events.
 *
 * Memory stays bounded whatever the file's size: the first 64 KiB, the last
 * 1 MiB, one piece of at most 1 MiB with a 2 KiB overlap, and a running hash.
 */
import { createHash, type Hash } from 'crypto';
import builtInSignatures from './data/upload-signatures.json';
import { SCRIPT_FILE } from './detect';
import { asciiLower, compileSignatures, latin1, SignatureMatcher, UPLOAD_SIGNATURE_LIMITS, type CompiledSignature } from './upload-signatures';

export type UploadKind = 'image' | 'document' | 'text' | 'archive' | 'media' | 'executable' | 'script' | 'html' | 'svg' | 'other';
export const UPLOAD_KINDS: readonly UploadKind[] = ['image', 'document', 'text', 'archive', 'media', 'executable', 'script', 'html', 'svg', 'other'];

export type UploadEngine = 'builtin' | 'custom' | 'clamav' | 'reputation' | 'policy';

/** One inspection finding: a `malicious_upload` rule. */
export type UploadFinding = { rule: string; engine: UploadEngine; signature?: string; capped?: boolean };

export type UploadVerdict = {
  type: string;
  kind: UploadKind;
  size: number;
  /** SHA-256 of the whole file, when the inspector saw all of it. */
  sha256?: string;
  /** The name's last extension, lower case (README "Upload event attributes"). */
  ext?: string;
  /** Built-in and own-signature findings, in the contract's order. */
  findings: UploadFinding[];
};

export type UploadMeta = { name?: string; contentType?: string };

export const DEFAULT_SCAN_BYTES = 8 * 1024 * 1024;
export const MAX_SCAN_BYTES = 64 * 1024 * 1024;
const HEAD_BYTES = 64 * 1024;
const TAIL_BYTES = 1024 * 1024;
const PIECE_BYTES = 1024 * 1024;
const MiB = 1024 * 1024;

/** The rule order of README "Inspection rules": the first finding is the one reported. */
export const UPLOAD_RULE_ORDER = [
  'upload.eicar',
  'upload.malware',
  'upload.reputation',
  'upload.webshell',
  'upload.signature',
  'upload.executable',
  'upload.script',
  'upload.polyglot',
  'upload.active_content',
  'upload.server_config',
  'upload.double_extension',
  'upload.archive_traversal',
  'upload.archive_symlink',
  'upload.archive_bomb',
  'upload.archive_encrypted',
  'upload.office_macro',
  'upload.office_ole',
  'upload.archive_script',
  'upload.type_mismatch',
  'upload.type_not_allowed',
  'upload.too_large',
  'upload.scan_unavailable',
] as const;

/** Rules that never block (README: *capped*). */
export const CAPPED_RULES: ReadonlySet<string> = new Set(['upload.office_ole', 'upload.archive_script', 'upload.type_mismatch']);

export const BUILT_IN_SIGNATURES: CompiledSignature[] = compileSignatures(builtInSignatures.rules).signatures;

// The EICAR test string, in two halves so this source file is not itself the test file.
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

const KIND_OF: Record<string, UploadKind> = {
  elf: 'executable', pe: 'executable', macho: 'executable', java_class: 'executable', wasm: 'executable', jar: 'executable', war: 'executable',
  jpeg: 'image', png: 'image', gif: 'image', webp: 'image', bmp: 'image', ico: 'image', tiff: 'image',
  pdf: 'document', ole2: 'document', docx: 'document', xlsx: 'document', pptx: 'document',
  zip: 'archive', gzip: 'archive', bzip2: 'archive', xz: 'archive', '7z': 'archive', rar: 'archive', tar: 'archive',
  mp4: 'media', webm: 'media', mp3: 'media', wav: 'media', ogg: 'media',
  php: 'script', jsp_asp: 'script', shebang: 'script',
  svg: 'svg', html: 'html', text: 'text', unknown: 'other',
};
export const kindOf = (type: string): UploadKind => KIND_OF[type] ?? 'other';
export const UPLOAD_TYPES: readonly string[] = Object.keys(KIND_OF);

const startsWith = (b: Uint8Array, sig: number[], at = 0) => b.length >= at + sig.length && sig.every((v, i) => b[at + i] === v);
const ascii = (b: Uint8Array, at: number, len: number) => latin1(b, at, Math.min(b.length, at + len));

/** The real type from the first bytes (README "Real type"); zip refinement happens at the end. */
export function sniffType(head: Uint8Array): string {
  if (startsWith(head, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (startsWith(head, [0x4d, 0x5a]) && head.length >= 0x40) {
    const off = head[0x3c] | (head[0x3d] << 8) | (head[0x3e] << 16) | (head[0x3f] << 24);
    if (off >= 0 && startsWith(head, [0x50, 0x45, 0, 0], off)) return 'pe';
  }
  for (const m of [[0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf], [0xce, 0xfa, 0xed, 0xfe], [0xcf, 0xfa, 0xed, 0xfe]]) if (startsWith(head, m)) return 'macho';
  if (startsWith(head, [0xca, 0xfe, 0xba, 0xbe])) {
    const n = head.length >= 8 ? ((head[4] << 24) >>> 0) + (head[5] << 16) + (head[6] << 8) + head[7] : Infinity;
    return n < 30 ? 'macho' : 'java_class';
  }
  if (startsWith(head, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (startsWith(head, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'png';
  if (ascii(head, 0, 6) === 'GIF87a' || ascii(head, 0, 6) === 'GIF89a') return 'gif';
  if (ascii(head, 0, 4) === 'RIFF' && ascii(head, 8, 4) === 'WEBP') return 'webp';
  if (ascii(head, 0, 2) === 'BM' && head.length >= 26) return 'bmp';
  if (startsWith(head, [0, 0, 1, 0])) return 'ico';
  if (startsWith(head, [0x49, 0x49, 0x2a, 0]) || startsWith(head, [0x4d, 0x4d, 0, 0x2a])) return 'tiff';
  if (ascii(head, 0, 1024).includes('%PDF-')) return 'pdf';
  if (startsWith(head, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole2';
  if (startsWith(head, [0x50, 0x4b, 3, 4]) || startsWith(head, [0x50, 0x4b, 5, 6])) return 'zip';
  if (startsWith(head, [0x1f, 0x8b])) return 'gzip';
  if (ascii(head, 0, 3) === 'BZh') return 'bzip2';
  if (startsWith(head, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0])) return 'xz';
  if (startsWith(head, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (startsWith(head, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return 'rar';
  if (ascii(head, 257, 5) === 'ustar') return 'tar';
  if (ascii(head, 4, 4) === 'ftyp') return 'mp4';
  if (startsWith(head, [0x1a, 0x45, 0xdf, 0xa3])) return 'webm';
  if (ascii(head, 0, 3) === 'ID3' || startsWith(head, [0xff, 0xfb]) || startsWith(head, [0xff, 0xf3]) || startsWith(head, [0xff, 0xf2])) return 'mp3';
  if (ascii(head, 0, 4) === 'RIFF' && ascii(head, 8, 4) === 'WAVE') return 'wav';
  if (ascii(head, 0, 4) === 'OggS') return 'ogg';
  if (startsWith(head, [0, 0x61, 0x73, 0x6d])) return 'wasm';
  // Text: skip a UTF-8 BOM and ASCII whitespace.
  let i = startsWith(head, [0xef, 0xbb, 0xbf]) ? 3 : 0;
  while (i < head.length && (head[i] === 0x20 || (head[i] >= 0x09 && head[i] <= 0x0d))) i++;
  const lead = asciiLower(ascii(head, i, 1024));
  if (lead.startsWith('<?php') || lead.startsWith('<?=')) return 'php';
  if (lead.startsWith('<%') || lead.startsWith('<jsp:')) return 'jsp_asp';
  if (lead.startsWith('#!/')) return 'shebang';
  const html = ['<!doctype html', '<html', '<head', '<body', '<script', '<iframe'].some((t) => lead.startsWith(t));
  if (html) return 'html';
  if (lead.includes('<svg')) return 'svg';
  if (!head.subarray(0, 8192).includes(0)) return 'text';
  return 'unknown';
}

// ---- names -------------------------------------------------------------------

const SERVER_CONFIG = new Set(['.htaccess', '.htpasswd', '.user.ini', 'web.config']);
const SCRIPT_EXT = /^(aspx?|jspx?|php[3-7]?|phar|phtml|sh|bash|py|pyc|pl|rb|so|dll|dylib|exe|cgi|js|mjs|cjs)$/i;

/** The last segment of a file name as a client sent it. */
export const baseName = (name: string) => name.split(/[\\/]/).pop() || '';

/** The name's last extension, lower case, `[a-z0-9]{1,10}`; undefined otherwise. */
export function extOf(name: string | undefined): string | undefined {
  if (!name) return undefined;
  const base = baseName(name).replace(/[. ]+$/, '');
  const dot = base.lastIndexOf('.');
  if (dot <= 0 && !base.startsWith('.')) return undefined;
  const ext = base.slice(dot + 1).toLowerCase();
  return /^[a-z0-9]{1,10}$/.test(ext) ? ext : undefined;
}

/** `upload.server_config` (README "Inspection rules"). */
export const isServerConfigName = (name: string) => SERVER_CONFIG.has(baseName(name).toLowerCase());

/** `upload.double_extension` (README "Inspection rules"). */
export function hasDoubleExtension(name: string): boolean {
  const base = baseName(name);
  if (base.includes('\u0000') || /%00/.test(base)) return true;
  if (/\.[^.]+[. ]+$/.test(base)) return true;
  const parts = base.split('.');
  if (parts.length < 3 && !base.includes(';')) return false;
  for (let i = 1; i < parts.length - 1; i++) {
    const seg = parts[i].split(';')[0];
    if (SCRIPT_EXT.test(seg)) return true;
  }
  // `shell.asp;.jpg`
  return /\.(aspx?|jspx?|php[3-7]?|phtml|cgi|pl)\s*;/i.test(base);
}

// ---- mismatch ---------------------------------------------------------------

const EXT_TYPES: Record<string, string[]> = {
  jpg: ['jpeg'], jpeg: ['jpeg'], jpe: ['jpeg'], png: ['png'], gif: ['gif'], webp: ['webp'], bmp: ['bmp'], ico: ['ico'], tif: ['tiff'], tiff: ['tiff'],
  pdf: ['pdf'], docx: ['docx', 'zip'], xlsx: ['xlsx', 'zip'], pptx: ['pptx', 'zip'], doc: ['ole2'], xls: ['ole2'], ppt: ['ole2'],
  zip: ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'war'], gz: ['gzip'], tgz: ['gzip'],
  mp4: ['mp4'], m4a: ['mp4'], mov: ['mp4'], mp3: ['mp3'], csv: ['text'], txt: ['text'], json: ['text'], md: ['text'],
};
const CT_TYPES: Record<string, string[]> = {
  'image/jpeg': ['jpeg'], 'image/png': ['png'], 'image/gif': ['gif'], 'image/webp': ['webp'], 'image/bmp': ['bmp'],
  'image/x-icon': ['ico'], 'image/vnd.microsoft.icon': ['ico'], 'image/tiff': ['tiff'], 'application/pdf': ['pdf'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx', 'zip'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['xlsx', 'zip'],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['pptx', 'zip'],
  'application/msword': ['ole2'], 'application/vnd.ms-excel': ['ole2'], 'application/vnd.ms-powerpoint': ['ole2'],
  'application/zip': ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'war'], 'application/gzip': ['gzip'],
  'video/mp4': ['mp4'], 'audio/mp4': ['mp4'], 'video/quicktime': ['mp4'], 'audio/mpeg': ['mp3'],
  'text/csv': ['text'], 'text/plain': ['text'], 'application/json': ['text'],
};

/** `upload.type_mismatch`: the name or declared type names a type, the bytes are another of a different kind. */
export function typeMismatch(type: string, meta: UploadMeta): boolean {
  if (type === 'unknown') return false;
  const ext = extOf(meta.name);
  const ct = (meta.contentType || '').split(';')[0].trim().toLowerCase();
  for (const expected of [ext ? EXT_TYPES[ext] : undefined, CT_TYPES[ct]]) {
    if (expected && !expected.includes(type) && kindOf(expected[0]) !== kindOf(type)) return true;
  }
  return false;
}

// ---- archives ----------------------------------------------------------------

export type ArchiveEntry = { name: string; symlink: boolean; encrypted: boolean; compressed: number; size: number };

const u16 = (b: Uint8Array, o: number) => b[o] | (b[o + 1] << 8);
const u32 = (b: Uint8Array, o: number) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const u64 = (b: Uint8Array, o: number) => u32(b, o) + u32(b, o + 4) * 2 ** 32;

/**
 * Zip entries from the central directory, found from the end record in
 * `tail` (the file's last bytes). null when the directory is not in `tail`.
 * `total` is the end record's entry count.
 */
export function zipEntries(tail: Uint8Array): { entries: ArchiveEntry[]; total: number } | null {
  let eocd = -1;
  for (let i = tail.length - 22; i >= Math.max(0, tail.length - 22 - 65535); i--) {
    if (tail[i] === 0x50 && tail[i + 1] === 0x4b && tail[i + 2] === 5 && tail[i + 3] === 6) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return null;
  let total = u16(tail, eocd + 10);
  let cdSize = u32(tail, eocd + 12);
  let cdEnd = eocd;
  if (total === 0xffff || cdSize === 0xffffffff) {
    const loc = eocd - 20;
    if (loc < 0 || u32(tail, loc) !== 0x07064b50) return { entries: [], total };
    // The ZIP64 end record sits right before its locator.
    const z = loc - 56;
    if (z < 0 || u32(tail, z) !== 0x06064b50) return { entries: [], total };
    total = u64(tail, z + 32);
    cdSize = u64(tail, z + 40);
    cdEnd = z;
  }
  const start = cdEnd - cdSize;
  if (start < 0) return { entries: [], total };
  const entries: ArchiveEntry[] = [];
  let p = start;
  while (p + 46 <= cdEnd && u32(tail, p) === 0x02014b50 && entries.length < 10001) {
    const madeBy = u16(tail, p + 4) >> 8;
    const flags = u16(tail, p + 8);
    let compressed = u32(tail, p + 20);
    let size = u32(tail, p + 24);
    const nameLen = u16(tail, p + 28);
    const extraLen = u16(tail, p + 30);
    const commentLen = u16(tail, p + 32);
    const attr = u32(tail, p + 38);
    const name = latin1(tail, p + 46, p + 46 + nameLen);
    // ZIP64 extra field: the sizes that read 0xffffffff, uncompressed first.
    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const id = u16(tail, e);
      const len = u16(tail, e + 2);
      if (id === 1) {
        let q = e + 4;
        if (size === 0xffffffff && q + 8 <= e + 4 + len) (size = u64(tail, q)), (q += 8);
        if (compressed === 0xffffffff && q + 8 <= e + 4 + len) compressed = u64(tail, q);
      }
      e += 4 + len;
    }
    const mode = (attr >>> 16) & 0o170000;
    entries.push({ name, symlink: madeBy === 3 && mode === 0o120000, encrypted: (flags & 1) === 1, compressed, size });
    p = extraEnd + commentLen;
  }
  return { entries, total };
}

const DRIVE = /^[A-Za-z]:/;
/** `upload.archive_traversal`: an entry name that leaves the directory it is extracted into. */
export function entryEscapes(name: string): boolean {
  const n = name.replace(/\\/g, '/');
  return n.startsWith('/') || DRIVE.test(n) || n.split('/').includes('..');
}

/** Reads tar headers as the bytes pass (README: ustar name and prefix, GNU `L`, pax `path`). */
class TarReader {
  entries: ArchiveEntry[] = [];
  private next = 0;
  private header: number[] = [];
  private want: { kind: 'L' | 'x'; left: number; bytes: number[]; skip: number } | null = null;
  private pendingName: string | null = null;
  done = false;

  feed(chunk: Uint8Array, offset: number): void {
    let i = 0;
    while (i < chunk.length && !this.done && this.entries.length <= 10000) {
      const pos = offset + i;
      if (this.want) {
        const take = Math.min(chunk.length - i, this.want.left);
        const room = (this.want.kind === 'L' ? 512 : 4096) - this.want.bytes.length;
        for (let k = 0; k < Math.min(take, room); k++) this.want.bytes.push(chunk[i + k]);
        this.want.left -= take;
        i += take;
        if (this.want.left === 0) {
          const text = latin1(Uint8Array.from(this.want.bytes));
          if (this.want.kind === 'L') this.pendingName = text.split('\u0000')[0];
          else {
            const m = /(?:^|\n)\d+ path=([^\n]*)\n/.exec(text);
            if (m) this.pendingName = m[1];
          }
          this.next = offset + i + this.want.skip;
          this.want = null;
        }
        continue;
      }
      if (pos < this.next) {
        i += Math.min(chunk.length - i, this.next - pos);
        continue;
      }
      const take = Math.min(chunk.length - i, 512 - this.header.length);
      for (let k = 0; k < take; k++) this.header.push(chunk[i + k]);
      i += take;
      if (this.header.length < 512) continue;
      const h = Uint8Array.from(this.header);
      this.header = [];
      if (h.every((b) => b === 0)) {
        this.done = true;
        break;
      }
      const field = (o: number, l: number) => latin1(h, o, o + l).split('\u0000')[0];
      const size = parseInt(field(124, 12).trim() || '0', 8) || 0;
      const type = String.fromCharCode(h[156] || 0x30);
      const padded = Math.ceil(size / 512) * 512;
      const dataStart = offset + i;
      if (type === 'L' || type === 'x') {
        this.want = { kind: type, left: Math.min(size, type === 'L' ? 512 : 4096), bytes: [], skip: padded - Math.min(size, type === 'L' ? 512 : 4096) };
        this.next = dataStart + padded;
        if (size === 0) this.want = null;
        continue;
      }
      if (type === 'g') {
        this.next = dataStart + padded;
        continue;
      }
      const prefix = field(345, 155);
      const base = field(0, 100);
      const name = this.pendingName ?? (prefix && ascii(h, 257, 5) === 'ustar' ? `${prefix}/${base}` : base);
      this.pendingName = null;
      this.entries.push({ name, symlink: type === '1' || type === '2', encrypted: false, compressed: size, size });
      this.next = dataStart + padded;
    }
  }
}

// ---- scanner -----------------------------------------------------------------

const POLYGLOT_MARKERS = ['<?php', '<script', '<jsp:', 'runat="server"'];
const ACTIVE_MARKERS = ['<script', 'javascript:', '<foreignobject', '<iframe', '<embed', '<object'];
const EVENT_HANDLER = /[\t\n\f\r /]on[a-z]{3,20}\s*=/;
const utf16 = (s: string) => s.split('').map((c) => `${c}\u0000`).join('');
const OLE_VBA = utf16('_VBA_PROJECT');
const OLE_ENCRYPTED = utf16('EncryptedPackage');
const OLE_NATIVE = utf16('\u0001Ole10Native');

export type ScannerOptions = { scanBytes?: number; custom?: CompiledSignature[]; trusted?: ReadonlySet<string> };

/**
 * Inspects a file fed in pieces. `push` as the bytes arrive, `finish` once.
 * `complete: false` at finish means the caller skipped part of the file: no
 * hash is reported then.
 */
export class UploadScanner {
  private size = 0;
  private head: Buffer = Buffer.alloc(0);
  private tailParts: Buffer[] = [];
  private tailLen = 0;
  private carry = '';
  private carryFolded = '';
  private scanned = 0;
  private readonly scanBytes: number;
  private readonly hash: Hash = createHash('sha256');
  private readonly builtin = new SignatureMatcher(BUILT_IN_SIGNATURES);
  private readonly custom: SignatureMatcher | null;
  private readonly markers = new Set<string>();
  private tar: TarReader | null = null;
  private tarChecked = false;
  private pending: Buffer[] = [];
  private pendingLen = 0;

  constructor(private readonly meta: UploadMeta = {}, private readonly opts: ScannerOptions = {}) {
    const s = opts.scanBytes;
    this.scanBytes = typeof s === 'number' && s > 0 ? Math.min(s, MAX_SCAN_BYTES) : DEFAULT_SCAN_BYTES;
    this.custom = opts.custom?.length ? new SignatureMatcher(opts.custom) : null;
  }

  get bytesSeen(): number {
    return this.size;
  }

  push(data: Uint8Array): void {
    if (!data.length) return;
    const chunk = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    const offset = this.size;
    this.size += chunk.length;
    this.hash.update(chunk);
    if (this.head.length < HEAD_BYTES) this.head = Buffer.concat([this.head, chunk.subarray(0, HEAD_BYTES - this.head.length)]);
    // The rolling tail: the last 1 MiB.
    this.tailParts.push(chunk);
    this.tailLen += chunk.length;
    while (this.tailLen - this.tailParts[0].length >= TAIL_BYTES) this.tailLen -= (this.tailParts.shift() as Buffer).length;
    // Tar headers, once the head says tar.
    if (!this.tarChecked && this.head.length >= 262) {
      this.tarChecked = true;
      if (sniffType(this.head) === 'tar') {
        this.tar = new TarReader();
        this.tar.feed(this.head.subarray(0, Math.min(this.head.length, offset + chunk.length)), 0);
        const fed = Math.min(this.head.length, offset + chunk.length);
        if (offset + chunk.length > fed) this.tar.feed(chunk.subarray(fed - offset), fed);
      }
    } else if (this.tar) this.tar.feed(chunk, offset);
    // Content scan of the first scanBytes, in pieces of at most 1 MiB.
    if (this.scanned < this.scanBytes) {
      const part = chunk.subarray(0, this.scanBytes - this.scanned);
      this.scanned += part.length;
      this.pending.push(part);
      this.pendingLen += part.length;
      if (this.pendingLen >= PIECE_BYTES) this.flushPiece(false);
    }
  }

  /**
   * Skips `n` bytes the caller does not read (the middle of a large file):
   * they count toward the size; the hash is then not reported, and tar
   * headers past this point are not read.
   */
  skip(n: number): void {
    if (n <= 0) return;
    this.flushPiece(false);
    this.carry = '';
    this.carryFolded = '';
    this.size += n;
    this.scanned = this.scanBytes;
    if (this.tar) this.tar.done = true;
  }

  private scanPiece(text: string, folded: string, final: boolean): void {
    this.builtin.feed(text, folded, final);
    this.custom?.feed(text, folded, final);
    for (const m of POLYGLOT_MARKERS) if (folded.includes(m)) this.markers.add(m);
    for (const m of ACTIVE_MARKERS) if (folded.includes(m)) this.markers.add(m);
    if (EVENT_HANDLER.test(folded)) this.markers.add('on*=');
    for (const m of [OLE_VBA, OLE_ENCRYPTED, OLE_NATIVE]) if (text.includes(m)) this.markers.add(m);
  }

  private flushPiece(final: boolean): void {
    if (!this.pendingLen && !final) return;
    const bytes = Buffer.concat(this.pending);
    this.pending = [];
    this.pendingLen = 0;
    const text = this.carry + latin1(bytes);
    const folded = this.carryFolded + asciiLower(latin1(bytes));
    this.scanPiece(text, folded, final);
    this.carry = text.slice(-UPLOAD_SIGNATURE_LIMITS.overlap);
    this.carryFolded = folded.slice(-UPLOAD_SIGNATURE_LIMITS.overlap);
  }

  /** The verdict. `complete`: the scanner saw every byte (only then is the hash reported). */
  finish(complete = true): UploadVerdict {
    this.flushPiece(true);
    const tail = Buffer.concat(this.tailParts).subarray(-TAIL_BYTES);
    // The last 1 MiB beyond what the content scan read.
    if (this.size > this.scanned) {
      const unseen = Math.min(tail.length, this.size - this.scanned);
      const extra = tail.subarray(tail.length - unseen);
      const text = latin1(extra);
      this.scanPiece(text, asciiLower(text), true);
    }
    const sha256 = complete ? this.hash.digest('hex') : undefined;
    let type = sniffType(this.head);
    const findings: UploadFinding[] = [];
    const add = (rule: string, extra: Partial<UploadFinding> = {}) => findings.push({ rule, engine: 'builtin', ...(CAPPED_RULES.has(rule) ? { capped: true } : {}), ...extra });
    let entries: ArchiveEntry[] = [];
    let total = 0;
    if (type === 'zip') {
      const z = zipEntries(tail);
      if (z) {
        entries = z.entries;
        total = z.total;
        const names = entries.map((e) => e.name.replace(/\\/g, '/'));
        const has = (p: (n: string) => boolean) => names.some(p);
        if (has((n) => n === '[Content_Types].xml')) {
          if (has((n) => n.startsWith('word/'))) type = 'docx';
          else if (has((n) => n.startsWith('xl/'))) type = 'xlsx';
          else if (has((n) => n.startsWith('ppt/'))) type = 'pptx';
        }
        if (type === 'zip' && has((n) => n.startsWith('WEB-INF/'))) type = 'war';
        else if (type === 'zip' && has((n) => n === 'META-INF/MANIFEST.MF')) type = 'jar';
      }
    } else if (this.tar) {
      entries = this.tar.entries;
      total = entries.length;
    }
    const kind = kindOf(type);
    const name = this.meta.name ?? '';
    const trusted = sha256 !== undefined && this.opts.trusted?.has(sha256);
    if (!trusted) {
      // upload.eicar
      if (this.size <= 256) {
        const text = latin1(this.head).replace(/[\s]+$/, '');
        if (text.length <= 128 && text.startsWith(EICAR)) add('upload.eicar');
      }
      const webshell = this.builtin.matched()[0];
      if (webshell) add('upload.webshell', { signature: webshell.id });
      const own = this.custom?.matched()[0];
      if (own) add('upload.signature', { engine: 'custom', signature: own.id });
      if (kind === 'executable') add('upload.executable');
      if (kind === 'script') add('upload.script');
      if (['image', 'document', 'media', 'archive'].includes(kind) && POLYGLOT_MARKERS.some((m) => this.markers.has(m))) add('upload.polyglot');
      if ((kind === 'html' || kind === 'svg') && (ACTIVE_MARKERS.some((m) => this.markers.has(m)) || this.markers.has('on*='))) add('upload.active_content');
      for (const f of nameFindings(name)) if (f.rule !== 'upload.type_mismatch') add(f.rule);
      if (entries.some((e) => entryEscapes(e.name))) add('upload.archive_traversal');
      if (entries.some((e) => e.symlink)) add('upload.archive_symlink');
      const declared = entries.reduce((s, e) => s + e.size, 0);
      const bomb =
        total > 10000 ||
        entries.length > 10000 ||
        declared > 1024 * MiB ||
        entries.some((e) => e.size > 10 * MiB && e.size > 1000 * Math.max(1, e.compressed)) ||
        (type === 'gzip' && tail.length >= 4 && this.size > 18 && (() => {
          const isize = tail.readUInt32LE(tail.length - 4);
          return isize > 10 * MiB && isize > 1000 * this.size;
        })());
      if (bomb) add('upload.archive_bomb');
      if (entries.some((e) => e.encrypted) || (type === 'ole2' && this.markers.has(OLE_ENCRYPTED))) add('upload.archive_encrypted');
      const last = (n: string) => n.replace(/\\/g, '/').split('/').pop() || '';
      if (entries.some((e) => last(e.name).toLowerCase() === 'vbaproject.bin') || (type === 'ole2' && this.markers.has(OLE_VBA))) add('upload.office_macro');
      if (entries.some((e) => /(^|\/)embeddings\/oleObject/i.test(e.name.replace(/\\/g, '/')) || /(^|\/)activeX\//i.test(e.name.replace(/\\/g, '/'))) || (type === 'ole2' && this.markers.has(OLE_NATIVE))) add('upload.office_ole');
      if (entries.some((e) => SCRIPT_ARCHIVE_ENTRY.test(last(e.name)))) add('upload.archive_script');
      if (typeMismatch(type, this.meta)) add('upload.type_mismatch');
    }
    findings.sort((a, b) => ruleRank(a.rule) - ruleRank(b.rule));
    return { type, kind, size: this.size, ...(sha256 ? { sha256 } : {}), ...(extOf(name) ? { ext: extOf(name) } : {}), findings };
  }
}

/** Position of a rule in README "Inspection rules" (the first finding is reported). */
export const ruleRank = (rule: string): number => {
  const i = (UPLOAD_RULE_ORDER as readonly string[]).indexOf(rule);
  return i < 0 ? UPLOAD_RULE_ORDER.length : i;
};

/**
 * The checks that read the file name and declared type only: for a file whose
 * bytes were inspected before its name was known (a stream the app wrote).
 */
export function nameFindings(name: string, type?: string, contentType?: string): UploadFinding[] {
  const out: UploadFinding[] = [];
  if (name && isServerConfigName(name)) out.push({ rule: 'upload.server_config', engine: 'builtin' });
  if (name && hasDoubleExtension(name)) out.push({ rule: 'upload.double_extension', engine: 'builtin' });
  if (type && typeMismatch(type, { name, contentType })) out.push({ rule: 'upload.type_mismatch', engine: 'builtin', capped: true });
  return out;
}

const SCRIPT_ARCHIVE_ENTRY = /\.(aspx?|jspx?|php[3-7]?|phar|phtml|cgi|pl|sh)$/i;

/** Inspects bytes already in memory. */
export function inspectBytes(data: Uint8Array, meta: UploadMeta = {}, opts: ScannerOptions = {}): UploadVerdict {
  const s = new UploadScanner(meta, opts);
  for (let i = 0; i < data.length; i += PIECE_BYTES) s.push(data.subarray(i, i + PIECE_BYTES));
  return s.finish(true);
}

/** Whether a verdict means active content (README "Backdoor checks", `backdoor.write_served`). */
export function isActiveContent(v: Pick<UploadVerdict, 'kind' | 'findings'>): boolean {
  return ['script', 'html', 'svg', 'executable'].includes(v.kind) || v.findings.some((f) => !f.capped && f.rule !== 'upload.too_large' && f.rule !== 'upload.type_not_allowed');
}

/** `backdoor.write_executable`: a destination named like code the server runs. */
export const isExecutableName = (path: string) => SCRIPT_FILE.test(baseName(path)) || isServerConfigName(path);
