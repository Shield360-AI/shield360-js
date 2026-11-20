/**
 * Upload signatures (sdk/rasp/README.md "Uploads", "Signatures"): a small,
 * YARA-like rule format for web shells and the organization's own rules.
 *
 * A rule is a few byte strings (text, hex, or a safe regular expression run
 * only around a plain-text anchor) and a condition over them. Everything is
 * bounded: string sizes, how many rules, how far a regular expression looks
 * and how many steps it may take, so a rule can never cost more than a fixed
 * amount of CPU per file. Rules are data; nothing here runs code.
 *
 * This file is shared: `sdk/typescript/src/rasp/upload-signatures.ts` and
 * `src/client/src/lib/security/uploads/upload-signatures.ts` are
 * byte-identical (a test in each tree says so), so the platform accepts
 * exactly what the SDK runs, and the console can test a rule against a sample
 * in the browser without the sample leaving it. It imports only rule-expr.
 */
import { compileRegex, regexMatches } from "./rule-expr";

/** Hard limits, identical on the platform and in every SDK. */
export const UPLOAD_SIGNATURE_LIMITS = Object.freeze({
	/** The organization's own rules. */
	rules: 64,
	/** JSON of all own rules together, in bytes. */
	totalBytes: 65536,
	stringsPerRule: 16,
	/** Bytes of a text or hex string. */
	minBytes: 3,
	maxBytes: 256,
	/** Bytes of a regex string's anchor. */
	anchorMax: 64,
	conditionChars: 256,
	conditionDepth: 8,
	idChars: 48,
	titleChars: 120,
	/** A regex runs on 256 bytes before each anchor occurrence to 1024 after it. */
	windowBefore: 256,
	windowAfter: 1024,
	/** Anchor occurrences tried per string and piece. */
	anchorsPerPiece: 8,
	/** Pike VM steps for every regex of one file together. */
	regexSteps: 1_000_000,
	/** Overlap between pieces, so a match across two pieces is found. */
	overlap: 2048,
});

export type UploadSignatureErrorCode =
	| "shape"
	| "id"
	| "title"
	| "strings"
	| "string_id"
	| "duplicate_string"
	| "string_kind"
	| "text"
	| "hex"
	| "regex"
	| "anchor"
	| "condition"
	| "unknown_string"
	| "too_many"
	| "too_large"
	| "duplicate_id";

export type UploadSignatureError = { code: UploadSignatureErrorCode; rule?: number; string?: string };

type StringSpec = { id: string; kind: "text" | "hex" | "regex"; bytes: string; nocase: boolean; prog?: ReturnType<typeof compileRegex>; anchor?: string };

type Cond = { op: "id"; i: number } | { op: "not"; x: Cond } | { op: "and" | "or"; xs: Cond[] } | { op: "atLeast"; n: number };

export type CompiledSignature = { id: string; title: string; strings: StringSpec[]; cond: Cond };

export type SignatureResult = { ok: true; signature: CompiledSignature } | { ok: false; error: UploadSignatureError };

const RULE_ID = /^[a-z0-9][a-z0-9_.-]{0,47}$/;
const STRING_ID = /^[a-z][a-z0-9_]{0,15}$/;
const HEX = /^[0-9a-fA-F]{2}( ?[0-9a-fA-F]{2})*$/;

/** UTF-8 bytes of a string, as a Latin-1 string (one character a byte). */
export function utf8Latin1(s: string): string {
	let out = "";
	for (const ch of s) {
		const c = ch.codePointAt(0) as number;
		if (c < 0x80) out += String.fromCharCode(c);
		else if (c < 0x800) out += String.fromCharCode(0xc0 | (c >> 6), 0x80 | (c & 63));
		else if (c < 0x10000) out += String.fromCharCode(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
		else out += String.fromCharCode(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
	}
	return out;
}

/** Bytes as a Latin-1 string: one character a byte, every byte kept as it is. */
export function latin1(bytes: Uint8Array, start = 0, end = bytes.length): string {
	let out = "";
	for (let i = start; i < end; i += 8192) {
		out += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, Math.min(end, i + 8192))));
	}
	return out;
}

/** Folds ASCII letters only (A-Z to a-z); every other character stays. */
export function asciiLower(s: string): string {
	return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

// ---- condition ---------------------------------------------------------------

function parseCondition(src: string, ids: Map<string, number>): Cond | UploadSignatureErrorCode {
	const text = src.trim();
	if (!text || text.length > UPLOAD_SIGNATURE_LIMITS.conditionChars) return "condition";
	if (text === "any") return { op: "atLeast", n: 1 };
	if (text === "all") return { op: "atLeast", n: ids.size };
	if (/^[0-9]{1,2}$/.test(text)) {
		const n = Number(text);
		return n >= 1 && n <= ids.size ? { op: "atLeast", n } : "condition";
	}
	const toks = text.match(/\(|\)|[A-Za-z_][A-Za-z0-9_]*|\S/g) || [];
	let pos = 0;
	let depth = 0;
	let unknown = false;
	const peek = () => toks[pos];
	const or = (): Cond | null => {
		const xs: Cond[] = [];
		const first = and();
		if (!first) return null;
		xs.push(first);
		while (peek() === "or") {
			pos++;
			const next = and();
			if (!next) return null;
			xs.push(next);
		}
		return xs.length === 1 ? xs[0] : { op: "or", xs };
	};
	const and = (): Cond | null => {
		const xs: Cond[] = [];
		const first = unary();
		if (!first) return null;
		xs.push(first);
		while (peek() === "and") {
			pos++;
			const next = unary();
			if (!next) return null;
			xs.push(next);
		}
		return xs.length === 1 ? xs[0] : { op: "and", xs };
	};
	const unary = (): Cond | null => {
		const t = peek();
		if (t === "not") {
			pos++;
			if (++depth > UPLOAD_SIGNATURE_LIMITS.conditionDepth) return null;
			const x = unary();
			depth--;
			return x ? { op: "not", x } : null;
		}
		if (t === "(") {
			pos++;
			if (++depth > UPLOAD_SIGNATURE_LIMITS.conditionDepth) return null;
			const x = or();
			depth--;
			if (!x || peek() !== ")") return null;
			pos++;
			return x;
		}
		if (t && STRING_ID.test(t) && t !== "and" && t !== "or" && t !== "not") {
			pos++;
			const i = ids.get(t);
			if (i === undefined) {
				unknown = true;
				return null;
			}
			return { op: "id", i };
		}
		return null;
	};
	const cond = or();
	if (unknown) return "unknown_string";
	if (!cond || pos !== toks.length) return "condition";
	return cond;
}

function holds(c: Cond, found: boolean[]): boolean {
	switch (c.op) {
		case "id":
			return found[c.i];
		case "not":
			return !holds(c.x, found);
		case "and":
			return c.xs.every((x) => holds(x, found));
		case "or":
			return c.xs.some((x) => holds(x, found));
		case "atLeast":
			return found.filter(Boolean).length >= c.n;
	}
}

// ---- compile -----------------------------------------------------------------

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function compileString(raw: unknown): StringSpec | UploadSignatureErrorCode {
	if (!isObject(raw)) return "string_kind";
	if (typeof raw.id !== "string" || !STRING_ID.test(raw.id) || ["and", "or", "not", "any", "all"].includes(raw.id)) return "string_id";
	const kinds = ["text", "hex", "regex"].filter((k) => raw[k] !== undefined);
	if (kinds.length !== 1) return "string_kind";
	const nocase = raw.nocase === true;
	const { minBytes, maxBytes, anchorMax } = UPLOAD_SIGNATURE_LIMITS;
	if (typeof raw.text === "string") {
		const bytes = utf8Latin1(raw.text);
		if (bytes.length < minBytes || bytes.length > maxBytes) return "text";
		return { id: raw.id, kind: "text", bytes: nocase ? asciiLower(bytes) : bytes, nocase };
	}
	if (typeof raw.hex === "string") {
		const hex = raw.hex.trim();
		if (!HEX.test(hex)) return "hex";
		const digits = hex.replace(/ /g, "");
		let bytes = "";
		for (let i = 0; i < digits.length; i += 2) bytes += String.fromCharCode(parseInt(digits.slice(i, i + 2), 16));
		if (bytes.length < minBytes || bytes.length > maxBytes) return "hex";
		return { id: raw.id, kind: "hex", bytes, nocase: false };
	}
	if (typeof raw.regex === "string") {
		const prog = compileRegex(raw.regex);
		if (!prog) return "regex";
		if (typeof raw.anchor !== "string") return "anchor";
		const anchor = utf8Latin1(raw.anchor);
		if (anchor.length < minBytes || anchor.length > anchorMax) return "anchor";
		return { id: raw.id, kind: "regex", bytes: anchor, nocase: false, prog, anchor };
	}
	return "string_kind";
}

/** Checks one rule and compiles it. */
export function compileSignature(raw: unknown, index?: number): SignatureResult {
	const fail = (code: UploadSignatureErrorCode, string?: string): SignatureResult => ({ ok: false, error: { code, ...(index !== undefined ? { rule: index } : {}), ...(string ? { string } : {}) } });
	if (!isObject(raw)) return fail("shape");
	if (typeof raw.id !== "string" || !RULE_ID.test(raw.id)) return fail("id");
	if (typeof raw.title !== "string" || !raw.title.trim() || raw.title.length > UPLOAD_SIGNATURE_LIMITS.titleChars) return fail("title");
	if (!Array.isArray(raw.strings) || raw.strings.length < 1 || raw.strings.length > UPLOAD_SIGNATURE_LIMITS.stringsPerRule) return fail("strings");
	const strings: StringSpec[] = [];
	const ids = new Map<string, number>();
	for (const s of raw.strings) {
		const sid = isObject(s) && typeof s.id === "string" ? s.id : undefined;
		const spec = compileString(s);
		if (typeof spec === "string") return fail(spec, sid);
		if (ids.has(spec.id)) return fail("duplicate_string", spec.id);
		ids.set(spec.id, strings.length);
		strings.push(spec);
	}
	if (typeof raw.condition !== "string" && typeof raw.condition !== "number") return fail("condition");
	const cond = parseCondition(String(raw.condition), ids);
	if (typeof cond === "string") return fail(cond);
	return { ok: true, signature: { id: raw.id, title: raw.title.trim(), strings, cond } };
}

/**
 * The organization's own rules as sent: every valid one, in order, and the
 * errors of the others. More than 64 rules or 64 KiB is refused whole.
 */
export function compileSignatures(raw: unknown): { signatures: CompiledSignature[]; errors: UploadSignatureError[] } {
	if (raw === undefined || raw === null) return { signatures: [], errors: [] };
	if (!Array.isArray(raw)) return { signatures: [], errors: [{ code: "shape" }] };
	if (raw.length > UPLOAD_SIGNATURE_LIMITS.rules) return { signatures: [], errors: [{ code: "too_many" }] };
	let size = 0;
	try {
		size = utf8Latin1(JSON.stringify(raw)).length;
	} catch {
		return { signatures: [], errors: [{ code: "shape" }] };
	}
	if (size > UPLOAD_SIGNATURE_LIMITS.totalBytes) return { signatures: [], errors: [{ code: "too_large" }] };
	const signatures: CompiledSignature[] = [];
	const errors: UploadSignatureError[] = [];
	const seen = new Set<string>();
	raw.forEach((r, i) => {
		const c = compileSignature(r, i);
		if (!c.ok) errors.push(c.error);
		else if (seen.has(c.signature.id)) errors.push({ code: "duplicate_id", rule: i });
		else {
			seen.add(c.signature.id);
			signatures.push(c.signature);
		}
	});
	return { signatures, errors };
}

// ---- matching ----------------------------------------------------------------

/**
 * Matches rules over a file read in pieces. Each piece is given as Latin-1
 * text (`latin1`) and its ASCII-folded copy; consecutive pieces overlap by
 * `UPLOAD_SIGNATURE_LIMITS.overlap` bytes. `final` marks the last piece.
 */
export class SignatureMatcher {
	private readonly found: boolean[][];
	readonly budget = { steps: UPLOAD_SIGNATURE_LIMITS.regexSteps };

	constructor(readonly signatures: CompiledSignature[]) {
		this.found = signatures.map((s) => s.strings.map(() => false));
	}

	feed(piece: string, folded: string, final: boolean): void {
		const { windowBefore, windowAfter, anchorsPerPiece } = UPLOAD_SIGNATURE_LIMITS;
		this.signatures.forEach((sig, r) => {
			sig.strings.forEach((s, i) => {
				if (this.found[r][i]) return;
				if (s.kind !== "regex") {
					if ((s.nocase ? folded : piece).includes(s.bytes)) this.found[r][i] = true;
					return;
				}
				if (this.budget.steps < 0) return;
				let at = piece.indexOf(s.bytes);
				for (let n = 0; at >= 0 && n < anchorsPerPiece; n++) {
					const end = at + s.bytes.length + windowAfter;
					// A window cut by the end of a piece is tried again in the next one (the overlap holds it).
					if (end > piece.length && !final) break;
					if (regexMatches(s.prog!, piece.slice(Math.max(0, at - windowBefore), Math.min(piece.length, end)), this.budget)) {
						this.found[r][i] = true;
						break;
					}
					if (this.budget.steps < 0) break;
					at = piece.indexOf(s.bytes, at + 1);
				}
			});
		});
	}

	/** The rules whose condition holds, in order. */
	matched(): CompiledSignature[] {
		return this.signatures.filter((sig, r) => holds(sig.cond, this.found[r]));
	}
}

/** Runs rules over a whole sample (the console's "Test against a sample"): the ids that match. */
export function matchSample(signatures: CompiledSignature[], bytes: Uint8Array): string[] {
	const m = new SignatureMatcher(signatures);
	const piece = 1024 * 1024;
	const { overlap } = UPLOAD_SIGNATURE_LIMITS;
	for (let start = 0; ; start += piece) {
		const from = Math.max(0, start - overlap);
		const end = Math.min(bytes.length, start + piece);
		const text = latin1(bytes, from, end);
		m.feed(text, asciiLower(text), end >= bytes.length);
		if (end >= bytes.length) break;
	}
	return m.matched().map((s) => s.id);
}
