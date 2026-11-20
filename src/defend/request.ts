/**
 * What Defend reads from a request: Node's IncomingMessage (Express, Koa's
 * req, plain http), a fetch Request (Next.js route handlers and middleware,
 * Hono, Workers-style handlers), or a plain object with method, url and
 * headers. Header values stay in memory for the one decision; nothing here is
 * logged or sent.
 */
import { parseIpBytes } from '../rasp/rule-expr';
import type { DefendCallOptions, DefendFacts } from './types';

export const MAX_CONTENT_ITEMS = 16;
export const MAX_CONTENT_ITEM = 8192;
const MAX_HEADER = 4096;

type HeaderBag = Record<string, string>;

function fromHeaders(raw: unknown): HeaderBag {
  const out: HeaderBag = {};
  const put = (k: unknown, v: unknown) => {
    if (typeof k !== 'string') return;
    const value = Array.isArray(v) ? v.filter((x) => typeof x === 'string').join(', ') : typeof v === 'string' ? v : undefined;
    if (value !== undefined) out[k.toLowerCase()] = value.slice(0, MAX_HEADER);
  };
  if (!raw) return out;
  if (typeof (raw as Headers).forEach === 'function' && typeof (raw as Headers).get === 'function') {
    (raw as Headers).forEach((v, k) => put(k, v));
    return out;
  }
  if (typeof raw === 'object') for (const [k, v] of Object.entries(raw as Record<string, unknown>)) put(k, v);
  return out;
}

/** The path before any `?`, percent-decoded once; the raw path when an escape is invalid. */
export function pathOf(target: string): string {
  let p = target || '/';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p)) {
    try {
      p = new URL(p).pathname;
    } catch {
      p = '/';
    }
  }
  const q = p.search(/[?#]/);
  if (q >= 0) p = p.slice(0, q);
  if (!p.startsWith('/')) p = `/${p}`;
  try {
    return decodeURIComponent(p);
  } catch {
    return p;
  }
}

const usableIp = (v: unknown): string | undefined => {
  if (typeof v !== 'string') return undefined;
  let s = v.trim();
  if (s.startsWith('[') && s.includes(']')) s = s.slice(1, s.indexOf(']'));
  if (s.startsWith('::ffff:') && s.includes('.')) s = s.slice(7);
  return parseIpBytes(s) ? s : undefined;
};

/** The address `hops` proxies from the right of X-Forwarded-For (hops 1: the last entry), or undefined. */
export function forwardedIp(header: string | undefined, hops: number): string | undefined {
  if (!header || hops < 1) return undefined;
  const parts = header.split(',').map((s) => s.trim()).filter(Boolean);
  return usableIp(parts[parts.length - hops]);
}

export type FactsOptions = { trustProxy?: number; geoHeaders?: { country?: string; asn?: string } };

/** The facts of a request of any supported shape. Never throws (an unreadable request gives `/` and GET). */
export function factsOf(req: unknown, call: DefendCallOptions = {}, o: FactsOptions = {}): DefendFacts {
  const r = (req ?? {}) as Record<string, unknown>;
  const headers = fromHeaders(r.headers);
  const method = typeof r.method === 'string' && r.method ? r.method.toUpperCase().slice(0, 16) : 'GET';
  const target = typeof r.originalUrl === 'string' ? r.originalUrl : typeof r.url === 'string' ? r.url : '/';
  const socket = r.socket as { remoteAddress?: unknown } | undefined;
  // Express `req.ip` honors its own `trust proxy`; then X-Forwarded-For only as far as trustProxy says; then the socket.
  const ip =
    usableIp(call.ip) ??
    usableIp(typeof r.ip === 'string' ? r.ip : undefined) ??
    forwardedIp(headers['x-forwarded-for'], o.trustProxy ?? 0) ??
    usableIp(socket?.remoteAddress);
  const facts: DefendFacts = { method, path: pathOf(target), headers };
  if (ip) facts.ip = ip;
  const country = call.country ?? (o.geoHeaders?.country ? headers[o.geoHeaders.country.toLowerCase()] : undefined);
  if (typeof country === 'string' && /^[A-Za-z]{2}$/.test(country.trim())) facts.country = country.trim().toUpperCase();
  const asnRaw = call.asn ?? (o.geoHeaders?.asn ? headers[o.geoHeaders.asn.toLowerCase()] : undefined);
  const asn = typeof asnRaw === 'number' ? asnRaw : typeof asnRaw === 'string' ? Number(asnRaw.replace(/^AS/i, '')) : NaN;
  if (Number.isInteger(asn) && asn > 0 && asn <= 4294967295) facts.asn = asn;
  const content = call.content === undefined ? [] : Array.isArray(call.content) ? call.content : [call.content];
  const kept = content.filter((c): c is string => typeof c === 'string' && c.length > 0).slice(0, MAX_CONTENT_ITEMS).map((c) => c.slice(0, MAX_CONTENT_ITEM));
  if (kept.length) facts.content = kept;
  return facts;
}

/** Whether the request carries something the agent verifier checks: a passport or a Web Bot Auth signature. */
export function carriesAgentProof(headers: HeaderBag): boolean {
  return Boolean(headers['shield360-agent'] || (headers['signature'] && headers['signature-input']));
}
