/**
 * SHIELD: credentials in URLs stay out of spans.
 *
 * The HTTP and undici instrumentations record the request URL with its query
 * string (`url.full`, `url.query`, and the older `http.url` / `http.target`).
 * Query strings carry credentials more often than they should: `?key=` on
 * some model APIs, `?token=` on password-reset and magic links, `?code=` on
 * OAuth callbacks, pre-signed `?X-Amz-Signature=`. The upstream
 * instrumentations redact only a few pre-signed URL parameters (http) or
 * none (undici).
 *
 * This processor runs when a span starts and replaces the value of every
 * query parameter whose name looks like a credential with `REDACTED`, and any
 * user:password in the URL, so the value never reaches an exporter. Parameter
 * names and every other value are kept.
 */
import type { Context } from '@opentelemetry/api';
import type { ReadableSpan, Span, SpanProcessor } from '@opentelemetry/sdk-trace-node';

export const REDACTED = 'REDACTED';

/** The span attributes that hold a URL or a query string. */
const URL_ATTRIBUTES = ['url.full', 'http.url'] as const;
const QUERY_ATTRIBUTES = ['url.query'] as const;
const TARGET_ATTRIBUTES = ['http.target'] as const;

const EXACT = new Set(['key', 'code', 'sig', 'auth', 'pwd', 'passwd', 'jwt', 'otp', 'session', 'sessionid', 'sid', 'awsaccesskeyid', 'hmac']);
const PARTS = ['token', 'secret', 'password', 'passphrase', 'apikey', 'accesskey', 'privatekey', 'signature', 'credential', 'authorization', 'clientsecret', 'securitytoken'];

/** Whether a query parameter's name names a credential (`api_key`, `X-Goog-Api-Key`, `access_token`, `code`...). */
export function isCredentialParam(name: string): boolean {
  const n = String(name).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!n) return false;
  if (EXACT.has(n)) return true;
  return PARTS.some((p) => n.includes(p));
}

/**
 * A query string (with or without its leading `?`) with credential values
 * replaced. The text is rewritten only when something is redacted, so an
 * ordinary query keeps its exact spelling.
 */
export function redactQueryString(query: string): string {
  if (typeof query !== 'string' || !query) return query;
  const lead = query.startsWith('?') ? '?' : '';
  const body = lead ? query.slice(1) : query;
  let changed = false;
  const parts = body.split('&').map((pair) => {
    const eq = pair.indexOf('=');
    const rawName = eq === -1 ? pair : pair.slice(0, eq);
    let name = rawName;
    try {
      name = decodeURIComponent(rawName.replace(/\+/g, ' '));
    } catch {
      // keep the raw name
    }
    if (eq === -1 || !isCredentialParam(name)) return pair;
    if (pair.slice(eq + 1) === REDACTED) return pair;
    changed = true;
    return `${rawName}=${REDACTED}`;
  });
  return changed ? lead + parts.join('&') : query;
}

/** A URL (absolute, or a path with a query) with credential query values and any user:password replaced. */
export function redactUrl(url: string): string {
  if (typeof url !== 'string' || !url) return url;
  const hashAt = url.indexOf('#');
  const noHash = hashAt === -1 ? url : url.slice(0, hashAt);
  const hash = hashAt === -1 ? '' : url.slice(hashAt);
  const q = noHash.indexOf('?');
  let base = q === -1 ? noHash : noHash.slice(0, q);
  const query = q === -1 ? '' : noHash.slice(q);
  // user:password@host
  base = base.replace(/^([a-z][a-z0-9+.-]*:\/\/)([^/@?#]*)@/i, (all, scheme: string, userinfo: string) => (userinfo === `${REDACTED}:${REDACTED}` ? all : `${scheme}${REDACTED}:${REDACTED}@`));
  const redactedQuery = query ? redactQueryString(query) : '';
  const fragment = hash ? `#${redactQueryString(hash.slice(1))}` : '';
  const out = base + redactedQuery + fragment;
  return out === url ? url : out;
}

type AttributeSpan = { attributes?: Record<string, unknown>; setAttribute(key: string, value: string): unknown };

/** Rewrites a started span's URL attributes in place. */
export function redactSpanUrls(span: AttributeSpan): void {
  const attrs = span.attributes;
  if (!attrs) return;
  for (const key of URL_ATTRIBUTES) {
    const v = attrs[key];
    if (typeof v === 'string') {
      const r = redactUrl(v);
      if (r !== v) span.setAttribute(key, r);
    }
  }
  for (const key of QUERY_ATTRIBUTES) {
    const v = attrs[key];
    if (typeof v === 'string') {
      const r = redactQueryString(v);
      if (r !== v) span.setAttribute(key, r);
    }
  }
  for (const key of TARGET_ATTRIBUTES) {
    const v = attrs[key];
    if (typeof v === 'string') {
      const r = redactUrl(v);
      if (r !== v) span.setAttribute(key, r);
    }
  }
}

export class QueryRedactionSpanProcessor implements SpanProcessor {
  onStart(span: Span, _parentContext: Context): void {
    try {
      redactSpanUrls(span as unknown as AttributeSpan);
    } catch {
      // never affects the span
    }
  }

  onEnd(span: ReadableSpan): void {
    // Attributes set after start (a hook, a redirect) are read-only by now; the
    // http instrumentation sets its URL attributes at start, so onStart sees them.
    void span;
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}
