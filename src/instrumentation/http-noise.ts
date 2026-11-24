/**
 * SHIELD: request tracing without the noise.
 *
 * HTTP and undici tracing are on by default so an app's requests are traces
 * and its database calls and log lines sit inside them. Two kinds of request
 * are left out, because they would bury the app's own traffic:
 *   - health probes (Kubernetes, load balancers, uptime checks), which arrive
 *     every few seconds and say nothing about the app;
 *   - the SDK's own calls to Shield360 (guard reports, heartbeats, config),
 *     which are not the app's work.
 */

import { httpRequestHook } from '../otel/edge-request';

const HEALTH_PATHS = new Set(['/health', '/healthz', '/healthcheck', '/ready', '/readyz', '/live', '/livez', '/ping', '/status', '/metrics', '/api/health']);
const PROBE_AGENTS = /^(kube-probe|ELB-HealthChecker|GoogleHC|Consul Health Check|Amazon-Route53-Health-Check-Service|UptimeRobot)/i;

/** Whether an incoming request is a health probe: a probe's user agent, or a well-known health path. */
export function isHealthProbe(url: string | undefined, userAgent: string | string[] | undefined): boolean {
  const agent = Array.isArray(userAgent) ? userAgent[0] : userAgent;
  if (agent && PROBE_AGENTS.test(agent)) return true;
  const path = (url || '').split('?')[0].replace(/\/+$/, '') || '/';
  return HEALTH_PATHS.has(path.toLowerCase());
}

/**
 * SHIELD: incoming paths an app asks to leave alone (SHIELD360_IGNORE_INCOMING_PATHS,
 * comma-separated prefixes, matched on path-segment boundaries: "/api/ingest"
 * covers "/api/ingest/otlp" but not "/api/ingestion"). Neither traced nor
 * captured by runtime protection. For machine endpoints that would otherwise
 * feed back into themselves, such as Shield360's own ingest when Shield360
 * runs the SDK.
 */
export function ignoredIncomingPrefixes(env: NodeJS.ProcessEnv = process.env): string[] {
  return String(env.SHIELD360_IGNORE_INCOMING_PATHS || '')
    .split(',')
    .map((p) => p.trim().replace(/\/+$/, ''))
    .filter((p) => p.startsWith('/') && p.length > 1);
}

let cachedPrefixes: { raw: string | undefined; list: string[] } | null = null;

/** Whether an incoming request's path is under one of SHIELD360_IGNORE_INCOMING_PATHS. */
export function isIgnoredIncomingPath(url: string | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.SHIELD360_IGNORE_INCOMING_PATHS;
  if (!raw) return false;
  if (!cachedPrefixes || cachedPrefixes.raw !== raw) cachedPrefixes = { raw, list: ignoredIncomingPrefixes(env) };
  const path = (url || '').split('?')[0].split('#')[0].toLowerCase();
  return cachedPrefixes.list.some((p) => {
    const prefix = p.toLowerCase();
    return path === prefix || path.startsWith(prefix + '/');
  });
}

/** The Shield360 host the SDK reports to, from SHIELD360_URL, or ''. */
export function shield360Host(env: NodeJS.ProcessEnv = process.env): string {
  try {
    return env.SHIELD360_URL ? new URL(env.SHIELD360_URL).host.toLowerCase() : '';
  } catch {
    return '';
  }
}

/** Whether an outgoing request goes to Shield360 itself. */
export function isOwnCall(host: string | undefined, own: string = shield360Host()): boolean {
  return !!own && !!host && host.toLowerCase() === own;
}

const KAFKA_MESSAGE_KEY = 'messaging.kafka.message.key';

/** Replaces the Kafka message key the instrumentation recorded with '?'. */
export function maskKafkaKey(span: { setAttribute(key: string, value: string): unknown }, info: { message?: { key?: unknown } | null }): void {
  // The instrumentation records a key only when it is truthy.
  if (info?.message?.key) span.setAttribute(KAFKA_MESSAGE_KEY, '?');
}

/** The options each default community instrumentation is created with (health probes and own calls left out, values kept out of statements). */
export function communityOptions(name: string): Record<string, unknown> | undefined {
  if (name === 'http') {
    return {
      // SHIELD: request correlation — Edge's request id on the server span (otel/edge-request.ts).
      requestHook: httpRequestHook,
      ignoreIncomingRequestHook: (req: { url?: string; headers?: Record<string, string | string[] | undefined> }) => {
        try {
          return isHealthProbe(req.url, req.headers?.['user-agent']) || isIgnoredIncomingPath(req.url);
        } catch {
          return false;
        }
      },
      ignoreOutgoingRequestHook: (options: { host?: string | null; hostname?: string | null; port?: string | number | null }) => {
        try {
          const name = options.hostname || options.host || '';
          const host = options.port && !String(name).includes(':') ? `${name}:${options.port}` : String(name);
          return isOwnCall(host) || isOwnCall(String(name));
        } catch {
          return false;
        }
      },
    };
  }
  if (name === 'undici') {
    return {
      ignoreRequestHook: (request: { origin?: string }) => {
        try {
          return !!request.origin && isOwnCall(new URL(request.origin).host);
        } catch {
          return false;
        }
      },
    };
  }
  // SHIELD: data minimisation — a cache command is recorded by name only: its
  // keys and values can hold personal data or secrets.
  if (name === 'redis' || name === 'ioredis') {
    return { dbStatementSerializer: (command: string) => String(command || '').toUpperCase() };
  }
  // Express: the route and its handler, not one span per middleware (expressInit, query, json…).
  if (name === 'express') return { ignoreLayersType: ['middleware'] };
  // One span per resolver is noise; field values are never recorded.
  if (name === 'graphql') return { ignoreTrivialResolveSpans: true, mergeItems: true, allowValues: false };
  // Query shapes only, values replaced (the instrumentation's default, kept explicit).
  if (name === 'mongodb') return { enhancedDatabaseReporting: false };
  // mysql2 formats a query's values into db.query.text unless masked: numbers
  // and quoted strings become '?'.
  if (name === 'mysql2') return { maskStatement: true };
  // Bound values stay out of mysql spans (the instrumentation's default, kept explicit).
  if (name === 'mysql') return { enhancedDatabaseReporting: false };
  // A Kafka message key often names a person or account: recorded as '?'.
  // Payloads are never recorded by the instrumentation.
  if (name === 'kafkajs') return { producerHook: maskKafkaKey, consumerHook: maskKafkaKey };
  // The SDK call is the span; the HTTP request under it would repeat it.
  if (name === 'aws-sdk') return { suppressInternalInstrumentation: true };
  return undefined;
}
