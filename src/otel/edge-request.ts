/**
 * SHIELD: request correlation — Shield360 Edge's request id and the trace id
 * on everything the app records while it serves that request, so Shield360
 * joins the app's log lines and spans to Edge's record of the request, even
 * when the app does not trace.
 *
 * Edge's id is taken from its signed context header when the app verified one
 * (rasp/edge-context.ts), else from the request's `X-Request-Id` (Edge always
 * sends its own there; a client's value never reaches the app under that
 * name). It goes on:
 *   - the app's server span, as `shield360.edge.request_id` (the http
 *     instrumentation's request hook, and the RASP capture);
 *   - every log record written during the request (app-logs.ts, and so the
 *     pino, winston, console and stdio bridges), with the trace id as
 *     `shield360.edge.trace_id` when no span is active.
 * Only an id-shaped value is used: letters, digits, `.`, `_` and `-`, 8 to 128
 * characters.
 */
import { trace, type Span } from '@opentelemetry/api';
import { currentContext } from '../rasp/context';

export const EDGE_REQUEST_ID_ATTR = 'shield360.edge.request_id';
export const EDGE_TRACE_ID_ATTR = 'shield360.edge.trace_id';
export const REQUEST_ID_HEADER = 'x-request-id';

const REQUEST_ID = /^[A-Za-z0-9._-]{8,128}$/;
const TRACEPARENT = /^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/;
const MAX_TRACES = 5000;

/** Request ids by trace id, for log lines written in spans under the server span. Bounded; oldest dropped. */
const byTrace = new Map<string, string>();

/** An id-shaped request id, or undefined. */
export function requestIdOf(value: unknown): string | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  return typeof v === 'string' && REQUEST_ID.test(v) ? v : undefined;
}

/** The trace id in a W3C traceparent, or undefined. */
export function traceIdOf(traceparent: unknown): string | undefined {
  const m = typeof traceparent === 'string' ? TRACEPARENT.exec(traceparent) : null;
  return m && !/^0+$/.test(m[1]) ? m[1] : undefined;
}

/** Records the request id on the request's server span and remembers it for the span's trace. */
export function tagServerSpan(span: Span | undefined, requestId: string | undefined): void {
  if (!span || !requestId) return;
  try {
    span.setAttribute(EDGE_REQUEST_ID_ATTR, requestId);
    const sc = span.spanContext();
    if (!sc || !trace.isSpanContextValid(sc)) return;
    if (byTrace.size >= MAX_TRACES) byTrace.delete(byTrace.keys().next().value as string);
    byTrace.set(sc.traceId, requestId);
  } catch {
    // never breaks the request
  }
}

/** The http instrumentation's request hook: an incoming request's `X-Request-Id` on its server span. */
export function httpRequestHook(span: Span, request: unknown): void {
  try {
    const req = request as { headers?: Record<string, unknown>; getHeader?: unknown };
    if (!req || typeof req.getHeader === 'function' || !req.headers) return; // an outgoing request
    tagServerSpan(span, requestIdOf(req.headers[REQUEST_ID_HEADER]));
  } catch {
    // never breaks the request
  }
}

/** Edge's request id and the trace id for what the app is doing now (either may be absent). */
export function currentEdgeIds(): { requestId?: string; traceId?: string; spanActive: boolean } {
  const ctx = currentContext();
  const sc = trace.getActiveSpan()?.spanContext();
  const active = !!sc && trace.isSpanContextValid(sc);
  const requestId = ctx?.edge?.rid ?? ctx?.requestId ?? (active ? byTrace.get(sc!.traceId) : undefined);
  const traceId = active ? sc!.traceId : traceIdOf(ctx?.edge?.tp) ?? ctx?.traceId;
  return { requestId, traceId, spanActive: active };
}

/** Test hook. */
export function resetEdgeRequests(): void {
  byTrace.clear();
}
