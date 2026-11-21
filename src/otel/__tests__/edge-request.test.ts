import { context, trace } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { createLogger, disableAppLogs, enableAppLogs } from '../app-logs';
import { currentEdgeIds, httpRequestHook, requestIdOf, resetEdgeRequests, traceIdOf } from '../edge-request';
import { captureRequest } from '../../rasp/capture';
import { storage } from '../../rasp/context';
import { communityOptions } from '../../instrumentation/http-noise';

/**
 * Request correlation: Edge's request id and the trace id ride on every log
 * record written while a request is served, and on its server span.
 */
const RID = '3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6';
const TRACE = '0af7651916cd43dd8448eb211c80319c';

function logs() {
  const exporter = new InMemoryLogRecordExporter();
  enableAppLogs(new LoggerProvider({ processors: [new SimpleLogRecordProcessor({ exporter })] }), 'info', { captureCodeLocation: false });
  return exporter;
}

describe('edge request correlation', () => {
  let cm: AsyncLocalStorageContextManager;
  beforeAll(() => {
    cm = new AsyncLocalStorageContextManager().enable();
    context.setGlobalContextManager(cm);
  });
  afterAll(() => {
    context.disable();
  });
  afterEach(() => {
    disableAppLogs();
    resetEdgeRequests();
  });

  it('accepts only id-shaped request ids and well-formed traceparents', () => {
    expect(requestIdOf(RID)).toBe(RID);
    expect(requestIdOf('short')).toBeUndefined();
    expect(requestIdOf('has space in it')).toBeUndefined();
    expect(requestIdOf('a'.repeat(129))).toBeUndefined();
    expect(traceIdOf(`00-${TRACE}-b7ad6b7169203331-01`)).toBe(TRACE);
    expect(traceIdOf(`00-${'0'.repeat(32)}-b7ad6b7169203331-01`)).toBeUndefined();
    expect(traceIdOf('junk')).toBeUndefined();
  });

  it('puts the request id and the trace id on a log record when the app does not trace', () => {
    const exporter = logs();
    const ctx = captureRequest({ framework: 'test', method: 'GET', url: '/a?q=1', headers: { 'x-request-id': RID, traceparent: `00-${TRACE}-b7ad6b7169203331-01` } });
    storage.run(ctx, () => createLogger().info('served'));
    const [record] = exporter.getFinishedLogRecords();
    expect(record.attributes['shield360.edge.request_id']).toBe(RID);
    expect(record.attributes['shield360.edge.trace_id']).toBe(TRACE);
  });

  it('ignores a request id that is not id-shaped', () => {
    const exporter = logs();
    const ctx = captureRequest({ framework: 'test', method: 'GET', url: '/', headers: { 'x-request-id': '<script>' } });
    storage.run(ctx, () => createLogger().info('served'));
    expect(exporter.getFinishedLogRecords()[0].attributes['shield360.edge.request_id']).toBeUndefined();
  });

  it('tags the server span from the http hook and carries the id to logs in child spans', () => {
    const exporter = logs();
    const spans = new InMemorySpanExporter();
    const tracer = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(spans)] }).getTracer('t');
    expect(communityOptions('http')?.requestHook).toBe(httpRequestHook);
    tracer.startActiveSpan('GET /a', (server) => {
      httpRequestHook(server, { headers: { 'x-request-id': RID } });
      // An outgoing request is never read.
      httpRequestHook(server, { headers: { 'x-request-id': 'other-request-id' }, getHeader: () => undefined });
      tracer.startActiveSpan('db', (child) => {
        expect(currentEdgeIds().requestId).toBe(RID);
        createLogger().info('query');
        child.end();
      });
      server.end();
    });
    const server = spans.getFinishedSpans().find((s) => s.name === 'GET /a')!;
    expect(server.attributes['shield360.edge.request_id']).toBe(RID);
    const [record] = exporter.getFinishedLogRecords();
    expect(record.attributes['shield360.edge.request_id']).toBe(RID);
    // The span carries the trace id; it is not repeated as an attribute.
    expect(record.attributes['shield360.edge.trace_id']).toBeUndefined();
    expect(record.spanContext?.traceId).toBe(server.spanContext().traceId);
  });

  it('adds nothing outside a request', () => {
    const exporter = logs();
    expect(trace.getActiveSpan()).toBeUndefined();
    createLogger().info('boot');
    expect(exporter.getFinishedLogRecords()[0].attributes['shield360.edge.request_id']).toBeUndefined();
  });
});
