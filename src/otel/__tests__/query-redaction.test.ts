/**
 * Credential query values never reach a span: the processor rewrites the URL
 * attributes the HTTP and undici instrumentations set when a span starts.
 */
import { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { isCredentialParam, QueryRedactionSpanProcessor, REDACTED, redactQueryString, redactUrl } from '../query-redaction';

describe('credential query parameters', () => {
  it.each(['key', 'api_key', 'apiKey', 'X-Goog-Api-Key', 'access_token', 'id_token', 'refresh_token', 'token', 'code', 'client_secret', 'password', 'sig', 'X-Amz-Signature', 'X-Amz-Security-Token', 'AWSAccessKeyId', 'session_id', 'jwt'])('%s is a credential', (name) => {
    expect(isCredentialParam(name)).toBe(true);
  });

  it.each(['q', 'page', 'limit', 'user', 'model', 'sort', 'monkey', 'keyword_count'])('%s is not', (name) => {
    expect(isCredentialParam(name)).toBe(false);
  });
});

describe('redactUrl', () => {
  it('replaces credential values and keeps everything else byte for byte', () => {
    expect(redactUrl('https://api.example.com/v1/models?key=AIzaSyA-secret&alt=json')).toBe(`https://api.example.com/v1/models?key=${REDACTED}&alt=json`);
    expect(redactUrl('/reset?token=abc123&lang=en#x')).toBe(`/reset?token=${REDACTED}&lang=en#x`);
    expect(redactUrl('/cb?code=4%2F0Ad&state=xyz')).toBe(`/cb?code=${REDACTED}&state=xyz`);
    expect(redactUrl('https://user:hunter2@db.example.com/x')).toBe(`https://${REDACTED}:${REDACTED}@db.example.com/x`);
    expect(redactUrl('https://example.com/search?q=hello%20world&page=2')).toBe('https://example.com/search?q=hello%20world&page=2');
  });

  it('handles encoded names, repeated and valueless parameters', () => {
    expect(redactQueryString('?api%5Fkey=s1&api_key=s2&debug')).toBe(`?api%5Fkey=${REDACTED}&api_key=${REDACTED}&debug`);
    expect(redactQueryString('a=1&b=2')).toBe('a=1&b=2');
    expect(redactQueryString('%E0%A4%A=1&token=x')).toBe(`%E0%A4%A=1&token=${REDACTED}`);
  });

  it('is idempotent', () => {
    const once = redactUrl('https://u:p@h/x?token=a&q=1');
    expect(redactUrl(once)).toBe(once);
  });
});

describe('QueryRedactionSpanProcessor', () => {
  it('rewrites url.full, url.query, http.url and http.target before any exporter sees them', () => {
    const exporter = new InMemorySpanExporter();
    const provider = new BasicTracerProvider({ spanProcessors: [new QueryRedactionSpanProcessor(), new SimpleSpanProcessor(exporter)] });
    const tracer = provider.getTracer('t');
    const span = tracer.startSpan('GET', {
      attributes: {
        'url.full': 'https://generativelanguage.googleapis.com/v1beta/models?key=AIzaSyA-real-key',
        'url.query': '?access_token=ya29.a0AfH6&fields=id',
        'http.url': 'http://svc/x?password=pw',
        'http.target': '/login?token=t0k3n',
        'url.path': '/v1beta/models',
      },
    });
    span.end();
    const attrs = exporter.getFinishedSpans()[0].attributes;
    expect(attrs['url.full']).toBe(`https://generativelanguage.googleapis.com/v1beta/models?key=${REDACTED}`);
    expect(attrs['url.query']).toBe(`?access_token=${REDACTED}&fields=id`);
    expect(attrs['http.url']).toBe(`http://svc/x?password=${REDACTED}`);
    expect(attrs['http.target']).toBe(`/login?token=${REDACTED}`);
    expect(attrs['url.path']).toBe('/v1beta/models');
    expect(JSON.stringify(attrs)).not.toMatch(/AIzaSyA-real-key|ya29|t0k3n|=pw\b/);
  });
});
