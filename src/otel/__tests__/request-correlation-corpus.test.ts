import { readFileSync } from 'fs';
import { join } from 'path';
import { requestIdOf, traceIdOf } from '../edge-request';
import { RASP_DIR } from '../../rasp/__tests__/corpus';

/** Request correlation: the shared vectors (sdk/rasp/testdata/request-correlation.json). */
type Case = { name: string; value: string | null; expect: string | null };
const corpus = JSON.parse(readFileSync(join(RASP_DIR, 'testdata', 'request-correlation.json'), 'utf8')) as { requestId: Case[]; traceparent: Case[] };

describe('request correlation corpus', () => {
  it.each(corpus.requestId.map((c) => [c.name, c] as const))('request id: %s', (_name, c) => {
    expect(requestIdOf(c.value) ?? null).toBe(c.expect);
  });
  it.each(corpus.traceparent.map((c) => [c.name, c] as const))('traceparent: %s', (_name, c) => {
    expect(traceIdOf(c.value) ?? null).toBe(c.expect);
  });
});
