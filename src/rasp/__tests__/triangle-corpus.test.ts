/**
 * SHIELD: protection triangle — the shared corpus sdk/rasp/testdata/triangle.json
 * (agent-guides/edge-deception-spec.md, "Protection triangle"), run from the
 * shared file. Every SDK's Edge-context code passes the same cases.
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import { edgeSaysSuspect, parseEdgeKeys, pathHash, ReplayCache, signVerdict, verifyEdgeContext, type EdgeContext } from '../edge-context';
import { RASP_DIR } from './corpus';

type ContextCase = { name: string; header: string; method: string; path: string; requestId: string | null; now: number; replayGroup: string | null; expect: Record<string, unknown> | null };
type VerdictCase = { name: string; rid: string; act: 'block' | 'flag'; cat: string; src: 'rasp' | 'sdk' | 'defend'; ttl: number; iat: number; expect: string | null };
const CORPUS = JSON.parse(readFileSync(join(RASP_DIR, 'testdata', 'triangle.json'), 'utf8')) as {
  edgeContext: unknown;
  parseKeys: { name: string; config: unknown; kids: string[] }[];
  context: ContextCase[];
  verdict: VerdictCase[];
  suspect: { context: EdgeContext; expect: boolean }[];
  pathHash: { path: string; hex: string }[];
};
const KEYS = parseEdgeKeys(CORPUS.edgeContext);

describe('protection triangle corpus', () => {
  it.each(CORPUS.parseKeys.map((c) => [c.name, c] as const))('parseKeys: %s', (_name, c) => {
    expect(parseEdgeKeys(c.config).map((k) => k.kid)).toEqual(c.kids);
  });

  it('context: every case, replay groups sharing a cache in order', () => {
    const caches = new Map<string, ReplayCache>();
    for (const c of CORPUS.context) {
      let cache: ReplayCache | null = null;
      if (c.replayGroup) {
        cache = caches.get(c.replayGroup) ?? new ReplayCache();
        caches.set(c.replayGroup, cache);
      }
      const got = verifyEdgeContext(KEYS, c.header, { method: c.method, path: c.path, ...(c.requestId ? { requestId: c.requestId } : {}) }, c.now * 1000, cache);
      expect([c.name, got]).toEqual([c.name, c.expect]);
    }
  });

  it.each(CORPUS.verdict.map((c) => [c.name, c] as const))('verdict: %s', (_name, c) => {
    expect(signVerdict(KEYS, { rid: c.rid, iat: c.iat, act: c.act, cat: c.cat, src: c.src, ttl: c.ttl })).toBe(c.expect);
  });

  it('suspect', () => {
    for (const c of CORPUS.suspect) expect([c.context, edgeSaysSuspect(c.context)]).toEqual([c.context, c.expect]);
  });

  it('pathHash', () => {
    for (const c of CORPUS.pathHash) expect(pathHash(c.path)).toBe(c.hex);
  });
});
