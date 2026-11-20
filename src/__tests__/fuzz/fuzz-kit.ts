/**
 * Seeded randomness for the property ("fuzz") tests. CI runs a small number
 * of iterations; run longer locally with
 *
 *   SHIELD360_FUZZ_ITERATIONS=200000 SHIELD360_FUZZ_SEED=7 npx jest src/__tests__/fuzz
 *
 * A failure prints the seed and iteration; add the failing input to the
 * test's regression seeds so it is checked on every run.
 */

export const FUZZ_SEED = Number(process.env.SHIELD360_FUZZ_SEED ?? 20261119) >>> 0;
export const FUZZ_ITERATIONS = Math.max(1, Number(process.env.SHIELD360_FUZZ_ITERATIONS ?? 400) | 0);

/** mulberry32: small, fast, deterministic. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export type Rand = {
  next: () => number;
  int: (n: number) => number;
  pick: <T>(xs: readonly T[]) => T;
  chance: (p: number) => boolean;
  string: (alphabet: string, max: number) => string;
};

export function rand(seed: number): Rand {
  const next = rng(seed);
  const int = (n: number) => Math.floor(next() * n);
  return {
    next,
    int,
    pick: (xs) => xs[int(xs.length)],
    chance: (p) => next() < p,
    string: (alphabet, max) => {
      const chars = Array.from(alphabet);
      let s = '';
      const len = int(max + 1);
      for (let i = 0; i < len; i++) s += chars[int(chars.length)];
      return s;
    },
  };
}
