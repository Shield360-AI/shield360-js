/**
 * Reads the verified claims of the signed Defend policy (typ
 * shield360-defend+jws). Anything malformed is dropped, never widened: a rule
 * whose condition cannot be read is left out entirely, a list entry that is
 * not an address is skipped.
 */
import { parseCidr } from '../rasp/rule-expr';
import { CLIENT_TYPES, type ClientType, type DefendPolicy, type DefendRule } from './types';

export const DEFEND_JWS_TYPE = 'shield360-defend+jws';
export const DEFEND_POLICY_PATH = '/api/defend/policy';

export const LIMITS = {
  rules: 200,
  list: 2000,
  cidrs: 50,
  paths: 10,
  path: 256,
  methods: 10,
  countries: 50,
  asns: 50,
  attacks: 16,
  maxRps: 100_000,
  maxBurst: 1_000_000,
  defaultTrapTtl: 900,
  maxTrapTtl: 86_400,
} as const;

const RULE_ID = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const METHOD = /^[A-Z]{3,10}$/;
const COUNTRY = /^[A-Z]{2}$/;
const ATTACK = /^[a-z_]{1,32}$/;
const ACTIONS = ['block', 'challenge', 'allow', 'monitor'] as const;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

function strings(v: unknown, max: number, ok: (s: string) => boolean): string[] | null {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) return null;
  const out: string[] = [];
  for (const x of v.slice(0, max)) {
    if (typeof x !== 'string' || !ok(x)) return null;
    if (!out.includes(x)) out.push(x);
  }
  return out;
}

const isCidr = (s: string) => s.length <= 64 && parseCidr(s) !== null;
const isPath = (s: string) => s.length <= LIMITS.path && s.startsWith('/') && !/[\s?#"'\\]/.test(s);

/** One rule, or null when any of its conditions cannot be read (it is then not enforced at all). */
export function parseRule(v: unknown): DefendRule | null {
  if (!isObj(v)) return null;
  if (typeof v.id !== 'string' || !RULE_ID.test(v.id)) return null;
  if (!(ACTIONS as readonly unknown[]).includes(v.action)) return null;
  const cidrs = strings(v.cidrs, LIMITS.cidrs, isCidr);
  const countries = strings(v.countries, LIMITS.countries, (s) => COUNTRY.test(s));
  const paths = strings(v.paths, LIMITS.paths, isPath);
  const methods = strings(v.methods, LIMITS.methods, (s) => METHOD.test(s));
  const attacks = strings(v.attacks, LIMITS.attacks, (s) => ATTACK.test(s));
  const clientTypes = strings(v.clientTypes, CLIENT_TYPES.length, (s) => (CLIENT_TYPES as readonly string[]).includes(s));
  if (!cidrs || !countries || !paths || !methods || !attacks || !clientTypes) return null;
  let asns: number[] = [];
  if (v.asns !== undefined && v.asns !== null) {
    if (!Array.isArray(v.asns) || !v.asns.every((a) => typeof a === 'number' && Number.isInteger(a) && a > 0 && a <= 4294967295)) return null;
    asns = (v.asns as number[]).slice(0, LIMITS.asns);
  }
  if (v.except !== undefined && typeof v.except !== 'boolean') return null;
  const rule: DefendRule = { id: v.id, action: v.action as DefendRule['action'] };
  if (cidrs.length) rule.cidrs = cidrs;
  if (countries.length) rule.countries = countries;
  if (asns.length) rule.asns = asns;
  if (v.except === true) {
    // "Everyone outside" with nothing named would match everyone: refused.
    if (!countries.length && !asns.length) return null;
    rule.except = true;
  }
  if (paths.length) rule.paths = paths.map((p) => (p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p));
  if (methods.length) rule.methods = methods;
  if (attacks.length) rule.attacks = attacks;
  if (clientTypes.length) rule.clientTypes = clientTypes as ClientType[];
  if (v.rate !== undefined) {
    const r = v.rate;
    if (!isObj(r)) return null;
    const rps = r.rps;
    const burst = r.burst === undefined ? 0 : r.burst;
    if (typeof rps !== 'number' || !Number.isFinite(rps) || rps <= 0 || rps > LIMITS.maxRps) return null;
    if (typeof burst !== 'number' || !Number.isInteger(burst) || burst < 0 || burst > LIMITS.maxBurst) return null;
    rule.rate = { rps, burst };
  }
  return rule;
}

function list(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    if (out.length >= LIMITS.list) break;
    if (typeof x === 'string' && isCidr(x) && !out.includes(x)) out.push(x);
  }
  return out;
}

/** The policy from verified claims; null when the claims hold no usable policy. */
export function parseDefendPolicy(claims: unknown): DefendPolicy | null {
  if (!isObj(claims) || typeof claims.version !== 'string' || typeof claims.exp !== 'number') return null;
  const rules: DefendRule[] = [];
  const ids = new Set<string>();
  for (const r of Array.isArray(claims.rules) ? claims.rules.slice(0, LIMITS.rules) : []) {
    const rule = parseRule(r);
    if (rule && !ids.has(rule.id)) {
      ids.add(rule.id);
      rules.push(rule);
    }
  }
  const t = isObj(claims.traps) ? claims.traps : {};
  const ttl = t.ttlSeconds;
  return {
    version: claims.version,
    exp: claims.exp,
    listsVersion: typeof claims.listsVersion === 'string' ? claims.listsVersion.slice(0, 64) : '',
    killSwitch: claims.killSwitch === true,
    rules,
    deny: list(claims.deny),
    challenge: list(claims.challenge),
    allow: list(claims.allow),
    traps: {
      // Absent: block. A trap hit is near certain (no person or verified agent ever reaches one), so it stops the client at once.
      action: t.action === 'monitor' || t.action === 'challenge' ? t.action : 'block',
      ttlSeconds: typeof ttl === 'number' && Number.isFinite(ttl) && ttl >= 1 ? Math.min(Math.floor(ttl), LIMITS.maxTrapTtl) : LIMITS.defaultTrapTtl,
    },
  };
}
