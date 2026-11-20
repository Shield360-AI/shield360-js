/**
 * The Defend decision, in order (the contract's "Decision"):
 *
 *   1. no usable policy        the fail mode (open: allow, closed: deny)
 *   2. kill switch             allow
 *   3. deny list               deny (response-rule blocks, the deny list)
 *   4. agent policy            deny when the agent verifier blocks
 *   5. trap hit                the policy's trap action (monitor by default)
 *   6. challenge list          challenge (response-rule challenges)
 *   7. rules, in order         the first block, challenge or allow wins;
 *                              monitor rules only add their reason
 *   8. sensitive data          deny only when the app asked for `block`
 *
 * Trusted clients (the allow list) and verified agents are never denied or
 * challenged by steps 5 to 8: their matches are reported only. Monitor mode
 * turns any decision into `allow` and keeps the real one in `wouldBe`.
 *
 * Pure apart from the two in-memory tables it is handed (rate buckets, marked
 * clients). No network, no file system.
 */
import { scanForInjection } from '../ai-security/injection';
import { scanOutput } from '../ai-security/output';
import { DEFAULT_POLICY as AI_DEFAULT_POLICY } from '../ai-security/policy';
import { inCidr, parseCidr, type Net } from '../rasp/rule-expr';
import type { ClientClassification, DefendDecision, DefendFacts, DefendMode, DefendPolicy, DefendResult, DefendRule, FailMode } from './types';

export const LIST_TTL_S = 60;
export const MAX_BUCKETS = 10_000;
const MAX_CONTENT_CHARS = 20_000;

/** Token buckets per rule and client address, at most MAX_BUCKETS (the oldest is dropped first). */
export class RateTable {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  constructor(private readonly cap = MAX_BUCKETS) {}

  /** Takes one token; returns false when the client is over the rate. */
  take(key: string, rps: number, burst: number, nowMs: number): boolean {
    const size = Math.max(1, burst || Math.ceil(rps));
    let b = this.buckets.get(key);
    if (!b) {
      if (this.buckets.size >= this.cap) {
        const oldest = this.buckets.keys().next().value;
        if (oldest !== undefined) this.buckets.delete(oldest);
      }
      b = { tokens: size, at: nowMs };
      this.buckets.set(key, b);
    } else {
      b.tokens = Math.min(size, b.tokens + ((nowMs - b.at) / 1000) * rps);
      b.at = nowMs;
    }
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return true;
    }
    return false;
  }

  get size(): number {
    return this.buckets.size;
  }
}

type Compiled = { deny: Net[]; challenge: Net[]; allow: Net[]; rules: Map<string, Net[]> };
const compiledCache = new WeakMap<DefendPolicy, Compiled>();

const nets = (list: readonly string[]) => list.map(parseCidr).filter((n): n is Net => n !== null);

function compiled(p: DefendPolicy): Compiled {
  let c = compiledCache.get(p);
  if (!c) {
    c = { deny: nets(p.deny), challenge: nets(p.challenge), allow: nets(p.allow), rules: new Map(p.rules.filter((r) => r.cidrs).map((r) => [r.id, nets(r.cidrs as string[])])) };
    compiledCache.set(p, c);
  }
  return c;
}

const inAny = (ip: string | undefined, list: Net[]) => !!ip && list.some((n) => inCidr(ip, n));

/** Whether `path` is `prefix` or below it on a segment boundary. */
export function pathUnder(path: string, prefix: string): boolean {
  if (prefix === '/' || path === prefix) return true;
  return path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);
}

export type ContentFindings = { promptInjection: boolean; sensitiveData: boolean };

/** Prompt injection and sensitive data in the text the caller passed. Never throws. */
export function checkContent(content: readonly string[] | undefined, sensitive: 'off' | 'monitor' | 'block'): ContentFindings {
  const out: ContentFindings = { promptInjection: false, sensitiveData: false };
  if (!content?.length) return out;
  let left = MAX_CONTENT_CHARS;
  for (const raw of content) {
    if (left <= 0) break;
    const text = raw.slice(0, left);
    left -= text.length;
    try {
      if (!out.promptInjection && scanForInjection(text, { source: 'prompt' }).detected) out.promptInjection = true;
    } catch {
      // fail open
    }
    try {
      if (sensitive !== 'off' && !out.sensitiveData) {
        const r = scanOutput(text, { policy: AI_DEFAULT_POLICY.output });
        if (r.findings.some((f) => f.kind === 'pii' || f.kind === 'secret')) out.sensitiveData = true;
      }
    } catch {
      // fail open
    }
  }
  return out;
}

export type EngineInput = {
  policy: DefendPolicy | null;
  facts: DefendFacts;
  mode: DefendMode;
  failMode: FailMode;
  /** The agent verifier's answer, when the request carried a passport or a signature. */
  agent?: { verified: boolean; blocked: boolean; reason?: string };
  /** The client is marked by a trap hit (Defend's own table or RASP deception's). */
  trapHit: boolean;
  classification?: ClientClassification | null;
  content: ContentFindings;
  sensitiveData: 'off' | 'monitor' | 'block';
  rates: RateTable;
  nowMs: number;
  /** Shared rate limit answers by rule id (POST /api/defend/decide); a rule without one uses the local bucket. */
  sharedOver?: Record<string, boolean>;
};

const RANK: Record<DefendDecision, number> = { allow: 0, require_sign_in: 1, challenge: 2, deny: 3 };

function geoMatches(rule: DefendRule, f: DefendFacts): boolean {
  if (!rule.countries && !rule.asns) return true;
  // Unknown country and network: a geo rule never matches (never widened), whichever way it points.
  if (!f.country && f.asn === undefined) return false;
  const inside = (!!f.country && !!rule.countries?.includes(f.country)) || (f.asn !== undefined && !!rule.asns?.includes(f.asn));
  return rule.except ? !inside : inside;
}

/** Every condition but the rate. */
function matches(rule: DefendRule, input: EngineInput, ruleNets: Net[] | undefined): boolean {
  const f = input.facts;
  if (rule.cidrs && !inAny(f.ip, ruleNets ?? [])) return false;
  if (!geoMatches(rule, f)) return false;
  if (rule.paths && !rule.paths.some((p) => pathUnder(f.path, p))) return false;
  if (rule.methods && !rule.methods.includes(f.method)) return false;
  if (rule.clientTypes && !(input.classification && rule.clientTypes.includes(input.classification.clientType))) return false;
  if (rule.attacks) {
    const seen = rule.attacks.some((a) => a === 'prompt_injection' && input.content.promptInjection);
    if (!seen) return false;
  }
  return true;
}

/** The rate rules whose other conditions this request meets (for shared rate limits). */
export function rateRulesFor(input: Omit<EngineInput, 'rates' | 'nowMs'> & { policy: DefendPolicy }): DefendRule[] {
  const c = compiled(input.policy);
  return input.policy.rules.filter((r) => r.rate && matches(r, input as EngineInput, c.rules.get(r.id)));
}

/** The decision for one request. Never throws: an internal error is the fail mode. */
export function decide(input: EngineInput): DefendResult {
  try {
    return decideUnsafe(input);
  } catch {
    return failResult(input.failMode, 'error', input.mode);
  }
}

export function failResult(failMode: FailMode, reason: string, mode: DefendMode): DefendResult {
  const decision: DefendDecision = failMode === 'closed' ? 'deny' : 'allow';
  return finish({ decision, reasons: [reason], ruleIds: [], ttl: 0 }, mode);
}

function finish(r: DefendResult, mode: DefendMode): DefendResult {
  if (mode === 'monitor' && r.decision !== 'allow') return { ...r, decision: 'allow', wouldBe: r.decision };
  return r;
}

function decideUnsafe(input: EngineInput): DefendResult {
  const { policy, facts: f, mode } = input;
  if (!policy) return failResult(input.failMode, 'policy_unavailable', mode);
  if (policy.killSwitch) return { decision: 'allow', reasons: ['kill_switch'], ruleIds: [], ttl: 0 };
  const c = compiled(policy);
  const reasons: string[] = [];
  const ruleIds: string[] = [];
  const clientType = input.agent?.verified ? 'verified_agent' : input.trapHit ? 'suspected_ai_agent' : input.classification?.clientType;
  const out = (decision: DefendDecision, ttl: number): DefendResult => finish({ decision, reasons, ruleIds, ttl, ...(clientType ? { clientType } : {}) }, mode);
  const trusted = inAny(f.ip, c.allow);
  const exempt = trusted || input.agent?.verified === true;
  if (input.classification?.reasons.length && !input.agent?.verified && !input.trapHit) for (const r of input.classification.reasons.slice(0, 8)) reasons.push(`client:${r}`);

  // 3. Deny list: an explicit block, before every exception but the kill switch.
  if (!trusted && inAny(f.ip, c.deny)) {
    reasons.push('deny_list');
    return out('deny', LIST_TTL_S);
  }
  // 4. The agent verifier's own policy said deny (its mode enforce).
  if (input.agent?.blocked) {
    reasons.push('agent_policy');
    if (input.agent.reason) reasons.push(`agent:${input.agent.reason}`);
    return out('deny', 0);
  }
  if (input.agent?.verified) reasons.push('agent_verified');
  else if (input.agent && input.agent.reason) reasons.push(`agent:${input.agent.reason}`);

  // 5. Trap hit: never for trusted clients or verified agents.
  if (input.trapHit && !exempt) {
    reasons.push('trap_hit');
    if (policy.traps.action !== 'monitor') return out(policy.traps.action === 'block' ? 'deny' : 'challenge', policy.traps.ttlSeconds);
  }
  // 6. Challenge list.
  if (!exempt && inAny(f.ip, c.challenge)) {
    reasons.push('challenge_list');
    return out('challenge', LIST_TTL_S);
  }
  if (input.content.promptInjection) reasons.push('prompt_injection');

  // 7. Rules, first match wins.
  let decision: DefendDecision = 'allow';
  let ttl = 0;
  for (const rule of policy.rules) {
    if (!matches(rule, input, c.rules.get(rule.id))) continue;
    if (rule.rate) {
      if (!f.ip) continue;
      const shared = input.sharedOver?.[rule.id];
      const over = shared !== undefined ? shared : !input.rates.take(`${rule.id}|${f.ip}`, rule.rate.rps, rule.rate.burst, input.nowMs);
      if (!over) continue;
      reasons.push('rate_limit');
      ttl = Math.max(1, Math.ceil(1 / rule.rate.rps));
    }
    ruleIds.push(rule.id);
    if (rule.action === 'allow') {
      reasons.push('rule:allow');
      return out('allow', 0);
    }
    if (rule.action === 'monitor' || exempt) {
      reasons.push(exempt && rule.action !== 'monitor' ? `rule:${rule.action}:exempt` : 'rule:monitor');
      continue;
    }
    reasons.push(`rule:${rule.action}`);
    decision = rule.action === 'block' ? 'deny' : 'challenge';
    break;
  }
  // 8. Sensitive data, only as strong as the app asked.
  if (input.content.sensitiveData) {
    reasons.push('sensitive_data');
    if (input.sensitiveData === 'block' && !exempt && RANK.deny > RANK[decision]) decision = 'deny';
  }
  return out(decision, decision === 'allow' ? 0 : ttl);
}
