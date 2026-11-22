/**
 * SHIELD: AI attack agents — the request glue (README "AI attack agents",
 * "Decision"). attack-agents.ts holds the pure parts; this file runs them for
 * the request in the context: the before-handler check (tripwire, agent
 * header, OAST, tool User-Agent, an earlier mark), the scoring once the app
 * answered, and the events, deter answers and Edge verdicts that follow.
 * Every entry point fails open; only the deter error leaves on purpose.
 */
import type { ServerResponse } from 'http';
import { currentContext, eventRouteOf, type RaspContext } from './context';
import { CONTEXT_HEADER, REQUEST_ID_HEADER, verifyEdgeContext } from './edge-context';
import { attackAgentConfig, modeFor, remoteConfig, reportAttackAgent, sendAgentVerdict, type FindingExtra } from './engine';
import { attackAgentTracker, hitsTripwire, tripwirePageFor, type AttackMark, type HeaderMap } from './attack-agents';
import { RaspDeterredError } from './types';

const isVerified = (ct: string | undefined): boolean => ct === 'verified_agent' || ct === 'verified_crawler';

/**
 * Names the signed-in user of the current request, so the behavior score
 * also follows the user across addresses. Call it from the app's auth
 * middleware once the user is known. 1 to 128 characters; anything else is
 * ignored. Never throws.
 */
export function identifyRaspUser(id: string | number): void {
  try {
    const ctx = currentContext();
    const v = typeof id === 'number' && Number.isFinite(id) ? String(id) : id;
    if (ctx?.inRequest && typeof v === 'string' && v.length >= 1 && v.length <= 128) ctx.user = v;
  } catch {
    // fail open
  }
}

const extraOf = (ctx: RaspContext, route?: string): FindingExtra => ({
  framework: ctx.framework,
  method: ctx.method,
  path: ctx.path,
  route: route ?? ctx.route ?? (ctx.path ? eventRouteOf(ctx.path) : undefined),
});

const valuesOf = function* (ctx: RaspContext): Generator<string> {
  for (const i of ctx.inputs) if (i.source === 'request') yield i.value;
};

/**
 * Carries the zero-code capture's state into an adapter's context, so the
 * before-handler check runs once per request.
 */
export function inheritAgents(ctx: RaspContext): void {
  const outer = currentContext();
  if (outer && outer !== ctx && outer.agentsChecked) {
    ctx.agentsChecked = true;
    ctx.agentHeaders = outer.agentHeaders;
    ctx.agentVerified = outer.agentVerified;
    ctx.user ??= outer.user;
  }
}

/**
 * The before-handler check. Throws the deter error (429) in block mode when
 * the client is marked; otherwise reports and lets the request go on.
 */
export function agentsBefore(ctx: RaspContext, headers: HeaderMap): void {
  if (ctx.agentsChecked) return;
  ctx.agentsChecked = true;
  try {
    const mode = modeFor('ai_attack_agent');
    if (mode === 'off') return;
    const cfg = attackAgentConfig();
    ctx.agentHeaders = headers;
    ctx.agentVerified = isVerified(ctx.edge?.ct);
    const r = attackAgentTracker().before({ ip: ctx.ip, user: ctx.user, path: ctx.path ?? '/', headers, inputs: valuesOf(ctx), verified: ctx.agentVerified }, cfg, Date.now());
    if (!r.marked) return;
    const block = mode === 'block';
    const rule = r.mark ? `attack_agent.${r.mark.reason}` : 'attack_agent.marked';
    const eventId = reportAttackAgent(rule, block, extraOf(ctx), r.mark ?? r.marked);
    if (!block) return;
    // The 429 is Shield360's own answer: never scored.
    ctx.agentsScored = true;
    sendAgentVerdict(r.marked.kind, cfg.markTtlSeconds, ctx);
    throw new RaspDeterredError(rule, eventId, cfg.retryAfterSeconds);
  } catch (e) {
    if (e instanceof RaspDeterredError) throw e;
  }
}

/** Scores the request once the app answered with `status`; marks, reports and (block) tells Edge. Never throws. */
export function agentsAfter(ctx: RaspContext, status: number): void {
  if (!ctx.agentsChecked || ctx.agentsScored) return;
  ctx.agentsScored = true;
  try {
    const mode = modeFor('ai_attack_agent');
    if (mode === 'off') return;
    const cfg = attackAgentConfig();
    let route: string | undefined;
    try {
      route = ctx.routeLater ? ctx.routeLater() : ctx.route;
    } catch {
      route = ctx.route;
    }
    const m = attackAgentTracker().after(
      { ip: ctx.ip, user: ctx.user, path: ctx.path ?? '/', headers: ctx.agentHeaders ?? {}, verified: ctx.agentVerified },
      { status, route: route || undefined, finding: ctx.agentFinding, own: ctx.ownBlock },
      cfg,
      Date.now(),
    );
    if (!m) return;
    const block = mode === 'block';
    reportAttackAgent('attack_agent.behavior', block, extraOf(ctx, route), m);
    if (block) sendAgentVerdict(m.kind, cfg.markTtlSeconds, ctx);
  } catch {
    // fail open
  }
}

const WATCH = Symbol('shield360.rasp.agentsWatch');
type Watch = { ctx: RaspContext };

/**
 * Scores the request when its status goes out: wraps the response's
 * `writeHead` (Node calls it for implicit headers too), so a mark can still
 * set the verdict header. A later adapter on the same response takes over
 * with its own context.
 */
export function watchStatus(res: ServerResponse | undefined, ctx: RaspContext): void {
  try {
    if (!res || typeof res.writeHead !== 'function') return;
    const held = (res as unknown as Record<symbol, Watch | undefined>)[WATCH];
    if (held) {
      held.ctx = ctx;
      return;
    }
    const w: Watch = { ctx };
    Object.defineProperty(res, WATCH, { value: w, configurable: true });
    const original = res.writeHead;
    res.writeHead = function (this: ServerResponse, ...args: unknown[]) {
      try {
        if (!this.headersSent) agentsAfter(w.ctx, typeof args[0] === 'number' ? args[0] : this.statusCode);
      } catch {
        // fail open
      }
      return (original as (...a: unknown[]) => ServerResponse).apply(this, args);
    } as typeof res.writeHead;
  } catch {
    // fail open
  }
}

/** A request as the tripwire and decoy scoring see it, before any capture. */
export type EarlyRequest = { framework: string; method: string; url: string; ip?: string; headers?: HeaderMap };

const extraEarly = (r: EarlyRequest): FindingExtra => {
  const q = r.url.indexOf('?');
  return { framework: r.framework, method: r.method, route: eventRouteOf(q >= 0 ? r.url.slice(0, q) : r.url) };
};

/**
 * The tripwire URL (README "AI attack agents", "Decision" 1): marks the
 * client and answers 404, or the deter error in block mode. Null when the
 * request is not a tripwire hit. Never throws.
 */
export function checkTripwire(r: EarlyRequest): { notFound?: true; blocked?: RaspDeterredError } | null {
  try {
    const mode = modeFor('ai_attack_agent');
    if (mode === 'off') return null;
    const cfg = attackAgentConfig();
    if (!cfg.tripwire || !hitsTripwire(r.url, cfg)) return null;
    const res = attackAgentTracker().before({ ip: r.ip, path: r.url, headers: {} }, cfg, Date.now());
    const mark = res.mark as AttackMark;
    const block = mode === 'block';
    const eventId = reportAttackAgent('attack_agent.tripwire', block, extraEarly(r), mark);
    return block ? { blocked: new RaspDeterredError('attack_agent.tripwire', eventId, cfg.retryAfterSeconds) } : { notFound: true };
  } catch {
    return null;
  }
}

/** Whether Edge verified the client of an early request (no replay cache: this only withholds the tripwire page). */
function verifiedEarly(r: EarlyRequest): boolean {
  const raw = r.headers?.[CONTEXT_HEADER];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return false;
  const keys = remoteConfig()?.edgeKeys ?? [];
  const q = r.url.indexOf('?');
  const rid = r.headers?.[REQUEST_ID_HEADER];
  const edge = verifyEdgeContext(keys, value, { method: r.method, path: q >= 0 ? r.url.slice(0, q) : r.url, requestId: typeof rid === 'string' ? rid : undefined }, Date.now(), null);
  return isVerified(edge?.ct);
}

/**
 * A decoy hit ("Deception"): scores it (10 points), reports a behavior mark,
 * and returns the tripwire page the 404 carries, when the tripwire is on.
 * Never throws.
 */
export function agentsDecoy(r: EarlyRequest): string | null {
  try {
    const mode = modeFor('ai_attack_agent');
    if (mode === 'off') return null;
    const cfg = attackAgentConfig();
    const verified = verifiedEarly(r);
    const m = attackAgentTracker().after({ ip: r.ip, path: r.url, headers: r.headers ?? {}, verified }, { status: 404, decoy: true }, cfg, Date.now());
    if (m) reportAttackAgent('attack_agent.behavior', mode === 'block', extraEarly(r), m);
    return tripwirePageFor(r.ip, cfg, verified);
  } catch {
    return null;
  }
}
