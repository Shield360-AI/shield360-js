/**
 * Behavior profiles (README "Behavior profiles (`novel_behavior`)"): the SDK
 * counts the shapes of what the app does at its sinks (processes it starts,
 * files it reads and writes, hosts it calls, SQL statements, types it
 * deserializes, modules it loads after start-up), reports them every 60 s so
 * Shield360 learns the app's profile, and, with the signed config's
 * `behavior` block in monitor or block mode, reports (and may block)
 * anything the profile has never seen. An exploit nobody has a rule for
 * still almost always makes the app do something new.
 *
 * Shapes never hold raw values (behavior-shapes.ts). Memory is bounded: at
 * most 5000 pending observations and 5000 dedupe entries. Nothing here throws
 * into the app except the block error.
 */
import { randomBytes } from 'crypto';
import { currentContext, eventRouteOf, type RaspContext } from './context';
import { handleFinding, novelBehaviorCap } from './engine';
import { BEHAVIOR_CATEGORIES, moduleShape, type BehaviorCategory } from './behavior-shapes';
import { RaspBlockedError } from './types';

export type BehaviorMode = 'off' | 'learn' | 'monitor' | 'block';
export const BEHAVIOR_MODES: readonly BehaviorMode[] = ['off', 'learn', 'monitor', 'block'];
/** Categories `block_categories` may name; `sql` never blocks (accepted there and ignored). */
export const BLOCKABLE: ReadonlySet<BehaviorCategory> = new Set<BehaviorCategory>(['process', 'file', 'outbound', 'deser', 'module']);
/** Shapes across `profile` and `deny`, and routes in `profile`. */
export const MAX_PROFILE_SHAPES = 5000;
export const MAX_SHAPE_LENGTH = 200;
export const MAX_ROUTE_LENGTH = 256;
export const MAX_PROFILE_VERSION = 128;
/** Distinct (route, category, shape) observations waiting for the next report. */
export const MAX_PENDING = 5000;
export const MAX_DEDUPE = 5000;
export const DEDUPE_MS = 10 * 60_000;
export const REPORT_MS = 60_000;
export const MAX_REPORT_OBSERVATIONS = 500;
export const MAX_REPORT_BYTES = 64 * 1024;
/** Start-up ends at the first sink call in a request, or this long after RASP starts. */
export const STARTUP_MS = 60_000;
/** The route of work outside a request. */
export const NO_ROUTE = '-';

/** Shapes of one category: exact strings, and prefixes (a shape ending in `*`). */
export class ShapeSet {
  readonly exact = new Set<string>();
  readonly prefixes: string[] = [];
  add(shape: string): void {
    this.exact.add(shape);
    if (shape.endsWith('*')) this.prefixes.push(shape.slice(0, -1));
  }
  has(shape: string): boolean {
    if (this.exact.has(shape)) return true;
    for (const p of this.prefixes) if (shape.startsWith(p)) return true;
    return false;
  }
}

type CategoryShapes = Map<BehaviorCategory, ShapeSet>;

export type BehaviorConfig = {
  mode: BehaviorMode;
  blockCategories: ReadonlySet<BehaviorCategory>;
  /** Route template (or `*`, the whole app, or `-`, outside requests) -> category -> shapes. */
  profile: Map<string, CategoryShapes>;
  deny: CategoryShapes;
  profileVersion: string;
  /** Shapes in profile + deny. */
  shapes: number;
};

export type BehaviorParse = { ok: true; config: BehaviorConfig | null } | { ok: false; reason: string };

const CATEGORY_SET: ReadonlySet<string> = new Set(BEHAVIOR_CATEGORIES);
const isPlainObject = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === 'object' && !Array.isArray(v);

/**
 * Reads the signed config's `behavior` block. Absent or null: off (null).
 * Anything that breaks the contract (an unknown mode or category, a shape
 * that is not a 1-200 character string, more than 5000 shapes) is refused
 * whole, with the reason.
 */
export function parseBehavior(v: unknown): BehaviorParse {
  if (v === undefined || v === null) return { ok: true, config: null };
  if (!isPlainObject(v)) return { ok: false, reason: 'behavior' };
  const mode = v.mode;
  if (typeof mode !== 'string' || !BEHAVIOR_MODES.includes(mode as BehaviorMode)) return { ok: false, reason: 'mode' };
  const blockCategories = new Set<BehaviorCategory>();
  if (v.block_categories !== undefined && v.block_categories !== null) {
    if (!Array.isArray(v.block_categories)) return { ok: false, reason: 'block_categories' };
    for (const c of v.block_categories) {
      if (typeof c !== 'string' || !CATEGORY_SET.has(c)) return { ok: false, reason: 'block_categories' };
      if (BLOCKABLE.has(c as BehaviorCategory)) blockCategories.add(c as BehaviorCategory);
    }
  }
  let profileVersion = '';
  if (v.profile_version !== undefined && v.profile_version !== null) {
    if (typeof v.profile_version !== 'string' || v.profile_version.length > MAX_PROFILE_VERSION) return { ok: false, reason: 'profile_version' };
    profileVersion = v.profile_version;
  }
  let shapes = 0;
  const readCategories = (raw: unknown): CategoryShapes | string => {
    if (!isPlainObject(raw)) return 'shapes';
    const out: CategoryShapes = new Map();
    for (const [cat, list] of Object.entries(raw)) {
      if (!CATEGORY_SET.has(cat) || !Array.isArray(list)) return 'shapes';
      const set = new ShapeSet();
      for (const s of list) {
        if (typeof s !== 'string' || !s || s.length > MAX_SHAPE_LENGTH) return 'shapes';
        if (++shapes > MAX_PROFILE_SHAPES) return 'limit';
        set.add(s);
      }
      out.set(cat as BehaviorCategory, set);
    }
    return out;
  };
  const profile = new Map<string, CategoryShapes>();
  if (v.profile !== undefined && v.profile !== null) {
    if (!isPlainObject(v.profile)) return { ok: false, reason: 'profile' };
    const routes = Object.entries(v.profile);
    if (routes.length > MAX_PROFILE_SHAPES) return { ok: false, reason: 'limit' };
    for (const [route, cats] of routes) {
      if (!route || route.length > MAX_ROUTE_LENGTH) return { ok: false, reason: 'profile' };
      const read = readCategories(cats);
      if (typeof read === 'string') return { ok: false, reason: read };
      profile.set(route, read);
    }
  }
  let deny: CategoryShapes = new Map();
  if (v.deny !== undefined && v.deny !== null) {
    const read = readCategories(v.deny);
    if (typeof read === 'string') return { ok: false, reason: read === 'shapes' ? 'deny' : read };
    deny = read;
  }
  return { ok: true, config: { mode: mode as BehaviorMode, blockCategories, profile, deny, profileVersion, shapes } };
}

export type Observation = { route: string; category: BehaviorCategory; shape: string; count: number; first_seen: string };
type Dedupe = { until: number; eventId: string };

type State = {
  config: BehaviorConfig | null;
  pending: Map<string, Observation>;
  dropped: number;
  dedupe: Map<string, Dedupe>;
  startupDone: boolean;
  startupTimer?: ReturnType<typeof setTimeout>;
  now: () => number;
  onWarning?: (reason: string) => void;
};

const state: State = { config: null, pending: new Map(), dropped: 0, dedupe: new Map(), startupDone: false, now: Date.now };
const warned = new Set<string>();

/**
 * Applies the signed config's `behavior` block (undefined: no signed config,
 * or one without the block: off). A block that breaks the contract is
 * refused and the last good one stays in force. Returns the parse result.
 */
export function setBehaviorConfig(raw: unknown): BehaviorParse {
  const r = parseBehavior(raw);
  if (r.ok) {
    state.config = r.config;
    if (!r.config || r.config.mode === 'off') {
      state.pending.clear();
      state.dropped = 0;
    }
  } else if (!warned.has(r.reason)) {
    warned.add(r.reason);
    try {
      state.onWarning?.(r.reason);
    } catch {
      // never
    }
  }
  return r;
}

export function behaviorConfig(): BehaviorConfig | null {
  return state.config;
}

/** The mode in force: the config's, `off` when RASP is not active or `novel_behavior` is off. */
export function behaviorMode(): BehaviorMode {
  const c = state.config;
  if (!c || c.mode === 'off') return 'off';
  return novelBehaviorCap() === 'off' ? 'off' : c.mode;
}

/** Cheap check for hooks: false means nothing about behavior runs for this call. */
export function behaviorOn(): boolean {
  return state.config !== null && state.config.mode !== 'off';
}

const ROUTE_CHARS = /[^\x21\x23-\x26\x28-\x3b\x3d\x3f-\x5b\x5d-\x7e]/g;

/** The route of the call: the framework's template, else the event route of the path; `-` outside a request. */
export function behaviorRoute(ctx: RaspContext | undefined = currentContext()): string {
  if (!ctx?.inRequest) return NO_ROUTE;
  let r = ctx.route;
  if (!r && ctx.routeLater) {
    try {
      r = ctx.routeLater();
    } catch {
      r = undefined;
    }
  }
  if (!r && ctx.path) r = eventRouteOf(ctx.path);
  if (!r) return NO_ROUTE;
  const s = r.replace(ROUTE_CHARS, '_').slice(0, MAX_ROUTE_LENGTH);
  return s.startsWith('/') ? s : NO_ROUTE;
}

function record(route: string, category: BehaviorCategory, shape: string): void {
  const key = `${route}\u0000${category}\u0000${shape}`;
  const o = state.pending.get(key);
  if (o) {
    o.count++;
    return;
  }
  if (state.pending.size >= MAX_PENDING) {
    state.dropped++;
    return;
  }
  state.pending.set(key, { route, category, shape, count: 1, first_seen: new Date(state.now()).toISOString() });
}

function dedupeEntry(key: string, now: number): Dedupe | undefined {
  const d = state.dedupe.get(key);
  if (d && now < d.until) return d;
  if (d) state.dedupe.delete(key);
  return undefined;
}

function remember(key: string, entry: Dedupe, now: number): void {
  if (state.dedupe.size >= MAX_DEDUPE) {
    for (const [k, d] of state.dedupe) if (now >= d.until) state.dedupe.delete(k);
    // Still full: the oldest goes (insertion order).
    while (state.dedupe.size >= MAX_DEDUPE) state.dedupe.delete(state.dedupe.keys().next().value as string);
  }
  state.dedupe.set(key, entry);
}

/** What the config says about one shape on one route: null (known, or learn mode), or the mode of its finding. */
export function decide(c: BehaviorConfig, route: string, category: BehaviorCategory, shape: string): 'block' | 'monitor' | null {
  if (c.mode === 'off' || c.mode === 'learn') return null;
  // Known-bad: blocked in monitor and block modes; sql never blocks.
  if (c.deny.get(category)?.has(shape)) return category === 'sql' ? 'monitor' : 'block';
  if (c.profile.get(route)?.get(category)?.has(shape) || c.profile.get('*')?.get(category)?.has(shape)) return null;
  return c.mode === 'block' && c.blockCategories.has(category) && category !== 'sql' ? 'block' : 'monitor';
}

/**
 * Observes one shape at a sink: counts it for the next report and, in
 * monitor or block mode, applies the decision. A novel (route, category,
 * shape) is reported at most once per 10 minutes per process; a block still
 * applies every time (with the first event's id). Throws only the block error.
 */
export function observe(category: BehaviorCategory, shape: string, sink: string, ctx: RaspContext | undefined = currentContext()): void {
  const c = state.config;
  if (!c || c.mode === 'off' || !shape) return;
  const cap = novelBehaviorCap();
  if (cap === 'off') return;
  const route = behaviorRoute(ctx);
  if (route !== NO_ROUTE) state.startupDone = true;
  record(route, category, shape);
  let mode = decide(c, route, category, shape);
  if (!mode) return;
  if (mode === 'block' && cap !== 'block') mode = 'monitor';
  const rule = `behavior.${category}`;
  const key = `${route}\u0000${category}\u0000${shape}`;
  const now = state.now();
  const seen = dedupeEntry(key, now);
  if (seen) {
    if (mode === 'block') {
      if (ctx) ctx.ownBlock = true;
      throw new RaspBlockedError('novel_behavior', rule, seen.eventId);
    }
    return;
  }
  const eventId = randomBytes(16).toString('hex');
  remember(key, { until: now + DEDUPE_MS, eventId }, now);
  handleFinding(
    { attack: 'novel_behavior', rule, mode, behavior: { shape, profileVersion: c.profileVersion } },
    sink,
    { eventId, ...(route !== NO_ROUTE ? { route } : {}) },
  );
}

/**
 * The hooks' entry point: computes the shapes only when behavior is on and
 * observes each. Fail open: any error but the block error is swallowed.
 */
export function observeWith(category: BehaviorCategory, sink: string, shapes: () => string | readonly string[] | null | undefined): void {
  if (!behaviorOn()) return;
  try {
    const s = shapes();
    if (!s) return;
    const ctx = currentContext();
    if (typeof s === 'string') observe(category, s, sink, ctx);
    else for (const one of s) observe(category, one, sink, ctx);
  } catch (e) {
    if (e instanceof RaspBlockedError) throw e;
  }
}

/** A module loaded at run time: observed only once start-up has finished (README "module"). */
export function observeModule(id: string, sink = 'module.require'): void {
  if (!behaviorOn()) return;
  if (!state.startupDone) {
    if (!currentContext()?.inRequest) return;
    state.startupDone = true;
  }
  observeWith('module', sink, () => moduleShape(id));
}

export function startupFinished(): boolean {
  return state.startupDone;
}

/** Starts the start-up clock (RASP init). */
export function startBehaviorClock(ms = STARTUP_MS): void {
  if (state.startupTimer) clearTimeout(state.startupTimer);
  state.startupDone = false;
  state.startupTimer = setTimeout(() => {
    state.startupDone = true;
  }, ms);
  state.startupTimer.unref?.();
}

/** Takes the pending observations and the drop count (the report), leaving none. */
export function takeObservations(): { observations: Observation[]; dropped: number } {
  const observations = [...state.pending.values()];
  const dropped = state.dropped;
  state.pending = new Map();
  state.dropped = 0;
  return { observations, dropped };
}

export function pendingCount(): number {
  return state.pending.size;
}

/** Tests and re-init: forgets the config, observations, dedupe and start-up state. */
export function resetBehavior(opts: { now?: () => number; onWarning?: (reason: string) => void } = {}): void {
  if (state.startupTimer) clearTimeout(state.startupTimer);
  state.config = null;
  state.pending = new Map();
  state.dropped = 0;
  state.dedupe = new Map();
  state.startupDone = false;
  state.startupTimer = undefined;
  state.now = opts.now ?? Date.now;
  state.onWarning = opts.onWarning;
  warned.clear();
}

/** Tests: marks start-up finished. */
export function finishStartup(): void {
  state.startupDone = true;
}

// ---- Observation report ----------------------------------------------------------

/** README "Observations": `app_version` is at most 64 characters. */
const MAX_APP_VERSION = 64;

export type BehaviorReport = {
  app: string;
  version: string;
  app_version?: string;
  environment?: string;
  observations: Observation[];
  dropped: number;
};

/**
 * The report body: at most 500 observations and 64 KB of JSON; the rest are
 * dropped and counted in `dropped`, with the drops since the last report.
 */
export function buildReport(
  meta: { app: string; version: string; appVersion?: string; environment?: string },
  taken: { observations: Observation[]; dropped: number }
): BehaviorReport {
  const appVersion = meta.appVersion?.trim().slice(0, MAX_APP_VERSION);
  const head: Omit<BehaviorReport, 'observations' | 'dropped'> = {
    app: meta.app,
    version: meta.version,
    ...(appVersion ? { app_version: appVersion } : {}),
    ...(meta.environment ? { environment: meta.environment } : {}),
  };
  // Room for `"dropped":<up to 10 digits>` and the punctuation around the list.
  let bytes = Buffer.byteLength(JSON.stringify({ ...head, observations: [], dropped: 0 })) + 10;
  const observations: Observation[] = [];
  let dropped = taken.dropped;
  for (const o of taken.observations) {
    const size = Buffer.byteLength(JSON.stringify(o)) + 1;
    if (observations.length >= MAX_REPORT_OBSERVATIONS || bytes + size > MAX_REPORT_BYTES) {
      dropped++;
      continue;
    }
    bytes += size;
    observations.push(o);
  }
  return { ...head, observations, dropped };
}

export type BehaviorReporterOptions = {
  url: string;
  apiKey: string;
  applicationName: string;
  sdkVersion?: string;
  /** The app's own version (service.version); left out of the report when unknown. */
  appVersion?: string;
  environment?: string;
  fetchImpl?: typeof fetch;
  intervalMs?: number;
};

const FETCH_TIMEOUT_MS = 10_000;

/** Sends the observations every 60 s and on stop; fire and forget, never throws. */
export class BehaviorReporter {
  private timer?: ReturnType<typeof setInterval>;
  private readonly endpoint: string;
  private sending: Promise<void> = Promise.resolve();
  private readonly onExit = () => void this.flush();

  constructor(private readonly o: BehaviorReporterOptions) {
    this.endpoint = `${o.url.replace(/\/+$/, '')}/api/app-security/rasp/behavior`;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.flush(), this.o.intervalMs ?? REPORT_MS);
    this.timer.unref?.();
    process.once('beforeExit', this.onExit);
  }

  /** Sends what is pending now (nothing when behavior is off). Never rejects. */
  flush(): Promise<void> {
    let taken: { observations: Observation[]; dropped: number };
    let on: boolean;
    try {
      taken = takeObservations();
      on = behaviorMode() !== 'off';
    } catch {
      return this.sending;
    }
    this.sending = this.sending
      .then(async () => {
        if (!on || (!taken.observations.length && !taken.dropped)) return;
        const body = buildReport({ app: this.o.applicationName, version: this.o.sdkVersion ?? '', appVersion: this.o.appVersion, environment: this.o.environment }, taken);
        const send = this.o.fetchImpl ?? globalThis.fetch;
        if (typeof send !== 'function') return;
        const init: RequestInit = {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.o.apiKey}` },
          body: JSON.stringify(body),
        };
        if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') init.signal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
        await send(this.endpoint, init);
      })
      .catch(() => undefined);
    return this.sending;
  }

  stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    process.removeListener('beforeExit', this.onExit);
    return this.flush();
  }
}
