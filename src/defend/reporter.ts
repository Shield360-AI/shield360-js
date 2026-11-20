/**
 * Sends Defend events to `POST /api/defend/report`, off the request path:
 * deny and challenge decisions (and what monitor mode would have done), trap
 * hits and failed sign-ins the app reports. Batched (100 a request, every 5 s),
 * at most 300 events a minute per process, repeats of the same event within
 * 10 s folded into one with a count. An event names the client address, the
 * path without its query, the method and reason codes: never a header, a body,
 * a query string, a user name or a password.
 */
import type { ClientType, DefendDecision } from './types';

export const DEFEND_REPORT_PATH = '/api/defend/report';
export const PER_MINUTE = 300;
export const FOLD_MS = 10_000;
export const FLUSH_MS = 5000;
export const BATCH = 100;
const MAX_QUEUED = 1000;
const TIMEOUT_MS = 10_000;

export type DefendEventKind = 'decision' | 'trap_hit' | 'failed_login';

export type DefendEvent = {
  at: string;
  kind: DefendEventKind;
  decision?: DefendDecision;
  monitored?: boolean;
  clientType?: ClientType;
  ip?: string;
  path?: string;
  method?: string;
  reasons: string[];
  ruleIds: string[];
  count: number;
};

export type DefendReporterOptions = {
  url: string;
  apiKey: string;
  app: string;
  sdkVersion?: string;
  fetchImpl?: typeof fetch;
  now?: () => number;
};

export class DefendReporter {
  private queue: DefendEvent[] = [];
  private folds = new Map<string, { event: DefendEvent; until: number }>();
  private windowStart = 0;
  private sentInWindow = 0;
  private timer?: ReturnType<typeof setInterval>;
  private readonly endpoint: string;
  dropped = 0;

  constructor(private readonly o: DefendReporterOptions) {
    this.endpoint = `${o.url.replace(/\/+$/, '')}${DEFEND_REPORT_PATH}`;
  }

  private now(): number {
    return (this.o.now ?? Date.now)();
  }

  /** Queues an event (folded with a recent repeat). Never throws. */
  add(e: Omit<DefendEvent, 'at' | 'count'>): void {
    try {
      const now = this.now();
      const key = [e.kind, e.decision ?? '', e.monitored ? 1 : 0, e.ip ?? '', e.path ?? '', e.method ?? '', e.reasons.join(','), e.ruleIds.join(',')].join('|');
      const fold = this.folds.get(key);
      if (fold && fold.until > now) {
        fold.event.count += 1;
        return;
      }
      if (now - this.windowStart >= 60_000) {
        this.windowStart = now;
        this.sentInWindow = 0;
      }
      if (this.sentInWindow >= PER_MINUTE || this.queue.length >= MAX_QUEUED) {
        this.dropped += 1;
        return;
      }
      this.sentInWindow += 1;
      const event: DefendEvent = { ...e, reasons: e.reasons.slice(0, 16), ruleIds: e.ruleIds.slice(0, 16), at: new Date(now).toISOString(), count: 1 };
      this.queue.push(event);
      if (this.folds.size > 5000) this.folds.clear();
      this.folds.set(key, { event, until: now + FOLD_MS });
    } catch {
      // never
    }
  }

  get pending(): number {
    return this.queue.length;
  }

  /** Sends what is queued. Never throws; a failed batch is dropped (events are best effort). */
  async flush(): Promise<void> {
    while (this.queue.length) {
      const batch = this.queue.splice(0, BATCH);
      try {
        const send = this.o.fetchImpl ?? globalThis.fetch;
        const init: RequestInit = {
          method: 'POST',
          headers: { Authorization: `Bearer ${this.o.apiKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ app: this.o.app, sdk: 'typescript', sdkVersion: this.o.sdkVersion ?? '', events: batch }),
        };
        if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') init.signal = AbortSignal.timeout(TIMEOUT_MS);
        await send(this.endpoint, init);
      } catch {
        this.dropped += batch.length;
      }
    }
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.flush(), FLUSH_MS);
    this.timer.unref?.();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush();
  }
}
