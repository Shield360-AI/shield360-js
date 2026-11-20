/**
 * Distinct paths per client over a sliding minute, bounded: the "roams
 * widely" signal (an agent exploring an app touches many paths fast, a person
 * a few). In memory, per process, at most `cap` clients and 64 paths each.
 */
export class BreadthCounter {
  private readonly clients = new Map<string, { since: number; paths: Set<string> }>();
  constructor(
    private readonly windowMs = 60_000,
    private readonly cap = 10_000,
  ) {}

  /** Records the path and returns the distinct paths in the current window. */
  see(client: string, path: string, nowMs = Date.now()): number {
    let c = this.clients.get(client);
    if (!c || nowMs - c.since > this.windowMs) {
      if (!c && this.clients.size >= this.cap) {
        const oldest = this.clients.keys().next().value;
        if (oldest !== undefined) this.clients.delete(oldest);
      }
      c = { since: nowMs, paths: new Set() };
      this.clients.delete(client);
      this.clients.set(client, c);
    }
    if (c.paths.size < 64) c.paths.add(path.split('/').slice(0, 4).join('/'));
    return c.paths.size;
  }
}
