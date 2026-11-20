/** Defend's honeypots: the shared HMAC crumb spec (agent-guides/edge-deception-spec.md), served and checked in the app. */
export { Crumbs, fingerprint, candidates, canonicalIp } from './crumb';
export type { Crumb, CrumbKind, CrumbState } from './crumb';
export { Honeypots, parseHoneypots, STATIC_DECOYS } from './honeypots';
export type { HoneypotHit, HoneypotMode, HoneypotSettings } from './honeypots';
