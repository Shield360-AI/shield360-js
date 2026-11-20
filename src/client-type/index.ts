/**
 * shield360/client-type: who is calling — a person, a verified agent,
 * unverified automation or a suspected AI agent — with the reasons.
 * Deterministic: no model, no network. Defend uses it by default.
 */
export { classifyClient, CLIENT_TYPES, BREADTH_AGENT, SIGNATURES_VERSION } from './classify';
export type { ClientType, ClientClassification, ClientSignals, Confidence } from './classify';
export { BreadthCounter } from './breadth';
