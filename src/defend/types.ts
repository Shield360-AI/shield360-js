/**
 * Shield360 Defend: app protection decided in the app, from a signed policy.
 * docs/latest/application-security/defend.mdx is the contract.
 */

export const DECISIONS = ['allow', 'deny', 'challenge', 'require_sign_in'] as const;
export type DefendDecision = (typeof DECISIONS)[number];

/**
 * Who is calling. `verified_agent`: a Shield360 agent passport or a Web Bot
 * Auth signature verified. `suspected_ai_agent`: the client hit a trap.
 * The other values come from a classifier passed as `classify`.
 */
export const CLIENT_TYPES = ['human', 'verified_agent', 'unverified_automation', 'suspected_ai_agent', 'ai_attack_agent', 'scanner'] as const;
export type ClientType = (typeof CLIENT_TYPES)[number];

/** A classification with the reasons behind it (each a short code, never a header value). */
export type ClientClassification = { clientType: ClientType; reasons: string[] };

export type DefendResult = {
  /** What to do with the request. In monitor mode this is always `allow` (see `wouldBe`). */
  decision: DefendDecision;
  /** Why: short codes such as `deny_list`, `rule:block`, `rate_limit`, `prompt_injection`, `trap_hit`. */
  reasons: string[];
  /** The ids of the rules that matched, in the order they were checked. */
  ruleIds: string[];
  /** Seconds the decision stays valid for this client (0: decide each request). */
  ttl: number;
  /** Set when monitor mode turned a stronger decision into `allow`. */
  wouldBe?: DefendDecision;
  /** The client type, when one is known. */
  clientType?: ClientType;
  /** A honeypot decoy to answer with instead of the app (harmless fake data holding crumbs for this client). */
  decoy?: { status: number; contentType: string; body: string };
  /** The crumb header value the middleware adds to an allowed response (honeypots on). */
  crumbHeader?: string;
  /** SHIELD: decoy and trap verdicts — the signed X-Shield360-Verdict for a trap hit, which the middleware puts on the response while its headers are open. */
  verdict?: string;
};

export type DefendMode = 'enforce' | 'monitor';
export type FailMode = 'open' | 'closed';

/** One compiled rule of the signed policy, checked in order: the first block, challenge or allow wins. */
export type DefendRule = {
  id: string;
  action: 'block' | 'challenge' | 'allow' | 'monitor';
  /** Client addresses and ranges; empty or absent: any. */
  cidrs?: string[];
  /** Countries (ISO 3166 alpha-2) and network owners (AS numbers); only when the app passes them. */
  countries?: string[];
  asns?: number[];
  /** Geo: everyone outside the countries and networks named. */
  except?: boolean;
  /** Path prefixes on a segment boundary; empty or absent: every path. */
  paths?: string[];
  /** Upper-case methods; empty or absent: every method. */
  methods?: string[];
  /** Attack categories the SDK can tell from the request; today `prompt_injection` (content passed by the caller). */
  attacks?: string[];
  /** Client types the rule is about; it matches only when the request's type is known and listed. */
  clientTypes?: ClientType[];
  /** The rule matches a client over this rate (requests a second, burst = bucket size). */
  rate?: { rps: number; burst: number };
};

export type DefendPolicy = {
  version: string;
  exp: number;
  /** The version of the deny, challenge and allow lists; the decisions feed names it so a change is fetched within seconds. */
  listsVersion: string;
  killSwitch: boolean;
  rules: DefendRule[];
  /** Addresses and ranges denied outright: response-rule blocks and the environment's deny list. */
  deny: string[];
  /** Addresses and ranges asked to prove they are human: response-rule challenges. */
  challenge: string[];
  /** Trusted clients: no Defend rule denies or challenges them. */
  allow: string[];
  /** What a client marked by a trap hit gets, and for how long it stays marked. Default block: a trap is never touched by a person or a verified agent. */
  traps: { action: 'monitor' | 'block' | 'challenge'; ttlSeconds: number };
  /** The environment's honeypots (Edge → Honeypots): the same crumbs Edge serves; null when off. */
  honeypots: import('../defend-traps/honeypots').HoneypotSettings | null;
  /** The keys Edge signs its context header with (protection triangle); empty without Edge. */
  edgeKeys: import('../rasp/edge-context').EdgeKey[];
};

/** What Defend reads from one request. Never logged, never sent as is. */
export type DefendFacts = {
  method: string;
  /** The path, before any `?`, percent-decoded once. */
  path: string;
  /** The query string, as received (honeypot crumbs are looked for in it; never reported). */
  query?: string;
  /** The path as received (not decoded): what Edge's context header hashes. */
  rawPath?: string;
  /** Edge's verified context for this request (protection triangle), when Edge is in front. */
  edge?: { ct: string; trap: number; fl: boolean; risk: number; rid?: string; rt?: string };
  ip?: string;
  country?: string;
  asn?: number;
  headers: Record<string, string>;
  /** Text the caller asks Defend to check (a prompt, a form field), capped. */
  content?: string[];
};

export type DefendCallOptions = {
  /** Text to run the prompt-injection and sensitive-data checks on. */
  content?: string | string[];
  /** Overrides the client address Defend would read. */
  ip?: string;
  country?: string;
  asn?: number;
};

export type DefendOptions = {
  /** The app's name in Shield360 (service.name). Required. */
  app: string;
  /** Shield360 URL and the project's API key: the policy is fetched with them. */
  url?: string;
  apiKey?: string;
  /** The environment's public key the signed policy must verify against (as RASP's configPublicKey). */
  configPublicKey?: string | object;
  /** Development only: trust on first use. Refused when NODE_ENV or ENVIRONMENT is production. */
  allowUnpinnedConfig?: boolean;
  /** `monitor` never denies: decisions are reported and returned with `wouldBe`. Default enforce (rules decide). */
  mode?: DefendMode;
  /** What happens without a usable policy or on an internal error. Default open. */
  failMode?: FailMode;
  /** Proxies in front of the app: the client address is read that many hops from the right of X-Forwarded-For. Default 0 (the socket's address). */
  trustProxy?: number;
  /** Request headers that carry the client's country and AS number, set by a proxy you trust (e.g. `cf-ipcountry`). */
  geoHeaders?: { country?: string; asn?: string };
  /** An agent verifier from `shield360/agents` (agentVerifier): passports and Web Bot Auth signatures are checked with it. */
  agents?: { check(input: unknown, opts?: { route?: string; method?: string }): Promise<AgentCheckLike> };
  /** A client classifier: returns the client type and its reasons. Default: shield360/client-type's classifyClient (with Edge's context and how widely the client roams). `false` turns classification off. */
  classify?: false | ((facts: DefendFacts, signals: { verifiedAgent: boolean; trapHit: boolean }) => ClientClassification | null | undefined);
  /** Sensitive data in `content`: `monitor` (default) adds a reason, `block` denies, `off` skips the check. */
  sensitiveData?: 'off' | 'monitor' | 'block';
  /** Report deny, challenge and trap decisions to Shield360 (default true when url and apiKey are set). */
  report?: boolean;
  /** Ask Shield360 for rate limits shared by every instance (POST /api/defend/decide). Adds a network call to requests a rate rule covers; local limits apply when it fails. Default off. */
  sharedRateLimits?: boolean | { timeoutMs?: number };
  /** Honeypots, when they are on for the environment: words from the app's own routes for decoy names, and whether a crumb header is added to responses (default true). */
  honeypots?: { words?: string[]; header?: boolean; files?: boolean };
  cacheDir?: string;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
  now?: () => number;
};

/** The parts of an agent check Defend reads. */
export type AgentCheckLike = { status: 'verified' | 'absent' | 'invalid'; blocked?: boolean; reason?: string; via?: string };
