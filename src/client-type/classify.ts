/**
 * Client type: who is calling, with the reasons, deterministic and explainable
 * (docs/latest/shield360/client-type.mdx). The same signatures as the Python
 * SDK (signatures.json, byte-identical copies, a test says so).
 *
 *   human                  nothing says it is automated
 *   verified_agent         a Shield360 agent passport or Web Bot Auth signature
 *                          verified, or Edge says it verified the client
 *   unverified_automation  a script, a library, a headless browser, a crawler
 *                          that only claims to be one
 *   suspected_ai_agent     a trap or LLM tripwire hit, an AI agent's own name,
 *                          an agent framework, or automation that roams widely
 *   ai_attack_agent        an autonomous pentest agent: its own header, or a
 *                          RASP mark (sdk/rasp/README.md "AI attack agents")
 *   scanner                an attack tool's User-Agent (sqlmap, nuclei, ffuf…)
 *
 * The strongest signal wins, in that order of trust: verified, trap, the
 * Edge context, then what the request itself says. Reasons are short codes
 * (`ua_ai_agent:claude-user`), never a header value.
 */
import SIGNATURES from './signatures.json';

export const SIGNATURES_VERSION: string = (SIGNATURES as { version: string }).version;
export const CLIENT_TYPES = ['human', 'verified_agent', 'unverified_automation', 'suspected_ai_agent', 'ai_attack_agent', 'scanner'] as const;
export type ClientType = (typeof CLIENT_TYPES)[number];
export type Confidence = 'high' | 'medium' | 'low';
export type ClientClassification = { clientType: ClientType; reasons: string[]; confidence: Confidence };

type Sig = { id: string; match: string };
type Signatures = { version: string; aiAgents: Sig[]; aiCrawlers: Sig[]; agentFrameworks: Sig[]; automation: Sig[]; headless: Sig[]; attackTools: Sig[]; attackAgentHeaders: Sig[] };
const S = SIGNATURES as Signatures;

const find = (ua: string, list: Sig[]) => list.find((s) => ua.includes(s.match));

export type ClientSignals = {
  /** A passport or Web Bot Auth signature verified. */
  verifiedAgent?: boolean;
  /** The client hit a trap (honeypot crumb, LLM tripwire, decoy). */
  trapHit?: boolean;
  /** What Edge says in a verified context header (`ct`, `trap`, `fl`, `risk`). */
  edge?: { ct?: string; trap?: number; fl?: boolean; risk?: number };
  /** Distinct paths this client asked for in the last minute (from the caller's own counter). */
  breadth?: number;
  /** The client's RASP mark (sdk/rasp/README.md "AI attack agents"), when it has one. */
  attackMark?: 'ai_attack_agent' | 'scanner';
};

/** The first attack agent header entry a request carries: a header named `match`, or starting with it when it ends in `-`. */
function agentHeader(headers: Record<string, string>): Sig | undefined {
  const names = Object.keys(headers).map((k) => k.toLowerCase());
  return S.attackAgentHeaders.find((s) => names.some((n) => n === s.match || (s.match.endsWith('-') && n.startsWith(s.match))));
}

/** Distinct paths a minute above which automation looks like an agent exploring. */
export const BREADTH_AGENT = 30;

export function classifyClient(headers: Record<string, string>, signals: ClientSignals = {}): ClientClassification {
  const ua = (headers['user-agent'] || '').toLowerCase().slice(0, 512);
  const out = (clientType: ClientType, reasons: string[], confidence: Confidence): ClientClassification => ({ clientType, reasons, confidence });
  if (signals.verifiedAgent) return out('verified_agent', ['agent_verified'], 'high');
  if (signals.edge?.ct === 'verified_agent' || signals.edge?.ct === 'verified_crawler') return out('verified_agent', [`edge:${signals.edge.ct}`], 'high');
  // An attack agent's own header, a RASP mark, then an attack tool's User-Agent (tool-only evidence stays `scanner`).
  const header = agentHeader(headers);
  if (header) return out('ai_attack_agent', [`attack_agent_header:${header.id}`], 'high');
  if (signals.attackMark === 'ai_attack_agent') return out('ai_attack_agent', ['attack_mark:ai_attack_agent'], 'high');
  const tool = ua ? find(ua, S.attackTools) : undefined;
  if (tool) return out('scanner', [`ua_attack_tool:${tool.id}`], 'high');
  if (signals.attackMark === 'scanner') return out('scanner', ['attack_mark:scanner'], 'high');
  if (signals.trapHit) return out('suspected_ai_agent', ['trap_hit'], 'high');
  if ((signals.edge?.trap ?? 0) >= 2) return out('suspected_ai_agent', [`edge:trap_level_${signals.edge?.trap}`], 'high');
  const reasons: string[] = [];
  if (signals.edge?.ct === 'suspected_agent') reasons.push('edge:suspected_agent');
  const agent = find(ua, S.aiAgents);
  if (agent) reasons.push(`ua_ai_agent:${agent.id}`);
  const framework = find(ua, S.agentFrameworks);
  if (framework) reasons.push(`ua_agent_framework:${framework.id}`);
  if (reasons.length) return out('suspected_ai_agent', reasons, signals.edge?.ct === 'suspected_agent' ? 'high' : 'medium');
  const crawler = find(ua, S.aiCrawlers);
  const automation = find(ua, S.automation);
  const headless = find(ua, S.headless);
  if (crawler) reasons.push(`ua_ai_crawler:${crawler.id}`);
  if (automation) reasons.push(`ua_automation:${automation.id}`);
  if (headless) reasons.push(`headless:${headless.id}`);
  if (!ua) reasons.push('no_user_agent');
  // A browser that says Chrome but sends none of the headers Chrome always sends.
  if (/chrome\/\d/.test(ua) && !headless && !headers['sec-ch-ua'] && !headers['sec-fetch-mode'] && !headers['accept-language']) reasons.push('browser_headers_missing');
  if (signals.edge?.ct === 'automation') reasons.push('edge:automation');
  if (reasons.length) {
    if ((signals.breadth ?? 0) >= BREADTH_AGENT) return out('suspected_ai_agent', [...reasons, 'breadth'], 'medium');
    return out('unverified_automation', reasons, crawler || automation || headless ? 'high' : 'medium');
  }
  if (signals.edge?.fl || (signals.edge?.risk ?? 0) >= 70) return out('unverified_automation', [signals.edge?.fl ? 'edge:flagged' : 'edge:risk'], 'medium');
  return out('human', [], 'low');
}
