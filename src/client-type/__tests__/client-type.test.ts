import { readFileSync } from 'fs';
import { join } from 'path';
import { BreadthCounter, classifyClient } from '../index';

describe('classifyClient', () => {
  const chrome = 'mozilla/5.0 (macintosh) applewebkit/537.36 chrome/131.0 safari/537.36';
  const browser = { 'user-agent': chrome, 'sec-ch-ua': '"Chromium"', 'sec-fetch-mode': 'navigate', 'accept-language': 'en' };

  it('a browser with its usual headers is a person', () => {
    expect(classifyClient(browser)).toEqual({ clientType: 'human', reasons: [], confidence: 'low' });
  });

  it('verified beats everything, then a trap hit, then Edge, then the request', () => {
    expect(classifyClient({ 'user-agent': 'python-requests/2.31' }, { verifiedAgent: true, trapHit: true }).clientType).toBe('verified_agent');
    expect(classifyClient(browser, { trapHit: true })).toEqual({ clientType: 'suspected_ai_agent', reasons: ['trap_hit'], confidence: 'high' });
    expect(classifyClient(browser, { edge: { ct: 'verified_crawler' } }).clientType).toBe('verified_agent');
    expect(classifyClient(browser, { edge: { trap: 2 } }).reasons).toEqual(['edge:trap_level_2']);
  });

  it('names AI agents, crawlers, frameworks, scripts and headless browsers with their reasons', () => {
    expect(classifyClient({ 'user-agent': 'Mozilla/5.0 AppleWebKit (compatible; Claude-User/1.0)' })).toMatchObject({ clientType: 'suspected_ai_agent', reasons: ['ua_ai_agent:claude-user'] });
    expect(classifyClient({ 'user-agent': 'langchain/0.3 python-httpx/0.27' }).reasons).toEqual(['ua_agent_framework:langchain']);
    expect(classifyClient({ 'user-agent': 'Mozilla/5.0 (compatible; GPTBot/1.2)' })).toMatchObject({ clientType: 'unverified_automation', reasons: ['ua_ai_crawler:gptbot'] });
    expect(classifyClient({ 'user-agent': 'curl/8.4.0' }).reasons).toEqual(['ua_automation:curl']);
    expect(classifyClient({ 'user-agent': chrome.replace('chrome/', 'headlesschrome/') }).reasons).toEqual(['headless:headlesschrome']);
    expect(classifyClient({}).reasons).toEqual(['no_user_agent']);
    expect(classifyClient({ 'user-agent': chrome }).reasons).toEqual(['browser_headers_missing']);
  });

  it('automation that roams widely is a suspected AI agent', () => {
    expect(classifyClient({ 'user-agent': 'python-httpx/0.27' }, { breadth: 40 })).toMatchObject({ clientType: 'suspected_ai_agent', reasons: ['ua_automation:python-httpx', 'breadth'] });
    expect(classifyClient(browser, { breadth: 40 }).clientType).toBe('human');
  });

  it('never reflects a header value in a reason', () => {
    const r = classifyClient({ 'user-agent': 'curl/8 <script>secret</script>' });
    expect(r.reasons.join()).not.toContain('secret');
  });
});

describe('BreadthCounter', () => {
  it('counts distinct paths per client in a window, bounded', () => {
    const b = new BreadthCounter(1000, 2);
    expect(b.see('a', '/x', 0)).toBe(1);
    expect(b.see('a', '/y', 10)).toBe(2);
    expect(b.see('a', '/y', 20)).toBe(2);
    expect(b.see('a', '/z', 2000)).toBe(1);
    b.see('b', '/x', 0);
    b.see('c', '/x', 0);
    expect(b.see('a', '/q', 2001)).toBe(1);
  });
});

it('keeps a byte-identical copy of the shared signatures', () => {
  const here = readFileSync(join(__dirname, '..', 'signatures.json'));
  const shared = readFileSync(join(__dirname, '..', '..', '..', '..', 'client-type', 'signatures.json'));
  expect(here.equals(shared)).toBe(true);
});
