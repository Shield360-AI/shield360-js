import { candidates, canonicalIp, Crumbs, fingerprint } from '../crumb';

// The shared specification's test vector (agent-guides/edge-deception-spec.md), the same Edge's Go tests use.
const SECRET = Buffer.from('0123456789abcdef0123456789abcdef');
const EPOCH_S = 86_400;
const at = (epoch: number) => () => epoch * EPOCH_S * 1000;

describe('crumbs (shared spec)', () => {
  it('matches the spec test vector byte for byte', () => {
    expect(fingerprint('192.0.2.1', 'Agent/1.0').toString('hex')).toBe('5330e5f83644');
    const c = new Crumbs(SECRET, EPOCH_S, 1, at(20000));
    expect(c.token('p', fingerprint('192.0.2.1', 'Agent/1.0'))).toBe('aeaaatraobjtbzpygzcgysx5gll3ruka');
  });

  it('verifies fresh, grace and burned crumbs, and refuses forgeries and the far future', () => {
    const fp = fingerprint('192.0.2.1', 'Agent/1.0');
    const tok = new Crumbs(SECRET, EPOCH_S, 1, at(20000)).token('c', fp);
    expect(new Crumbs(SECRET, EPOCH_S, 1, at(20000)).verify(tok)).toEqual({ kind: 'c', epoch: 20000, owner: fp.toString('hex'), state: 'fresh' });
    expect(new Crumbs(SECRET, EPOCH_S, 1, at(20001)).verify(tok)?.state).toBe('grace');
    expect(new Crumbs(SECRET, EPOCH_S, 1, at(20002)).verify(tok)?.state).toBe('burned');
    expect(new Crumbs(SECRET, EPOCH_S, 1, at(19998)).verify(tok)).toBeNull();
    expect(new Crumbs(Buffer.alloc(32, 7), EPOCH_S, 1, at(20000)).verify(tok)).toBeNull();
    const flipped = tok.slice(0, -1) + (tok.endsWith('a') ? 'b' : 'a');
    expect(new Crumbs(SECRET, EPOCH_S, 1, at(20000)).verify(flipped)).toBeNull();
  });

  it('attributes a crumb to the client it was served to (foreign when another presents it)', () => {
    const c = new Crumbs(SECRET, EPOCH_S, 1, at(20000));
    const tok = c.token('p', fingerprint('192.0.2.1', 'Agent/1.0'));
    expect(c.verify(tok)?.owner).not.toBe(fingerprint('198.51.100.9', 'Agent/1.0').toString('hex'));
  });

  it('normalizes addresses like Go netip and finds token candidates cheaply', () => {
    expect(canonicalIp('::ffff:192.0.2.1')).toBe('192.0.2.1');
    expect(canonicalIp('2001:DB8:0:0:0:0:0:1')).toBe('2001:db8::1');
    expect(candidates('/admin/_internal/aeaaatraobjtbzpygzcgysx5gll3ruka/verify')).toEqual(['aeaaatraobjtbzpygzcgysx5gll3ruka']);
    expect(candidates('/a/' + 'b'.repeat(33))).toEqual([]);
  });
});
