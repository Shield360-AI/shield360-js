/**
 * Property tests for the custom-rule expression language (rasp/rule-expr.ts),
 * which evaluates expressions and regular expressions that arrive in the
 * signed config. Properties:
 *
 *   1. compileRuleExpr, compileRegex and evaluateRuleExpr never throw, on
 *      any input.
 *   2. Evaluation is bounded: no expression the compiler accepts, against
 *      any subject, takes more than a fixed time (no ReDoS).
 *   3. The Pike VM agrees with JavaScript's backtracking engine (dotAll,
 *      ASCII subjects) on every pattern both accept: the safe subset means
 *      what the README says it means.
 */
import { compileRegex, compileRuleExpr, DEFAULT_RULE_BUDGET, evaluateRuleExpr, RULE_EXPR_LIMITS, type RuleSubject } from '../../rasp/rule-expr';
import { FUZZ_ITERATIONS, FUZZ_SEED, rand, type Rand } from './fuzz-kit';

const FIELDS = ['request.method', 'request.path', 'request.route', 'request.ip', 'input.value', 'input.key', 'input.source', 'sink.name', 'attack.type', 'attack.rule', 'app.name'];
const MAPS = ['request.headers', 'request.query', 'request.body'];
const REGEX_ALPHABET = 'ab.^$|?*+()[]{}\\-dws0123,:';
const SUBJECT_ALPHABET = 'ab \n0_-';

/** Inputs that once found a problem, or are classic ReDoS shapes; always checked. */
const REGRESSION_PATTERNS = ['^(?:a|a)*b$', '(a|aa)*c', '(.*a){20}', 'a{100}a{100}', '(?:a|b|ab)*$', '[ab]*[ab]*[ab]*[ab]*c', '.*.*.*.*.*.*x', '(a+)+', '\\d{100}\\w{100}'];
const REGRESSION_EXPRESSIONS = [
  'input.value.matches("(?:a|a)*b")',
  '!(!(!(!(!(!(!(!(!(!(!(true)))))))))))',
  'request.headers["__proto__"] == "x"',
  'request.headers["constructor"].startsWith("f")',
  'request.ip.inCidr("0.0.0.0/0") && request.ip.inCidr("::/0")',
  '"a" in ["a","a","a"] || "\\u0000" == "\\x00"',
];

function regex(r: Rand): string {
  return r.string(REGEX_ALPHABET, 24);
}

function str(r: Rand): string {
  return JSON.stringify(r.string('ab"\\/\n\u0000 é😀', 12));
}

function term(r: Rand, depth: number): string {
  if (depth <= 0 || r.chance(0.3)) {
    const k = r.int(6);
    if (k === 0) return str(r);
    if (k === 1) return r.pick(['true', 'false', 'null']);
    if (k === 2) return `${r.pick(MAPS)}[${str(r)}]`;
    return r.pick(FIELDS);
  }
  const k = r.int(9);
  const a = () => term(r, depth - 1);
  switch (k) {
    case 0:
      return `${a()} && ${a()}`;
    case 1:
      return `${a()} || ${a()}`;
    case 2:
      return `!(${a()})`;
    case 3:
      return `${a()} ${r.pick(['==', '!=', '<', '<=', '>', '>='])} ${a()}`;
    case 4:
      return `${a()} in [${str(r)}, ${str(r)}]`;
    case 5:
      return `${r.pick(FIELDS)}.${r.pick(['startsWith', 'endsWith', 'contains'])}(${str(r)})`;
    case 6:
      return `${r.pick(FIELDS)}.matches(${JSON.stringify(regex(r))})`;
    case 7:
      return `${r.pick(FIELDS)}.lowerAscii() == ${str(r)}`;
    default:
      return `request.ip.inCidr(${JSON.stringify(r.pick(['10.0.0.0/8', '::1/128', '1.2.3.4', 'x', '300.1.1.1/8']))})`;
  }
}

/** A valid-looking expression, sometimes mangled byte by byte. */
function expression(r: Rand): string {
  let e = term(r, 1 + r.int(5));
  if (r.chance(0.3)) {
    const chars = Array.from(e);
    for (let i = 0, n = 1 + r.int(4); i < n && chars.length; i++) {
      const at = r.int(chars.length);
      const op = r.int(3);
      if (op === 0) chars.splice(at, 1);
      else if (op === 1) chars.splice(at, 0, r.pick(Array.from('()[]"\\.!&|=<>, \u0000')));
      else chars[at] = r.pick(Array.from('()[]"\\.!&|=<>, '));
    }
    e = chars.join('');
  }
  return e;
}

function adversarialValue(r: Rand): string {
  const n = r.pick([0, 1, 64, 4096, 10_000]);
  return r.chance(0.5) ? 'a'.repeat(n) + r.pick(['', 'b', 'c', '!']) : r.string(SUBJECT_ALPHABET, Math.min(n, 512));
}

function subject(r: Rand): RuleSubject {
  const inputs = Array.from({ length: r.int(6) }, (_, i) => ({ value: adversarialValue(r), key: `query.k${i}`, source: 'request' }));
  const headers: Record<string, string> = Object.create(null);
  headers['user-agent'] = adversarialValue(r);
  return {
    app: 'app',
    request: { method: 'GET', path: `/${adversarialValue(r).slice(0, 2048)}`, route: '/x', ip: r.pick(['10.1.2.3', '::1', 'junk', '']), headers, query: { q: adversarialValue(r) }, body: {} },
    inputs,
    sink: 'fs',
    attack: { type: 'sqli', rule: 'r1' },
  };
}

/** Wall-clock bound for one evaluation. The step budget makes it far smaller in practice. */
const MAX_EVAL_MS = 2_000;

function checkExpression(src: string, r: Rand, label: string): boolean {
  let compiled: ReturnType<typeof compileRuleExpr>;
  try {
    compiled = compileRuleExpr(src);
  } catch (e) {
    throw new Error(`${label}: compileRuleExpr threw on ${JSON.stringify(src)}: ${String(e)}`);
  }
  if (!compiled.ok) return false;
  for (let k = 0; k < 2; k++) {
    const s = subject(r);
    const t0 = Date.now();
    let res: ReturnType<typeof evaluateRuleExpr>;
    try {
      res = evaluateRuleExpr(compiled.expr, s, { steps: DEFAULT_RULE_BUDGET });
    } catch (e) {
      throw new Error(`${label}: evaluateRuleExpr threw on ${JSON.stringify(src)}: ${String(e)}`);
    }
    const ms = Date.now() - t0;
    if (ms > MAX_EVAL_MS) throw new Error(`${label}: ${JSON.stringify(src)} took ${ms} ms`);
    expect(typeof res.matched).toBe('boolean');
  }
  return true;
}

describe('rule-expr properties', () => {
  it('regression seeds stay bounded and never throw', () => {
    const r = rand(FUZZ_SEED);
    for (const p of REGRESSION_PATTERNS) checkExpression(`input.value.matches(${JSON.stringify(p)})`, r, `seed pattern ${p}`);
    for (const e of REGRESSION_EXPRESSIONS) checkExpression(e, r, `seed expression ${e}`);
  });

  it('never throws and stays bounded on random and mangled expressions', () => {
    const r = rand(FUZZ_SEED);
    let accepted = 0;
    for (let i = 0; i < FUZZ_ITERATIONS; i++) if (checkExpression(expression(r), r, `seed ${FUZZ_SEED} iteration ${i}`)) accepted++;
    // The generator must reach the evaluator, not only the parser's refusals.
    expect(accepted).toBeGreaterThan(FUZZ_ITERATIONS * 0.1);
  });

  it('accepts no expression over the size limits', () => {
    const big = `app.name == ${JSON.stringify('a'.repeat(RULE_EXPR_LIMITS.expressionBytes))}`;
    expect(compileRuleExpr(big).ok).toBe(false);
    const deep = `${'!('.repeat(RULE_EXPR_LIMITS.depth + 2)}true${')'.repeat(RULE_EXPR_LIMITS.depth + 2)}`;
    expect(compileRuleExpr(deep).ok).toBe(false);
  });

  it('the Pike VM agrees with JavaScript on every pattern both accept', () => {
    const r = rand(FUZZ_SEED ^ 0x9e3779b9);
    let compared = 0;
    for (let i = 0; i < FUZZ_ITERATIONS * 5; i++) {
      const pattern = regex(r);
      let prog: ReturnType<typeof compileRegex>;
      try {
        prog = compileRegex(pattern);
      } catch (e) {
        throw new Error(`compileRegex threw on ${JSON.stringify(pattern)}: ${String(e)}`);
      }
      if (!prog) continue;
      let native: RegExp;
      try {
        native = new RegExp(pattern, 's');
      } catch {
        continue;
      }
      const expr = compileRuleExpr(`app.name.matches(${JSON.stringify(pattern)})`);
      if (!expr.ok) throw new Error(`compileRegex accepted ${JSON.stringify(pattern)} but the expression did not compile`);
      for (let k = 0; k < 4; k++) {
        const value = r.string(SUBJECT_ALPHABET, 16);
        const ours = evaluateRuleExpr(expr.expr, { app: value }).matched;
        const theirs = native.test(value);
        if (ours !== theirs) throw new Error(`pattern ${JSON.stringify(pattern)} on ${JSON.stringify(value)}: VM ${ours}, RegExp ${theirs}`);
        compared++;
      }
    }
    expect(compared).toBeGreaterThan(0);
  });
});
