// Smoke test for @hailbytes/password-analyzer.
// Uses node:test (built-in, no devDeps) and a minimal DOM shim
// just so the custom-element module can load in Node.

import { test } from 'node:test';
import assert from 'node:assert/strict';

class FakeElement {
  constructor() { this.children = []; this.style = {}; this.classList = { add(){}, remove(){}, toggle(){} }; }
  appendChild(c) { this.children.push(c); return c; }
  setAttribute() {}
  getAttribute() { return null; }
  addEventListener() {}
  removeEventListener() {}
  querySelector() { return new FakeElement(); }
  querySelectorAll() { return []; }
  getElementById() { return new FakeElement(); }
  set innerHTML(_v) {} get innerHTML() { return ''; }
  set textContent(_v) {} get textContent() { return ''; }
  dispatchEvent() { return true; }
  attachShadow() { return new FakeElement(); }
}

globalThis.HTMLElement = class HTMLElement extends FakeElement {};
globalThis.customElements = { define() {}, get() { return undefined; } };
globalThis.document = {
  createElement: () => new FakeElement(),
  createElementNS: () => new FakeElement(),
};
globalThis.CustomEvent = class CustomEvent {
  constructor(type, init = {}) { this.type = type; this.detail = init.detail; this.bubbles = !!init.bubbles; this.composed = !!init.composed; }
};
globalThis.window = globalThis;
const { analyze } = await import('../hailbytes-password-strength.js');

test('common passwords score Very Weak and are flagged', () => {
  for (const p of ['password', 'abc123', '12345678']) {
    const r = analyze(p);
    assert.equal(r.score, 0, p);
    assert.equal(r.label, 'Very Weak', p);
    assert.ok(r.dictionaryWords.includes('Common password'), p);
    assert.equal(r.checks.noCommon.pass, false, p);
  }
});

test('detects repeated characters', () => {
  const r = analyze('aaaaaaaa');
  assert.ok(r.patterns.some((m) => m.startsWith('Repeated chars')));
  assert.equal(r.composition.uniqueChars, 1);
  assert.equal(r.checks.noPatterns.pass, false);
});

test('detects keyboard and sequential patterns', () => {
  assert.ok(analyze('qwertyuiop').patterns.some((m) => m.startsWith('Keyboard pattern')));
  assert.ok(analyze('12345678').patterns.some((m) => m.startsWith('Sequential numbers')));
});

test('composition counts character classes', () => {
  const r = analyze('xK#9vL2!qZ@8mN4$');
  assert.deepEqual(r.composition, {
    length: 16, lowerCount: 4, upperCount: 4, numberCount: 4, symbolCount: 4, uniqueChars: 16,
  });
  for (const k of ['length', 'longLength', 'lowercase', 'uppercase', 'numbers', 'symbols', 'highEntropy']) {
    assert.equal(r.checks[k].pass, true, k);
  }
});

test('strong random password scores Very Strong with long crack time', () => {
  const r = analyze('xK#9vL2!qZ@8mN4$');
  assert.ok(r.score >= 80);
  assert.equal(r.label, 'Very Strong');
  assert.equal(r.crackTime, 'Centuries');
});

test('scores are ordered weak < medium < strong', () => {
  const weak = analyze('aaaaaaaa').score;
  const mid = analyze('Tr0ub4dor&3').score;
  const strong = analyze('xK#9vL2!qZ@8mN4$').score;
  assert.ok(weak < mid && mid < strong, `${weak} ${mid} ${strong}`);
});

test('score is always clamped to 0..100 and entropy grows with length', () => {
  let prev = -1;
  for (let n = 1; n <= 40; n += 3) {
    const r = analyze('aB3$'.repeat(10).slice(0, n));
    assert.ok(r.score >= 0 && r.score <= 100);
    assert.ok(r.entropy > prev);
    prev = r.entropy;
  }
});
