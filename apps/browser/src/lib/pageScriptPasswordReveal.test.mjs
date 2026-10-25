import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

const script = readFileSync(new URL("../../../../packages/ardiacore/ios/page_script.js", import.meta.url), "utf8");
const start = script.indexOf("  const typedByUser = new WeakSet();\n");
const end = script.indexOf("  const installNotifications = ", start);
const guardStart = script.indexOf("  const guard = ");
const guardEnd = script.indexOf("  const later = ", guardStart);
assert.ok(start > 0 && end > start && guardStart > 0 && guardEnd > guardStart);
const source = script.slice(guardStart, guardEnd) + script.slice(start, end);

function page() {
  const hosts = [];
  const timers = [];
  class Target {
    listeners = new Map();
    addEventListener(type, fn) {
      const listeners = this.listeners.get(type) || [];
      listeners.push(fn);
      this.listeners.set(type, listeners);
    }
    fire(type, init = {}) {
      const event = { type, target: this, isTrusted: true, preventDefault() {}, stopPropagation() {}, ...init };
      for (const fn of this.listeners.get(type) || []) fn(event);
    }
  }
  class Element extends Target {
    style = {};
    isConnected = true;
    parentElement = null;
    attachShadow() {
      this.button = new Element();
      return { querySelector: () => this.button };
    }
    getBoundingClientRect() {
      return { width: 200, height: 32, right: 200, top: 0 };
    }
    closest() {
      return null;
    }
  }
  class HTMLInputElement extends Element {
    type = "password";
    value = "";
    autofilled = false;
    selectionStart = 2;
    selectionEnd = 4;
    matches(selector) {
      assert.ok(selector === ":autofill" || selector === ":-webkit-autofill");
      return this.autofilled;
    }
    focus() {
      document.activeElement = this;
      document.fire("focusin", { target: this });
    }
    setSelectionRange(start, end) {
      this.selectionStart = start;
      this.selectionEnd = end;
    }
  }
  const document = new Target();
  document.createElement = () => new Element();
  document.documentElement = { appendChild: (host) => hosts.push(host) };
  const window = new Target();
  runInNewContext(source, {
    apply: Reflect.apply,
    document,
    HTMLInputElement,
    getComputedStyle: () => ({ paddingRight: "4", borderRightWidth: "1", color: "black" }),
    addEventListener: window.addEventListener.bind(window),
    requestAnimationFrame: (fn) => timers.push(fn),
    setTimeout: (fn) => timers.push(fn),
  });
  const field = new HTMLInputElement();
  field.focus();
  return {
    document,
    field,
    input(value, { autofilled = false, trusted = true } = {}) {
      field.value = value;
      field.autofilled = autofilled;
      document.fire("input", { target: field, isTrusted: trusted });
    },
    visible: () => hosts.some((host) => host.style.display === "block"),
    click: () => hosts.at(-1)?.button.fire("click"),
    settle: () => { while (timers.length) timers.shift()(); },
  };
}

test("trusted autofill input cannot expose a saved password through Ardia's eye", () => {
  const p = page();
  p.input("fixture-saved-password", { autofilled: true });
  p.click();
  assert.equal(p.field.type, "password");
  assert.equal(p.visible(), false);
});

test("an eye already shown rechecks autofill on click without another input event", () => {
  const p = page();
  p.input("manual-password");
  assert.equal(p.visible(), true);
  p.field.value = "fixture-saved-password";
  p.field.autofilled = true;
  p.click();
  assert.equal(p.field.type, "password");
  assert.equal(p.visible(), false);
  p.field.autofilled = false;
  p.field.focus();
  assert.equal(p.visible(), false);
});

test("autofill input hides an existing eye and revokes its manual-input eligibility", () => {
  const p = page();
  p.input("manual-password");
  assert.equal(p.visible(), true);
  p.input("fixture-saved-password", { autofilled: true });
  assert.equal(p.visible(), false);
  p.field.autofilled = false;
  p.field.focus();
  assert.equal(p.visible(), false);
});

test("a focus update conceals a revealed field that has become autofilled", () => {
  const p = page();
  p.input("manual-password");
  p.click();
  assert.equal(p.field.type, "text");
  p.field.value = "fixture-saved-password";
  p.field.autofilled = true;
  p.field.focus();
  assert.equal(p.field.type, "password");
  assert.equal(p.visible(), false);
});

test("autofill input immediately conceals an already revealed password", () => {
  const p = page();
  p.input("manual-password");
  p.click();
  assert.equal(p.field.type, "text");
  p.input("fixture-saved-password", { autofilled: true });
  assert.equal(p.field.type, "password");
  assert.equal(p.visible(), false);
  p.field.autofilled = false;
  p.field.focus();
  assert.equal(p.visible(), false);
});

test("click conceals an already revealed password that became autofilled without an input event", () => {
  const p = page();
  p.input("manual-password");
  p.click();
  assert.equal(p.field.type, "text");
  p.field.value = "fixture-saved-password";
  p.field.autofilled = true;
  p.click();
  assert.equal(p.field.type, "password");
  assert.equal(p.visible(), false);
  p.field.autofilled = false;
  p.field.focus();
  assert.equal(p.visible(), false);
});

test("manual typing still reveals, preserves selection, toggles and conceals on blur", () => {
  const p = page();
  p.input("manual-password");
  assert.equal(p.visible(), true);
  p.click();
  assert.equal(p.field.type, "text");
  assert.deepEqual([p.field.selectionStart, p.field.selectionEnd], [2, 4]);
  p.click();
  assert.equal(p.field.type, "password");
  p.click();
  p.document.activeElement = null;
  p.document.fire("focusout", { target: p.field });
  p.settle();
  assert.equal(p.field.type, "password");
  assert.equal(p.visible(), false);
});

test("untrusted input cannot enable the eye, and clearing permits fresh manual typing", () => {
  const p = page();
  p.input("script-password", { trusted: false });
  assert.equal(p.visible(), false);
  p.input("fixture-saved-password", { autofilled: true });
  p.input("");
  assert.equal(p.visible(), false);
  p.input("new-manual-password");
  assert.equal(p.visible(), true);
  p.click();
  assert.equal(p.field.type, "text");
});
