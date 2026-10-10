// EdgeGuard for Node.js: the Rust engine compiled to WebAssembly. No native build, no threads,
// no files, so it runs the same on a laptop and in a serverless function.
//
//   cargo build --profile wasm --target wasm32-unknown-unknown --no-default-features --features wasm
//   → target/wasm32-unknown-unknown/wasm/edgeguard.wasm
import { readFileSync } from "node:fs";

/** What to look for, as bit flags (combine with |). */
export const Category = Object.freeze({
  /** Instruction-override phrases in English and Hebrew; strict enough for business email. */
  INJECTION: 1,
  /** The broad roleplay list ("act as a", "pretend to be"); noisy on ordinary text. */
  INJECTION_BROAD: 2,
  EMAIL: 4,
  /** Luhn-valid card numbers, in one block or the usual groups. */
  CREDIT_CARD: 8,
  /** Israeli ID numbers with a valid check digit, next to an ID keyword. */
  IL_ID: 16,
  /** Israeli IBANs with valid check digits. */
  IBAN: 32,
  /** API keys, tokens, private keys, "password: ...". */
  SECRET: 64,
  CUSTOM: 128,
  /** Links with strong signs of phishing: look-alike domains, IP hosts, "user@host", punycode, program downloads. */
  LINK: 256,
  /** Everything redact() can replace. */
  DATA: 4 | 8 | 16 | 32 | 64,
});

/** Warning signs on a link; everything but "shortener" is strong enough to warn about. */
export const STRONG_REASONS = Object.freeze(["lookalike", "ip", "userinfo", "idn", "executable", "script", "mismatch"]);

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * @typedef {{ code: number, category: string, start: number, end: number }} Finding
 * `start`/`end` are string indices (UTF-16, like String.prototype.slice). Injection findings
 * have an empty range: they flag the text, there is nothing to cut out.
 *
 * @typedef {{ start: number, end: number, host: string, site: string, reasons: string[] }} Link
 * `site` is the registrable domain ("leumi.co.il" for "www.leumi.co.il"), what an allow-list compares.
 *
 * @typedef {{ index: number, host: string, site: string, reasons: string[] }} AnchorVerdict
 */

export class EdgeGuard {
  /** @param {WebAssembly.Module} module */
  constructor(module) {
    this.module = module;
    this.instance = new WebAssembly.Instance(module, {});
  }

  /** @param {string | URL} path */
  static fromFile(path) {
    return new EdgeGuard(new WebAssembly.Module(readFileSync(path)));
  }

  /** @param {BufferSource} bytes */
  static fromBytes(bytes) {
    return new EdgeGuard(new WebAssembly.Module(bytes));
  }

  /**
   * Every finding in the given categories.
   * @param {string} text
   * @param {number} [categories]
   * @returns {Finding[]}
   */
  scan(text, categories = Category.INJECTION | Category.DATA) {
    const bytes = encoder.encode(text);
    const findings = JSON.parse(this.#call("eg_scan", bytes, categories) || "[]");
    const index = utf16Index(bytes, findings.flatMap((f) => [f.start, f.end]));
    return findings.map((f) => ({ ...f, start: index.get(f.start), end: index.get(f.end) }));
  }

  /**
   * Every link in plain text (with or without http://), with its warning signs.
   * @param {string} text
   * @returns {Link[]}
   */
  links(text) {
    const bytes = encoder.encode(text);
    const links = JSON.parse(this.#call("eg_links", bytes, 0) || "[]");
    const index = utf16Index(bytes, links.flatMap((l) => [l.start, l.end]));
    return links.map((l) => ({ ...l, start: index.get(l.start), end: index.get(l.end) }));
  }

  /**
   * HTML links (href and visible text): the suspicious ones, through Outlook/Google redirects,
   * including text that shows one address while the link goes to another.
   * @param {{ href: string, text: string }[]} anchors
   * @returns {AnchorVerdict[]}
   */
  anchors(anchors) {
    const clean = (s) => String(s).replace(/[\t\r\n]+/g, " ");
    const input = anchors.map((a) => `${clean(a.href)}\t${clean(a.text)}`).join("\n");
    return JSON.parse(this.#call("eg_anchors", encoder.encode(input), 0) || "[]").map(({ i, ...rest }) => ({ index: i, ...rest }));
  }

  /**
   * The text with data in the given categories replaced by placeholders ([CARD], [ID], [IBAN],
   * [SECRET], [EMAIL]).
   * @param {string} text
   * @param {number} [categories]
   */
  redact(text, categories = Category.CREDIT_CARD | Category.IL_ID | Category.IBAN | Category.SECRET) {
    return this.#call("eg_redact", encoder.encode(text), categories);
  }

  #call(fn, bytes, categories) {
    const wasm = this.instance.exports;
    try {
      const ptr = wasm.eg_alloc(bytes.length);
      new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);
      const packed = fn === "eg_links" || fn === "eg_anchors" ? wasm[fn](ptr, bytes.length) : wasm[fn](ptr, bytes.length, categories);
      wasm.eg_free(ptr, bytes.length);
      const out = Number(packed >> 32n);
      const len = Number(packed & 0xffffffffn);
      if (!out) return "";
      const result = decoder.decode(new Uint8Array(wasm.memory.buffer, out, len));
      wasm.eg_free(out, len);
      return result;
    } catch (error) {
      // A trap leaves the instance unusable: start a fresh one for the next call.
      this.instance = new WebAssembly.Instance(this.module, {});
      throw error;
    }
  }
}

/** Maps UTF-8 byte offsets (on character boundaries) to UTF-16 string indices. */
function utf16Index(bytes, offsets) {
  const map = new Map();
  const wanted = [...new Set(offsets)].sort((a, b) => a - b);
  let i = 0;
  let units = 0;
  for (const offset of wanted) {
    while (i < offset) {
      const b = bytes[i];
      const width = b < 0x80 ? 1 : b < 0xe0 ? 2 : b < 0xf0 ? 3 : 4;
      units += width === 4 ? 2 : 1;
      i += width;
    }
    map.set(offset, units);
  }
  return map;
}
