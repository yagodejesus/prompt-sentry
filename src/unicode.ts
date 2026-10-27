import type { Finding } from "./types.js";

export interface Span {
  start: number;
  end: number;
}

interface CodePoint {
  i: number;
  cp: number;
  ch: string;
}

const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
const isVariationSelector = (cp: number) => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const isBidi = (cp: number) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
const ZERO_WIDTH = new Set([
  0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff, 0x180e, 0x00ad, 0x034f, 0x115f, 0x1160,
  0x3164, 0xffa0, 0x17b4, 0x17b5,
]);
const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;
const LETTER = /[\p{L}\p{M}]/u;
const LATIN = /\p{Script=Latin}/u;
const SKIN_TONE = (cp: number) => cp >= 0x1f3fb && cp <= 0x1f3ff;

export const isInvisible = (cp: number): boolean =>
  isTag(cp) || isVariationSelector(cp) || ZERO_WIDTH.has(cp) || isBidi(cp);

export function codePoints(s: string): CodePoint[] {
  const out: CodePoint[] = [];
  let i = 0;
  for (const ch of s) {
    out.push({ i, cp: ch.codePointAt(0)!, ch });
    i += ch.length;
  }
  return out;
}

/** Shows invisible characters as ⟨U+XXXX⟩ and truncates. */
export function printable(s: string, max = 80): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    out += isInvisible(cp) ? `⟨U+${cp.toString(16).toUpperCase().padStart(4, "0")}⟩` : ch;
    if (out.length >= max) return out.slice(0, max - 1) + "…";
  }
  return out.replace(/\s+/g, " ").trim();
}

const nonLatinLetter = (ch: string | undefined) => !!ch && LETTER.test(ch) && !LATIN.test(ch);

function legitimateJoiner(cps: CodePoint[], k: number): boolean {
  const c = cps[k].cp;
  if (c === 0xfeff && k === 0) return true; // byte-order mark
  if (c === 0x200d) {
    let a = k - 1;
    while (a >= 0 && (isVariationSelector(cps[a].cp) || SKIN_TONE(cps[a].cp))) a--;
    const b = cps[k + 1];
    if (a >= 0 && b && PICTOGRAPHIC.test(cps[a].ch) && PICTOGRAPHIC.test(b.ch)) return true; // 👩‍💻
  }
  if (c === 0x200c || c === 0x200d) {
    if (nonLatinLetter(cps[k - 1]?.ch) && nonLatinLetter(cps[k + 1]?.ch)) return true; // Persian, Indic scripts
  }
  return false;
}

function utf8(bytes: number[]): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
}

export interface UnicodeScan {
  findings: Finding[];
  /** Spans that `sanitize` removes. */
  strip: Span[];
}

export function scanUnicode(text: string): UnicodeScan {
  const cps = codePoints(text);
  const findings: Finding[] = [];
  const strip: Span[] = [];
  const at = (k: number) => (k < cps.length ? cps[k].i : text.length);

  let k = 0;
  while (k < cps.length) {
    const { cp } = cps[k];

    if (isTag(cp)) {
      let e = k;
      while (e < cps.length && isTag(cps[e].cp)) e++;
      const flag = k > 0 && cps[k - 1].cp === 0x1f3f4 && e - k <= 7 && cps[e - 1].cp === 0xe007f; // 🏴󠁧󠁢󠁳󠁣󠁴󠁿
      if (!flag) {
        const decoded = cps
          .slice(k, e)
          .map((c) => (c.cp >= 0xe0020 && c.cp <= 0xe007e ? String.fromCharCode(c.cp - 0xe0000) : ""))
          .join("");
        findings.push({
          type: "unicode-tags",
          severity: "high",
          message: `Text hidden in ${e - k} invisible Unicode tag characters ("ASCII smuggling")`,
          index: cps[k].i,
          length: at(e) - cps[k].i,
          excerpt: `⟨${e - k} tag characters⟩`,
          decoded,
        });
        strip.push({ start: cps[k].i, end: at(e) });
      }
      k = e;
      continue;
    }

    if (isVariationSelector(cp)) {
      let e = k;
      while (e < cps.length && isVariationSelector(cps[e].cp)) e++;
      if (e - k >= 2) {
        const bytes = cps.slice(k, e).map((c) => (c.cp <= 0xfe0f ? c.cp - 0xfe00 : c.cp - 0xe0100 + 16));
        const decoded = utf8(bytes);
        const readable = (decoded.match(/[\p{L}\p{N}\p{P}\p{Zs}]/gu) ?? []).length;
        findings.push({
          type: "variation-selectors",
          severity: e - k >= 4 && readable >= 3 ? "high" : "medium",
          message: `${e - k} consecutive variation selectors — data hidden after a visible character`,
          index: cps[k].i,
          length: at(e) - cps[k].i,
          excerpt: `⟨${e - k} variation selectors⟩`,
          decoded,
        });
        // keep a single leading presentation selector (e.g. the one in ❤️)
        const keepFirst = cp === 0xfe0f || cp === 0xfe0e;
        strip.push({ start: keepFirst ? at(k + 1) : cps[k].i, end: at(e) });
      }
      k = e;
      continue;
    }

    if (isBidi(cp)) {
      let e = k;
      while (e < cps.length && isBidi(cps[e].cp)) e++;
      findings.push({
        type: "bidi-control",
        severity: "medium",
        message: "Bidirectional control characters can make text read differently from how it is displayed",
        index: cps[k].i,
        length: at(e) - cps[k].i,
        excerpt: printable(text.slice(Math.max(0, cps[k].i - 15), at(e) + 15)),
      });
      strip.push({ start: cps[k].i, end: at(e) });
      k = e;
      continue;
    }

    if (ZERO_WIDTH.has(cp) && !legitimateJoiner(cps, k)) {
      let e = k;
      while (e < cps.length && ZERO_WIDTH.has(cps[e].cp) && !legitimateJoiner(cps, e)) e++;
      const n = e - k;
      const insideWord = LETTER.test(cps[k - 1]?.ch ?? "") && LETTER.test(cps[e]?.ch ?? "");
      const onlySoftHyphens = cps.slice(k, e).every((c) => c.cp === 0x00ad);
      const severity = n >= 8 ? "high" : onlySoftHyphens ? "low" : insideWord ? "medium" : "low";
      findings.push({
        type: "zero-width",
        severity,
        message:
          n >= 8
            ? `${n} consecutive zero-width characters — possible hidden (steganographic) message`
            : insideWord
              ? "Zero-width character inside a word — can split keywords to evade filters"
              : "Invisible zero-width character",
        index: cps[k].i,
        length: at(e) - cps[k].i,
        excerpt: printable(text.slice(Math.max(0, cps[k].i - 15), at(e) + 15)),
      });
      strip.push({ start: cps[k].i, end: at(e) });
      k = e;
      continue;
    }
    k++;
  }

  for (const m of text.matchAll(/[\p{L}\p{M}]{2,}/gu)) {
    const word = m[0];
    if (LATIN.test(word) && /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(word)) {
      findings.push({
        type: "mixed-script",
        severity: "medium",
        message: "Word mixes Latin with Cyrillic/Greek look-alike letters (homoglyphs)",
        index: m.index!,
        length: word.length,
        excerpt: word,
      });
    }
  }
  return { findings, strip };
}

/** Reveals messages hidden with Unicode tag characters or variation selectors. */
export function revealHidden(text: string): string[] {
  return scanUnicode(text)
    .findings.filter((f) => f.decoded)
    .map((f) => f.decoded!);
}

const CONFUSABLES: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ј: "j", ѕ: "s", ԁ: "d", һ: "h", ӏ: "l",
  ɡ: "g", ο: "o", α: "a", ε: "e", ι: "i", κ: "k", ν: "v", ρ: "p", τ: "t", υ: "u", χ: "x",
  А: "a", В: "b", Е: "e", К: "k", М: "m", Н: "h", О: "o", Р: "p", С: "c", Т: "t", Х: "x", У: "y", І: "i",
  Ѕ: "s", Ј: "j", Α: "a", Β: "b", Ε: "e", Ζ: "z", Η: "h", Ι: "i", Κ: "k", Μ: "m", Ν: "n", Ο: "o", Ρ: "p",
  Τ: "t", Υ: "y", Χ: "x",
};
const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s" };

export interface Normalized {
  text: string;
  /** map[k] = offset in the original string of normalized character k. */
  map: number[];
}

/** Lower-cases, NFKC-folds, maps homoglyphs (optionally leetspeak) and drops invisible characters. */
export function normalizeForMatching(text: string, leet = false): Normalized {
  let out = "";
  const map: number[] = [];
  for (const { i, cp, ch } of codePoints(text)) {
    if (isInvisible(cp)) continue;
    let piece = CONFUSABLES[ch] ?? ch.normalize("NFKC").toLowerCase();
    if (leet) piece = piece.replace(/[013457@$]/g, (c) => LEET[c]);
    for (let u = 0; u < piece.length; u++) {
      out += piece[u];
      map.push(i);
    }
  }
  map.push(text.length);
  return { text: out, map };
}
