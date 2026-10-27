# prompt-sentry 🛡️

[![CI](https://github.com/yagodejesus/prompt-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/yagodejesus/prompt-sentry/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/prompt-sentry.svg)](https://www.npmjs.com/package/prompt-sentry)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

**Find and strip prompt injection hidden in untrusted text — before your AI agent reads it.**

> 🇧🇷 *Detecta e remove prompt injection escondido em páginas, e-mails e documentos antes que eles cheguem ao seu agente de IA: texto invisível em Unicode, HTML oculto, imagens que vazam dados, payloads em base64 e frases de ataque em inglês, português e espanhol. Zero dependências.*

Agents that browse the web, read e-mails or summarise documents treat everything they read as potential instructions. Attackers know it, and they hide commands where **people can't see them but models can**: invisible Unicode characters, `display:none` blocks, HTML comments, `alt` text, base64 blobs, and image URLs that quietly send your conversation to their server when rendered.

`prompt-sentry` is a small, dependency-free TypeScript library (Node, browsers, edge runtimes) that finds those tricks, tells you exactly where they are, and removes them.

```ts
import { scan, sanitize, spotlight } from "prompt-sentry";

const page = await fetch(url).then((r) => r.text());

const report = scan(page);
report.risk;      // "high"
report.findings;  // [{ type: "unicode-tags", decoded: "Ignore all previous instructions…", index: 812, … }, …]

const { text } = sanitize(page);            // invisible chars, hidden HTML and exfiltration links removed
const wrapped = spotlight(text, { source: "a web page" });
// put wrapped.instructions in your system prompt and wrapped.text in the user turn
```

## Install

```bash
npm install prompt-sentry
```

ESM, Node ≥ 20 (also runs in modern browsers, Deno, Bun and edge runtimes — only standard Web APIs are used).

## What it detects

| Type | Severity | Technique |
|---|---|---|
| `unicode-tags` | high | **ASCII smuggling**: text written with invisible Unicode *tag* characters (U+E0000 block). Decoded and shown to you. Emoji flags like 🏴󠁧󠁢󠁳󠁣󠁴󠁿 are recognised as legitimate. |
| `variation-selectors` | high/medium | Bytes hidden in runs of variation selectors after an emoji or letter. Decoded. Normal emoji (❤️, 1️⃣) are fine. |
| `zero-width` | high/medium/low | Zero-width characters splitting keywords (`ig​nore`) or long zero-width runs (steganography). Joiners in emoji (👩‍💻) and Persian/Indic text are fine. |
| `bidi-control` | medium | Right-to-left overrides that make text read differently from how it looks ("Trojan Source"). |
| `mixed-script` | medium | Words mixing Latin with Cyrillic/Greek look-alikes (`Ignоre`). |
| `instruction` | high/medium | Phrases that try to override instructions, change the assistant's role, reveal the system prompt, hide things from the user or send data elsewhere — in **English, Portuguese and Spanish**, after folding homoglyphs, full-width letters, invisible characters and l33tspeak. |
| `role-marker` | high/medium | Chat-template tokens (`<|im_start|>`, `[INST]`, `<<SYS>>`) and fake `SYSTEM:` / `<system>` tags. |
| `hidden-html` | high/low | Text people can't see: `display:none`, `visibility:hidden`, `font-size:0`, `opacity:0`, off-screen positioning, transparent or white text, `hidden`, `aria-hidden`, plus instructions inside `<script>`, `<style>`, `<template>`, `<noscript>`. High when the hidden text contains instructions. |
| `html-comment` | high | Instructions inside `<!-- comments -->`. |
| `hidden-attribute` | high | Instructions inside `alt`, `title`, `aria-label`, `content`, `value`, `placeholder` or `data-*`. |
| `exfiltration` | high/medium/low | Markdown or HTML images (and links) whose URL carries data — template placeholders like `{chat_history}`, long encoded values, or parameters such as `?data=` — to domains outside your allowlist. |
| `encoded-payload` | high | Base64 strings that decode to instructions. |

Every finding has the exact `index`/`length` in your input, a printable `excerpt` (invisible characters shown as `⟨U+200B⟩`) and, when something was hidden, the `decoded` text.

## API

### `scan(text, options?) → { risk, score, findings }`

```ts
scan(input, {
  html: "auto",                         // true | false | "auto" (default)
  allowedDomains: ["mycompany.com"],    // images outside the list are reported
  decodeBase64: true,                   // default
});
```

`risk` is the highest severity found (`"none" | "low" | "medium" | "high"`); `score` is 0–100.

### `sanitize(text, options?) → { text, changed, findings, risk }`

Removes invisible characters (keeping legitimate emoji sequences), hidden HTML elements, comments, scripts, instruction-bearing attributes, encoded payloads and data-carrying images/links. Options:

| Option | Default | |
|---|---|---|
| `removeHiddenHtml` | `true` | drop hidden elements, comments and non-rendered tags |
| `stripExfiltration` | `true` | replace suspicious images/links with `[removed image from host]` |
| `redactInstructions` | `false` | also replace instruction phrases with `replacement` |
| `replacement` | `"[removed: suspected prompt injection]"` | |
| `normalize` | `false` | apply NFKC to the output |

### `spotlight(text, options?) → { text, instructions }`

Implements **spotlighting** ([Hines et al., 2024](https://arxiv.org/abs/2403.14720)): marks untrusted content so the model can tell data apart from instructions. Modes:

- `"delimit"` (default) — wraps the content in random, unforgeable boundary markers;
- `"datamark"` — replaces whitespace with `ˆ`, so every word carries the "this is data" mark;
- `"encode"` — base64-encodes the content.

The content is sanitised first (disable with `sanitize: false`). Add `instructions` to your system prompt.

### `revealHidden(text) → string[]`

Returns the messages hidden with tag characters or variation selectors — handy for incident analysis.

## Command line

```bash
npx prompt-sentry page.html                     # report, exit code 1 on high risk
curl -s https://example.com | npx prompt-sentry --json
npx prompt-sentry email.txt --sanitize > clean.txt
npx prompt-sentry docs/*.md --fail-on medium    # in CI, for content you feed to RAG
```

## Example: a guarded tool for an agent

```ts
import { sanitize, spotlight } from "prompt-sentry";

export async function readWebPage(url: string): Promise<string> {
  const html = await fetch(url).then((r) => r.text());
  const { text, risk, findings } = sanitize(html, { allowedDomains: [new URL(url).hostname] });
  if (risk === "high") console.warn(`prompt-sentry: ${findings.length} finding(s) on ${url}`);
  return spotlight(text, { source: `the web page ${url}`, sanitize: false }).text;
}
```

## Limitations

Prompt injection can't be solved by filtering alone: a well-written attack in plain, visible language can look exactly like legitimate content. `prompt-sentry` removes the *hidden* channels and flags the common phrasings — use it as one layer, together with least-privilege tools, human confirmation for sensitive actions and output filtering.

- Phrase detection is pattern-based (EN/PT/ES) and will miss novel wording. Contributions of new patterns and languages are very welcome.
- HTML parsing is lightweight (no DOM); CSS from external stylesheets or classes such as `.sr-only` isn't evaluated, only inline styles and attributes.

## Development

```bash
git clone https://github.com/yagodejesus/prompt-sentry && cd prompt-sentry
npm install
npm test
```

## License

MIT © Yago de Jesus Martins
