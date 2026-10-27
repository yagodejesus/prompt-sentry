#!/usr/bin/env node
import { readFileSync } from "node:fs";

import { sanitize, scan } from "./index.js";
import type { Finding, Risk } from "./types.js";
import { VERSION } from "./version.js";

const HELP = `prompt-sentry ${VERSION} — find prompt injection hidden in untrusted text

Usage: prompt-sentry [file] [options]      (reads stdin when no file is given)

Options:
  --json               machine-readable output
  --sanitize           print the cleaned text to stdout (report goes to stderr)
  --redact             with --sanitize, also replace instruction-like phrases
  --html / --no-html   force HTML mode on or off (default: auto)
  --allow a.com,b.org  domains that images and links may point to
  --fail-on LEVEL      exit 1 at this risk: low | medium | high (default) | never
  -v, --version        print the version
  -h, --help           show this help
`;

const RANK: Record<Risk | "never", number> = { none: 0, low: 1, medium: 2, high: 3, never: 99 };
const COLORS: Record<string, string> = { high: "31", medium: "33", low: "36" };

function position(text: string, index: number): string {
  const before = text.slice(0, index);
  const line = before.split("\n").length;
  return `${line}:${index - before.lastIndexOf("\n")}`;
}

function main(argv: string[]): number {
  const args = [...argv];
  const flag = (name: string) => {
    const i = args.indexOf(name);
    if (i >= 0) args.splice(i, 1);
    return i >= 0;
  };
  const option = (name: string) => {
    const i = args.indexOf(name);
    if (i < 0) return undefined;
    const value = args[i + 1];
    args.splice(i, 2);
    return value;
  };
  if (flag("-h") || flag("--help")) {
    process.stdout.write(HELP);
    return 0;
  }
  if (flag("-v") || flag("--version")) {
    process.stdout.write(VERSION + "\n");
    return 0;
  }
  const json = flag("--json");
  const doSanitize = flag("--sanitize");
  const redact = flag("--redact");
  const html = flag("--html") ? true : flag("--no-html") ? false : "auto";
  const allow = option("--allow")?.split(",").map((d) => d.trim()).filter(Boolean);
  const failOn = (option("--fail-on") ?? "high") as Risk | "never";
  if (!(failOn in RANK) || failOn === "none") {
    process.stderr.write(`invalid --fail-on value: ${failOn}\n`);
    return 2;
  }
  const file = args.find((a) => !a.startsWith("-"));
  const input = readFileSync(file ?? 0, "utf8");

  const options = { html, allowedDomains: allow, redactInstructions: redact } as const;
  const result = scan(input, options);
  const failed = RANK[result.risk] >= RANK[failOn];

  if (doSanitize) process.stdout.write(sanitize(input, options).text);
  const out = doSanitize ? process.stderr : process.stdout;

  if (json) {
    out.write(JSON.stringify(result, null, 2) + "\n");
    return failed ? 1 : 0;
  }
  const color = out.isTTY && !process.env.NO_COLOR;
  const paint = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const name = file ?? "stdin";
  out.write(
    `${paint("1", name)}: risk ${paint(COLORS[result.risk] ?? "32", result.risk.toUpperCase())} ` +
      `(score ${result.score}) — ${result.findings.length} finding(s)\n`,
  );
  for (const f of result.findings as Finding[]) {
    out.write(
      `  ${position(input, f.index).padEnd(8)} ${paint(COLORS[f.severity], f.severity.padEnd(6))} ` +
        `${f.type.padEnd(19)} ${f.message}\n`,
    );
    out.write(`  ${"".padEnd(8)} ${"".padEnd(6)} ${"".padEnd(19)} ${f.decoded ? "decoded: " + JSON.stringify(f.decoded.slice(0, 120)) : f.excerpt}\n`);
  }
  return failed ? 1 : 0;
}

process.exitCode = main(process.argv.slice(2));
