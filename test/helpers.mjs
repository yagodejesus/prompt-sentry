/** Hide ASCII text in Unicode tag characters (U+E0000 block). */
export const tags = (s) => [...s].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");

/** Hide UTF-8 bytes in variation selectors after a visible character. */
export const selectors = (s) =>
  [...new TextEncoder().encode(s)]
    .map((b) => String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + b - 16))
    .join("");

export const types = (result) => result.findings.map((f) => f.type);
