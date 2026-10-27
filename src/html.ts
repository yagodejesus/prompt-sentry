export interface HtmlRegion {
  start: number;
  end: number;
  kind: "hidden" | "comment" | "nonrendered";
  reason: string;
  inner: string;
}

export interface HtmlAttribute {
  name: string;
  value: string;
  /** Offsets of the value (without quotes) in the input. */
  start: number;
  end: number;
}

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
const RAWTEXT = new Set(["script", "style", "textarea", "title"]);
const NONRENDERED = new Set(["script", "style", "template", "noscript"]);
const TOKEN = /<!--[\s\S]*?(?:-->|$)|<(\/?)([a-zA-Z][\w:-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
const ATTRIBUTE = /([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
const TEXT_ATTRIBUTES = /^(?:alt|title|aria-label|aria-description|content|value|placeholder|summary|data-[\w.-]+)$/i;

const HIDING: Array<[RegExp, string]> = [
  [/display\s*:\s*none/i, "display:none"],
  [/visibility\s*:\s*(?:hidden|collapse)/i, "visibility:hidden"],
  [/(?:^|[;\s])opacity\s*:\s*0*(?:\.0+)?\s*(?:;|$|!)/i, "opacity:0"],
  [/font-size\s*:\s*0*(?:\.0+)?\s*(?:px|em|rem|pt|%)?\s*(?:;|$|!)/i, "font-size:0"],
  [/(?:left|top|right|text-indent|margin-left|margin-top)\s*:\s*-\d{3,}(?:\.\d+)?(?:px|em|rem)?\s*(?:;|$|!)/i, "off-screen position"],
  [/(?:^|[;\s])color\s*:\s*(?:transparent|rgba\([^)]*,\s*0(?:\.0+)?\s*\))/i, "transparent text"],
  [/clip\s*:\s*rect\(\s*0/i, "clip:rect(0…)"],
  [/transform\s*:\s*scale\(\s*0(?:\.0+)?\s*\)/i, "scale(0)"],
  [/(?:^|[;\s])color\s*:\s*(?:#fff(?:fff)?|white)\b/i, "white text"],
];

export function looksLikeHtml(text: string): boolean {
  return /<\/[a-zA-Z][\w:-]*\s*>|<(?:br|img|meta|input|hr|div|span|p|a)\b[^<>]*>|<!--/i.test(text);
}

function hiddenReason(attrs: string): string | null {
  const style = /\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
  if (style) {
    const css = style[1] ?? style[2] ?? style[3] ?? "";
    for (const [re, reason] of HIDING) if (re.test(css)) return reason;
  }
  if (/(?:^|\s)hidden(?=\s|=|\/|$)/i.test(attrs)) return "hidden attribute";
  if (/\baria-hidden\s*=\s*["']?true/i.test(attrs)) return "aria-hidden";
  return null;
}

export function innerText(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

interface Open {
  name: string;
  start: number;
  contentStart: number;
  reason: string | null;
  kind: HtmlRegion["kind"];
}

/** Finds content a browser would not show: hidden elements, comments, scripts — plus text attributes. */
export function scanHtml(text: string): { regions: HtmlRegion[]; attributes: HtmlAttribute[] } {
  const regions: HtmlRegion[] = [];
  const attributes: HtmlAttribute[] = [];
  const stack: Open[] = [];
  const insideHidden = () => stack.some((o) => o.reason);
  const close = (o: Open, end: number, innerEnd: number) => {
    if (o.reason && !insideHidden()) {
      regions.push({ start: o.start, end, kind: o.kind, reason: o.reason, inner: text.slice(o.contentStart, innerEnd) });
    }
  };

  TOKEN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TOKEN.exec(text))) {
    const [whole, slash, rawName, attrs] = m;
    const start = m.index;
    const end = start + whole.length;
    if (whole.startsWith("<!--")) {
      if (!insideHidden()) {
        const inner = whole.slice(4, whole.endsWith("-->") ? -3 : undefined);
        regions.push({ start, end, kind: "comment", reason: "an HTML comment", inner });
      }
      continue;
    }
    const name = rawName.toLowerCase();
    if (slash) {
      let j = stack.length - 1;
      while (j >= 0 && stack[j].name !== name) j--;
      if (j < 0) continue; // stray closing tag
      while (stack.length > j) {
        const o = stack.pop()!;
        close(o, end, start);
      }
      continue;
    }

    const attrsStart = start + 1 + rawName.length;
    for (const a of (attrs ?? "").matchAll(ATTRIBUTE)) {
      if (!TEXT_ATTRIBUTES.test(a[1])) continue;
      const value = a[2] ?? a[3] ?? a[4] ?? "";
      const valueStart = attrsStart + a.index! + a[0].length - value.length - (a[4] === undefined ? 1 : 0);
      attributes.push({ name: a[1].toLowerCase(), value, start: valueStart, end: valueStart + value.length });
    }

    const selfClosing = VOID.has(name) || /\/\s*$/.test(attrs ?? "");
    if (selfClosing) continue;
    const reason = NONRENDERED.has(name) ? `<${name}>` : hiddenReason(attrs ?? "");
    const kind: HtmlRegion["kind"] = NONRENDERED.has(name) ? "nonrendered" : "hidden";

    if (RAWTEXT.has(name)) {
      const closer = new RegExp(`</${name}\\s*>`, "gi");
      closer.lastIndex = end;
      const c = closer.exec(text);
      const closeEnd = c ? c.index + c[0].length : text.length;
      close({ name, start, contentStart: end, reason, kind }, closeEnd, c ? c.index : text.length);
      TOKEN.lastIndex = closeEnd;
      continue;
    }
    stack.push({ name, start, contentStart: end, reason, kind });
  }
  while (stack.length) {
    const o = stack.pop()!;
    close(o, text.length, text.length);
  }
  return { regions, attributes };
}
