export type Severity = "low" | "medium" | "high";
export type Risk = "none" | Severity;

export type FindingType =
  | "unicode-tags"
  | "variation-selectors"
  | "zero-width"
  | "bidi-control"
  | "mixed-script"
  | "instruction"
  | "role-marker"
  | "hidden-html"
  | "html-comment"
  | "hidden-attribute"
  | "exfiltration"
  | "encoded-payload";

export interface Finding {
  type: FindingType;
  severity: Severity;
  /** Human-readable explanation. */
  message: string;
  /** UTF-16 offset in the scanned input. */
  index: number;
  /** Length (UTF-16 code units) of the offending span. */
  length: number;
  /** Short, printable excerpt (invisible characters shown as ⟨U+XXXX⟩). */
  excerpt: string;
  /** Text revealed by decoding hidden characters or an encoded payload. */
  decoded?: string;
  /** Pattern id for instruction findings (e.g. "ignore-previous"). */
  rule?: string;
  /** URL involved in an exfiltration finding. */
  url?: string;
}

export interface ScanOptions {
  /** Treat the input as HTML. Default "auto" (detected from the content). */
  html?: boolean | "auto";
  /** Domains that images and links may point to (subdomains included). */
  allowedDomains?: string[];
  /** Decode long base64 strings and look for instructions inside. Default true. */
  decodeBase64?: boolean;
}

export interface ScanResult {
  /** Highest severity found, or "none". */
  risk: Risk;
  /** 0–100: high = 40, medium = 15, low = 3 points each. */
  score: number;
  findings: Finding[];
}

export interface SanitizeOptions extends ScanOptions {
  /** Remove hidden HTML elements, <script>/<style>/<template> and comments. Default true. */
  removeHiddenHtml?: boolean;
  /** Replace images/links that carry data to unknown domains. Default true. */
  stripExfiltration?: boolean;
  /** Replace instruction-like phrases with `replacement`. Default false (they are only reported). */
  redactInstructions?: boolean;
  /** Text used for redactions. */
  replacement?: string;
  /** Apply Unicode NFKC normalisation to the output (folds full-width and other look-alikes). Default false. */
  normalize?: boolean;
}

export interface SanitizeResult {
  text: string;
  changed: boolean;
  /** Findings of the scan performed on the original input. */
  findings: Finding[];
  risk: Risk;
}
