import type { FindingType, Severity } from "./types.js";
import { normalizeForMatching } from "./unicode.js";

export interface Pattern {
  id: string;
  type: FindingType;
  severity: Severity;
  message: string;
  re: RegExp;
}

// JavaScript's \b only understands ASCII; this boundary also works next to "é", "ç", "ã"…
const W = "[\\p{L}\\p{N}_]";
const BOUNDARY = `(?:(?<=${W})(?!${W})|(?<!${W})(?=${W}))`;

function rule(id: string, type: FindingType, severity: Severity, message: string, re: RegExp): Pattern {
  return { id, type, severity, message, re: new RegExp(re.source.replace(/\\b/g, BOUNDARY), "gmu") };
}

const MSG = {
  ignore: "Tries to override the previous instructions",
  fresh: "Announces new instructions",
  reveal: "Asks to reveal the system prompt or hidden instructions",
  conceal: "Asks to hide something from the user",
  send: "Asks to send data to an external address",
  role: "Tries to change the assistant's role or behaviour",
  authority: "Claims to come from the system, the developer or an administrator",
  addresses: "Speaks directly to an AI reading the content",
  jailbreak: "Uses jailbreak phrasing",
};

export const PATTERNS: Pattern[] = [
  // ---------------------------------------------------------------- English
  rule("ignore-previous", "instruction", "high", MSG.ignore,
    /\b(?:ignore|disregard|forget|override|bypass|skip|drop)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|initial|original|system|all|any|your|the)\b[^.\n]{0,30}?\b(?:instructions?|prompts?|rules?|directions?|guidelines?|context|messages?|commands?|guardrails?)\b/),
  rule("new-instructions", "instruction", "high", MSG.fresh,
    /\b(?:new|updated|real|actual|true|revised|additional|secret|important)\s+(?:system\s+)?(?:instructions?|prompt|directives?|task|objective|orders?)\s*[:\-—]/),
  rule("reveal-prompt", "instruction", "high", MSG.reveal,
    /\b(?:reveal|print|show|output|repeat|leak|display|dump|tell me)\b[^.\n]{0,30}?(?:system prompt|your (?:instructions|rules|prompt)|hidden (?:prompt|instructions)|initial prompt|developer (?:message|prompt))/),
  rule("conceal-from-user", "instruction", "high", MSG.conceal,
    /\b(?:do not|don't|dont|never|without)\b[^.\n]{0,25}?\b(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|alert(?:ing)?|notify(?:ing)?|let)\b[^.\n]{0,20}?\b(?:user|human|operator|owner)s?\b/),
  rule("send-data", "instruction", "high", MSG.send,
    /\b(?:send|post|forward|upload|exfiltrate|e-?mail|transmit|submit|leak)\b[^.\n]{0,60}?\b(?:to|at|into)\b\s*(?:https?:\/\/|www\.|[\w.+-]+@[\w-]+\.)/),
  rule("role-override", "instruction", "medium", MSG.role,
    /\b(?:you are now|from now on,? you|you must now|act as (?:an?|the)|pretend (?:to be|you are)|roleplay as|switch to [^.\n]{0,15}mode)\b/),
  rule("authority-claim", "instruction", "medium", MSG.authority,
    /\b(?:this is|message from|note from|instructions? from|update from)\s+(?:the\s+|your\s+)?(?:system|developer|admin(?:istrator)?|openai|anthropic|google|security team|it department)\b/),
  rule("addresses-ai", "instruction", "medium", MSG.addresses,
    /\b(?:if you are|as|dear|attention|note to|hey)\s+(?:an?\s+)?(?:ai|llm|language model|ai assistant|chatbot|ai agent|gpt|chatgpt|claude|gemini|copilot)\b/),
  rule("ai-reading-this", "instruction", "medium", MSG.addresses,
    /\b(?:ai|llm|language model|assistant|agent|chatbot|model)s?\b[^.\n]{0,30}?\b(?:reading|processing|summari[sz]ing|analy[sz]ing|browsing)\s+this\b/),
  rule("jailbreak", "instruction", "medium", MSG.jailbreak,
    /\b(?:developer mode|dan mode|do anything now|jailbroken|no restrictions|without (?:any )?restrictions|unfiltered mode)\b/),
  // ------------------------------------------------------------- Portuguese
  rule("ignore-previous-pt", "instruction", "high", MSG.ignore,
    /\b(?:ignore|ignora|ignorar|desconsidere|desconsidera|desconsiderar|esqueça|esqueca|esquece|esquecer|descarte|despreze)\b[^.\n]{0,40}?\b(?:instruções|instrucoes|instrução|instrucao|orientações|orientacoes|regras|ordens|comandos|mensagens|diretrizes|prompt)\b/),
  rule("new-instructions-pt", "instruction", "high", MSG.fresh,
    /\b(?:novas?|verdadeiras?|reais|atualizadas?|importantes?)\s+(?:instruções|instrucoes|instrução|instrucao|ordens|tarefas?|diretrizes)(?:\s+do sistema)?\s*[:\-—]/),
  rule("reveal-prompt-pt", "instruction", "high", MSG.reveal,
    /\b(?:revele|mostre|exiba|imprima|repita|vaze)\b[^.\n]{0,30}?(?:prompt do sistema|prompt de sistema|suas instruções|suas instrucoes|instruções ocultas|instrucoes ocultas|prompt inicial)/),
  rule("conceal-from-user-pt", "instruction", "high", MSG.conceal,
    /\b(?:não|nao|nunca|sem)\b[^.\n]{0,25}?\b(?:conte|contar|diga|dizer|informe|informar|mencione|mencionar|revele|revelar|avise|avisar)\b[^.\n]{0,20}?\b(?:usuário|usuario|usuária|usuaria|humano|cliente)s?\b/),
  rule("send-data-pt", "instruction", "high", MSG.send,
    /\b(?:envie|enviar|mande|mandar|encaminhe|encaminhar|transmita|poste|publique)\b[^.\n]{0,60}?\b(?:para|a|ao)\b\s*(?:https?:\/\/|www\.|[\w.+-]+@[\w-]+\.)/),
  rule("role-override-pt", "instruction", "medium", MSG.role,
    /\b(?:a partir de agora,? (?:você|voce)|(?:você|voce) agora (?:é|e)|finja (?:ser|que)|aja como|atue como|comporte-se como)\b/),
  // ---------------------------------------------------------------- Spanish
  rule("ignore-previous-es", "instruction", "high", MSG.ignore,
    /\b(?:ignora|ignore|olvida|olvide|descarta|omite)\b[^.\n]{0,40}?\b(?:instrucciones|indicaciones|reglas|órdenes|ordenes)\b/),
  rule("role-override-es", "instruction", "medium", MSG.role,
    /\b(?:a partir de ahora,? (?:eres|tú|tu)|ahora eres|actúa como|actua como|finge ser)\b/),
  rule("conceal-from-user-es", "instruction", "high", MSG.conceal,
    /\bno\b[^.\n]{0,20}?\b(?:le\s+)?(?:digas|cuentes|informes|menciones|reveles)\b[^.\n]{0,20}?\busuario\b/),
  // ------------------------------------------------------- chat-template tokens
  rule("chat-template-token", "role-marker", "high", "Chat-template control token in content",
    /<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id)\|>|\[\/?inst\]|<<\/?sys>>/),
  rule("fake-role-tag", "role-marker", "medium", "Fake system/assistant role marker",
    /<\/?(?:system|assistant|instructions?|admin)>|^\s*#{1,4}\s*(?:system|instructions?)\b|^\s*(?:system|assistant)\s*:/),
];

export interface PatternMatch {
  pattern: Pattern;
  start: number;
  end: number;
}

/** Runs every pattern on a normalized copy of `text` (homoglyphs, invisible chars and leetspeak folded). */
export function matchPatterns(text: string): PatternMatch[] {
  const results: PatternMatch[] = [];
  const seen = new Set<string>();
  for (const leet of [false, true]) {
    const n = normalizeForMatching(text, leet);
    for (const pattern of PATTERNS) {
      for (const m of n.text.matchAll(pattern.re)) {
        const s = m.index!;
        const e = s + m[0].length;
        if (e === s) continue;
        const start = n.map[s];
        const last = n.map[e - 1];
        const end = last + (text.codePointAt(last)! > 0xffff ? 2 : 1);
        const key = `${pattern.id}:${start}`;
        if (seen.has(key)) continue;
        seen.add(key);
        results.push({ pattern, start, end });
      }
    }
  }
  return results;
}
