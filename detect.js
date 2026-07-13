'use strict';
// Obfuscator detection — scoped to the 5 supported obfuscators.

const KNOWN = [
  {
    name: 'Hercules',
    marks: [/Obfuscated by Hercules/i, /hercules-obfuscator\.xyz/i],
    struct: [/_ENV\s*\)\s*\(\s*\)/, /getfenv/],
  },
  {
    name: 'Ironveil',
    marks: [/Obfuscated using ironveil/i, /ironveil\b/i],
    struct: [/return\(function\(\.\.\.\)return\(function\(\.\.\.\)/],
  },
  {
    name: 'Prometheus',
    marks: [/Prometheus Obfuscator by levno-710/i, /This Script is Part of the Prometheus/i, /__prometheus_/, /_WATERMARK/],
    // ConstantArray rotate/shuffle decoder + WrapInFunction shell — survives
    // variable renaming, so it fingerprints even a "Weak" build.
    struct: [/return\(function\(\.\.\.\)/, /for \w+,\w+ in ipairs\(\{\{\d/],
  },
  {
    name: 'MoonSec',
    marks: [/moonsec/i, /moonsec\.(to|com|net)/i, /MoonSecV?\s*3/i],
    struct: [/return\s*\(?function\(\.\.\.\)/, /(\\\d{1,3}){40,}/],
  },
  {
    name: 'Moonveil',
    marks: [/moonveil/i],
    struct: [/function\s+\w+\([\w,]{3,20}\)/, /\w+\[\d{4,5}\]/],
  },
  {
    name: 'Kers0ne',
    marks: [/Protected By Kers0ne Obfuscator/i, /Base66 Multi-?XOR/i],
    // the base66 pair decoder `(a-1)*66+(b-1)` is unique enough on its own to
    // fingerprint the format even without the header comment.
    struct: [/\(\s*_?\w+\s*-\s*1\s*\)\s*\*\s*66\s*\+\s*\(\s*_?\w+\s*-\s*1\s*\)/],
  },
  {
    name: 'Luraph',
    // Luraph is the strongest commercial Lua obfuscator. Watermark comment
    // (`Luraph Obfuscator vX` / lura.ph) plus its `LPH!`/`LPH|` bytecode blob
    // markers. Full source recovery is not statically achievable — routed to
    // best-effort recovery.
    marks: [/Luraph Obfuscator/i, /lura\.ph/i, /LPH_?(NO_VIRTUALIZE|JIT|ENCFUNC)/],
    struct: [/return\s*\(\s*\{/, /LPH[!|]/],
  },
  {
    name: 'KarmaVM',
    // "Karma Obfuscator [luarmor-bot...]" — a runtime register-VM (distinct
    // from KarmaProtect's static string transforms). Its constant-fetch table
    // `o.h`/`L[...]` register model + luarmor-bot host fingerprint it.
    marks: [/Karma Obfuscator/i, /luarmor-bot/i],
    struct: [/return\s*\(\s*\{\s*\w+\s*=\s*function\s*\(/, /\bL\[\d{3,5}\]/],
  },
  {
    name: 'Voltils',
    // Voltils (voltils.cc/load/<slug>/run) — a key-system-gated loader delivered
    // from behind a Cloudflare managed challenge. The loadstring host + `/load/…/run`
    // route are the reliable fingerprint; the real script is served only to a keyed,
    // verified executor session.
    marks: [/voltils\.cc/i, /Voltils Obfuscation v[\d.]+/i, /dsc\.gg\/Voltils/i, /\bvoltils\b/i],
    // Body fingerprints: the `__voltils_<rand>` global the header installs, and the
    // loadstring `/load/<slug>/run` route. Either raises confidence past threshold.
    struct: [/__voltils_[A-Za-z0-9]+/, /voltils\.cc\/load\/[A-Za-z0-9_-]+\/run/i],
  },
  {
    name: 'Syscure',
    // Syscure (auth.syscure.vip / syscure.vip) delivers its obfuscated payload
    // from a `/obf/<hash>.lua` endpoint that sits behind a Cloudflare anti-bot
    // challenge, so the loadstring host is the reliable fingerprint. The payload
    // itself (when a raw body is submitted) is a Luau method-table VM similar to
    // the Luraph family — routed to best-effort recovery.
    marks: [/syscure\.vip/i, /\bsyscure\b/i],
    struct: [/\/obf\/[0-9a-f]{16,}\.lua/i],
  },
  {
    name: 'Pew',
    // Pew v1 (ex-Luraph dev). No watermark — it's a control-flow-flattened
    // register VM emitted as one line: `return(function(<many 2-char params>,...)`
    // followed by a `while(<var>)do if((<var>)<=(<num>))then …` numeric state
    // dispatch with deeply nested comparisons and uppercase hex (`0XB`) literals.
    // Structural-only fingerprint; routed to best-effort recovery (it's a VM).
    marks: [/\bPew\s+Obfuscator\b/i],
    struct: [
      /^return\s*\(\s*function\s*\(\s*(?:[A-Za-z]{2}\s*,\s*){30,}\.\.\.\s*\)/,
      /while\s*\(\s*\w{2}\s*\)\s*do\s+if\s*\(\s*\(\s*\w{2}\s*\)\s*<=\s*\(\s*\d/,
    ],
  },
  {
    name: 'KarmaProtect',
    marks: [/Protected By Karma Lua Hosting/i, /--\[\[karma:\d+\]\]/, /karma-lua-hosting/i],
    // return(function(...) ... end)(...) shell + the string.char/byte alias
    // preamble it always emits — survives every option toggle.
    struct: [
      /return\s*\(\s*function\s*\(\s*\.\.\.\s*\)/,
      /local\s+\w+\s*=\s*string\.char\s*;\s*local\s+\w+\s*=\s*string\.byte/,
    ],
  },
];

// Structural Luraph fingerprint (survives watermark removal — e.g. onyxv2 which
// replaces the `-- Luraph Obfuscator vX` comment with an ASCII banner). Luraph
// v13/v14 emits a method-table VM: `return({ <k>=function(self,...) ... })` that
// is immediately invoked via a `}):<ident>()(...)` tail, uses bit32.* ops, and
// packs constants as obfuscated hex/binary literals (often with `_` separators).
function looksLikeLuraph(src) {
  let score = 0;
  if (/return\s*\(\s*\{\s*[A-Za-z_]\w*\s*=\s*function\s*\(/.test(src.slice(0, 4000))) score += 3;
  if (/\}\s*\)\s*:\s*[A-Za-z_]\w*\s*\(\s*\)\s*\(\s*\.\.\.\s*\)\s*;?\s*$/.test(src.trimEnd())) score += 4;
  if (/\bbit32\.(band|bor|bxor|bnot|lshift|rshift|lrotate|rrotate|countlz|countrz)\b/.test(src)) score += 2;
  if (/0[xX][0-9a-fA-F]+_|0[bB][01]+_/.test(src)) score += 1; // Luau `_` digit separators
  // many single/double-char method keys mapping to functions (VM opcode handlers)
  const handlers = (src.slice(0, 20000).match(/[,{]\s*[A-Za-z_]\w?\s*=\s*function\s*\(/g) || []).length;
  if (handlers >= 8) score += 2;
  return score;
}

function detectObfuscator(src) {
  const head = src.slice(0, 4096);
  let best = { name: null, confidence: 0, signals: [] };
  for (const o of KNOWN) {
    const signals = [];
    let score = 0;
    for (const re of o.marks) {
      if (re.test(head) || re.test(src)) { score += 60; signals.push('watermark'); break; }
    }
    let hits = 0;
    for (const re of o.struct) if (re.test(src)) hits++;
    if (o.struct.length && hits === o.struct.length) { score += 35; signals.push(`structure x${hits}`); }
    else if (hits) { score += 15 * hits; signals.push(`partial x${hits}`); }
    if (score > best.confidence) best = { name: o.name, confidence: Math.min(99, score), signals };
  }
  return best.name ? best : { name: null, confidence: 0, signals: [] };
}

module.exports = { detectObfuscator, looksLikeLuraph };
