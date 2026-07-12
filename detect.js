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

module.exports = { detectObfuscator };
