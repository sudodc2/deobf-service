'use strict';
// Generic best-effort Lua/Luau deobfuscator.
//
// Runs when none of the 6 format-specific tools (Hercules, Ironveil, MoonSec,
// Prometheus, Moonveil, KarmaProtect) claim the input. It applies safe, static,
// source-preserving passes that work on ANY Lua and returns as much recovered
// source as possible without ever executing the untrusted script:
//   - string.char / string.byte alias + direct-call decoding
//   - \ddd and \xHH escape normalisation inside string literals
//   - integer arithmetic constant folding
//   - adjacent string-concatenation folding  ("a".."b" -> "ab")
//   - table.concat({...}) of literal arrays folding
//   - junk-statement removal (empty if/while/do blocks, dead `_` sinks)
//   - whitespace / block re-indentation (beautify)
//
// Unknown or dynamic constructs are left byte-for-byte intact — we never guess
// runtime behaviour. A luaparse pass is used only to VALIDATE that a rewrite did
// not break syntax; if a pass would produce invalid Lua it is rolled back.

const luaparse = require('luaparse');

// ── Sudo ownership detection ─────────────────────────────────────────────────
// The service must never be a tool for stripping our own protection system, so
// we refuse to deobfuscate anything the Sudo engine produced.
//
// Detection is two-layered so it can't be fooled by simply deleting the top
// comment (the previous bypass):
//   1) Visible markers — the branded header, invite, and _SUDO_ globals.
//   2) Structural fingerprints — invariant code shapes the engine ALWAYS emits
//      (anti-grab string-join decoder, base85 Horner decode, Z85 alphabet tail,
//      writefile-guard dump var). These survive removal of the comment/invite/
//      _SUDO_ names, and a build must match >= 2 of them to count as Sudo. They
//      were picked against real third-party obfuscators (WeAreDevs, MoonSec,
//      Prometheus, IY, etc.) so ordinary/foreign scripts score 0.
const SUDO_INVITE = 'discord.gg/ZyXAgmSVPA';
const SUDO_MARKERS = [
  /Protected by Sudo/i,
  /discord\.gg\/ZyXAgmSVPA/i,
  /_SUDO_[A-Z0-9_]/,
];

const SUDO_STRUCTURAL = [
  // anti-grab vararg string accumulator
  /function\(\.\.\.\)\s*local _a=\{\.\.\.\} local _r=""/,
  // its join loop
  /local _r="" for _z=1,#_a do _r=_r\.\./,
  // base85 Horner-form decode expression
  /\(\(\(_c1\*85\+_c2\)\*85\+_c3\)\*/,
  // Z85-style alphabet tail used by the opaque blob decoder
  /XYZ\.-:\+=\^!\/\*\?&<>\(\)\[\]\{\}@%/,
  // writefile-guard dump sentinel
  /if _wfDump/,
];

function sudoStructuralScore(src) {
  return SUDO_STRUCTURAL.reduce((n, re) => n + (re.test(src) ? 1 : 0), 0);
}

function isSudoOwned(src) {
  const head = src.slice(0, 8192);
  if (SUDO_MARKERS.some((re) => re.test(head) || re.test(src))) return true;
  // Marker-stripped Sudo output still carries its structural fingerprints.
  return sudoStructuralScore(src) >= 2;
}

// ── arithmetic evaluator (integers, + - * and parens only) ───────────────────
function evalArith(expr) {
  let i = 0;
  const s = expr;
  const skip = () => { while (i < s.length && /\s/.test(s[i])) i++; };
  function primary() {
    skip();
    if (s[i] === '(') { i++; const v = addsub(); skip(); if (s[i] !== ')') throw 0; i++; return v; }
    if (s[i] === '-') { i++; return -primary(); }
    if (s[i] === '+') { i++; return primary(); }
    const m = /^\d+/.exec(s.slice(i));
    if (!m) throw 0;
    i += m[0].length;
    return parseInt(m[0], 10);
  }
  function mul() { let v = primary(); for (;;) { skip(); if (s[i] === '*') { i++; v *= primary(); } else break; } return v; }
  function addsub() { let v = mul(); for (;;) { skip(); if (s[i] === '+') { i++; v += mul(); } else if (s[i] === '-') { i++; v -= mul(); } else break; } return v; }
  const r = addsub(); skip();
  if (i !== s.length) throw 0;
  return r;
}
const ARITH_ONLY = /^[\s\d+\-*()]+$/;

function toLuaString(str) {
  let out = '"';
  for (let k = 0; k < str.length; k++) {
    const c = str.charCodeAt(k);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else if (c < 32 || c > 126) out += '\\' + c;
    else out += str[k];
  }
  return out + '"';
}

function splitArgs(s) {
  const args = [];
  let depth = 0, br = 0, start = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (c === '(' ) depth++;
    else if (c === ')') depth--;
    else if (c === '{') br++;
    else if (c === '}') br--;
    else if (c === ',' && depth === 0 && br === 0) { args.push(s.slice(start, k)); start = k + 1; }
  }
  args.push(s.slice(start));
  return args.filter((a) => a.trim().length > 0);
}

function matchParen(src, open) {
  let depth = 0;
  for (let k = open; k < src.length; k++) {
    if (src[k] === '(') depth++;
    else if (src[k] === ')') { depth--; if (depth === 0) return k; }
  }
  return -1;
}
const isIdentChar = (c) => c && /[A-Za-z0-9_]/.test(c);

// Replace  name( numexpr, numexpr, ... )  -> decoded string, for a given callee
// spelling (`string.char`, or a local alias to it).
function decodeCharCalls(src, callee) {
  let out = '', idx = 0;
  while (idx < src.length) {
    const at = src.indexOf(callee, idx);
    if (at === -1) { out += src.slice(idx); break; }
    const before = at > 0 ? src[at - 1] : '';
    const afterPos = at + callee.length;
    let p = afterPos;
    while (p < src.length && /\s/.test(src[p])) p++;
    if (isIdentChar(before) || src[p] !== '(') { out += src.slice(idx, afterPos); idx = afterPos; continue; }
    const close = matchParen(src, p);
    if (close === -1) { out += src.slice(idx, afterPos); idx = afterPos; continue; }
    const inner = src.slice(p + 1, close);
    let decoded = null;
    try {
      const chars = splitArgs(inner).map((a) => {
        if (!ARITH_ONLY.test(a)) throw 0;
        const code = evalArith(a);
        if (code < 0 || code > 0x10ffff) throw 0;
        return code;
      });
      if (chars.length) decoded = String.fromCharCode(...chars);
    } catch (_) { decoded = null; }
    if (decoded === null) { out += src.slice(idx, afterPos); idx = afterPos; }
    else { out += src.slice(idx, at) + toLuaString(decoded); idx = close + 1; }
  }
  return out;
}

// Fold parenthesised integer arithmetic, keeping the parentheses so we never
// strip a function-call/index argument list:  f(1+2*3) -> f(7),  (1+2) -> (3).
// Only folds when there is at least one operator inside (so a bare (3) call is
// left untouched).
function foldArith(src) {
  const re = /\(\s*-?\d+(?:\s*[-+*]\s*-?\d+)+\s*\)/g;
  let prev = null, cur = src, guard = 0;
  while (prev !== cur && guard++ < 60) {
    prev = cur;
    cur = cur.replace(re, (m) => {
      const inner = m.slice(1, -1);
      try { return ARITH_ONLY.test(inner) ? '(' + String(evalArith(inner)) + ')' : m; } catch (_) { return m; }
    });
  }
  return cur;
}

// Normalise \ddd and \xHH escapes inside double/single quoted string literals to
// printable characters (leaves non-printables as escapes). Skips long-bracket
// strings and comments by only matching quoted literals.
function decodeStringEscapes(src) {
  const strRe = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g;
  return src.replace(strRe, (lit) => {
    const q = lit[0];
    const body = lit.slice(1, -1);
    if (!/\\(?:\d{1,3}|x[0-9a-fA-F]{2})/.test(body)) return lit;
    let decoded = '';
    for (let k = 0; k < body.length; k++) {
      if (body[k] === '\\') {
        const rest = body.slice(k + 1);
        let m;
        if ((m = /^x([0-9a-fA-F]{2})/.exec(rest))) { decoded += String.fromCharCode(parseInt(m[1], 16)); k += 1 + m[1].length; }
        else if ((m = /^(\d{1,3})/.exec(rest))) { decoded += String.fromCharCode(parseInt(m[1], 10) & 0xff); k += m[1].length; }
        else { decoded += body[k] + (body[k + 1] || ''); k += 1; }
      } else decoded += body[k];
    }
    const s = q === '"' ? toLuaString(decoded) : toLuaString(decoded);
    return s;
  });
}

// Fold adjacent string-literal concatenation:  "a".."b".."c" -> "abc"
function foldConcat(src) {
  const re = /("(?:\\.|[^"\\])*")\s*\.\.\s*("(?:\\.|[^"\\])*")/;
  let cur = src, guard = 0;
  while (re.test(cur) && guard++ < 500) {
    cur = cur.replace(re, (_, a, b) => {
      try { return toLuaString(JSON.parse(a) + JSON.parse(b)); } catch (_) { return _; }
    });
  }
  return cur;
}

// Fold  table.concat({ "a","b" })  and  table.concat({ "a","b" }, "-")  when all
// elements are string literals.
function foldTableConcat(src) {
  const re = /table\.concat\s*\(\s*\{([^{}]*)\}\s*(?:,\s*("(?:\\.|[^"\\])*")\s*)?\)/g;
  return src.replace(re, (whole, inner, sep) => {
    const parts = splitArgs(inner);
    if (!parts.length) return whole;
    let vals;
    try { vals = parts.map((p) => { const t = p.trim(); if (!/^"(?:\\.|[^"\\])*"$/.test(t)) throw 0; return JSON.parse(t); }); }
    catch (_) { return whole; }
    const glue = sep ? JSON.parse(sep) : '';
    return toLuaString(vals.join(glue));
  });
}

// Convert hexadecimal integer literals (0x1c, 0X6A, 0xFFp0-free) to decimal so
// the reconstructed source is easier to read. Skips anything inside string
// literals / comments and leaves hex floats (0x1p4) and hex with fractional or
// binary-exponent parts untouched.
function foldHexNumbers(src) {
  // token-aware scan so we never rewrite hex that appears inside a string
  const re = /("(?:\\.|[^"\\])*")|('(?:\\.|[^'\\])*')|(\[(=*)\[[\s\S]*?\]\4\])|(--\[(=*)\[[\s\S]*?\]\6\])|(--[^\n]*)|((?<![\w.])0[xX][0-9a-fA-F]+(?![\w.]))/g;
  return src.replace(re, (m, dq, sq, longstr, _l1, longcmt, _l2, linecmt, hex) => {
    if (!hex) return m; // strings/comments passed through verbatim
    const n = parseInt(hex, 16);
    if (!Number.isSafeInteger(n)) return m;
    return String(n);
  });
}

// Remove obviously-dead junk statements.
function stripJunk(src) {
  return src
    .replace(/\bif\s+false\s+then\b[\s\S]*?\bend\b/g, '')
    .replace(/\bwhile\s+false\s+do\b[\s\S]*?\bend\b/g, '')
    .replace(/\bif\s+(-?\d+)\s*==\s*(-?\d+)\s+then\s+end\s*;?/g, (m, a, b) => (a === b ? '' : m))
    .replace(/\blocal\s+_\s*=\s*-?\d+\s*;?/g, '')
    .replace(/\bdo\s+local\s+_\s*=\s*-?\d+\s+end\s*;?/g, '')
    .replace(/\bfor\s+_\s*=\s*-?\d+\s*,\s*-?\d+\s+do\s+end\s*;?/g, '');
}

function tidyAliases(src) {
  return src
    .replace(/rawget\s*\(\s*_G\s*,\s*"([A-Za-z_]\w*)"\s*\)/g, '$1')
    .replace(/(?:_G|getfenv\(\))\s*\[\s*"([A-Za-z_]\w*)"\s*\]/g, '$1')
    .replace(/string\s*\[\s*"([A-Za-z_]\w*)"\s*\]/g, 'string.$1')
    .replace(/table\s*\[\s*"([A-Za-z_]\w*)"\s*\]/g, 'table.$1');
}

// Replace every string literal and comment with an opaque placeholder so the
// line-splitting / indentation logic can never cut through the middle of a
// literal (which would silently corrupt the recovered source). Returns the
// masked text plus the table needed to restore the originals verbatim.
function maskLiterals(src) {
  const store = [];
  let out = '';
  let i = 0;
  const n = src.length;
  const stash = (text) => { const id = store.length; store.push(text); return '\u0000' + id + '\u0000'; };
  const longBracket = (start) => {
    // start points at '['; match [=*[ ... ]=*] ; return end index or -1.
    let j = start + 1; let eq = 0;
    while (src[j] === '=') { eq++; j++; }
    if (src[j] !== '[') return -1;
    const close = ']' + '='.repeat(eq) + ']';
    const end = src.indexOf(close, j + 1);
    return end === -1 ? n : end + close.length;
  };
  while (i < n) {
    const c = src[i];
    // comments
    if (c === '-' && src[i + 1] === '-') {
      if (src[i + 2] === '[') {
        const e = longBracket(i + 2);
        if (e !== -1 && /^\[=*\[/.test(src.slice(i + 2, i + 4 + 8))) { out += stash(src.slice(i, e)); i = e; continue; }
      }
      let e = src.indexOf('\n', i);
      if (e === -1) e = n;
      out += stash(src.slice(i, e));
      i = e;
      continue;
    }
    // long-bracket string
    if (c === '[' && (src[i + 1] === '[' || src[i + 1] === '=')) {
      const e = longBracket(i);
      if (e !== -1) { out += stash(src.slice(i, e)); i = e; continue; }
    }
    // quoted string
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === c) { j++; break; }
        if (src[j] === '\n') break;
        j++;
      }
      out += stash(src.slice(i, j));
      i = j;
      continue;
    }
    out += c;
    i++;
  }
  return { masked: out, store };
}

function restoreLiterals(text, store) {
  return text.replace(/\u0000(\d+)\u0000/g, (_, id) => store[Number(id)]);
}

// Token/keyword-aware re-indenter. Operates only on masked code so it never
// touches the contents of strings or comments.
function beautify(src) {
  const { masked, store } = maskLiterals(src.replace(/\r/g, ''));
  let s = masked
    .replace(/[ \t]+/g, ' ')
    .replace(/\s*;\s*/g, ';\n')
    .replace(/([^\s])\s+(local\s)/g, '$1\n$2')
    .replace(/([^\s])\s+(return\b)/g, '$1\n$2')
    .replace(/\bthen\b/g, 'then\n')
    .replace(/\bdo\b/g, 'do\n')
    .replace(/\brepeat\b/g, 'repeat\n')
    .replace(/\belse\b/g, '\nelse\n')
    .replace(/\belseif\b/g, '\nelseif ')
    .replace(/\bend\b/g, '\nend\n')
    .replace(/\buntil\b/g, '\nuntil ');
  const lines = s.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
  let indent = 0;
  const out = [];
  for (const line of lines) {
    const dedent = /^(end|else|elseif|until|\}|\))/.test(line);
    if (dedent && indent > 0) indent--;
    out.push('  '.repeat(Math.max(indent, 0)) + line);
    const opens = /(\bthen|\bdo|\brepeat)$/.test(line)
      || /\bfunction\b[^)]*\)\s*$/.test(line)
      || /^else$/.test(line)
      || /^elseif\b.*then$/.test(line);
    if (opens) indent++;
  }
  return restoreLiterals(out.join('\n'), store);
}

// Validate that a candidate rewrite still parses; if not, keep the previous text.
function safePass(before, fn, label, notes) {
  let after;
  try { after = fn(before); } catch (_) { return before; }
  if (after === before) return before;
  try {
    luaparse.parse(after, { luaVersion: '5.1', comments: false });
  } catch (_) {
    // rewrite broke syntax (input may not be valid Lua either) — accept only if
    // the input itself did not parse, otherwise roll back.
    let inputOk = true;
    try { luaparse.parse(before, { luaVersion: '5.1', comments: false }); } catch (_) { inputOk = false; }
    if (inputOk) return before;
  }
  notes.push(label);
  return after;
}

function deobfuscate(src) {
  if (isSudoOwned(src)) {
    return {
      output: null,
      refused: true,
      notes: [
        'This script is protected by the Sudo obfuscation system (ownership marker detected).',
        'Deobfuscation is intentionally disabled for our own protection engine.',
      ],
    };
  }

  const notes = ['Generic best-effort pass (no exact format match) — static analysis only, dynamic code preserved.'];
  let s = src;

  // string.char alias(es):  local X = string.char
  const aliasRe = /local\s+(\w+)\s*=\s*string\.char\b/g;
  const aliases = [];
  let am;
  while ((am = aliasRe.exec(s))) aliases.push(am[1]);
  for (const a of aliases) s = safePass(s, (x) => decodeCharCalls(x, a), `Decoded string.char alias "${a}".`, notes);
  s = safePass(s, (x) => decodeCharCalls(x, 'string.char'), 'Decoded direct string.char(...) calls.', notes);

  s = safePass(s, decodeStringEscapes, 'Normalised \\ddd / \\xHH string escapes.', notes);
  s = safePass(s, foldConcat, 'Folded adjacent string concatenation.', notes);
  s = safePass(s, foldTableConcat, 'Folded table.concat of literal arrays.', notes);
  s = safePass(s, foldArith, 'Folded integer arithmetic constants.', notes);
  s = safePass(s, foldHexNumbers, 'Converted hexadecimal literals to decimal.', notes);
  s = safePass(s, tidyAliases, 'Resolved _G / string / table index aliases.', notes);
  s = safePass(s, stripJunk, 'Removed dead junk statements.', notes);

  const output = beautify(s).trim() + '\n';
  notes.push('NOTE: Best-effort static recovery. Variable names randomised by the obfuscator cannot be restored, and any runtime/VM-decoded logic that is not statically present is left as-is.');
  return { output, notes };
}

// Build a raw "dump" of everything the recovery pulled out of a script:
// every decoded string literal and every numeric constant, de-duplicated and
// listed. Useful when full source can't be reconstructed but the decoded
// strings/constants (URLs, webhooks, config, keys) are still valuable.
function buildDump(src) {
  if (!src || typeof src !== 'string') return '';
  const { masked, store } = maskLiterals(src);
  const strings = [];
  const seenStr = new Set();
  for (const lit of store) {
    const q = lit[0];
    if (q !== '"' && q !== "'" && !lit.startsWith('[[') && !lit.startsWith('[=')) continue;
    // skip long-bracket comments; keep string literals
    let val = lit;
    if (q === '"' || q === "'") val = lit.slice(1, -1);
    else {
      const m = /^\[(=*)\[([\s\S]*)\]\1\]$/.exec(lit);
      if (!m) continue;
      val = m[2];
    }
    if (val.length === 0) continue;
    if (seenStr.has(val)) continue;
    seenStr.add(val);
    strings.push(val);
  }

  const numbers = [];
  const seenNum = new Set();
  const numRe = /-?\b\d+(?:\.\d+)?\b/g;
  let nm;
  while ((nm = numRe.exec(masked))) {
    const n = nm[0];
    if (seenNum.has(n)) continue;
    seenNum.add(n);
    numbers.push(n);
    if (numbers.length > 5000) break;
  }

  const lines = [];
  lines.push('-- Sudo Deobfuscator — raw decoded dump');
  lines.push('-- https://discord.gg/ZyXAgmSVPA');
  lines.push('-- Every decoded string + numeric constant the deobfuscator recovered.');
  lines.push('-- (Use this when full source cannot be reconstructed.)');
  lines.push('');
  lines.push('-- ===== Decoded strings (' + strings.length + ') =====');
  strings.forEach((s, i) => { lines.push('[' + (i + 1) + '] ' + toLuaString(s)); });
  lines.push('');
  lines.push('-- ===== Numeric constants (' + numbers.length + ') =====');
  numbers.forEach((n, i) => { lines.push('[' + (i + 1) + '] ' + n); });
  lines.push('');
  return lines.join('\n');
}

module.exports = {
  deobfuscate,
  buildDump,
  isSudoOwned,
  sudoStructuralScore,
  evalArith,
  decodeCharCalls,
  decodeStringEscapes,
  foldConcat,
  foldTableConcat,
  foldArith,
  foldHexNumbers,
  stripJunk,
  SUDO_INVITE,
};
