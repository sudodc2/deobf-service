'use strict';
// KarmaProtect (karma-lua-hosting.lovable.app) deobfuscator.
//
// KarmaProtect is a purely static string-transform obfuscator (no runtime VM),
// so its transforms are fully reversible except variable renaming (one-way).
// Reference: their in-browser bundle assets/obfuscator-*.js. Transforms:
//   - wrapper:      return(function(...) <PREAMBLE> <BODY> end)(...)
//   - preamble:     local A=string.char;local B=string.byte; + rawget aliases
//   - encryptStr:   "str"           -> A(<numexpr>,<numexpr>,...)      (A=string.char)
//   - encodeConst:  <number>        -> <numexpr>  (arithmetic on integer literals)
//   - junkCode:     local _=N; / if N==M then end; / for _=N,M do end; / do local _=N end;
//   - controlFlow:  local P=pcall;P(function() <body> end);
//   - antiFormat:   comments stripped, whitespace collapsed to single spaces
//   - antiTamper:   trailing  --[[karma:<checksum>]]   (sum of charCodes % 1000003)

// ── arithmetic evaluator for the number-expression grammar ──────────────────
// Only integers with + - * and parentheses appear in generated numexprs.
function evalArith(expr) {
  let i = 0;
  const s = expr;
  function skip() { while (i < s.length && /\s/.test(s[i])) i++; }
  function parsePrimary() {
    skip();
    if (s[i] === '(') {
      i++;
      const v = parseAddSub();
      skip();
      if (s[i] !== ')') throw new Error('unbalanced');
      i++;
      return v;
    }
    if (s[i] === '-') { i++; return -parsePrimary(); }
    if (s[i] === '+') { i++; return parsePrimary(); }
    const m = /^\d+/.exec(s.slice(i));
    if (!m) throw new Error('not a number at ' + i);
    i += m[0].length;
    return parseInt(m[0], 10);
  }
  function parseMul() {
    let v = parsePrimary();
    for (;;) {
      skip();
      if (s[i] === '*') { i++; v *= parsePrimary(); }
      else break;
    }
    return v;
  }
  function parseAddSub() {
    let v = parseMul();
    for (;;) {
      skip();
      if (s[i] === '+') { i++; v += parseMul(); }
      else if (s[i] === '-') { i++; v -= parseMul(); }
      else break;
    }
    return v;
  }
  const r = parseAddSub();
  skip();
  if (i !== s.length) throw new Error('trailing input');
  return r;
}

const ARITH_ONLY = /^[\s\d+\-*()]+$/;

// Encode a JS string as a Lua double-quoted literal.
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

// Split a call's argument list on top-level commas.
function splitArgs(s) {
  const args = [];
  let depth = 0, start = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === ',' && depth === 0) { args.push(s.slice(start, k)); start = k + 1; }
  }
  args.push(s.slice(start));
  return args.filter((a) => a.trim().length > 0);
}

// Find the matching ')' for the '(' at position `open`.
function matchParen(src, open) {
  let depth = 0;
  for (let k = open; k < src.length; k++) {
    if (src[k] === '(') depth++;
    else if (src[k] === ')') { depth--; if (depth === 0) return k; }
  }
  return -1;
}

function isIdentChar(c) { return c && /[A-Za-z0-9_]/.test(c); }

// Replace every  alias( numexpr, numexpr, ... )  with the decoded Lua string.
function decodeCharCalls(src, alias) {
  const needle = alias;
  let out = '';
  let idx = 0;
  while (idx < src.length) {
    const at = src.indexOf(needle, idx);
    if (at === -1) { out += src.slice(idx); break; }
    const before = at > 0 ? src[at - 1] : '';
    const afterPos = at + needle.length;
    const after = src[afterPos];
    // must be a standalone identifier immediately followed by '('
    if (isIdentChar(before) || after !== '(') {
      out += src.slice(idx, afterPos);
      idx = afterPos;
      continue;
    }
    const close = matchParen(src, afterPos);
    if (close === -1) { out += src.slice(idx, afterPos); idx = afterPos; continue; }
    const inner = src.slice(afterPos + 1, close);
    let decoded = null;
    try {
      const parts = splitArgs(inner);
      const chars = parts.map((p) => {
        if (!ARITH_ONLY.test(p)) throw new Error('non-arith arg');
        const code = evalArith(p);
        if (code < 0 || code > 0x10ffff) throw new Error('bad code');
        return code;
      });
      decoded = String.fromCharCode(...chars);
    } catch (_) {
      decoded = null;
    }
    if (decoded === null) {
      out += src.slice(idx, afterPos);
      idx = afterPos;
    } else {
      out += src.slice(idx, at) + toLuaString(decoded);
      idx = close + 1;
    }
  }
  return out;
}

// Fold standalone integer-only parenthesized arithmetic (encodeConstants).
function foldConstants(src) {
  const re = /\(\s*-?\d+(?:\s*[-+*]\s*-?\d+)*\s*\)/g;
  let prev = null, cur = src, guard = 0;
  while (prev !== cur && guard++ < 50) {
    prev = cur;
    cur = cur.replace(re, (m) => {
      try {
        if (!ARITH_ONLY.test(m)) return m;
        return String(evalArith(m));
      } catch (_) { return m; }
    });
  }
  return cur;
}

// Remove the junk statements KarmaProtect injects (all use the `_` sink var).
function stripJunk(src) {
  return src
    .replace(/local\s+_\s*=\s*-?\d+\s*;/g, '')
    .replace(/if\s+-?\d+\s*==\s*-?\d+\s+then\s+end\s*;/g, '')
    .replace(/for\s+_\s*=\s*-?\d+\s*,\s*-?\d+\s+do\s+end\s*;/g, '')
    .replace(/do\s+local\s+_\s*=\s*-?\d+\s+end\s*;/g, '');
}

// Tidy the alias-resolved global fetches for readability (semantics preserved).
function tidyAliases(src) {
  return src
    .replace(/rawget\s*\(\s*_G\s*,\s*"([A-Za-z_]\w*)"\s*\)/g, '$1')
    .replace(/string\s*\[\s*"([A-Za-z_]\w*)"\s*\]/g, 'string.$1')
    .replace(/table\s*\[\s*"([A-Za-z_]\w*)"\s*\]/g, 'table.$1');
}

// Minimal Lua re-indenter for the antiFormat single-line output.
function beautify(src) {
  let s = src.replace(/\r/g, '');
  // break statements/blocks onto their own lines
  s = s
    .replace(/;/g, ';\n')
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
  const opensWith = /(\bthen|\bdo|\brepeat|\)\s*$|function[^\n]*\)|\bfunction\b)$/;
  for (let line of lines) {
    const dedent = /^(end|else|elseif|until|\})/.test(line);
    if (dedent && indent > 0) indent--;
    out.push('  '.repeat(indent) + line);
    const opensBlock = /(\bthen|\bdo|\brepeat)$/.test(line) ||
      /\bfunction\b[^)]*\)\s*$/.test(line) ||
      /^else$/.test(line) || /^elseif\b.*then$/.test(line);
    if (opensBlock) indent++;
  }
  return out.join('\n');
}

function detect(src) {
  const marks = [
    /Protected By Karma Lua Hosting/i,
    /--\[\[karma:\d+\]\]/,
    /karma-lua-hosting/i,
  ];
  for (const re of marks) if (re.test(src)) return true;
  // structural: wrapper + string.char/byte alias preamble
  return /return\s*\(\s*function\s*\(\s*\.\.\.\s*\)/.test(src) &&
    /local\s+\w+\s*=\s*string\.char\s*;\s*local\s+\w+\s*=\s*string\.byte/.test(src);
}

function verifyTamper(src) {
  const m = /--\[\[karma:(\d+)\]\]\s*$/.exec(src.trimEnd());
  if (!m) return { present: false, valid: null };
  const body = src.slice(0, src.lastIndexOf('\n--[[karma:'));
  let sum = 0;
  for (let k = 0; k < body.length; k++) sum = (sum + body.charCodeAt(k)) % 1000003;
  return { present: true, valid: sum === Number(m[1]), expected: sum, found: Number(m[1]) };
}

function deobfuscate(src) {
  const notes = [];
  const tamper = verifyTamper(src);
  if (tamper.present) {
    notes.push(tamper.valid
      ? 'Anti-tamper checksum verified (intact, unmodified).'
      : `Anti-tamper checksum MISMATCH (found ${tamper.found}, expected ${tamper.expected}) — the script was edited after protection.`);
  }

  let s = src;
  // strip watermark comments
  s = s.replace(/--\[\[karma:\d+\]\]\s*$/g, '');
  s = s.replace(/--\[\[\s*Protected By Karma Lua Hosting\s*\]\]/g, '');

  // unwrap outer  return(function(...) ... end)(...)
  const wrap = /return\s*\(\s*function\s*\(\s*\.\.\.\s*\)([\s\S]*)end\s*\)\s*\(\s*\.\.\.\s*\)\s*$/.exec(s.trim());
  if (wrap) s = wrap[1];

  // locate the char alias:  local <A>=string.char
  const charM = /local\s+(\w+)\s*=\s*string\.char\s*;/.exec(s);
  if (charM) {
    s = decodeCharCalls(s, charM[1]);
    notes.push(`Decoded string.char alias "${charM[1]}" — all encrypted strings recovered.`);
  } else {
    notes.push('No string.char alias found; strings may already be plain.');
  }

  s = foldConstants(s);
  notes.push('Folded arithmetic constant encoding back to literals.');
  s = tidyAliases(s);
  const beforeJunk = s.length;
  s = stripJunk(s);
  if (s.length !== beforeJunk) notes.push('Removed junk-code statements.');

  // unwrap control-flow pcall shell:  local P=pcall;P(function() BODY end);
  const cf = /local\s+(\w+)\s*=\s*pcall\s*;\s*\1\s*\(\s*function\s*\(\s*\)([\s\S]*)end\s*\)\s*;?/.exec(s);
  if (cf) { s = s.replace(cf[0], cf[2]); notes.push('Unwrapped control-flow pcall shell.'); }

  const output = beautify(s).trim() + '\n';
  notes.push('NOTE: KarmaProtect variable renaming is one-way — original local/param names cannot be recovered (they are replaced with random names). Everything else (strings, numbers, structure) is fully restored.');

  return { output, notes };
}

module.exports = { deobfuscate, detect, evalArith, decodeCharCalls, foldConstants, verifyTamper };
