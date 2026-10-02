'use strict';
// Lua XOR-key string obfuscator + simple byte-array wrappers — "decryp1-style".
//
// These are SOURCE-LEVEL obfuscators (not bytecode VMs): the real strings are
// stored as numeric byte arrays or single-key XOR and rebuilt at runtime by a
// deterministic `string.char(...)`/`bit32.bxor` loop. Because the whole
// transform is pure arithmetic on literals, we can replay it statically and
// recover the plaintext source — no VM, no execution, no environment.
//
// Lua operators: `~` is bitwise XOR (Lua 5.3+/Luau); `^` is EXPONENTIATION, not
// XOR — never treat a^b as a xor decode. `bit32.bxor`/`bxor` are real XOR calls.
//
// Shapes handled:
//   local t={103,104,105}; local s="" for i=1,#t do s=s..string.char(bit32.bxor(t[i],42)) end
//   local t={...}; for i,x in ipairs(t) do s=s..string.char(x~k) end   (Luau ~ xor)
//   string.char(bit32.bxor(65,9),66~9,...)                            (inline xor calls)
//   local b={98,121,116,101}; loadstring(string.char(unpack(b)))      (byte-array wrap)

const luaparse = require('luaparse');

function looksLikeXorKey(src) {
  let score = 0;
  const head = src.slice(0, 8192);
  // numeric byte-array table + a char/bxor rebuild loop is the signature.
  if (/\{\s*\d{1,3}\s*(,\s*\d{1,3}\s*){7,}\}/.test(src)) score += 2;
  if (/string\.char\s*\(\s*(?:bit32\.)?bxor|bxor\s*\(\s*\w+\s*\[|\.char\s*\([^)]*~/.test(src)) score += 2;
  if (/(\\x[0-9a-fA-F]{2}){8,}/.test(head) && /string\.char|loadstring/.test(src)) score += 1;
  if (/for\s+\w+\s*=\s*1\s*,\s*#\w+\s*do\s*[\s\S]{0,200}?string\.char/.test(src)) score += 2;
  return score;
}

// bit32.bxor semantics in JS (Lua 5.2 bit32 is 32-bit; Luau ~ is 32-bit too).
function bxor(a, b) { return ((a | 0) ^ (b | 0)) >>> 0; }
function band(a, b) { return ((a | 0) & (b | 0)) >>> 0; }

// Pull a top-level numeric literal table:  NAME = { 1, 2, 3, ... }
function* numericTables(src) {
  const re = /(?:local\s+)?([A-Za-z_][\w]*)\s*=\s*\{\s*([\d\s,\-]+)\}/g;
  let m;
  while ((m = re.exec(src))) {
    const nums = m[2].split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => Number.isFinite(n));
    if (nums.length >= 4 && nums.every((n) => n >= 0 && n <= 255)) yield { name: m[1], nums, span: [m.index, m.index + m[0].length] };
  }
}

// Find the decode loop for a table and replay it. Returns {decoded, printable,
// loopSpan, resultVar} or null. loopSpan covers the whole `for ... end`
// statement so the caller can drop the (now-dead) indexing loop entirely.
function decodeTableLoop(src, tbl) {
  const name = tbl.name;
  const loopRe = /for\s+[\s\S]{0,80}?\bdo\b\s*([\s\S]{0,300}?)\bend\b/g;
  let m;
  while ((m = loopRe.exec(src))) {
    const body = m[1];
    if (!body.includes(name)) continue;
    const cm = /string\.char\s*\(([^)]*)\)/.exec(body);
    if (!cm) continue;
    const expr = cm[1];
    // transforms: bit32.bxor(name[i],K) / name[i] ~ K  (NEVER ^ — that's pow)
    let dec = null;
    const xorK = /(?:bxor|~)\s*\(?\s*[^,()]*?(\d{1,3})\s*\)?\s*$/.exec(expr);
    const subK = /-\s*(\d{1,3})\s*(?:%|$|\))/.exec(expr);
    const addK = /\+\s*(\d{1,3})\s*(?:%|$|\))/.exec(expr);
    const modM = /%\s*(\d{1,3})/.exec(expr);
    if (xorK) {
      const k = parseInt(xorK[1], 10);
      dec = tbl.nums.map((n) => bxor(n, k));
    } else if (subK) {
      const k = parseInt(subK[1], 10);
      dec = tbl.nums.map((n) => band(n - k, 0xff));
    } else if (addK) {
      const k = parseInt(addK[1], 10);
      dec = tbl.nums.map((n) => band(n + k, 0xff));
    } else if (modM) {
      dec = tbl.nums.map((n) => band(n, 0xff));
    } else if (/^\s*\w+\s*\[\s*\w+\s*\]\s*$/.test(expr)) {
      // plain string.char(name[i]) — no transform
      dec = tbl.nums;
    }
    if (dec && dec.length) {
      // result var = the concat accumulator `X = X .. string.char(...)`
      const rv = /(\w+)\s*=\s*\1?\s*\.\./.exec(body) || /(\w+)\s*=\s*string\.char/.exec(body);
      const resultVar = rv ? rv[1] : null;
      return {
        decoded: dec.map((b) => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13 ? String.fromCharCode(b) : `\\${b}`).join(''),
        printable: printableRatio(dec),
        loopSpan: [m.index, m.index + m[0].length],
        resultVar,
      };
    }
  }
  return null;
}

function printableRatio(bytes) {
  const p = bytes.filter((b) => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13).length;
  return bytes.length ? p / bytes.length : 0;
}

// Split an argument list on TOP-LEVEL commas only (ignore commas inside nested
// parens/brackets/strings) so `bxor(65,7)` isn't split mid-call.
function splitTopCommas(s) {
  const parts = [];
  let depth = 0, last = 0, q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) { parts.push(s.slice(last, i)); last = i + 1; }
  }
  parts.push(s.slice(last));
  return parts;
}

// Decode one string.char argument element to a byte, or return null.
// Handles: `a ~ k` (xor), `bit32.bxor(a,k)`/`bxor(a,k)`, `a - k`, `a`, `(a-k)%256`.
// `a ^ b` is exponentiation (huge) — NOT decoded (returns null → leave call).
function decodeCharElement(p0) {
  const p = p0.trim();
  let m;
  if ((m = /^(\d{1,3})\s*~\s*(\d{1,3})$/.exec(p))) return bxor(+m[1], +m[2]);
  if ((m = /(?:bit32\.)?bxor\s*\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/.exec(p))) return bxor(+m[1], +m[2]);
  if ((m = /^\(?\s*(\d{1,3})\s*-\s*(\d{1,3})\s*\)?(?:\s*%\s*\d{1,3})?$/.exec(p))) return band(+m[1] - +m[2], 0xff);
  if ((m = /^(\d{1,3})$/.exec(p))) return +m[1];
  return null;
}

// Inline XOR / arithmetic inside string.char( ... ) — balanced-paren scan so a
// nested `bxor(...)` doesn't split the call, then decode each top-level arg.
function decodeInlineChar(src) {
  const re = /string\.char\s*\(/g;
  let m, result = '', last = 0;
  while ((m = re.exec(src))) {
    const argStart = m.index + m[0].length;
    // scan to the matching close paren (skip string literals)
    let depth = 1, i = argStart, q = null;
    for (; i < src.length && depth > 0; i++) {
      const c = src[i];
      if (q) { if (c === '\\') i++; else if (c === q) q = null; continue; }
      if (c === '"' || c === "'") { q = c; continue; }
      if (c === '(') depth++;
      else if (c === ')') depth--;
    }
    if (depth !== 0) break;
    const inner = src.slice(argStart, i - 1);
    const parts = splitTopCommas(inner);
    const bytes = [];
    let usedTransform = false, ok = true;
    for (const raw of parts) {
      const b = decodeCharElement(raw);
      if (b == null) { ok = false; break; }
      if (b > 255) { ok = false; break; }
      bytes.push(b);
      if (/[~\-]|bxor|\(/.test(raw)) usedTransform = true;
    }
    if (!ok || !bytes.length || !usedTransform) continue;
    if (printableRatio(bytes) < 0.8) continue;
    const s = bytes.map((b) => (b >= 32 && b < 127) ? String.fromCharCode(b) : `\\${b}`).join('');
    result += src.slice(last, m.index) + JSON.stringify(s);
    last = i;
    re.lastIndex = i;
  }
  result += src.slice(last);
  return result;
}

// Replace the numeric table AND its whole decode loop with a literal string.
// Conservative: only rewrite when we decoded >70% printable and got a result var.
function deobfuscate(source) {
  const src = typeof source === 'string' ? source : '';
  const notes = [];
  if (!src.trim()) throw new Error('empty input');

  let out = src;
  let recovered = 0;

  // Pass 1: inline string.char with XOR/arithmetic elements (balanced parens).
  const beforeInline = out;
  out = decodeInlineChar(out);
  if (out !== beforeInline) { recovered++; notes.push('Decoded inline string.char XOR/arith byte sequences.'); }

  // Pass 2: byte-array tables consumed by a decode loop. Replace the WHOLE
  // `for ... end` decode statement (not just the table) so the indexing loop
  // doesn't survive to index a now-string literal — and bind the result var.
  for (const tbl of [...numericTables(out)]) {
    const dec = decodeTableLoop(out, tbl);
    if (dec && dec.resultVar && dec.printable >= 0.7 && dec.decoded.length >= 4) {
      // replace the for-loop span first (higher index), then the table decl,
      // so earlier spans stay valid.
      const loopAssign = `${dec.resultVar} = ${JSON.stringify(dec.decoded)}`;
      const tableAssign = `local ${tbl.name} = ${JSON.stringify(dec.decoded)} --[[decoded byte array]]`;
      // apply the later span first
      const [first, second] = tbl.span[0] < dec.loopSpan[0]
        ? [[tbl.span, tableAssign], [dec.loopSpan, loopAssign]]
        : [[dec.loopSpan, loopAssign], [tbl.span, tableAssign]];
      // order descending by start so replacements don't shift earlier spans
      const spans = [first, second].sort((a, b) => b[0][0] - a[0][0]);
      for (const [[s0, s1], repl] of spans) out = out.slice(0, s0) + repl + out.slice(s1);
      recovered++;
      notes.push(`Decoded byte-array "${tbl.name}" (${tbl.nums.length} bytes) — replaced its decode loop with the literal string.`);
    }
  }

  if (recovered === 0) throw new Error('no XOR-key/byte-array decode pattern matched');

  // Validate result still parses as Lua if it looks like we rewrote real code.
  try { luaparse.parse(out, { luaVersion: '5.1', comments: false }); } catch (_) { /* keep best-effort */ }

  return {
    output: out,
    notes,
    recovered: out,
    partial: recovered < 2,
  };
}

function detect(src) {
  const score = looksLikeXorKey(src);
  return { name: 'Lua XOR-key string obf', confidence: Math.min(99, score * 16), signals: [`score ${score}`] };
}

module.exports = { deobfuscate, detect, looksLikeXorKey };
