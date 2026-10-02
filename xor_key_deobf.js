'use strict';
// Lua XOR-key string obfuscator + simple byte-array wrappers — "decryp1-style".
//
// These are SOURCE-LEVEL obfuscators (not bytecode VMs): the real strings are
// stored as numeric byte arrays or single-key XOR and rebuilt at runtime by a
// deterministic `string.char(...)`/`bit32.bxor` loop. Because the whole
// transform is pure arithmetic on literals, we can replay it statically and
// recover the plaintext source — no VM, no execution, no environment.
//
// Shapes handled:
//   local t={103,104,105}; local s="" for i=1,#t do s=s..string.char(bit32.bxor(t[i],42)) end
//   local t={...}; for i,x in ipairs(t) do s=s..string.char(x~k) end   (Luau ~ xor)
//   string.char(65^9,66^9,...)                                        (inline xor)
//   string.char((n-1)*?, ...) / (b%256) byte-array concat             (plain arrays)
//   local b={98,121,116,101}; loadstring(string.char(unpack? b))      (byte-array wrap)

const luaparse = require('luaparse');

function looksLikeXorKey(src) {
  let score = 0;
  const head = src.slice(0, 8192);
  // numeric byte-array table + a char/bxor rebuild loop is the signature.
  if (/\{\s*\d{1,3}\s*(,\s*\d{1,3}\s*){7,}\}/.test(src)) score += 2;
  if (/string\.char\s*\(\s*(?:bit32\.)?b?xor|bxor\s*\(\s*\w+\s*\[|\.char\s*\([^)]*\^/.test(src)) score += 2;
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

// Find the decode loop for a table and replay it. Returns decoded string or null.
function decodeTableLoop(src, tbl) {
  // pattern A:  s = s .. string.char(bit32.bxor(t[i], KEY))   inside a for over t
  // capture the KEY literal and the concat var; supports ~, bxor, bit32.bxor, +, -, %
  const name = tbl.name;
  // generic: for ... do  X = X .. string.char(EXPR)  end  where EXPR references name[i] or name[x]
  const loopRe = /for\s+[\s\S]{0,80}?do\s*([\s\S]{0,300}?)\bend\b/g;
  let m;
  while ((m = loopRe.exec(src))) {
    const body = m[1];
    if (!body.includes(name)) continue;
    // EXPR forms inside string.char(...)
    const cm = /string\.char\s*\(([^)]*)\)/.exec(body);
    if (!cm) continue;
    const expr = cm[1];
    // deduce the transform applied to each element. Try candidates on first bytes.
    // candidate transforms keyed by discovered literal constants.
    const keyMatch = /(\d{1,3})\s*(?:\)|,|\s*end|\s*$)/.exec(expr);
    // forms:
    //   bit32.bxor(name[i], K) / name[i] ~ K  / name[i] ^ K
    let dec = null;
    const xorK = /(?:bxor|~|\^)\s*\(?\s*[^,()]*?(\d{1,3})\s*\)?\s*$/.exec(expr);
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
      return { decoded: dec.map((b) => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13 ? String.fromCharCode(b) : `\\${b}`).join(''), printable: printableRatio(dec) };
    }
  }
  return null;
}

function printableRatio(bytes) {
  const p = bytes.filter((b) => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13).length;
  return bytes.length ? p / bytes.length : 0;
}

// Inline XOR / arithmetic inside string.char( expr, expr, ... )
function decodeInlineChar(src) {
  // string.char(a^K, b^K, ...) or string.char(bit32.bxor(a,K), ...) or char(a-K,...)
  return src.replace(/string\.char\s*\(([^)]*)\)/g, (whole, inner) => {
    const parts = inner.split(',');
    const bytes = [];
    let usedTransform = false;
    for (const raw of parts) {
      const p = raw.trim();
      let m;
      if ((m = /^(\d{1,3})\s*(?:~|\^)\s*(\d{1,3})$/.exec(p))) { bytes.push(bxor(+m[1], +m[2])); usedTransform = true; }
      else if ((m = /(?:bit32\.)?bxor\s*\(?\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)?/.exec(p))) { bytes.push(bxor(+m[1], +m[2])); usedTransform = true; }
      else if ((m = /^(\d{1,3})\s*-\s*(\d{1,3})$/.exec(p))) { bytes.push(band(+m[1] - +m[2], 0xff)); usedTransform = true; }
      else if ((m = /^(\d{1,3})$/.exec(p))) { bytes.push(+m[1]); }
      else return whole; // unknown element — leave whole call alone
    }
    if (!bytes.length || !usedTransform) return whole;
    const ratio = printableRatio(bytes);
    if (ratio < 0.8) return whole;
    const s = bytes.map((b) => (b >= 32 && b < 127) ? String.fromCharCode(b) : `\\${b}`).join('');
    return JSON.stringify(s);
  });
}

// Replace a `local s = "" ... build loop` producing one decoded string with a
// literal assignment. Conservative: only rewrite when we decoded >70% printable.
function deobfuscate(source) {
  const src = typeof source === 'string' ? source : '';
  const notes = [];
  if (!src.trim()) throw new Error('empty input');

  let out = src;
  let recovered = 0;

  // Pass 1: inline string.char with XOR/arithmetic elements.
  const beforeInline = out;
  out = decodeInlineChar(out);
  if (out !== beforeInline) { recovered++; notes.push('Decoded inline string.char XOR/arith byte sequences.'); }

  // Pass 2: byte-array tables consumed by a decode loop.
  for (const tbl of numericTables(out)) {
    const dec = decodeTableLoop(out, tbl);
    if (dec && dec.printable >= 0.7 && dec.decoded.length >= 4) {
      // replace the table literal AND the build loop region with a literal string.
      // We rewrite the table's assignment to the decoded literal so downstream
      // concat uses it; junk loop is left but now references a literal.
      recovered++;
      notes.push(`Decoded byte-array "${tbl.name}" (${tbl.nums.length} bytes) via its XOR/arith build loop.`);
      // Mark decoded value in a comment for transparency (source-preserving).
      // The loop already rebuilds it at runtime; we annotate + also inline where safe.
      out = out.slice(0, tbl.span[0]) +
        `${tbl.name} = ${JSON.stringify(dec.decoded)} --[[decoded from byte array]]` +
        out.slice(tbl.span[1]);
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
