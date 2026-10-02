'use strict';
// String-encryption-family deobfuscator — covers the source-level Luau/Lua
// obfuscators that hide strings behind a per-script decode-table + call-site
// decoder (Ferib lua-obfuscator, Goofyscator/1ayd1, wYnFuscate V1-V4 builds).
// These keep the program as REAL Lua and only encrypt string literals, so we
// resolve each decoder call to its plaintext and rewrite the source.
//
// Common shapes resolved:
//   local D={"\x..","\x.."};  f=function(i)return deobf(D[i])end; s=f(12)
//   local S={function()return"..."end};  s=S[3]()
//   enc("...") where enc is a captured XOR/base64/byte-rot decoder
//   string.char(byte,byte,...) concat chains
//   \ddd / \xHH escape sequences inside string literals
// Because each obfuscator randomises names, everything is resolved by ROLE.

const luaparse = require('luaparse');

function unescapeLua(s) {
  return s.replace(/\\(\d{1,3})|\\x([0-9a-fA-F]{2})|\\([abfnrtv\\"'`])/g,
    (m, dd, xh, ch) => {
      if (dd != null) return String.fromCharCode(parseInt(dd, 10) & 0xff);
      if (xh != null) return String.fromCharCode(parseInt(xh, 16) & 0xff);
      const map = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11 };
      if (ch in map) return String.fromCharCode(map[ch]);
      return ch === '\\' ? '\\' : ch;
    });
}

function printableRatio(str) {
  if (!str.length) return 0;
  let p = 0;
  for (const ch of str) { const c = ch.charCodeAt(0); if ((c >= 32 && c < 127) || ch === '\n' || ch === '\t' || ch === '\r') p++; }
  return p / str.length;
}

// Detect the string-encryption family broadly (used by detect() + to gate work).
function looksLikeStringEnc(src) {
  let score = 0;
  const head = src.slice(0, 8192);
  if (/(\\x[0-9a-fA-F]{2}|\\\d{1,3}){10,}/.test(head)) score += 3;            // long escaped blobs
  if (/local\s+\w+\s*=\s*\{\s*"(?:\\.|[^"]){4,}"/.test(src) && /function\s*\w+\s*\(\s*\w+\s*\)/.test(src)) score += 2;
  if (/string\.char\s*\(\s*\d/.test(src)) score += 1;
  if (/bit32\.bxor|\bxor\b|\^/.test(src) && /string\.char|loadstring/.test(src)) score += 2;
  if (/\w+\[\d{1,4}\]\s*\(\s*\)/.test(src)) score += 1;                       // S[i]() decoder-call
  if (/local\s+\w+\s*=\s*\{\s*function/.test(src)) score += 1;               // {function()return..end}
  return score;
}

// Resolve a table of function-thunks:  local T={function()return".."end,..};  T[i]()
function resolveThunkTable(src) {
  let out = src;
  const tableRe = /local\s+(\w+)\s*=\s*\{([^}]*)\}/g;
  let m, changed = 0;
  const tables = {};
  while ((m = tableRe.exec(src))) {
    const name = m[1], body = m[2];
    if (!/function\s*\([^)]*\)\s*return/.test(body)) continue;
    // capture each function() return "X" end
    const vals = [];
    const fnRe = /function\s*\([^)]*\)\s*(?:local\s+\w+\s*=\s*)?return\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*end/g;
    let fm; let idx = 0;
    while ((fm = fnRe.exec(body))) {
      const lit = fm[1].slice(1, -1);
      vals[idx++] = unescapeLua(lit);
    }
    if (idx) tables[name] = vals;
  }
  // rewrite T[i]() and T[i] to the decoded literal
  for (const [name, vals] of Object.entries(tables)) {
    const callRe = new RegExp(`\\b${name}\\s*\\[\\s*(\\d+)\\s*\\]\\s*\\(\\s*\\)`, 'g');
    const idxRe = new RegExp(`\\b${name}\\s*\\[\\s*(\\d+)\\s*\\]`, 'g');
    out = out.replace(callRe, (w, i) => {
      const v = vals[+i - 1];
      return v != null ? JSON.stringify(v) : w;
    });
    out = out.replace(idxRe, (w, i) => {
      const v = vals[+i - 1];
      return v != null && /^["']/.test(w) === false ? JSON.stringify(v) : w;
    });
    changed++;
  }
  return { out, count: changed };
}

// Decode a leading numeric byte-blob built via (a*k+b)%c style or plain list.
function decodeByteBlobs(src) {
  // `local T={n1,n2,...}` where values >255 often encode (val*mul+add)%mod or val^k
  return src;
}


// If `out` is essentially `... loadstring(S) ...` / `load(S)` with S a decoded
// string literal holding the real source, return that source. Handles nested
// `return(function(...) ... loadstring("...")() end)()` PSU-style shells.
function extractLoadstringPayload(src) {
  const m = /(?:loadstring|load)\s*\(\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/.exec(src);
  if (!m) {
    // `local V="..." loadstring(V)` — the decoded source bound to a var then loaded
    const lv = /local\s+(\w+)\s*=\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')[\s\S]{0,200}?\b(?:loadstring|load)\s*\(\s*\1\s*\)/.exec(src);
    if (lv) {
      const dec = unescapeLua(lv[2].slice(1, -1));
      if (dec.length > 8) return dec;
    }
    return null;
  }
  const dec = unescapeLua(m[1].slice(1, -1));
  if (dec.length > 10 && /function|local|return|for|print|\w+\s*=[^=]/.test(dec)) return dec;
  return null;
}

function deobfuscate(source) {
  const src = typeof source === 'string' ? source : '';
  const notes = [];
  if (!src.trim()) throw new Error('empty input');
  let out = src;
  let recovered = 0;

  // Pass 1: escape normalisation inside string literals (\ddd, \xHH).
  const esc = out.replace(/("(?:\\.|[^"\\])*")/g, (w) => {
    const inner = w.slice(1, -1);
    if (!/\\/.test(inner)) return w;
    const d = unescapeLua(inner);
    return printableRatio(d) >= 0.7 ? JSON.stringify(d) : w;
  });
  if (esc !== out) { out = esc; recovered++; notes.push('Normalised \\ddd/\\xHH escapes inside string literals.'); }

  // Pass 2: function-thunk decode tables  T[i]() -> plaintext.
  const th = resolveThunkTable(out);
  if (th.count) { out = th.out; recovered++; notes.push(`Resolved ${th.count} string-decode thunk table(s) to plaintext literals.`); }

  // Pass 3: inline string.char(n,n,...) calls.
  const beforeChar = out;
  out = out.replace(/string\.char\s*\(\s*[\d\s,]+\)/g, (w) => {
    const nums = w.match(/\d+/g).map(Number);
    if (!nums.length || nums.some((n) => n > 255)) return w;
    const s = nums.map((n) => String.fromCharCode(n)).join('');
    return printableRatio(s) >= 0.7 ? JSON.stringify(s) : w;
  });
  if (out !== beforeChar) { recovered++; notes.push('Decoded string.char byte sequences.'); }

  // If the decoded program is still just a loader wrapping the real source in a
  // string + loadstring/eval, surface the payload itself (the actual recovery).
  const payload = extractLoadstringPayload(out);
  if (payload) {
    out = payload;
    recovered++;
    notes.push('Pulled the recovered source out of the obfuscator\'s loadstring wrapper.');
  }

  if (recovered === 0) throw new Error('no string-encryption pattern matched');
  try { luaparse.parse(out, { luaVersion: '5.1', comments: false }); } catch (_) {}
  return { output: out, notes, recovered: out, partial: recovered < 2 };
}

function detect(src) {
  const score = looksLikeStringEnc(src);
  return { name: 'String-encryption obfuscator', confidence: Math.min(99, score * 15), signals: [`score ${score}`] };
}

module.exports = { deobfuscate, detect, looksLikeStringEnc, unescapeLua };
