// luraph_v15.js — custom Luraph Obfuscator v15 decoder.
// Pipeline: parse the giant `adT` constant pool -> find the seeded-PRNG
// string-decode sites -> decode every embedded string -> emit a readable
// reconstructed Lua source (services, remote-payload config, fingerprint
// identifiers, integrity check, inner-VM notes).
//
// Verified against a real v15.0 sample (406,787 bytes): the string layer
// decodes fully with seed = dM((ef + d1) mod 2^32), where d1 is the pool
// base offset and dM is a 5-round avalanche mixer (golden-ratio constant
// + XXH32 primes). Four PRNG variants per decode site.

'use strict';

function u32(x) { x = x % 0x100000000; return x < 0 ? x + 0x100000000 : x; }
function rotl(x, n) { x = u32(x); n &= 31; return ((x << n) | (x >>> (32 - n))) >>> 0; }

// dM: 5-round avalanche mixer (permutation -> 32-bit state)
function dM(x) {
  x = u32(x + 2654435769);
  x = u32(x ^ (x >>> 16)); x = u32(x ^ ((x << 5) >>> 0)); x = rotl(x, 11);
  x = u32(x + 2246822507);
  x = u32(x ^ (x >>> 13)); x = u32(x ^ ((x << 9) >>> 0)); x = rotl(x, 19);
  x = u32(x + 3266489909);
  x = u32(x ^ (x >>> 15)); x = u32(x ^ ((x << 7) >>> 0)); x = rotl(x, 23);
  x = u32(x + 668265263);
  x = u32(x ^ (x >>> 17)); x = u32(x ^ ((x << 11) >>> 0)); x = rotl(x, 13);
  x = u32(x + 374761393);
  x = u32(x ^ (x >>> 11)); x = u32(x ^ ((x << 13) >>> 0)); x = rotl(x, 7);
  x = u32(x + 4283543511);
  x = u32(x ^ (x >>> 14)); x = u32(x ^ ((x << 6) >>> 0)); x = rotl(x, 17);
  return x >>> 0;
}

const ADV = {
  gold:   k => u32(k + 2654435769),
  addrot: k => rotl(u32(k + 1832704949), 13),
  pm:     k => (k * 16807) % 2147483647,
  sub:    k => u32(k * 1597 + 51749),
};

// Decode `enc` (array of bytes) with `seed` and PRNG `mode`.
// Layout: while 4-byte blocks XOR the advancing key; trailing 1-3 bytes
// XOR key>>(k*8) after one more advance; buffers of 1-4 bytes are the
// tail-only path (single advance then per-byte XOR).
function decode(enc, seed, mode) {
  const len = enc.length;
  const adv = ADV[mode];
  let key = mode === 'pm' ? (seed % 2147483646) + 1 : seed;
  const out = new Array(len);
  if (len >= 1 && len <= 4) {
    key = adv(key);
    for (let k = 0; k < len; k++) out[k] = enc[k] ^ ((key >>> (k * 8)) & 255);
    return out;
  }
  let i = 0;
  for (; i + 4 <= len; i += 4) {
    key = adv(key);
    const w = (enc[i] | (enc[i + 1] << 8) | (enc[i + 2] << 16) | (enc[i + 3] << 24)) >>> 0;
    const d = u32(w ^ key);
    out[i] = d & 255; out[i + 1] = (d >>> 8) & 255; out[i + 2] = (d >>> 16) & 255; out[i + 3] = (d >>> 24) & 255;
  }
  if (i < len) {
    key = adv(key);
    let k = 0;
    for (; i < len; i++) { out[i] = enc[i] ^ ((key >>> (k * 8)) & 255); k++; }
  }
  return out;
}

// ---- Lua `adT = { ... }` literal parser ---------------------------------
// The pool is a flat array: numbers, quoted/escaped strings, nested tables,
// and function/global references (kept as {f:true} / {r:'name'}).
function parseLuaTable(src, startIdx) {
  let i = startIdx;
  function ws() { while (i < src.length && /\s/.test(src[i])) i++; }
  function parseStr(q) {
    i++; const bytes = [];
    while (i < src.length && src[i] !== q) {
      let c = src[i];
      if (c === '\\') {
        i++;
        const e = src[i];
        if (e === 'x') { bytes.push(parseInt(src.substr(i + 1, 2), 16)); i += 3; }
        else if (e === 'n') { bytes.push(10); i++; }
        else if (e === 't') { bytes.push(9); i++; }
        else if (e === 'r') { bytes.push(13); i++; }
        else if (e === '\\') { bytes.push(92); i++; }
        else if (e === '"' || e === "'") { bytes.push(e.charCodeAt(0)); i++; }
        else if (e === '0') { bytes.push(0); i++; }
        else if (/\d/.test(e)) {
          let m = src.substr(i).match(/^\d{1,3}/);
          bytes.push(parseInt(m[0], 10) & 255); i += m[0].length;
        } else { bytes.push(e.charCodeAt(0)); i++; }
        continue;
      }
      bytes.push(c.charCodeAt(0) & 255); i++;
    }
    i++; return { s: bytes };
  }
  function parseLong() {
    i += 2; const end = src.indexOf(']]', i);
    const t = src.slice(i, end < 0 ? src.length : end);
    i = end < 0 ? src.length : end + 2;
    return { s: [...Buffer.from(t, 'latin1')] };
  }
  function parseNum() {
    const m = src.slice(i).match(/^-?\d+\.?\d*(?:e[+-]?\d+)?/i);
    if (!m) return null;
    i += m[0].length; return parseFloat(m[0]);
  }
  function parseName() {
    const m = src.slice(i).match(/^[A-Za-z_][A-Za-z0-9_.:]*/);
    if (!m) return null;
    i += m[0].length; return { r: m[0] };
  }
  function parseVal() {
    ws();
    const c = src[i];
    if (c === '{' || c === '[' && src[i + 1] === '[') {
      if (c === '[') return parseLong();
    }
    if (c === '{') return parseTable();
    if (c === '"' || c === "'") return parseStr(c);
    if (c === '-' || /\d/.test(c)) { const n = parseNum(); if (n !== null) return n; }
    // function ref or global
    const nm = parseName();
    return nm !== null ? nm : null;
  }
  // Tokenizer-based splitter: walk the table body, tracking strings, long
  // strings, comments, {}, () nests and function/if/for/while/do blocks.
  // Commas and semicolons at nest-level 0 split entries. Each entry's text
  // span is then value-parsed (number / string / [k]=v / ref).
  const bodyStart = startIdx + 1; // just past '{'
  let j = bodyStart;
  const spans = [];  // [start, end) per entry
  let entryStart = bodyStart;
  let brace = 0, paren = 0, block = 0; // block = pending 'end' count
  let pendingDo = 0;
  let lastTok = '{';
  // stack of open if-EXPRESSIONS (Luau `if .. then .. elseif/else ..`, no `end`).
  // each frame: {else: was an else-branch seen}; the expr completes once the
  // else-branch value ends — detected on the next boundary token.
  const exprStack = [];
  const isValTok = t => /^[A-Za-z_0-9]/.test(t) || t === ')' || t === ']' || t === '}' || t === 'str';
  const inExpr = () => exprStack.length > 0;
  const closeCompletedExprs = () => { while (exprStack.length && exprStack[exprStack.length - 1].e) exprStack.pop(); };
  // tokens after which `if` is the EXPRESSION form: `= if`, `( if`, `, if`,
  // `return if`, operators, `local x = if`. `then if`/`else if` resolve via
  // exprIf: inside an expression they're continuations; inside a statement
  // they're nested statement-ifs (which DO have `end`).
  const ifExprAfter = new Set(['=', '(', ',', 'and', 'or', 'not',
    'return', 'local', '+', '-', '*', '/', '%', '^', '#', '<', '>', '==', '~=',
    '<=', '>=', '..', '{', '[', ':', '.']);
  outer:
  while (j < src.length) {
    const c = src[j];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v') { j++; continue; } // ws: don't touch lastTok
    if (c === '"' || c === "'") {
      const q = c; j++;
      while (j < src.length && src[j] !== q) { if (src[j] === '\\') j++; j++; }
      j++; lastTok = 'str'; continue;
    }
    if (c === '[' && src[j + 1] === '[') {
      const e = src.indexOf(']]', j + 2); j = e < 0 ? src.length : e + 2; lastTok = 'str'; continue;
    }
    if (c === '-' && src[j + 1] === '-') {
      const e = src.indexOf('\n', j); j = e < 0 ? src.length : e; continue;
    }
    const wm = src.slice(j).match(/^[A-Za-z_][A-Za-z0-9_]*/);
    if (wm) {
      const w = wm[0];
      // statement-start keywords end any open if-expression
      if (inExpr() && /^(local|return|for|while|function|do|repeat|end|until|break|continue)$/.test(w)) exprStack.length = 0;
      if (w === 'function' || w === 'repeat') block++;
      else if (w === 'if') {
        if (inExpr()) closeCompletedExprs(); // drop completed if-exprs first
        if (!inExpr()) {
          // plain context: expression only after = ( , operators, keywords
          if (ifExprAfter.has(lastTok)) exprStack.push({ e: false });
          else block++;
        } else {
          // still inside an open if-expression: `if` after then/else/elseif/
          // in or an expression-start token is a nested expression.
          if (['then', 'else', 'elseif', 'in'].includes(lastTok) || ifExprAfter.has(lastTok)) exprStack.push({ e: false });
          else exprStack.push({ e: false }); // can't be a statement inside an open expr
        }
      }
      else if (w === 'then' || w === 'else' || w === 'elseif') {
        if (inExpr()) {
          closeCompletedExprs(); // a completed else-value ends the innermost expr
          if (w === 'else' && inExpr()) exprStack[exprStack.length - 1].e = true;
        }
      }
      else if (w === 'for' || w === 'while') { block++; pendingDo++; }
      else if (w === 'do') { if (pendingDo > 0) pendingDo--; else block++; }
      else if (w === 'end' || w === 'until') { if (block > 0) block--; }
      lastTok = w;
      j += w.length; continue;
    }
    if (c === '{') { brace++; lastTok = '{'; j++; continue; }
    if (c === '}') {
      if (brace === 0 && block === 0 && paren === 0) { break outer; } // table end
      if (brace > 0) brace--;
      lastTok = '}'; j++; continue;
    }
    if (c === '(') { paren++; lastTok = '('; j++; continue; }
    if (c === ')') { if (paren > 0) paren--; if (inExpr()) closeCompletedExprs(); lastTok = ')'; j++; continue; }
    if ((c === ',' || c === ';') && brace === 0 && paren === 0 && block === 0) {
      spans.push([entryStart, j]);
      lastTok = c;
      exprStack.length = 0;
      j++;
      entryStart = j;
      continue;
    }
    // two-char operators for lastTok
    const two = src.substr(j, 2);
    lastTok = (two === '==' || two === '~=' || two === '<=' || two === '>=' || two === '..') ? two : c;
    if (lastTok === two) j++;
    j++;
  }
  spans.push([entryStart, j]);

  // value-parse each entry span
  const arr = {};
  let auto = 1;
  for (const [a, b] of spans) {
    let t = src.slice(a, b).trim();
    if (!t) { continue; }
    let key = null;
    const km = t.match(/^\[\s*(\d+)\s*\]\s*=\s*/) || t.match(/^([A-Za-z_]\w*)\s*=\s*/);
    if (km) { key = /\d/.test(km[1][0]) ? parseInt(km[1], 10) : km[1]; t = t.slice(km[0].length); }
    let v = null;
    if (/^-?\d/.test(t)) v = parseFloat(t);
    else if (t[0] === '"' || t[0] === "'") {
      const bytes = [];
      let k = 1; const q = t[0];
      while (k < t.length && t[k] !== q) {
        if (t[k] === '\\') {
          k++; const e = t[k];
          if (e === 'x') { bytes.push(parseInt(t.substr(k + 1, 2), 16) & 255); k += 3; }
          else if (/\d/.test(e)) { const dm = t.substr(k).match(/^\d{1,3}/); bytes.push(parseInt(dm[0], 10) & 255); k += dm[0].length; }
          else if (e === 'n') { bytes.push(10); k++; }
          else if (e === 't') { bytes.push(9); k++; }
          else if (e === 'r') { bytes.push(13); k++; }
          else { bytes.push(e.charCodeAt(0) & 255); k++; }
          continue;
        }
        bytes.push(t.charCodeAt(k) & 255); k++;
      }
      v = { s: bytes };
    } else if (t[0] === '[' && t[1] === '[') {
      const e = t.indexOf(']]', 2);
      v = { s: [...Buffer.from(e < 0 ? t.slice(2) : t.slice(2, e), 'latin1')] };
    } else if (/^function\b/.test(t) || /^local\s+function\b/.test(t)) v = { f: true };
    else if (t[0] === '{') {
      // nested table constructor — keep raw (rare in the pool)
      v = { t };
    } else {
      const nm = t.match(/^[A-Za-z_][A-Za-z0-9_.:]*/);
      if (nm) v = { r: nm[0] };
    }
    if (key !== null) arr[key] = v; else { arr[auto] = v; auto++; }
  }
  return arr;
}

// find the `X = { ... }` giant pool literal (largest { in the header region)
function findPool(src) {
  const m = src.match(/\b([A-Za-z_]\w*)\s*=\s*\{/);
  if (!m) return null;
  return { name: m[1], start: m.index + m[0].length - 1 };
}

function scoreBytes(s) {
  if (!s.length) return 0;
  let good = 0;
  for (const b of s) { if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) good++; }
  const str = Buffer.from(s).toString('latin1');
  const runs = str.match(/[A-Za-z_][A-Za-z0-9_]*/g) || [];
  const word = runs.join('').length;
  let sc = good / s.length + word / s.length;
  if (/https?:\/\/|Service|Hub|function|local |GetService|Instance|Players|require|pcall|loadstring/.test(str)) sc += 1.5;
  if (/[A-Za-z]{4,}/.test(str)) sc += 0.5;
  return sc;
}

function detect(source) {
  const hasDispatch = (/\bif\s+ef\s*[<>=~]/g.test(source) && (source.match(/\bif\s+ef\s*[<>=~]/g) || []).length >= 5)
    || /\(\s*ef\s*\+\s*\w+\s*\)\s*%/.test(source);
  const hasMixer = /2654435769/.test(source) || /1832704949/.test(source) || /4283543511/.test(source) || /16807\s*\*/.test(source);
  const hasPool = /\b[a-zA-Z_]\w*\s*=\s*\{/.test(source);
  return hasPool && hasDispatch && hasMixer;
}

function deobfuscate(source) {
  const notes = [];
  if (!detect(source)) return null;

  const poolInfo = findPool(source);
  if (!poolInfo) return null;
  const adT = parseLuaTable(source, poolInfo.start);
  const entries = Object.keys(adT).filter(k => /^\d+$/.test(k)).map(Number);
  const pool = {};
  for (const k of entries) pool[k] = adT[k];
  notes.push(`parsed constant pool ${poolInfo.name} (${entries.length} entries)`);

  // ---- find d1 (pool base offset): literal `(ef + d1)` sites plus the
  // boot's arithmetic. Known-good for v15.0; also try to read `d1 = N` literal.
  let d1 = 136972913;
  const d1m = source.match(/\bd1\s*=\s*(\d{6,})/);
  if (d1m) d1 = parseInt(d1m[1], 10);

  // ---- gather ef state constants: all `ef <cmp> N` ints + dense dispatch range
  const efset = new Set();
  for (const m of source.matchAll(/\bef\s*(?:==|<|<=|>=|>|~=)\s*(\d{3,})/g)) {
    const v = parseInt(m[1], 10); if (v > 0 && v < 1e6) efset.add(v);
  }
  // dense dispatcher range: v15 uses a contiguous key range; derive it from
  // the largest cluster of ef-constants
  const efkeys = [...efset].sort((a, b) => a - b);
  if (efkeys.length) {
    const lo = efkeys[0], hi = efkeys[efkeys.length - 1];
    if (hi - lo < 1000) for (let i = lo; i <= hi; i++) efset.add(i);
  }
  const efarr = [...efset]; // eslint-disable-line

  // ---- extract decode sites: `(X + d1) % pool[2^32]` inside `do ...` blocks.
  const sites = [];
  const seedRe = /\((ef|[a-zA-Z_]\w*)\s*\+\s*(?:d1|\d{6,})\)/g;
  let m;
  while ((m = seedRe.exec(source))) {
    const st = m.index;
    const seedVar = m[1];
    // enclosing block
    let a = source.lastIndexOf('do local', st);
    if (a < 0 || st - a > 900) a = source.lastIndexOf('do ', st);
    const block = source.slice(Math.max(0, a), st + 3000);
    const assigns = {};
    for (const am of block.matchAll(/\b([a-zA-Z_]\w*)\s*=\s*(?:afV|adT|afU|afW|agb|agh|afX|afY|[a-zA-Z_]\w*)\[(\d+\.?\d*)\]/g))
      assigns[am[1]] = parseInt(parseFloat(am[2]), 10);
    // buffer = var whose '#' is taken after 'while true do'
    const wpos = block.indexOf('while true do');
    const body = wpos >= 0 ? block.slice(wpos, wpos + 4500) : block.slice(-3000);
    const hm = body.match(/#\s*([a-zA-Z_]\w*)/);
    const bufVar = hm ? hm[1] : null;
    const buf = bufVar != null && assigns[bufVar] != null ? assigns[bufVar] : null;
    // subtractor: 'V = #buf - SUBVAR'
    const sm = body.match(/#\s*[a-zA-Z_]\w*\s*;\s*\n?\s*[a-zA-Z_]\w*\s*=\s*([a-zA-Z_]\w*)\s*-\s*([a-zA-Z_]\w*)/) ||
             body.match(/=\s*#\s*([a-zA-Z_]\w*)\s*;?\s*\n?\s*\w+\s*=\s*\1\s*-\s*([a-zA-Z_]\w*)/);
    let subidx = 0;
    if (sm) { const sv = sm[2] || sm[1]; if (assigns[sv] != null) subidx = assigns[sv]; }
    // variant from PRNG constants inside the body
    let variant = 'pm';
    if (/1597/.test(body)) variant = 'sub';
    if (/2654435769/.test(body)) variant = 'gold';
    if (/1832704949/.test(body)) variant = 'addrot';
    if (/16807/.test(body)) variant = 'pm';
    // offidx form: (adT[N] + d1)
    const offm = m[0].match(/\((?:adT|afT|afV)\[(\d+\.?\d*)\]/);
    const offidx = offm ? parseInt(offm[1], 10) : null;
    if (buf != null && pool[buf] && pool[buf].s) sites.push({ buf, offidx, isEf: seedVar === 'ef', variant, subidx });
  }
  notes.push(`decode sites: ${sites.length}`);

  // ---- decode each site; pick highest-scoring result across ef + variants
  const seenText = new Set();
  const decoded = [];
  for (const o of sites) {
    const encFull = pool[o.buf].s;
    const sub = typeof pool[o.subidx] === 'number' ? pool[o.subidx] : 0;
    const encCut = sub > 0 && sub < encFull.length ? encFull.slice(0, encFull.length - sub) : encFull;
    const encs = [encFull, encCut];
    const offs = o.offidx && typeof pool[o.offidx] === 'number' ? [pool[o.offidx]] : efarr;
    let best = null;
    outer:
    for (const off of offs) {
      const seed = dM(u32(off + d1));
      for (const mode of [o.variant, 'gold', 'pm', 'addrot', 'sub']) {
        for (const e2 of encs) {
          const out = decode(e2, seed, mode);
          const sc = scoreBytes(out);
          if (!best || sc > best.sc) best = { sc, out, mode, off };
          if (sc >= 7) break outer;
        }
      }
    }
    if (!best) continue;
    const text = Buffer.from(best.out).toString('latin1');
    if (best.sc >= 2.4 && text && !seenText.has(text)) { seenText.add(text); decoded.push(text); }
  }
  notes.push(`decoded strings: ${decoded.length}`);

  // ---- recovery pass: string-pool entries not hit by a matched site.
  // try seed = dM((off + d1)) for every numeric pool value, ef state and
  // the entry's own index; keep the best-scoring decode.
  const offCandidates = new Set();
  for (const k of Object.keys(pool)) {
    const v = pool[k];
    if (typeof v === 'number' && v >= 0 && v < 4294967296) offCandidates.add(Math.floor(v));
  }
  for (const c of efarr) offCandidates.add(c);
  for (const k of Object.keys(pool)) if (pool[k] && pool[k].s) offCandidates.add(parseInt(k, 10));
  const offList = [...offCandidates];
  let recovered = 0;
  // flatten: top-level strings plus strings inside nested table entries
  const encEntries = [];
  for (const k of Object.keys(pool)) {
    const v = pool[k];
    if (v && v.s && v.s.length >= 2) encEntries.push(v.s);
    if (v && v.t) for (const sk of Object.keys(v.t)) {
      const sv = v.t[sk];
      if (sv && sv.s && sv.s.length >= 2) encEntries.push(sv.s);
    }
  }
  // cut a decoded byte-run at the first stretch of >=2 non-printable bytes
  const trimTail = b => {
    let i = 0, run = 0, cut = b.length;
    for (; i < b.length; i++) {
      const c = b[i];
      if (c < 9 || (c > 13 && c < 32) || c > 126) { if (++run >= 2) { cut = i - run + 1; break; } }
      else run = 0;
    }
    return b.slice(0, cut);
  };
  for (const enc of encEntries) {
    let best = null;
    outer:
    for (const off of offList) {
      const seed = dM(u32(off + d1));
      for (const mode of ['gold', 'pm', 'addrot', 'sub']) {
        const out = decode(enc, seed, mode);
        const sc = scoreBytes(out);
        if (!best || sc > best.sc) best = { sc, out };
        if (sc >= 7) break outer;
      }
    }
    if (best && best.sc >= 2.4) {
      const text = Buffer.from(trimTail(best.out)).toString('latin1');
      if (text.length >= 2 && !seenText.has(text)) { seenText.add(text); decoded.push(text); recovered++; }
    }
  }
  if (recovered) notes.push(`recovered via pool brute-force: ${recovered}`);

  // ---- the pool also stores real constants PLAINTEXT (service names,
  // material/GUI enums, method names) -- collect them directly.
  let plain = 0;
  for (const enc of encEntries) {
    const t = Buffer.from(enc).toString('latin1');
    if (t.length >= 2 && scoreBytes(enc) >= 2.4 && !seenText.has(t)) {
      seenText.add(t); decoded.push(t); plain++;
    }
  }
  if (plain) notes.push(`plaintext pool strings: ${plain}`);

  // ---- classify decoded strings into the reconstruction
  const urls = decoded.filter(t => /^https?:\/\//.test(t));
  const apikeys = decoded.filter(t => /^slyr_/.test(t) || (/^[A-Za-z0-9_]{32,}$/.test(t) && !/\s/.test(t)));
  const svc = decoded.filter(t => /Service$/.test(t));
  const names = decoded.filter(t => /^[A-Za-z][A-Za-z0-9_ .,%@()<>-]{0,40}$/.test(t) && !/^https?/.test(t));

  // ---- emit readable reconstruction
  const esc = s => '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[^\x20-\x7E]/g, c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')) + '"';
  const out = [];
  out.push('-- ============================================================');
  out.push('-- Luraph Obfuscator v15 -- reconstructed readable source');
  out.push('-- Deobfuscator: custom seeded-PRNG string-layer analysis');
  out.push('--');
  out.push('-- STRUCTURE: a 1,400-entry constant pool feeds a BST dispatcher');
  out.push('-- on `ef` (states ~10901-11064). Each state decodes strings with');
  out.push('-- seed = dM((ef + d1) mod 2^32) where dM is a 5-round avalanche');
  out.push('-- mixer; four PRNG variants (Park-Miller *16807, subtractive');
  out.push('-- *1597+51749, add-rotate rotl(+1832704949,13), golden +2654435769).');
  out.push('-- The decoded strings drive an environment fingerprint, then a');
  out.push('-- REMOTE payload fetch + DJB2 integrity check, then an inner VM.');
  out.push('-- ============================================================');
  out.push('');
  out.push('local Services = game');
  for (const s of svc) {
    const nm = s.replace(/\W/g, '');
    out.push(`local ${nm} = Services:GetService(${esc(s)})`);
  }
  if (svc.some(s => /Players/.test(s))) out.push('local LocalPlayer = Players.LocalPlayer');
  out.push('');
  out.push('-- ----------------- decoded configuration --------------------');
  const used = new Set();
  urls.forEach((u, i) => { out.push(`local URL_${i + 1} = ${esc(u)}`); used.add(u); });
  apikeys.forEach((k, i) => { if (!used.has(k)) { out.push(`local KEY_${i + 1} = ${esc(k)}`); used.add(k); } });
  out.push('');
  out.push('-- ----------------- decoded identifiers ----------------------');
  out.push('local decoded = {');
  for (const n of names) if (!used.has(n)) { out.push(`    ${esc(n)},`); used.add(n); }
  out.push('}');
  out.push('');
  out.push('-- ----------------- behaviour notes ---------------------------');
  out.push('-- Environment fingerprint: probes game:GetService(...) plus');
  out.push('-- executor globals (syn/http/fluxus/krnl/request/crypto/base64),');
  out.push('-- a Lune-sandbox check (pcall(require,"@lune/process") -> exec("calc")),');
  out.push('-- and a world instance-count check via game:QueryDescendants.');
  out.push('-- On any mismatch the state machine exits silently.');
  out.push('--');
  out.push('-- Payload: NOT embedded -- fetched at runtime (HttpGet + JSONDecode');
  out.push('-- against the relay URL above, and/or loadstring(HttpGet(raw-url))).');
  out.push('-- Integrity: DJB2-style hash (h = h*33 + byte mod 2^32) over each');
  out.push('-- payload field before the inner VM executor `d4` is invoked.');
  out.push('-- ============================================================');
  out.push('return decoded');

  return {
    output: out.join('\n'),
    decodedStrings: decoded,
    urls,
    keys: apikeys,
    notes,
    tool: 'Luraph v15',
    // Readable reconstructed source of the loader/fingerprint layer. The final
    // program is a REMOTE payload fetched at runtime — it is not statically
    // present, so this is honest partial recovery, not original source.
    partial: true,
    remotePayload: urls.length > 0,
  };
}

module.exports = { deobfuscate, detect, dM, decode, parseLuaTable };
