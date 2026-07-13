'use strict';
// WeAreDevs Obfuscator (v1.0.0 — wearedevs.net/obfuscator).
//
// Structure of a protected script:
//   1. local S = { "<b64>", "<b64>", ... }   -- string/constant pool, each entry
//      is base64-encoded with a PER-BUILD RANDOMISED alphabet.
//   2. a shuffle loop that reverses sub-ranges of S.
//   3. local D = { <char>=<idx>, ... }        -- the randomised base64 alphabet
//      (char -> 0..63), written as obfuscated integer arithmetic.
//   4. a decode loop that base64-decodes every S entry in place using D.
//   5. a register VM (`return(function(...) ... end)(...)`) that interprets the
//      decoded pool as its bytecode/constant pool.
//
// The VM control flow is genuinely virtualised, so byte-exact source cannot be
// statically reconstructed. BUT the entire string pool (step 1-4) is a pure,
// deterministic transform we can replay in JS — which recovers EVERY plaintext
// constant the script uses (service/method names, remote names, URLs, webhooks,
// messages, etc.). That is the actionable content of the script.

function looksLikeWeAreDevs(src) {
  if (!src || typeof src !== 'string') return 0;
  const head = src.slice(0, 6000);
  let score = 0;
  if (/wearedevs\.net\/obfuscator/i.test(head)) score += 6;
  if (/local\s+S\s*=\s*\{\s*"/.test(head)) score += 1;
  // the signature base64 decode loop: q + M*64^(3-n) split into 3 bytes
  if (/64\s*\^\s*\(\s*3\s*-/.test(src) || /64\^\(3-/.test(src)) score += 3;
  if (/for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{\s*\{/.test(src)) score += 1;
  if (/getfenv\s+and\s+getfenv\(\)\s*or\s*_ENV/.test(src)) score += 2;
  return score;
}

// Decode Lua \ddd / \xHH / common escapes in a double-quoted literal body.
function decodeLuaEscapes(body) {
  let out = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c !== '\\') { out += c; continue; }
    const n = body[i + 1];
    if (n === 'x' || n === 'X') {
      const h = body.slice(i + 2, i + 4);
      if (/^[0-9a-fA-F]{1,2}$/.test(h)) { out += String.fromCharCode(parseInt(h, 16)); i += 1 + h.length; continue; }
    }
    if (n >= '0' && n <= '9') {
      let d = n; let j = i + 2;
      while (d.length < 3 && body[j] >= '0' && body[j] <= '9') { d += body[j]; j++; }
      out += String.fromCharCode(parseInt(d, 10) & 0xff);
      i = j - 1; continue;
    }
    const map = { n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', f: '\f', v: '\v', '\\': '\\', '"': '"', "'": "'", '\n': '\n' };
    if (n in map) { out += map[n]; i += 1; continue; }
    out += n; i += 1;
  }
  return out;
}

// Safe arithmetic-only evaluator for the D-table values (e.g. "-503811+503825").
function evalArith(expr) {
  const clean = String(expr).trim();
  if (!/^[-+*/%()\d\s.]+$/.test(clean)) return null;
  try {
    // eslint-disable-next-line no-new-func
    const v = Function('"use strict";return (' + clean + ');')();
    return (typeof v === 'number' && isFinite(v)) ? v : null;
  } catch (_) { return null; }
}

// Extract the randomised base64 alphabet (char -> value 0..63) from `local D={...}`.
function extractAlphabet(src) {
  const m = /local\s+D\s*=\s*\{([^}]*)\}/.exec(src);
  if (!m) return null;
  const body = m[1];
  const map = {};
  // keys: ["x"] | ['x'] | bareIdentifier ; value: arithmetic up to , or } or newline-before-next-key
  const re = /(?:\[\s*(['"])([\s\S]*?)\1\s*\]|([A-Za-z_]\w*))\s*=\s*([^,;}\n]+)/g;
  let e;
  while ((e = re.exec(body))) {
    const ch = e[2] !== undefined ? decodeLuaEscapes(e[2]) : e[3];
    const val = evalArith(e[4]);
    if (ch == null || ch.length !== 1 || val == null) continue;
    if (val < 0 || val > 63) continue;
    map[ch] = val;
  }
  return Object.keys(map).length >= 32 ? map : null;
}

// Extract the raw (still base64-encoded) string pool `local S={ "..","..." }`.
function extractPool(src) {
  const m = /local\s+S\s*=\s*\{([\s\S]*?)\}\s*for\b/.exec(src);
  if (!m) return null;
  const body = m[1];
  const out = [];
  const re = /"((?:\\.|[^"\\])*)"/g;
  let e;
  while ((e = re.exec(body))) out.push(decodeLuaEscapes(e[1]));
  return out.length ? out : null;
}

// base64-decode one token using the randomised alphabet, mirroring the script's
// own decode loop (4 symbols -> 24 bits -> 3 bytes, with '=' padding).
function decodeToken(tok, alpha) {
  const N = [];
  let q = 0, n = 0;
  for (let l = 0; l < tok.length; l++) {
    const s = tok[l];
    const M = alpha[s];
    if (M !== undefined) {
      q = q + M * Math.pow(64, 3 - n);
      n += 1;
      if (n === 4) {
        n = 0;
        N.push(Math.floor(q / 65536) & 0xff);
        N.push(Math.floor((q % 65536) / 256) & 0xff);
        N.push(q % 256 & 0xff);
        q = 0;
      }
    } else if (s === '=') {
      N.push(Math.floor(q / 65536) & 0xff);
      if (l + 1 >= tok.length || tok[l + 1] !== '=') {
        N.push(Math.floor((q % 65536) / 256) & 0xff);
      }
      break;
    }
  }
  return Buffer.from(N).toString('latin1');
}

// Parse the shuffle loop's ipairs({{lo,hi},...}) sub-range list. The VM reverses
// each S[lo..hi] range in place BEFORE base64-decoding, so we must replay it to
// recover the correct constant-pool ordering (needed for VM index resolution).
function extractShuffle(src) {
  const m = /ipairs\s*\(\s*\{\s*(\{[\s\S]*?\})\s*\}\s*\)/.exec(src);
  if (!m) return [];
  const body = m[1];
  const pairs = [];
  const re = /\{\s*([^,{}]+?)\s*[,;]\s*([^,{}]+?)\s*\}/g;
  let e;
  while ((e = re.exec(body))) {
    const lo = evalArith(e[1]); const hi = evalArith(e[2]);
    if (lo != null && hi != null) pairs.push([lo, hi]);
  }
  return pairs;
}

// M(idx) = S[idx - OFFSET]; recover OFFSET from `local function M(M)return S[M-(..)]end`.
function extractMOffset(src) {
  const m = /function\s+M\s*\(\s*M\s*\)\s*return\s+S\s*\[\s*M\s*-\s*\(([^)]*)\)\s*\]/.exec(src);
  if (!m) return null;
  return evalArith(m[1]);
}

function reverseRange(arr, lo, hi) {
  lo -= 1; hi -= 1; // 1-based inclusive -> 0-based
  while (lo < hi) { const t = arr[lo]; arr[lo] = arr[hi]; arr[hi] = t; lo++; hi--; }
}

// Fully recover the decoded constant pool in correct VM index order, plus the
// M() offset so callers can resolve M(k) -> S[k-offset].
function decodePool(src) {
  const alpha = extractAlphabet(src);
  const raw = extractPool(src);
  if (!alpha || !raw) return null;
  const arr = raw.slice();
  for (const [lo, hi] of extractShuffle(src)) reverseRange(arr, lo, hi);
  const S = arr.map((t) => (t === '' ? '' : decodeToken(t, alpha)));
  return { S, offset: extractMOffset(src), alpha };
}

function toLuaString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else if (c < 0x20 || c > 0x7e) out += '\\' + c;
    else out += s[i];
  }
  return out + '"';
}

const SUDO_INVITE = 'https://discord.gg/ZyXAgmSVPA';

// Recover every plaintext constant from a WeAreDevs-protected script.
function deobfuscate(src) {
  const alpha = extractAlphabet(src);
  const pool = extractPool(src);
  if (!alpha || !pool) {
    return {
      output: null,
      partial: true,
      notes: ['Recognised the WeAreDevs obfuscator header but could not locate the string pool / alphabet table (format variant). Falling back to generic recovery.'],
      _fallback: true,
    };
  }

  const decoded = pool.map((t) => (t === '' ? '' : decodeToken(t, alpha)));

  // Keep readable constants for the "source" view: printable strings only.
  const printable = decoded.filter((s) => s && /[\x20-\x7e]/.test(s) && !/[\x00-\x08\x0e-\x1f]/.test(s));
  const uniq = [];
  const seen = new Set();
  for (const s of printable) { if (!seen.has(s)) { seen.add(s); uniq.push(s); } }

  // Attempt full static devirtualization: rebuild the flattened VM into readable
  // per-function Lua with real control flow and all constants inlined.
  let devirt = null;
  try {
    // Lazy require to avoid a circular dependency at module-load time.
    devirt = require('./tools/wearedevs/emit.js').devirt(src);
  } catch (e) {
    devirt = null;
  }

  if (devirt && devirt.output) {
    const notes = [
      'WeAreDevs obfuscator (wearedevs.net) detected — a register-based, control-flow-flattened VM.',
      `Statically devirtualised: recovered the VM's constant pool (${decoded.filter((s) => s).length} entries) and rebuilt the flattened dispatcher into ${devirt.functions} function(s) / ${devirt.blocks} basic blocks with real control flow, all constants inlined.`,
      'This is a functionally-faithful reconstruction. Original local names & comments were discarded by the obfuscator, so registers/temps use generated names (R[n], generated locals). Register-lifetime bookkeeping (refcounts) is stripped for readability. Full raw pool + CFG in dump.lua.',
    ];
    return {
      output: devirt.output,
      decodedConstants: uniq,
      devirt: true,
      functions: devirt.functions,
      blocks: devirt.blocks,
      partial: true,
      notes,
    };
  }

  // Fallback: static lift unavailable for this variant — return the constant pool.
  const notes = [
    'WeAreDevs obfuscator (wearedevs.net) detected — a register-based VM format.',
    `Replayed the script's own string-pool decoder: recovered ${decoded.filter((s) => s).length} constants (${uniq.length} unique printable).`,
    'Static devirtualization did not complete for this build variant, so byte-exact source could not be rebuilt — but every string/constant the script uses is recovered below in plaintext.',
  ];

  const lines = [];
  lines.push('--[[ WeAreDevs deobfuscation — Sudo Deobfuscator');
  lines.push('     ' + SUDO_INVITE);
  lines.push('     Recovered plaintext constant pool (VM control flow not devirtualised). ]]');
  lines.push('');
  lines.push('-- ===== Recovered strings / constants (' + uniq.length + ' unique) =====');
  uniq.forEach((s, i) => { lines.push('[' + (i + 1) + '] ' + toLuaString(s)); });
  lines.push('');

  return {
    output: lines.join('\n'),
    decodedConstants: uniq,
    partial: true,
    notes,
  };
}

// Raw dump: the full decoded pool in original index order (incl. duplicates/blanks),
// so a reader can map VM constant indices back to their plaintext values.
function buildDump(src) {
  const alpha = extractAlphabet(src);
  const pool = extractPool(src);
  if (!alpha || !pool) return '';
  const decoded = pool.map((t) => (t === '' ? '' : decodeToken(t, alpha)));
  const lines = [];
  lines.push('-- Sudo Deobfuscator — WeAreDevs raw decoded string pool');
  lines.push('-- ' + SUDO_INVITE);
  lines.push('-- Full constant pool in VM index order (' + decoded.length + ' entries).');
  lines.push('');
  decoded.forEach((s, i) => { lines.push('[' + (i + 1) + '] ' + toLuaString(s)); });
  lines.push('');

  // Append the reconstructed control-flow graph (basic blocks + resolved edges).
  try {
    const cfgmod = require('./tools/wearedevs/cfg.js');
    const cfg = cfgmod.build(src);
    const kinds = {};
    cfg.blocks.forEach((b) => { kinds[b.edge.kind] = (kinds[b.edge.kind] || 0) + 1; });
    lines.push('-- ===== Reconstructed VM control-flow graph =====');
    lines.push('-- dispatcher state var: ' + cfg.stateVar);
    lines.push('-- blocks: ' + cfg.blocks.length + '  edges: ' + JSON.stringify(kinds));
    lines.push('');
    cfg.blocks.forEach((b) => {
      const e = b.edge;
      let s = 'block #' + b.id + '  state[' + b.lo + ',' + b.hi + ')  -> ' + e.kind;
      if (e.kind === 'jump') { const t = cfg.blockForState(e.to); s += ' #' + (t ? t.id : '?'); }
      if (e.kind === 'branch') { const ta = cfg.blockForState(e.tTo); const fb = cfg.blockForState(e.fTo); s += ' T:#' + (ta ? ta.id : '?') + ' F:#' + (fb ? fb.id : '?'); }
      lines.push(s);
    });
    lines.push('');
  } catch (e) { /* CFG unavailable for this variant */ }

  return lines.join('\n');
}

module.exports = {
  looksLikeWeAreDevs,
  deobfuscate,
  buildDump,
  extractAlphabet,
  extractPool,
  extractShuffle,
  extractMOffset,
  decodePool,
  decodeToken,
  evalArith,
  SUDO_INVITE,
};
