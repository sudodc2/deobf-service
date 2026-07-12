'use strict';
// Prometheus deobfuscation.
//
// Prometheus (levno-710) applies a pipeline of AST transforms. This module
// reverses the static, non-VM layers derived from the obfuscator source:
//   - Watermark          -> strip the injected watermark string/var
//   - NumbersToExpressions -> constant-fold arithmetic back to literals
//   - EncryptStrings / SplitStrings -> decode \NN / string.char / concat runs
//   - WrapInFunction     -> unwrap the outer return(function()...end)() shell
// then beautifies. The Vmify VM layer (present in every preset) requires full
// devirtualization and is reported as work-in-progress rather than silently
// producing wrong output.

function stripWatermark(src) {
  let n = 0;
  const out = src
    .replace(/--.*This Script is Part of the Prometheus[^\n]*\n?/gi, () => { n++; return ''; })
    .replace(/local\s+_WATERMARK\s*=\s*(["'])(?:\\.|(?!\1).)*\1\s*;?\n?/g, () => { n++; return ''; });
  return { out, n };
}

// Fold simple numeric arithmetic expressions (Add/Sub/Mul/Mod chains over
// literals) that NumbersToExpressions produced. Iterated to a fixpoint.
function foldNumbers(src) {
  let s = src, n = 0, changed = true, guard = 0;
  const numeric = /\(\s*(-?(?:0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?))\s*([+\-*%])\s*(-?(?:0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?))\s*\)/;
  while (changed && guard++ < 5000) {
    changed = false;
    s = s.replace(numeric, (m, a, op, b) => {
      const x = Number(a), y = Number(b);
      if (!Number.isFinite(x) || !Number.isFinite(y)) return m;
      let v;
      if (op === '+') v = x + y; else if (op === '-') v = x - y; else if (op === '*') v = x * y; else v = x % y;
      if (!Number.isFinite(v)) return m;
      changed = true; n++;
      return String(v);
    });
  }
  return { out: s, n };
}

function decodeStrings(src) {
  let n = 0;
  let out = src.replace(/(["'])((?:\\\d{1,3}|\\x[0-9A-Fa-f]{2}|\\.|[^\\])*?)\1/g, (m, q, body) => {
    if (!/\\(\d{1,3}|x[0-9A-Fa-f]{2})/.test(body)) return m;
    let dec = '', ok = true;
    body.replace(/\\(\d{1,3})|\\x([0-9A-Fa-f]{2})|\\([nrtabfv\\"'])|(.)/g, (_x, d, h, e, lit) => {
      let c;
      if (d !== undefined) c = parseInt(d, 10);
      else if (h !== undefined) c = parseInt(h, 16);
      else if (e !== undefined) { dec += ({ n: '\n', r: '\r', t: '\t', '\\': '\\', '"': '"', "'": "'" }[e]) || e; return ''; }
      else { dec += lit; return ''; }
      if (c > 255) ok = false;
      dec += String.fromCharCode(c);
      return '';
    });
    if (!ok) return m;
    const printable = dec.replace(/[^\x20-\x7E]/g, '').length;
    if (dec.length && printable / dec.length > 0.85) { n++; return q + dec.replace(/\\/g, '\\\\').replace(new RegExp(q, 'g'), '\\' + q) + q; }
    return m;
  });
  out = out.replace(/(?:string\.)?char\s*\(\s*([\d\s,]+?)\s*\)/g, (m, nums) => {
    const codes = nums.split(',').map((x) => parseInt(x.trim(), 10)).filter(Number.isFinite);
    if (codes.length < 2 || codes.some((c) => c < 0 || c > 255)) return m;
    const str = String.fromCharCode(...codes);
    if (str.replace(/[^\x20-\x7E]/g, '').length / str.length < 0.85) return m;
    n++; return '"' + str.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  });
  return { out, n };
}

function beautify(src) {
  try {
    let s = src.replace(/\r\n/g, '\n');
    if (s.split('\n').length < 4) {
      s = s.replace(/\bthen\b/g, 'then\n').replace(/\bdo\b/g, 'do\n')
        .replace(/\bend\b/g, '\nend\n').replace(/\belse\b/g, '\nelse\n').replace(/;\s*/g, '\n');
    }
    const lines = s.split('\n'); let depth = 0; const out = [];
    for (const raw of lines) {
      const line = raw.trim(); if (!line) continue;
      const dedent = /^(end|else|elseif|until|\}|\))/.test(line);
      if (dedent) depth = Math.max(0, depth - 1);
      out.push('    '.repeat(depth) + line);
      const opens = (line.match(/\b(function|then|do|repeat)\b/g) || []).length + (line.match(/[\{(]\s*$/g) || []).length;
      const closes = (line.match(/\b(end|until)\b/g) || []).length + (line.match(/^[})]/g) || []).length;
      depth = Math.max(0, depth + opens - closes);
    }
    return out.join('\n');
  } catch { return src; }
}

function hasVM(src) {
  // Prometheus Vmify emits a dispatch loop over a numeric-indexed instruction
  // table; every non-Minify preset includes it.
  return /while\s+true\s+do/.test(src) && /\[\s*\d+\s*\]/.test(src) && /function\([\w,]*\)/.test(src);
}

function deobfuscate(src) {
  const notes = [];
  let work = src;
  const wm = stripWatermark(work); work = wm.out; if (wm.n) notes.push(`Stripped watermark (${wm.n}).`);
  const ds = decodeStrings(work); work = ds.out; if (ds.n) notes.push(`Decoded ${ds.n} encrypted/split string(s).`);
  const fn = foldNumbers(work); work = fn.out; if (fn.n) notes.push(`Folded ${fn.n} number expression(s) back to literals.`);
  if (hasVM(work)) {
    notes.push('Prometheus Vmify VM detected. Static layers reversed; full VM devirtualization is in progress (iterative). Output below is the de-VM-wrapped/decoded intermediate, not final source yet.');
  } else {
    notes.push('No VM layer detected (Minify/Weak-no-Vmify) — output should be close to original source.');
  }
  return { output: beautify(work), notes, partial: hasVM(work) };
}

module.exports = { deobfuscate };
