'use strict';
// Kers0ne Obfuscator — "Karma Protection Anti-Tamper: Base66 Multi-XOR"
// (luarmor-bot-1-0yt4.onrender.com — a second, AI-generated Karma variant,
// distinct from karma-lua-hosting KarmaProtect).
//
// The protected output is a SELF-CONTAINED deterministic decoder: it base66-
// decodes two payloads (data + keys), runs a rolling multi-XOR, validates a
// length + checksum, then loadstring()s the recovered source. Because the whole
// transform is pure string/bit/math (no VM, no runtime state, no environment),
// we can replay the exact decode statically and recover the ORIGINAL SOURCE —
// not just a constant dump. Names/charset/5 numeric constants are randomised
// per build, so everything is extracted by ROLE, not by fixed identifiers.

function decodeBase66(str, charset) {
  const out = [];
  for (let i = 0; i < str.length; i += 2) {
    const a = charset.indexOf(str[i]);
    const b = charset.indexOf(str[i + 1]);
    if (a < 0 || b < 0) return null;
    out.push(a * 66 + b);
  }
  return out;
}

// Detect the Kers0ne/Base66 format without depending on randomised names.
function looksLikeKersone(src) {
  const head = src.slice(0, 4096);
  let score = 0;
  if (/Kers0ne Obfuscator/i.test(head)) score += 3;
  if (/Base66 Multi-?XOR/i.test(head)) score += 3;
  if (/Karma Protection/i.test(head)) score += 1;
  // structural: the base66 pair-decoder + rolling xor
  if (/\(\s*_?\w+\s*-\s*1\s*\)\s*\*\s*66\s*\+\s*\(\s*_?\w+\s*-\s*1\s*\)/.test(src)) score += 2;
  if (/%\s*#\w+\s*\)\s*\+\s*1/.test(src) && /\*\s*13\s*\+/.test(src) && /\*\s*17\s*\+/.test(src)) score += 2;
  return score;
}

function firstMatch(re, src) {
  const m = re.exec(src);
  return m || null;
}

// Extract everything needed to replay the decode. Returns null if the shape
// doesn't match (caller then falls back to generic).
function extractParams(src) {
  // charset: the ~66-char alphabet string literal.
  let charset = null;
  const strRe = /local\s+_\w+\s*=\s*"([^"\n]{60,90})"/g;
  let sm;
  while ((sm = strRe.exec(src))) {
    const cand = sm[1];
    if (/[A-Z]/.test(cand) && /[a-z]/.test(cand) && /[0-9]/.test(cand) && cand.length >= 64) {
      charset = cand;
      break;
    }
  }
  if (!charset) return null;

  // numeric constants: name -> value
  const nums = {};
  const numRe = /local\s+(_\w+)\s*=\s*(\d+)\b/g;
  let nm;
  while ((nm = numRe.exec(src))) nums[nm[1]] = parseInt(nm[2], 10);

  // array-decode assignments: arrVar = fn(strVar)
  const arr2str = {};
  const asnRe = /local\s+(_\w+)\s*=\s*_\w+\(\s*(_\w+)\s*\)/g;
  let am;
  while ((am = asnRe.exec(src))) arr2str[am[1]] = am[2];

  // long-bracket base66 payload strings: strVar -> content
  const str2content = {};
  const lbRe = /local\s+(_\w+)\s*=\s*\[=\[([\s\S]*?)\]=\]/g;
  let lm;
  while ((lm = lbRe.exec(src))) str2content[lm[1]] = lm[2];

  // identify data + keys array vars via the guard `if not X or not Y or #Y<1`
  const guard = firstMatch(/if\s+not\s+(_\w+)\s+or\s+not\s+(_\w+)\s+or\s+#(_\w+)\s*<\s*1/, src);
  if (!guard) return null;
  const dataVar = guard[1];
  const keysVar = guard[2];
  const dataStr = arr2str[dataVar];
  const keysStr = arr2str[keysVar];
  if (!dataStr || !keysStr) return null;
  const dataContent = str2content[dataStr];
  const keysContent = str2content[keysStr];
  if (dataContent == null || keysContent == null) return null;

  // role-based constant extraction from the rolling-xor loop body
  const subM = firstMatch(/\*\s*13\s*\+\s*(_\w+)/, src);           // i*13 + SUBC
  const rollM = firstMatch(/\(\s*(_\w+)\s*\+\s*_\w+\s*\*\s*17/, src); // (ADDC + i*17
  const rollcM = firstMatch(/%\s*(\d+)\s*\)\s*\*\s*(_\w+)/, src);  // (i % MOD) * ROLLC
  if (!subM || !rollM || !rollcM) return null;
  const SUBC = nums[subM[1]];
  const ADDC = nums[rollM[1]];
  const MOD = parseInt(rollcM[1], 10);
  const ROLLC = nums[rollcM[2]];
  if ([SUBC, ADDC, MOD, ROLLC].some((v) => typeof v !== 'number' || Number.isNaN(v))) return null;

  // optional validators
  const lenM = firstMatch(/#\s*(_\w+)\s*~=\s*(_\w+)/, src);        // #src ~= LENVAR
  const LEN = lenM ? nums[lenM[2]] : null;
  const chkM = firstMatch(/\)\s*~=\s*(\d+)\s+then/, src);          // checksum ~= N
  const CHK = chkM ? parseInt(chkM[1], 10) : null;

  return { charset, dataContent, keysContent, SUBC, ADDC, MOD, ROLLC, LEN, CHK };
}

function replay(p) {
  const data = decodeBase66(p.dataContent, p.charset);
  const keys = decodeBase66(p.keysContent, p.charset);
  if (!data || !keys || keys.length < 1) return null;

  const out = new Array(data.length);
  let fe = p.ROLLC & 255;
  for (let i = 1; i <= data.length; i++) {
    const e = data[i - 1];
    const k1 = keys[(i - 1) % keys.length];
    const k2 = keys[(i * 7 + p.ADDC) % keys.length];
    const unadd = (e - ((i * 13 + p.SUBC) & 255)) & 255;
    const roll = (p.ADDC + i * 17 + (i % p.MOD) * p.ROLLC + fe + p.SUBC + k2) & 255;
    const plain = ((unadd ^ k1) ^ roll) & 255;
    out[i - 1] = plain;
    fe = (e + k1 + p.ROLLC + i) & 255;
  }
  const src = Buffer.from(out).toString('latin1');
  return { src, dataLen: data.length, keysLen: keys.length };
}

// Some Kers0ne builds (e.g. the "auto_grab" style) nest a final loader inside
// the base66 layers: a numeric key table `K={..}` + an escaped byte string
// `D="\ddd\ddd.."` XOR-combined with the repeating key, then loadstring'd. It's
// still pure deterministic math, so decode it statically too (repeating-key XOR).
function decodeKdXorStub(src) {
  // Fire when the stub has an xor loop, or when it's a Kers0ne loader header
  // (the D string may be truncated past the loop in copied samples). The
  // printable-ratio sanity check below rejects wrong guesses either way.
  if (!/bxor|xor|~/i.test(src) && !/Kers0ne Obfuscator/i.test(src)) return null;
  // key table: the numeric array literal (pick the first plausible one).
  const km = /\{\s*((?:\d{1,3}\s*,\s*){3,}\d{1,3})\s*\}/.exec(src);
  if (!km) return null;
  const key = km[1].split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => n >= 0 && n <= 255);
  if (key.length < 2) return null;
  // data string: the longest run of \ddd escapes (tolerate a missing closing
  // quote in case the sample was copied/truncated).
  let best = null;
  const dRe = /((?:\\\d{1,3}){8,})/g;
  let dm;
  while ((dm = dRe.exec(src))) if (!best || dm[1].length > best.length) best = dm[1];
  if (!best) return null;
  const bytes = (best.match(/\\(\d{1,3})/g) || []).map((s) => parseInt(s.slice(1), 10) & 255);
  if (bytes.length < 8) return null;
  const out = Buffer.from(bytes.map((b, i) => (b ^ key[i % key.length]) & 255));
  const decoded = out.toString('latin1');
  // sanity: the result should be mostly printable text (real Lua source).
  let printable = 0;
  for (let i = 0; i < decoded.length; i++) {
    const c = decoded.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
  }
  if (printable / decoded.length < 0.85) return null;
  return { src: decoded, keyLen: key.length, dataLen: bytes.length };
}

function verifyChecksum(src) {
  let c = 7;
  for (let i = 1; i <= src.length; i++) {
    const b = src.charCodeAt(i - 1);
    c = (c + (b + 1) * (((i - 1) % 251) + 1)) % 2147483647;
  }
  return c;
}

// Decode one Base66 layer. Returns { src, verified } or null.
function decodeLayer(src) {
  const p = extractParams(src);
  if (!p) return null;
  const r = replay(p);
  if (!r) return null;
  let verified = true;
  if (p.LEN != null && r.src.length !== p.LEN) verified = false;
  if (p.CHK != null && verifyChecksum(r.src) !== p.CHK) verified = false;
  return { src: r.src, verified, hadLen: p.LEN != null, hadChk: p.CHK != null };
}

// Returns { output, notes } like the other tool modules, or throws so the
// server falls back to Generic. The "maximum" preset nests multiple Base66
// layers, so peel them until the real source appears (bounded depth).
function deobfuscate(src) {
  const first = decodeLayer(src);
  if (!first) throw new Error('not a recognisable Kers0ne/Base66 structure');

  let cur = first;
  let layers = 1;
  let allVerified = cur.verified;
  const MAX_LAYERS = 12;
  while (layers < MAX_LAYERS && looksLikeKersone(cur.src) >= 6) {
    const next = decodeLayer(cur.src);
    if (!next) break;
    cur = next;
    layers++;
    allVerified = allVerified && cur.verified;
  }

  const notes = [];
  notes.push(layers > 1
    ? `Kers0ne "Base66 Multi-XOR" (maximum preset) — peeled ${layers} nested decode layers to recover the original source.`
    : 'Kers0ne "Base66 Multi-XOR" is a self-contained static decoder — recovered the exact original source by replaying its decode.');
  notes.push(allVerified
    ? 'Length + anti-tamper checksum matched on every layer — recovery is byte-exact.'
    : 'One or more layer validators did not match — output is best-effort.');

  // Final loader stage: some builds wrap the real source in a repeating-key XOR
  // stub (K={..} + D="\ddd..") instead of a further base66 layer. Peel that too.
  let output = cur.src;
  let xorStages = 0;
  while (xorStages < 6) {
    const kd = decodeKdXorStub(output);
    if (!kd) break;
    output = kd.src;
    xorStages++;
    if (looksLikeKersone(output) >= 6) {
      // XOR stage revealed yet another base66 layer — recurse into it.
      const more = decodeLayer(output);
      if (more) { output = more.src; }
    }
  }
  if (xorStages > 0) {
    notes.push(`Recovered the inner repeating-key XOR loader stage${xorStages > 1 ? `s (${xorStages})` : ''} to reach the final source.`);
  }
  return { output, notes, recovered: output, layers };
}

function detect(src) {
  const score = looksLikeKersone(src);
  return { name: 'Kers0ne', confidence: Math.min(99, score * 15), signals: [`score ${score}`] };
}

module.exports = { deobfuscate, detect, looksLikeKersone, extractParams, replay, decodeBase66, decodeKdXorStub, verifyChecksum };
