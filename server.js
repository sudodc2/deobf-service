'use strict';
// Deobfuscation backend service.
// POST /deobf { source?, url?, type? } -> { ok, detected, tool, output, notes, artifacts }
// Runs the real per-obfuscator tools installed in the image.

const express = require('express');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const dns = require('node:dns').promises;
const net = require('node:net');

const { detectObfuscator } = require('./detect.js');
const ironveil = require('./tools/ironveil/index.js');
const prometheus = require('./prometheus_deobf.js');
const karma = require('./karma_deobf.js');
const generic = require('./generic_deobf.js');

const ROOT = __dirname;
const HERCULES = path.join(ROOT, 'tools/hercules/deobfhercules.py');
const MOONSEC_BIN = process.env.MOONSEC_BIN || path.join(ROOT, 'tools/moonsec/bin/Release/net9.0/MoonsecDeobfuscator');
const MOONVEIL_DECOMPILE = path.join(ROOT, 'tools/moonveil/moonveil_decompile.py');
const UNLUAC = process.env.UNLUAC_JAR || path.join(ROOT, 'tools/unluac.jar');

const MAX_BYTES = 3 * 1024 * 1024;

// SECURITY: submitted scripts are treated as inert data. The only tool that
// would *run* the input is the Moonveil tracer (it deserializes by executing
// under luau, whose stdlib has no io/os.execute/network). Set
// DEOBF_ALLOW_LUA_EXEC=0 to disable script execution entirely; either way the
// tracer subprocess only ever sees SAFE_CHILD_ENV (no secrets).
const ALLOW_LUA_EXEC = process.env.DEOBF_ALLOW_LUA_EXEC !== '0';
// Minimal env for child analysers: never leak our secrets (shared key, tokens)
// into a subprocess that might touch attacker-controlled input.
const SAFE_CHILD_ENV = { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: process.env.HOME || '/tmp' };

const app = express();
app.use(express.json({ limit: '6mb' }));

// Optional shared-secret gate so only the bot can call /deobf.
const SHARED = process.env.DEOBF_SHARED_SECRET || '';
app.use((req, res, next) => {
  if (req.path === '/health' || !SHARED) return next();
  if (req.get('x-deobf-key') === SHARED) return next();
  return res.status(401).json({ ok: false, error: 'unauthorized' });
});

// ── SSRF-guarded remote fetch for loadstring/HttpGet URLs ───────────────────
const URL_RE = /https?:\/\/[^\s"'`)\]]+/g;
const FETCH_HINTS = [/game:HttpGet/i, /HttpGet\s*\(/i, /loadstring\s*\(/i, /syn\.request/i, /request\s*\(\s*\{/i];

function extractRemoteUrl(src) {
  if (!FETCH_HINTS.some((re) => re.test(src))) return null;
  const urls = src.match(URL_RE);
  if (!urls) return null;
  const pref = urls.find((u) => /raw|pastebin|paste|gist|githubusercontent|\.lua($|\?)/i.test(u));
  return (pref || urls[0]).replace(/[)\]"'`,;]+$/, '');
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] === 0;
  }
  return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80');
}

async function safeFetch(url) {
  let u;
  try { u = new URL(url); } catch { throw new Error('bad url'); }
  if (!/^https?:$/.test(u.protocol)) throw new Error('unsupported protocol');
  const addrs = await dns.lookup(u.hostname, { all: true });
  if (addrs.some((a) => isPrivateIp(a.address))) throw new Error('blocked private address');
  const res = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': 'deobf-service' } });
  if (!res.ok) throw new Error(`fetch ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_BYTES) throw new Error('remote too large');
  return buf.toString('utf8');
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'deob-'));
}

// ── per-obfuscator runners ──────────────────────────────────────────────────

function runHercules(src) {
  const d = tmpdir();
  const inp = path.join(d, 'in.lua'), out = path.join(d, 'out.lua');
  fs.writeFileSync(inp, src);
  const r = spawnSync('python3', [HERCULES, inp, out], { encoding: 'utf8', timeout: 60000, env: SAFE_CHILD_ENV });
  if (r.status !== 0 || !fs.existsSync(out)) throw new Error('hercules: ' + (r.stderr || 'no output'));
  return { output: fs.readFileSync(out, 'utf8'), notes: ['Hercules static devirtualization — full source recovery.'] };
}

function runIronveil(src) {
  const out = ironveil.deobfuscate(src);
  return { output: out, notes: ['Ironveil devirtualization — full recovery.'] };
}

function runMoonSec(src) {
  if (!fs.existsSync(MOONSEC_BIN)) throw new Error('MoonSec tool not built in this image');
  const d = tmpdir();
  const inp = path.join(d, 'in.lua'), bc = path.join(d, 'out.luac'), asm = path.join(d, 'out.asm');
  fs.writeFileSync(inp, src);
  const notes = [];
  const dev = spawnSync(MOONSEC_BIN, ['-dev', '-i', inp, '-o', bc], { encoding: 'utf8', timeout: 90000, env: SAFE_CHILD_ENV });
  if (dev.status !== 0 || !fs.existsSync(bc)) throw new Error('moonsec devirt: ' + (dev.stderr || 'failed'));
  notes.push('MoonSec V3 devirtualized to Lua 5.1 bytecode.');
  // disassembly for reference
  spawnSync(MOONSEC_BIN, ['-dis', '-i', inp, '-o', asm], { encoding: 'utf8', timeout: 90000, env: SAFE_CHILD_ENV });
  // bytecode -> source via unluac if available
  let output = '';
  if (fs.existsSync(UNLUAC)) {
    const dec = spawnSync('java', ['-jar', UNLUAC, bc], { encoding: 'utf8', timeout: 90000, maxBuffer: 16 * 1024 * 1024, env: SAFE_CHILD_ENV });
    if (dec.status === 0 && dec.stdout && dec.stdout.trim()) {
      output = dec.stdout;
      notes.push('Bytecode decompiled to source via unluac.');
    }
  }
  const artifacts = { 'out.luac.b64': fs.readFileSync(bc).toString('base64') };
  if (fs.existsSync(asm)) artifacts['out.asm'] = fs.readFileSync(asm, 'utf8');
  if (!output) {
    output = fs.existsSync(asm) ? fs.readFileSync(asm, 'utf8') : '-- MoonSec: recovered bytecode (see out.luac artifact)';
    notes.push('Source decompiler unavailable — returning disassembly + raw bytecode artifact.');
  }
  return { output, notes, artifacts };
}

function runMoonveilStatic(src) {
  const d = tmpdir();
  const inp = path.join(d, 'in.lua');
  const out = path.join(d, 'moonveil_decompiled.lua');
  fs.writeFileSync(inp, src);
  const mvEnv = { ...SAFE_CHILD_ENV, MOONVEIL_OUT_DIR: d };
  if (!ALLOW_LUA_EXEC) mvEnv.MOONVEIL_NO_EXEC = '1';
  if (process.env.MOONVEIL_LUAU) mvEnv.MOONVEIL_LUAU = process.env.MOONVEIL_LUAU;
  if (process.env.LUAU_BIN) mvEnv.LUAU_BIN = process.env.LUAU_BIN;
  const r = spawnSync('python3', [MOONVEIL_DECOMPILE, inp, out], {
    encoding: 'utf8', timeout: 120000, maxBuffer: 32 * 1024 * 1024,
    cwd: path.dirname(MOONVEIL_DECOMPILE),
    env: mvEnv,
  });
  let output = '';
  if (fs.existsSync(out)) output = fs.readFileSync(out, 'utf8');
  if (!output.trim()) output = '-- Moonveil static pass produced no source.\n-- ' + String(r.stdout || r.stderr || '').split('\n').filter(Boolean).slice(-6).join('\n-- ');
  return {
    output,
    notes: [
      'Moonveil static pass (strings/disasm/CFG). Partial by design.',
      'Moonveil is environment-locked: full source recovery needs a runtime trace from your Roblox executor (two-phase). Use /moonveil-trace to get the harness.',
    ],
    partial: true,
  };
}

// ── main endpoint ────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/deobf', async (req, res) => {
  try {
    let source = typeof req.body.source === 'string' ? req.body.source : '';
    let fetchedFrom = null;
    const forced = req.body.type ? String(req.body.type).toLowerCase() : null;

    if (req.body.url) {
      try {
        source = await safeFetch(String(req.body.url));
        fetchedFrom = String(req.body.url);
      } catch (e) {
        return res.status(400).json({ ok: false, error: `fetch failed: ${String(e.message || e)}` });
      }
    }
    if (!source) return res.status(400).json({ ok: false, error: 'no source or url' });
    if (Buffer.byteLength(source) > MAX_BYTES) return res.status(413).json({ ok: false, error: 'too large' });

    // A bare URL pasted as the script (no loadstring/HttpGet wrapper) means
    // "fetch this and deobfuscate what's there" — otherwise we'd just echo the
    // URL back as its own output.
    if (!fetchedFrom && /^https?:\/\/\S+$/i.test(source.trim())) {
      try { const u = source.trim(); source = await safeFetch(u); fetchedFrom = u; }
      catch (e) { return res.status(400).json({ ok: false, error: `fetch failed: ${String(e.message || e)}` }); }
    }

    // loadstring/HttpGet stub -> fetch the real payload first
    if (!fetchedFrom) {
      const stubUrl = extractRemoteUrl(source);
      if (stubUrl) {
        try { source = await safeFetch(stubUrl); fetchedFrom = stubUrl; } catch (e) { /* keep original */ }
      }
    }

    // Never deobfuscate our own Sudo-protected output.
    if (generic.isSudoOwned(source)) {
      return res.json({ ok: true, detected: { name: 'Sudo', confidence: 99, signals: ['ownership marker'] }, tool: 'Sudo', fetchedFrom, output: null, protected: true, notes: ['This script is protected by the Sudo obfuscation system. Deobfuscation is intentionally disabled for our own protection engine.'] });
    }

    const detected = detectObfuscator(source);
    const which = forced || ((detected.confidence >= 30 ? detected.name : '') || '').toLowerCase();
    let result;
    let tool = detected.name || forced;
    try {
      if (which.includes('hercules')) result = runHercules(source);
      else if (which.includes('ironveil')) result = runIronveil(source);
      else if (which.includes('moonsec')) result = runMoonSec(source);
      else if (which.includes('prometheus')) result = prometheus.deobfuscate(source);
      else if (which.includes('moonveil')) result = runMoonveilStatic(source);
      else if (which.includes('karma')) result = karma.deobfuscate(source);
      else {
        // No named format matched — attempt best-effort generic recovery on ANY
        // input instead of giving up.
        result = generic.deobfuscate(source);
        tool = 'Generic';
      }
    } catch (toolErr) {
      // A named tool failed: fall back to generic best-effort rather than erroring.
      try {
        const g = generic.deobfuscate(source);
        return res.json({ ok: true, detected, tool: 'Generic', fetchedFrom, ...g, notes: [`Detected ${detected.name || forced} but its dedicated deobfuscator failed (${String(toolErr.message || toolErr)}); returning generic best-effort recovery instead.`, ...(g.notes || [])] });
      } catch (_) {
        return res.json({ ok: true, detected, tool: detected.name || forced, fetchedFrom, output: null, notes: [`Detected ${detected.name || forced} but the deobfuscator failed: ${String(toolErr.message || toolErr)}`], failed: true });
      }
    }

    return res.json({ ok: true, detected, tool, fetchedFrom, ...result });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`deobf-service on :${PORT}`));
