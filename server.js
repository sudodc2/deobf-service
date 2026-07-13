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
const crypto = require('node:crypto');

const { detectObfuscator, looksLikeLuraph } = require('./detect.js');
const ironveil = require('./tools/ironveil/index.js');
const prometheus = require('./prometheus_deobf.js');
const karma = require('./karma_deobf.js');
const kersone = require('./kersone_deobf.js');
const wearedevs = require('./wearedevs_deobf.js');
const generic = require('./generic_deobf.js');

const ROOT = __dirname;
const HERCULES = path.join(ROOT, 'tools/hercules/deobfhercules.py');
const MOONSEC_BIN = process.env.MOONSEC_BIN || path.join(ROOT, 'tools/moonsec/bin/Release/net9.0/MoonsecDeobfuscator');
const MOONVEIL_DECOMPILE = path.join(ROOT, 'tools/moonveil/moonveil_decompile.py');
const UNLUAC = process.env.UNLUAC_JAR || path.join(ROOT, 'tools/unluac.jar');

const MAX_BYTES = 3 * 1024 * 1024;
// Per-subprocess wall-clock cap. Heavy native tools (MoonSec .NET, unluac,
// Moonveil) used to run 60–120s each and stack, which — combined with Render
// cold starts — made the Discord command hang/time out. Bound them tightly so
// /deobf always returns quickly (falling back to Generic if a tool overruns).
const TOOL_TIMEOUT = parseInt(process.env.DEOBF_TOOL_TIMEOUT_MS || '25000', 10);

// SECURITY: submitted scripts are treated as inert data. The only tool that
// would *run* the input is the Moonveil tracer (it deserializes by executing
// under luau, whose stdlib has no io/os.execute/network). This now FAILS CLOSED:
// running attacker-controlled Lua is disabled unless an operator explicitly
// opts in with DEOBF_ALLOW_LUA_EXEC=1. Every other path is pure static
// analysis, so the default is fully safe; either way the tracer subprocess
// only ever sees SAFE_CHILD_ENV (no secrets).
const ALLOW_LUA_EXEC = process.env.DEOBF_ALLOW_LUA_EXEC === '1';
// Minimal env for child analysers: never leak our secrets (shared key, tokens)
// into a subprocess that might touch attacker-controlled input.
const SAFE_CHILD_ENV = { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: process.env.HOME || '/tmp' };

const app = express();
app.use(express.json({ limit: '6mb' }));

// Shared-secret gate so only the bot can call /deobf. Fails CLOSED: if the
// secret isn't configured, every non-health request is rejected rather than
// left open to the world.
const SHARED = process.env.DEOBF_SHARED_SECRET || '';

function timingSafeEq(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

app.use((req, res, next) => {
  if (req.path === '/health') return next();
  if (!SHARED) {
    console.error('DEOBF_SHARED_SECRET not configured — refusing request');
    return res.status(503).json({ ok: false, error: 'service unavailable' });
  }
  const key = req.get('x-deobf-key');
  if (key && timingSafeEq(key, SHARED)) return next();
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
  // Normalise IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) to its IPv4 form
  // so a mapped address can't smuggle a private target past the IPv4 checks.
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (m) ip = m[1];
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] === 0 ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127); // CGNAT
  }
  return ip === '::1' || ip === '::' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80');
}

async function assertPublicHost(hostname) {
  // Reject literals and resolved addresses that point at internal ranges. This
  // is checked for EVERY hop (initial + each redirect) so a public URL can't
  // 302 into the metadata service / loopback / RFC1918 space.
  if (net.isIP(hostname) && isPrivateIp(hostname)) throw new Error('blocked private address');
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) throw new Error('blocked private address');
}

async function safeFetch(url) {
  // Manual redirect following with per-hop SSRF validation. `redirect:'follow'`
  // would let a public URL bounce to a private one without re-checking, so we
  // resolve+validate every hop ourselves and cap the chain length.
  const MAX_REDIRECTS = 5;
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let u;
    try { u = new URL(current); } catch { throw new Error('bad url'); }
    if (!/^https?:$/.test(u.protocol)) throw new Error('unsupported protocol');
    await assertPublicHost(u.hostname);

    const res = await fetch(current, {
      redirect: 'manual',
      headers: { 'User-Agent': 'deobf-service' },
      signal: AbortSignal.timeout(20000),
    });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) throw new Error(`redirect ${res.status} without location`);
      current = new URL(loc, current).toString();
      continue;
    }
    if (!res.ok) throw new Error(`fetch ${res.status}`);
    // Reject on declared length first, then stream with a hard cap so a lying
    // Content-Length / chunked body can't buffer unbounded memory.
    const cl = parseInt(res.headers.get('content-length') || '0', 10);
    if (cl && cl > MAX_BYTES) throw new Error('remote too large');
    if (!res.body) {
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > MAX_BYTES) throw new Error('remote too large');
      return buf.toString('utf8');
    }
    const chunks = [];
    let total = 0;
    for await (const chunk of res.body) {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += b.length;
      if (total > MAX_BYTES) throw new Error('remote too large');
      chunks.push(b);
    }
    return Buffer.concat(chunks).toString('utf8');
  }
  throw new Error('too many redirects');
}

// Strip Lua comments so we can judge how much *real* code a script has (used to
// tell a thin loader stub apart from a full script that merely calls loadstring).
function stripLuaComments(src) {
  return src
    .replace(/--\[(=*)\[[\s\S]*?\]\1\]/g, '')
    .replace(/--[^\n]*/g, '');
}

// A "thin loader" is a script whose entire job is to fetch+run a remote payload
// (e.g. `loadstring(game:HttpGet("..."))()`), with essentially no logic of its
// own. We only auto-follow these — a full script that happens to call HttpGet is
// left alone so we don't chase its sub-modules.
function looksLikeThinLoader(src) {
  const code = stripLuaComments(src).replace(/\s+/g, ' ').trim();
  if (!code || code.length > 600) return false;
  if (!extractRemoteUrl(src)) return false;
  // Must be dominated by a loadstring/HttpGet/require-style fetch call.
  return /(loadstring|HttpGet|HttpGetAsync|GetAsync|readfile|request|http_request|syn\.request)/i.test(code);
}

// Detect an anti-bot / challenge / error HTML page returned instead of Lua so we
// stop the chain and report honestly instead of trying to "deobfuscate" HTML.
function looksLikeHtmlOrChallenge(src) {
  const h = src.slice(0, 600).toLowerCase();
  return /<!doctype html|<html|just a moment|cf-browser-verification|challenge-platform|attention required|cloudflare/.test(h);
}

// Terminal gated loaders: the luarmor `_bsdata` bootstrap (decrypts + fetches a
// key-locked script at runtime) and the luarmor "executor not supported" kick
// stub. Both are dead-ends for static recovery, so the chain stops here.
function isGatedTerminal(src) {
  if (/\b_bsdata\d*\s*=/.test(src) && /luarmor/i.test(src)) return 'luarmor key-gated bootstrap';
  if (/executor is not supported by luarmor/i.test(src)) return 'luarmor unsupported-executor stub';
  return null;
}

// Follow a chain of thin loaders (onyx -> luarmor -> ...) up to a small cap,
// re-using the SSRF-guarded fetch and refusing to revisit a URL. Returns the
// final payload + the visited chain + a stop reason for transparency.
async function resolveLoaderChain(startSrc, startUrl) {
  const MAX_LOADER_HOPS = 4;
  const chain = [];
  let src = startSrc;
  let seen = new Set(startUrl ? [startUrl] : []);
  let stop = null;
  for (let hop = 0; hop < MAX_LOADER_HOPS; hop++) {
    if (looksLikeHtmlOrChallenge(src)) { stop = 'anti-bot/challenge or non-Lua page'; break; }
    const gated = isGatedTerminal(src);
    if (gated) { stop = gated; break; }
    if (!looksLikeThinLoader(src)) break;
    const next = extractRemoteUrl(src);
    if (!next || seen.has(next)) { stop = next ? 'loader loop' : null; break; }
    seen.add(next);
    let fetched;
    try { fetched = await safeFetch(next); }
    catch (e) { stop = `could not fetch ${next} (${e && e.message})`; break; }
    chain.push(next);
    src = fetched;
  }
  return { src, chain, stop };
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'deob-'));
}

// Non-comment source length (a mostly-diagnostic dump reads as "thin").
function thinLen(out) {
  if (!out) return 0;
  return out.split('\n').filter((l) => l.trim() && !l.trim().startsWith('--')).join('').trim().length;
}
function isThinOutput(out) {
  return thinLen(out) < 40;
}

// ── per-obfuscator runners ──────────────────────────────────────────────────

function runHercules(src) {
  const d = tmpdir();
  const inp = path.join(d, 'in.lua'), out = path.join(d, 'out.lua');
  fs.writeFileSync(inp, src);
  const r = spawnSync('python3', [HERCULES, inp, out], { encoding: 'utf8', timeout: TOOL_TIMEOUT, env: SAFE_CHILD_ENV });
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
  const dev = spawnSync(MOONSEC_BIN, ['-dev', '-i', inp, '-o', bc], { encoding: 'utf8', timeout: TOOL_TIMEOUT, env: SAFE_CHILD_ENV });
  if (dev.status !== 0 || !fs.existsSync(bc)) throw new Error('moonsec devirt: ' + (dev.stderr || 'failed'));
  notes.push('MoonSec V3 devirtualized to Lua 5.1 bytecode.');
  // bytecode -> source via unluac if available
  let output = '';
  if (fs.existsSync(UNLUAC)) {
    const dec = spawnSync('java', ['-jar', UNLUAC, bc], { encoding: 'utf8', timeout: TOOL_TIMEOUT, maxBuffer: 16 * 1024 * 1024, env: SAFE_CHILD_ENV });
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

function runKersone(src) {
  // Static, deterministic replay of the Kers0ne "Base66 Multi-XOR" decoder.
  // Never executes the submitted script — it only re-runs the pure decode math.
  // The recovery is the byte-exact ORIGINAL source, so we return it as-is rather
  // than pushing it through the generic transformer (which could rewrite the
  // author's own legitimate code, e.g. fold a real `1+2`).
  const r = kersone.deobfuscate(src);
  const notes = [...(r.notes || [])];
  let output = r.output;

  // If the recovered layer is STILL obfuscated (another format, or an escape-
  // heavy custom decrypt stub), push it through the generic best-effort pass to
  // squeeze out more instead of stopping at an intermediate stub. Clean short
  // source (e.g. print("HI")) is left byte-exact.
  const escapeHits = (output.match(/\\\d{1,3}/g) || []).length;
  const inner = detectObfuscator(output);
  const stillObfuscated =
    escapeHits > 20 ||
    (inner.name && inner.confidence >= 30) ||
    /Kers0ne Obfuscator/i.test(output.slice(0, 200));
  if (stillObfuscated) {
    try {
      const g = generic.deobfuscate(output);
      if (g && g.output && g.output.trim().length > 0) {
        output = g.output;
        notes.push('The recovered layer was itself another custom decrypt stub — ran generic best-effort recovery on it to decode as much of the final source as possible.');
        for (const n of g.notes || []) notes.push(n);
      }
    } catch (_) { /* keep the byte-exact base66 recovery */ }
  }
  return { output, notes, recovered: r.recovered };
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
    encoding: 'utf8', timeout: TOOL_TIMEOUT, maxBuffer: 32 * 1024 * 1024,
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
        console.error('safeFetch(url) failed:', e && e.message);
        return res.status(400).json({ ok: false, error: 'could not fetch the provided URL' });
      }
    }
    if (!source) return res.status(400).json({ ok: false, error: 'no source or url' });
    if (Buffer.byteLength(source) > MAX_BYTES) return res.status(413).json({ ok: false, error: 'too large' });

    // A bare URL pasted as the script (no loadstring/HttpGet wrapper) means
    // "fetch this and deobfuscate what's there" — otherwise we'd just echo the
    // URL back as its own output.
    if (!fetchedFrom && /^https?:\/\/\S+$/i.test(source.trim())) {
      try { const u = source.trim(); source = await safeFetch(u); fetchedFrom = u; }
      catch (e) { console.error('safeFetch(bare) failed:', e && e.message); return res.status(400).json({ ok: false, error: 'could not fetch the provided URL' }); }
    }

    // loadstring/HttpGet stub -> fetch the real payload first. Record the reason
    // if the fetch fails so we can report a gated endpoint honestly instead of
    // silently echoing the loader line back as "recovered source".
    let loaderChain = [];
    let loaderStop = null;
    if (!fetchedFrom) {
      const stubUrl = extractRemoteUrl(source);
      if (stubUrl) {
        try { source = await safeFetch(stubUrl); fetchedFrom = stubUrl; }
        catch (e) { loaderStop = `could not fetch ${stubUrl} (${e && e.message})`; }
      }
    }

    // Follow further loader hops (e.g. onyxv2 -> luarmor loader -> ...). We only
    // chase scripts that are *nothing but* a loader stub, and stop at an anti-bot
    // page or a key-gated endpoint, reporting the chain + why we stopped.
    if (fetchedFrom) {
      const resolved = await resolveLoaderChain(source, fetchedFrom);
      if (resolved.chain.length) {
        source = resolved.src;
        loaderChain = resolved.chain;
        fetchedFrom = resolved.chain[resolved.chain.length - 1];
      }
      if (resolved.stop) loaderStop = resolved.stop;
    }

    // If, after following everything we safely can, the payload is STILL just a
    // loader stub (target un-fetchable) or an anti-bot/challenge page, don't
    // pretend we recovered source — report the gate honestly as a partial result.
    // A key-gated terminal (luarmor bootstrap / unsupported-executor stub) has no
    // end-source statically present, so treat it as loader-only rather than
    // claiming "full" recovery of the bootstrap.
    const gatedTerminal = isGatedTerminal(source);
    const finalIsLoader = looksLikeThinLoader(source) || !!gatedTerminal;
    const finalIsChallenge = looksLikeHtmlOrChallenge(source);
    if (finalIsLoader || finalIsChallenge) {
      const gateUrl = extractRemoteUrl(source) || fetchedFrom;
      const chainBlob = loaderChain.join(' ') + ' ' + (fetchedFrom || '') + ' ' + source;
      const isSyscure = /syscure/i.test(chainBlob);
      const isVoltils = /voltils/i.test(chainBlob);
      const notes = [];
      if (loaderChain.length) notes.push(`Followed loader chain (${loaderChain.length} hop${loaderChain.length > 1 ? 's' : ''}): ${loaderChain.join(' -> ')}`);
      if (isVoltils) {
        notes.push('Voltils is a key-system-gated loader served from behind a Cloudflare managed challenge, so the source is not statically fetchable:');
        notes.push('The `voltils.cc/load/<slug>/run` endpoint requires (1) a valid key obtained from their key channel and (2) passing a Cloudflare challenge — a plain HTTP client gets the challenge page (the 403 here), not the script. Only a keyed, verified executor session receives the real payload.');
        notes.push('To analyze the actual Voltils body, capture the final delivered script from your executor and submit that raw body — the service will then run best-effort recovery. I will not bypass the key system or the anti-bot challenge.');
      } else if (isSyscure) {
        notes.push('Syscure uses a multi-stage challenge-response delivery, so the source is not statically fetchable by design:');
        notes.push('1) grabber gate — a plain HTTP client (no executor User-Agent) is served a Cloudflare challenge / decoy, which is the 403 you see here. 2) single-use slug + executor math challenge. 3) IP-fingerprinted, one-time HMAC payload token (short TTL). 4) the final Lua is heavy-obfuscated per request. Only a real executor that solves the challenge in-session receives the payload.');
        notes.push('To analyze the actual Syscure body, capture the final delivered script from your executor and submit that raw body — the service will run best-effort recovery (decode strings/constants + structure). The final payload is a heavy per-request VM (Luraph-family method-table VM), so like Luraph it is best-effort, not guaranteed clean source. The loadstring URL alone cannot yield any source.');
      } else if (finalIsChallenge) {
        notes.push(`The endpoint (${fetchedFrom || gateUrl}) is behind an anti-bot/Cloudflare challenge, so its real body can't be fetched server-side. This is not a bypassable step — the actual script is delivered only to a verified client.`);
      } else if (gatedTerminal) {
        notes.push(`This resolves to a ${gatedTerminal}: it decrypts and fetches the real, key-locked script from the protection provider's servers at runtime. The underlying source is delivered only to a licensed/keyed client, so it is not statically present here.`);
      } else {
        notes.push(`This is a thin loader that fetches its real script at runtime from ${gateUrl || 'a remote endpoint'}. That endpoint is key-gated / not publicly fetchable, so the underlying source is not statically present here.`);
        if (loaderStop) notes.push(`Stopped at: ${loaderStop}.`);
      }
      notes.push('No obfuscated body was recovered — there is nothing to deobfuscate beyond the loader itself.');
      const urls = (source.match(URL_RE) || []).map((u) => u.replace(/[)\]"'`,;]+$/, ''));
      const dumpLines = [
        '-- Sudo Deobfuscator — loader analysis',
        '-- The submitted script is a thin loader; the real payload is fetched at runtime.',
        '',
        `-- ===== Loader chain (${loaderChain.length}) =====`,
        ...loaderChain.map((u, i) => `[${i + 1}] ${u}`),
        '',
        `-- ===== Remote URL(s) referenced (${urls.length}) =====`,
        ...urls.map((u, i) => `[${i + 1}] ${u}`),
      ];
      // Name the protection provider when we can (syscure/luarmor/…) so the label
      // is specific instead of a generic "Loader".
      const provider = detectObfuscator(source);
      const chainStr = loaderChain.join(' ') + ' ' + (fetchedFrom || '');
      let providerName = 'Loader';
      if (provider.name && provider.confidence >= 60) providerName = provider.name;
      else if (/voltils/i.test(chainStr)) providerName = 'Voltils';
      else if (/syscure/i.test(chainStr)) providerName = 'Syscure';
      else if (/luarmor/i.test(chainStr) || gatedTerminal) providerName = 'Luarmor';
      return res.json({
        ok: true,
        detected: { name: providerName, confidence: 90, signals: [finalIsChallenge ? 'anti-bot gated endpoint' : 'thin remote loader'] },
        tool: providerName === 'Loader' ? 'Loader' : `${providerName} (loader)`,
        fetchedFrom,
        loaderChain,
        output: source.trim(),
        partial: true,
        loaderOnly: true,
        notes,
        dump: dumpLines.join('\n') + '\n',
      });
    }
    const loaderNotes = [];
    if (loaderChain.length) loaderNotes.push(`Followed loader chain (${loaderChain.length} hop${loaderChain.length > 1 ? 's' : ''}): ${loaderChain.join(' -> ')}`);

    // Never deobfuscate our own Sudo-protected output. Detection uses visible
    // markers AND strip-resistant structural fingerprints, so removing the top
    // comment / invite / _SUDO_ globals no longer bypasses the refusal.
    if (generic.isSudoOwned(source)) {
      const structural = generic.sudoStructuralScore(source);
      const signals = structural >= 2 ? [`structural fingerprint (${structural}/5)`] : ['ownership marker'];
      return res.json({ ok: true, detected: { name: 'Sudo', confidence: 99, signals }, tool: 'Sudo', fetchedFrom, output: null, protected: true, notes: ['This script is protected by the Sudo obfuscation system. Deobfuscation is intentionally disabled for our own protection engine.'] });
    }

    // Kers0ne "Base66 Multi-XOR" is a very specific self-contained decoder;
    // give it its own high-confidence detection ahead of the generic detector.
    const kersoneScore = kersone.looksLikeKersone(source);
    const wearedevsScore = wearedevs.looksLikeWeAreDevs(source);
    let detected = detectObfuscator(source);
    if (kersoneScore >= 6 && kersoneScore >= detected.confidence / 15) {
      detected = { name: 'Kers0ne', confidence: Math.min(99, kersoneScore * 15), signals: [`base66 multi-xor (score ${kersoneScore})`] };
    }
    // WeAreDevs is a self-contained string-pool decoder + register VM; give it a
    // dedicated high-confidence route ahead of the generic detector.
    if (wearedevsScore >= 8) {
      detected = { name: 'WeAreDevs', confidence: Math.min(99, wearedevsScore * 9), signals: [`wearedevs vm (score ${wearedevsScore})`] };
    }
    // Luraph structural fingerprint — catches watermark-stripped builds (e.g.
    // onyxv2's ASCII banner) that the comment-based detector would miss/mislabel.
    const luraphScore = looksLikeLuraph(source);
    // Only claim Luraph when no stronger, more specific format already matched
    // (KarmaVM/WeAreDevs/etc. also use bit32/method-tables) — override weak or
    // already-Luraph/Moonveil guesses, never a high-confidence dedicated match.
    if (luraphScore >= 7 && (detected.confidence < 60 || /^(luraph|moonveil)$/i.test(detected.name || ''))) {
      detected = { name: 'Luraph', confidence: Math.min(99, luraphScore * 9), signals: [`luraph vm (structural score ${luraphScore})`] };
    }
    const which = forced || ((detected.confidence >= 30 ? detected.name : '') || '').toLowerCase();
    let result;
    let tool = detected.name || forced;
    try {
      if (which.includes('kers')) result = runKersone(source);
      else if (which.includes('wearedevs')) {
        result = wearedevs.deobfuscate(source);
        if (result && result._fallback) result = generic.deobfuscate(source);
      }
      else if (which.includes('hercules')) result = runHercules(source);
      else if (which.includes('ironveil')) result = runIronveil(source);
      else if (which.includes('moonsec')) result = runMoonSec(source);
      else if (which.includes('prometheus')) result = prometheus.deobfuscate(source);
      else if (which.includes('moonveil')) result = runMoonveilStatic(source);
      // KarmaProtect = static string-transform obfuscator (dedicated decoder).
      // "KarmaVM"/"Luraph" are runtime bytecode VMs with no static full-source
      // recovery — fall through to generic best-effort (keeps the detected name).
      else if (which.includes('karma') && !which.includes('karmavm')) result = karma.deobfuscate(source);
      else {
        // No named format matched — attempt best-effort generic recovery on ANY
        // input instead of giving up.
        result = generic.deobfuscate(source);
        tool = 'Generic';
      }
    } catch (toolErr) {
      // A named tool failed: fall back to generic best-effort rather than erroring.
      // Log the real error server-side; never leak it in the public response.
      console.error('named tool failed:', detected.name || forced, toolErr && toolErr.message);
      try {
        const g = generic.deobfuscate(source);
        return res.json({ ok: true, detected, tool: 'Generic', fetchedFrom, ...g, notes: [`Detected ${detected.name || forced} but its dedicated deobfuscator failed; returning generic best-effort recovery instead.`, ...(g.notes || [])] });
      } catch (_) {
        return res.json({ ok: true, detected, tool: detected.name || forced, fetchedFrom, output: null, notes: [`Detected ${detected.name || forced} but the deobfuscator failed.`], failed: true });
      }
    }

    // Guarantee useful output: if a named tool recovered almost nothing (only
    // diagnostics/comments — e.g. a VM format it can't fully devirtualize, or a
    // misdetection), fall back to generic best-effort so the user always gets
    // as much real recovery as possible instead of an empty/diagnostic dump.
    if (tool !== 'Generic' && result && !result.protected && isThinOutput(result.output)) {
      try {
        const g = generic.deobfuscate(source);
        const gLen = g && g.output ? g.output.trim().length : 0;
        if (gLen > thinLen(result.output)) {
          result = { ...g, notes: [`Detected ${detected.name || tool}, but its dedicated pass recovered little source here; returning generic best-effort recovery instead.`, ...(g.notes || [])] };
          tool = 'Generic';
        }
      } catch (_) { /* keep the tool's partial output */ }
    }

    // Prefer the WeAreDevs full constant-pool dump when that route ran; else the
    // generic string/number dump built from the reconstructed output.
    let dump = null;
    if (result && !result.protected && !result.refused) {
      if (which.includes('wearedevs')) dump = wearedevs.buildDump(source) || null;
      if (!dump && result.output) dump = generic.buildDump(result.output);
    }
    // Don't surface a sub-threshold detector guess as if it were identified.
    // If the label wasn't confident enough to route (which===''), present it as
    // unrecognized rather than misleading (e.g. a 15%-confidence "Moonveil").
    let outDetected = detected;
    if (!which && detected && detected.confidence < 30) {
      outDetected = { name: null, confidence: 0, signals: ['no known-format signature (generic best-effort)'] };
    }
    if (loaderNotes.length && result) result = { ...result, notes: [...loaderNotes, ...(result.notes || [])] };
    // Voltils v7.4 is a heavy compile-to-VM obfuscator (a ~20-byte input expands
    // to ~100KB): an encoded constant-pool blob + `z()`-indexed string builders
    // with per-request-randomised offsets, in the Luraph family. Static recovery
    // is therefore best-effort (decoded escapes/numbers + structure), not clean
    // original source — be explicit so we never over-claim.
    if (result && !result.protected && /^voltils$/i.test(outDetected.name || '')) {
      result = { ...result, partial: true, notes: ['Voltils Obfuscation v7.4 is a compile-to-VM obfuscator (Luraph-family): the real source is compiled into a virtual machine over an encoded constant pool with per-request-randomised indexing, so like Luraph this is best-effort recovery (normalised literals + structure), not byte-exact original source.', ...(result.notes || [])] };
    }
    return res.json({ ok: true, detected: outDetected, tool, fetchedFrom, loaderChain, ...result, dump });
  } catch (e) {
    console.error('deobf handler error:', e && e.stack ? e.stack : e);
    return res.status(500).json({ ok: false, error: 'internal error' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`deobf-service on :${PORT}`));
