'use strict';
// Obfuscator detection — scoped to the 5 supported obfuscators.

const KNOWN = [
  {
    name: 'Hercules',
    banner: /Obfuscated by Hercules/i,
    marks: [/Obfuscated by Hercules/i, /hercules-obfuscator\.xyz/i],
    struct: [/_ENV\s*\)\s*\(\s*\)/, /getfenv/],
  },
  {
    name: 'Ironveil',
    marks: [/Obfuscated using ironveil/i, /ironveil\b/i],
    struct: [/return\(function\(\.\.\.\)return\(function\(\.\.\.\)/],
  },
  {
    name: 'Prometheus',
    banner: /Prometheus Obfuscator by|This Script is Part of the Prometheus/i,
    marks: [/Prometheus Obfuscator by levno-710/i, /This Script is Part of the Prometheus/i, /__prometheus_/, /_WATERMARK/],
    // ConstantArray rotate/shuffle decoder + WrapInFunction shell — survives
    // variable renaming, so it fingerprints even a "Weak" build.
    struct: [/{(?:\s*"\\\d{2,3})+/, /for\s+\w+,\w+\s+in\s+ipairs\s*\(\s*\{\s*\{|return\s*\(\s*function\s*\(\s*\.\.\.\s*\)/],
  },
  {
    name: 'WeAreDevs',
    banner: /wearedevs\.net\/obfuscator/i,
    // WeAreDevs is Prometheus under the hood — --[[ vX https://wearedevs.net/obfuscator ]]
    // banner + local a={"\ddd";"\ddd";...} escaped-string const table.
    marks: [/wearedevs/i, /wearedevs\.net/i],
    struct: [/local\s+\w+\s*=\s*\{(?:\s*"\\\d{2,3})+/, /(\\\d{2,3}){20,}/],
  },
  {
    name: 'MoonSec',
    marks: [/moonsec/i, /moonsec\.(to|com|net)/i, /MoonSecV?\s*3/i],
    // real MoonSec signature: `c%0x...` hex-remainder arithmetic inside the
    // decode loop + the giant escaped-string blob — the function()...shell +
    // \ddd alone matched Ferib/IronBrew too loosely.
    struct: [/%0x[0-9a-fA-F]/, /(\\\d{1,3}){40,}|local\s+\w\s*=\s*string\.byte/],
  },
  {
    name: 'Moonveil',
    marks: [/moonveil/i],
    struct: [/function\s+\w+\([\w,]{3,20}\)/, /\[\d{4,5}\]/],
  },
  {
    name: 'Kers0ne',
    banner: /Protected By Kers0ne/i,
    marks: [/Protected By Kers0ne Obfuscator/i, /Base66 Multi-?XOR/i],
    // the base66 pair decoder `(a-1)*66+(b-1)` is unique enough on its own to
    // fingerprint the format even without the header comment.
    struct: [/\(\s*_?\w+\s*-\s*1\s*\)\s*\*\s*66\s*\+\s*\(\s*_?\w+\s*-\s*1\s*\)/],
  },
  {
    name: 'Luraph',
    // Luraph is the strongest commercial Lua obfuscator. Watermark comment
    // (`Luraph Obfuscator vX` / lura.ph) plus its `LPH!`/`LPH|` bytecode blob
    // markers. Full source recovery is not statically achievable — routed to
    // best-effort recovery.
    marks: [/Luraph Obfuscator/i, /lura\.ph/i, /LPH_?(NO_VIRTUALIZE|JIT|ENCFUNC)/],
    struct: [/return\s*\(\s*\{/, /LPH[!|]/],
  },
  {
    name: 'KarmaVM',
    // "Karma Obfuscator [luarmor-bot...]" — a runtime register-VM (distinct
    // from KarmaProtect's static string transforms). Its constant-fetch table
    // `o.h`/`L[...]` register model + luarmor-bot host fingerprint it.
    marks: [/Karma Obfuscator/i, /luarmor-bot/i],
    struct: [/return\s*\(\s*\{\s*\w+\s*=\s*function\s*\(/, /\bL\[\d{3,5}\]/],
  },
  {
    name: 'Voltils',
    // Voltils (voltils.cc/load/<slug>/run) — a key-system-gated loader delivered
    // from behind a Cloudflare managed challenge. The loadstring host + `/load/…/run`
    // route are the reliable fingerprint; the real script is served only to a keyed,
    // verified executor session.
    marks: [/voltils\.cc/i, /Voltils Obfuscation v[\d.]+/i, /dsc\.gg\/Voltils/i, /\bvoltils\b/i],
    // Body fingerprints: the `__voltils_<rand>` global the header installs, and the
    // loadstring `/load/<slug>/run` route. Either raises confidence past threshold.
    struct: [/__voltils_[A-Za-z0-9]+/, /voltils\.cc\/load\/[A-Za-z0-9_-]+\/run/i],
  },
  {
    name: 'Syscure',
    // Syscure (auth.syscure.vip / syscure.vip) delivers its obfuscated payload
    // from a `/obf/<hash>.lua` endpoint that sits behind a Cloudflare anti-bot
    // challenge, so the loadstring host is the reliable fingerprint. The payload
    // itself (when a raw body is submitted) is a Luau method-table VM similar to
    // the Luraph family — routed to best-effort recovery.
    marks: [/syscure\.vip/i, /\bsyscure\b/i],
    struct: [/\/obf\/[0-9a-f]{16,}\.lua/i],
  },
  {
    name: 'Pew',
    // Pew v1 (ex-Luraph dev). No watermark — it's a control-flow-flattened
    // register VM emitted as one line: `return(function(<many 2-char params>,...)`
    // followed by a `while(<var>)do if((<var>)<=(<num>))then …` numeric state
    // dispatch with deeply nested comparisons and uppercase hex (`0XB`) literals.
    // Structural-only fingerprint; routed to best-effort recovery (it's a VM).
    marks: [/\bPew\s+Obfuscator\b/i],
    struct: [
      /^return\s*\(\s*function\s*\(\s*(?:[A-Za-z]{2}\s*,\s*){30,}\.\.\.\s*\)/,
      /while\s*\(\s*\w{2}\s*\)\s*do\s+if\s*\(\s*\(\s*\w{2}\s*\)\s*<=\s*\(\s*\d/,
    ],
  },
  {
    name: 'KarmaProtect',
    marks: [/Protected By Karma Lua Hosting/i, /--\[\[karma:\d+\]\]/, /karma-lua-hosting/i],
    // return(function(...) ... end)(...) shell + the string.char/byte alias
    // preamble it always emits — survives every option toggle.
    struct: [
      /return\s*\(\s*function\s*\(\s*\.\.\.\s*\)/,
      /local\s+\w+\s*=\s*string\.char\s*;\s*local\s+\w+\s*=\s*string\.byte/,
    ],
  },
  {
    name: 'Lua XOR-key string obf',
    marks: [/xor.?key/i, /decryp1/i],
    // a numeric byte-array table + a string.char(t[i]) rebuild loop is the
    // signature regardless of whether an xor/arith key is applied.
    struct: [
      /\{\s*\d{1,3}\s*(,\s*\d{1,3}\s*){4,}\}/,
      // string.char(t[i]) OR an aliased char fn x(t[i]) fed through a concat loop
      /(?:string\.char|\w{1,40})\s*\(\s*\w{1,40}\s*\[\s*\w{1,40}\s*\]|bxor|\w{1,40}\s*\[\s*\w{1,40}\s*\]\s*~/,
    ],
  },
  {
    name: 'Byte-table loadstring',
    // Flurace/ByteProtect/local-byte-array: {"\ddd","\ddd",...} table fed to
    // loadstring / table.concat — string-encryption family shape.
    marks: [/Flurace/i, /ByteProtect/i, /Secure by Flurace/i],
    struct: [/\{\s*"(?:\\\d{1,3}|\\x[0-9a-fA-F]{2})"|\{\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}/, /loadstring\s*\(|string\.char\s*\(\s*(?:table\.unpack|\w+\s*\[)/],
  },
  {
    name: 'String-encryption obfuscator',
    marks: [/ferib/i, /goofyscat/i, /wynfusc/i, /lua.?obfuscator/i],
    // thunk-table `{function()return"s"end,...}` OR a dense \xHH/\ddd escaped
    // blob + a decode call — either alone fingerprints this family.
    struct: [
      /local\s+\w+\s*=\s*\{\s*function\s*\([^)]*\)\s*return/,
      /\[\s*\d+\s*\]\s*\(\s*\)/,
      /(\\x[0-9a-fA-F]{2}|\\\d{1,3}){6,}/,
    ],
  },
  {
    name: 'Soteria',
    marks: [/SOTR[\x01$!]/i, /soteria/i, /SOTR_/],
    struct: [/return\s*\(\s*\{[\s\S]{0,40}=function/, /bit32\./],
  },
  {
    name: 'Centurion',
    marks: [/centurion/i, /centurion\.best/i],
    struct: [/return\s*\(\s*\{[\s\S]{0,40}=function/],
  },
  {
    name: 'wYnFuscate',
    banner: /Protected by wYnFuscate/i,
    // real banner `-- Protected by wYnFuscate: https://wynfuscate.com` + the
    // getfenv bootstrap `return(function(Ja,JB,JW,...)if not Ja then Ja=getfenv`
    marks: [/wynfusc/i, /wYnFuscate/i, /Protected by wYnFuscate/i],
    struct: [/return\s*\(\s*function\s*\(\s*(J\w+\s*,\s*J\w+|\.\.\.)/, /if\s+not\s+\w+\s+then\s+\w+\s*=\s*getfenv|local\s+B\d+\s*=/],
  },
  {
    name: 'MoonVeil v2',
    marks: [/moonveil/i, /mv2_/i],
    struct: [/function\s+\w+\([\w,]{3,20}\)/, /\[\d{4,5}\]/],
  },
  {
    name: 'lual.org',
    banner: /Obfuscated by lual/i,
    // lual.org free web obfuscator — constant-array + a rotating decoder table
    // wrapped in a return(function(...)...end) shell; watermark in header.
    marks: [/lual\.org/i, /Obfuscated by lual/i, /lualorg/i],
    // the const-array + literal-index-read shape is lual-specific when the
    // source is *mostly* the decoder table — require a real indexed read, not
    // any `t[i]` (IronBrew/LZW fill loops were stealing this).
    struct: [/local\s+\w+\s*=\s*\{\s*\d+\s*,\s*\d+/, /local\s+\w+\s*=\s*\w+\s*\[\s*\w+\s*[+\-]\s*\d+\s*\]/],
  },
  {
    name: 'Env-keyed/sealed',
    // fake-executor / env-keyed string seal: strings are keyed off a runtime
    // value (executor name, HWID, env var) so they only decode under the real
    // environment — we recover the decode fn + keyed constants, marked partial.
    marks: [/syn\b/i, /KRNL|Fluxus|Volt|executor/i],
    struct: [/getgenv|getrenv|identifyexecutor|getexecutorname/, /string\.char|bit32\.bxor/],
  },
  {
    name: 'IronBrew1',
    banner: /generated using ironbrew1/i,
    // IronBrew 1 — `generated using ironbrew1` + the signature massive-dummy-param
    // shell return(function(a,a,b,b,b,b,c,d,...) ... end). Older sibling of IB2.
    marks: [/ironbrew\s*1/i, /ironbrew1/i],
    struct: [/return\s*\(\s*function\s*\(\s*[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\s*,/, /\(\s*a\s*,\s*a\s*,\s*b\s*,\s*b\s*,\s*b\s*,\s*b\s*,/],
  },
  {
    name: 'IronBrew2',
    banner: /generated using ironbrew2|ironbrew\\s*2/i,
    marks: [/ironbrew(?!1)/i, /IB2_/i],
    // IronBrew2's real signature: an LZW string decompressor
    // `local function s(d) ... n[l]=i(l) ... local a=256` feeding a register-VM
    // closure `local function h(l,e,a)` that re-enters `h(i(),{},H())`.
    struct: [/local\s+function\s+\w+\s*\(\s*\w+\s*\)\s*local\s+\w+\s*,\w+\s*,\w+\s*=/, /\[\s*\w+\s*\]\s*=\s*\w+\s*\(\s*\w+\s*\)/, /local\s+\w+\s*=\s*256/, /local\s+function\s+\w+\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)/,
      // IronBrew2's builtin-alias preamble — single-letter locals bound to
      // string.byte/sub/char + math.ldexp + getfenv (ldexp is near-unique).
      /local\s+\w\s*=\s*string\.byte\b/, /local\s+\w\s*=\s*math\.ldexp\b/],
  },
  {
    name: 'PSU',
    banner: /This file was obfuscated using PSU/i,
    marks: [/This file was obfuscated using PSU/i, /PSU\s*Obfuscator/i, /psu\s*\d/i],
    // PSU wraps the whole source in a giant escaped-string constant fed to a
    // char-build loop — the (\d{3}){n} signature + loadstring tail.
    struct: [/\w\[\s*\({0,2}\s*\d{5,}\s*[-+]\s*#/, /(\\\d{2,3}){30,}|"This file was obfuscated using PSU/],
  },
  {
    name: 'SynapseXen',
    banner: /Synapse\\s*Xen\\s*v[\\d.]+\\s*by/i,
    // `--[[ Synapse Xen vX by Synapse GP / VM Hash: <sha> ]]` + the signature
    // `SynapseXen_<mixed lI garbage>=select` locals — the camel prefix is unique.
    marks: [/Synapse\s*Xen/i, /SynapseXen_/i],
    struct: [/SynapseXen_\w+/, /VM\s+Hash\s*:/],
  },
  {
    name: 'Boronide',
    banner: /herrtt'?s?\\s*obfuscator/i,
    // herrtt's obfuscator — `--[[ herrtt's obfuscator, vX ]]` + the
    // `([[herrtts obf, ...]]):gsub('(.*)',function` bootstrap.
    marks: [/herrtt'?s?\s*obf/i, /herrtt/i],
    struct: [/\(\[\[[\s\S]{0,60}?\]\]\)\s*:?gsub\s*\(|:gsub\s*\(\s*['"]\.\*['"]/],
  },
  {
    name: '77fuscator',
    banner: /77fuscator\\s*v?[\\d.]+/i,
    // `do local a=[[77fuscator vX ...]];return(function(a)` + numeric
    // `bj=0 while true do if bj>=` control-flow state machine.
    marks: [/77fuscator/i],
    struct: [/while\s+true\s+do\s+if\s+\w+\s*(>=|<=|<|>)/, /=\s*0\s+while\s+true\s+do/],
  },
  {
    name: 'LPS',
    // Ascii85-style decoder — the powers-of-85 accumulate `(t-33)+(s-33)*85+
    // (r-33)*7225+(q-33)*614125+(c-33)*52200625` is unique to LPS.
    marks: [/\*52200625|\*614125/],
    struct: [/\*\s*(85|7225|614125|52200625)/, /\[\^!-u?z\]/],
  },
  {
    name: 'LuaObfuscator (Ferib)',
    banner: /Obfuscated.{0,20}LuaObfuscator/i,
    // Ferib luaobfuscator.com — sequential `local v0=tonumber;local v1=string.byte;
    // local v2=...; vN` numbered aliases bound to builtins (the v0..vN run is
    // distinctive vs IronBrew's single-letter K,N,C,... aliases).
    marks: [/luaobfuscator/i, /Ferib/i, /Obfuscated.{0,20}LuaObfuscator/i,
      // `local v0=` numbered-alias preamble is effectively Ferib's signature —
      // no other engine numbers its builtin aliases v0,v1,v2,... in order.
      /local\s+v0\s*=\s*[\w.]+\s*;/],
    struct: [/(?:local\s+v\d+\s*=\s*[^;\n]+;\s*){4,}/, /local\s+v\d+\s*=\s*getfenv|v\d+\s*=\s*math\.ldexp/],
  },
  {
    name: 'IronBrew3',
    banner: /ironbrew3:tm:,\\s*v?\\d/i,
    // `--ironbrew3:tm:, vX` + `repeat if not(not(` control-flow + the
    // scrambled multi-char param shell.
    marks: [/ironbrew\s*3/i, /ironbrew3/i, /:tm:,\s*v?\d/i],
    struct: [/repeat\s+if\s+not\s*\(\s*not\s*\(/, /return\s*\(\s*function\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+/],
  },
  {
    name: 'Lua Obscura',
    marks: [/luaobscura/i, /\bObscura\b/i, /\bVega\b.{0,20}Atlas|\bAtlas\b.{0,20}Vega/i],
    struct: [/protected virtual machine|devirtualization/i, /seed\s*=|loadstring\s*-?free|ModuleScript/i],
  },

  {
    name: 'LuaLock',
    marks: [/LuaLock/i, /lualock\.dev/i, /affine byte permutation/i],
    struct: [/opcode|register-?based bytecode|encrypted constant/i, /tamper-?detection|anti-?introspection|loadstring/i],
  },
  {
    name: 'AztupBrew',
    marks: [/AztupBrew|Aztup/i, /\bw0y\b|Sweetie|sweetie/i, /protectme|Protected\s*Watermark/i],
    struct: [/GetFenv|SetFenv|HookFunction|hookfunction/i, /instr|stacks|locals|mem_from_top/i],
  },

];

// Structural Luraph fingerprint (survives watermark removal — e.g. onyxv2 which
// replaces the `-- Luraph Obfuscator vX` comment with an ASCII banner). Luraph
// v13/v14 emits a method-table VM: `return({ <k>=function(self,...) ... })` that
// is immediately invoked via a `}):<ident>()(...)` tail, uses bit32.* ops, and
// packs constants as obfuscated hex/binary literals (often with `_` separators).
function looksLikeLuraph(src) {
  let score = 0;
  if (/return\s*\(\s*\{\s*[A-Za-z_]\w*\s*=\s*function\s*\(/.test(src.slice(0, 4000))) score += 3;
  if (/\}\s*\)\s*:\s*[A-Za-z_]\w*\s*\(\s*\)\s*\(\s*\.\.\.\s*\)\s*;?\s*$/.test(src.trimEnd())) score += 4;
  if (/\bbit32\.(band|bor|bxor|bnot|lshift|rshift|lrotate|rrotate|countlz|countrz)\b/.test(src)) score += 2;
  if (/0[xX][0-9a-fA-F]+_|0[bB][01]+_/.test(src)) score += 1; // Luau `_` digit separators
  // many single/double-char method keys mapping to functions (VM opcode handlers)
  const handlers = (src.slice(0, 20000).match(/[,{]\s*[A-Za-z_]\w?\s*=\s*function\s*\(/g) || []).length;
  if (handlers >= 8) score += 2;
  return score;
}

function extractClaimedVersion(src, family) {
  const head = src.slice(0, 16384);
  const escaped = String(family || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`${escaped}(?:\\s+Obfuscator)?\\s*(?:version|ver|v)?\\s*([0-9]+(?:\\.[0-9]+){0,3})`, 'i'),
    /(?:version|ver)\s*[:=-]?\s*v?([0-9]+(?:\.[0-9]+){0,3})/i,
  ];
  for (const re of patterns) {
    const match = re.exec(head);
    if (match) return match[1];
  }
  return null;
}

function detectObfuscator(src) {
  const head = src.slice(0, 4096);
  // Bound the expensive full-file scans: fingerprints/watermarks/decoder
  // preambles always live in the first chunk of an obfuscated file. Several
  // struct patterns are linear on small inputs but quadratic on giant
  // minified blobs (greedy \w+ before '['), so scanning beyond this window
  // added minutes for zero signal. 256KB covers real signatures while
  // capping worst-case regex cost.
  const SCAN_MAX = 256 * 1024;
  const body = src.length > SCAN_MAX ? src.slice(0, SCAN_MAX) : src;
  let best = { name: null, confidence: 0, signals: [], claimedVersion: null, versionVerified: false };
  const candidates = [];
  for (const o of KNOWN) {
    const signals = [];
    let score = 0;
    if (o.banner && o.banner.test(head)) { score += 90; signals.push('banner'); }
    for (const re of o.marks) {
      if (re.test(head) || re.test(body)) { score += 60; signals.push('watermark'); break; }
    }
    let hits = 0;
    for (const re of o.struct) if (re.test(body)) hits++;
    if (o.struct.length && hits === o.struct.length) { score += 35; signals.push(`structure x${hits}`); }
    else if (hits) { score += 15 * hits; signals.push(`partial x${hits}`); }
    const claimedVersion = extractClaimedVersion(src, o.name);
    const versionVerified = Boolean(claimedVersion && hits > 0 && signals.includes('watermark'));
    if (claimedVersion) signals.push(versionVerified ? `version ${claimedVersion} structurally corroborated` : `claimed version ${claimedVersion}`);
    if (score >= 30) candidates.push({ name: o.name, confidence: Math.min(99, score) });
    if (score > best.confidence) {
      best = { name: o.name, confidence: Math.min(99, score), signals, claimedVersion, versionVerified };
    }
  }
  candidates.sort((a, b) => b.confidence - a.confidence);
  best.candidates = candidates.filter((c) => c.name !== best.name);
  return best.name ? best : { name: null, confidence: 0, signals: [], claimedVersion: null, versionVerified: false, candidates: [] };
}

module.exports = { KNOWN, detectObfuscator, looksLikeLuraph, extractClaimedVersion };
