'use strict';
// VM-family best-effort devirtualizer — Soteria v7.x, Centurion, wYnFuscate V5,
// MoonVeil v2, and other compile-to-VM Luau obfuscators. These compile the real
// program into a custom bytecode/register VM over an encoded constant pool; the
// original .lua text does not exist in the protected file. Like Luraph, full
// source recovery is not statically achievable — we recover what's real:
//   - the decoded constant pool (every API/string the program calls)
//   - string-table / decoder dumps (plaintext the VM fetches)
//   - structural notes (opcode count, proto layout, anti-tamper surface)
// We never execute the input. Output is a readable reconstruction of the
// recovered constants + structure, marked partial.

const luaparse = require('luaparse');

const FAMILY = {
  soteria:   { marks: [/SOTR[\x01$!]/, /soteria/i, /SOTR_/], tag: 'Soteria v7.x (Luau typed register-VM)' },
  centurion: { marks: [/centurion/i, /CENT_/, /centurion\.best/i], tag: 'Centurion (compile-to-VM)' },
  wynfusc5:  { marks: [/wynfusc/i, /wYnFuscate/i], tag: 'wYnFuscate V5 (online-key sealed VM)' },
  moonveil2: { marks: [/moonveil/i, /mv2_/i], tag: 'MoonVeil v2 (two-phase VM)' },
};

function detectVmFamily(src) {
  const head = src.slice(0, 8192);
  const hits = [];
  for (const [key, f] of Object.entries(FAMILY)) {
    if (f.marks.some((re) => re.test(head) || re.test(src))) hits.push({ key, tag: f.tag });
  }
  // generic compile-to-VM shape: return({...}) handler table + dense escaped blob
  if (!hits.length && /return\s*\(\s*\{[\s\S]{0,40}=function/.test(head) && /(\\x[0-9a-fA-F]{2}|\\\d{1,3}){30,}/.test(src)) {
    hits.push({ key: 'vm', tag: 'compile-to-VM Lua obfuscator (register-VM family)' });
  }
  return hits;
}

// Extract real string constants — short readable literals, NOT giant code blobs.
// A VM obfuscator's constant pool is its quoted literals; we keep printable
// strings under 120 chars (real API names / messages), decoded from escapes.
function extractStrings(src) {
  const out = new Set();
  let m;
  // quoted literals (Luraph/other VMs store constants as "\ddd"/"\xHH"/plain)
  const strRe = /"((?:\\.|[^"\\]){2,120})"|'((?:\\.|[^'\\]){2,120})'/g;
  while ((m = strRe.exec(src))) {
    const raw = m[1] || m[2];
    const dec = raw.replace(/\\x([0-9a-fA-F]{2})|\\(\d{1,3})/g, (w, x, d) => String.fromCharCode(x ? parseInt(x, 16) : parseInt(d, 10)));
    for (const run of dec.matchAll(/[ -~]{3,}/g)) {
      const s = run[0];
      // keep real constants: API names, identifiers, short messages — not
      // minified code fragments (which contain ;,=,(){} and keyword soup)
      if (/[;{}]|\b(function|local|return|end|then|else|do|if|for|while)\b/.test(s)) continue;
      if (s.length >= 3 && !/^\d+$/.test(s)) out.add(s);
    }
  }
  return [...out].slice(0, 400);
}

// The real constant pool of a call-arg VM (Luraph v13+): the payload is passed
// as arguments to the outer function — `)(116,table,_ENV,"v",256,type,
// 4294967296,rawget,117,bit,...)`. Parse that tail's identifier/number/string
// constants — the program's actual API surface + numeric constants.
function callArgConstants(src) {
  // find the invocation tail `)(...)` — the arg list after the outer function
  const call = src.match(/\)\s*\(\s*([\s\S]{0,6000}?)\)\s*;?\s*$/);
  if (!call) return [];
  const args = call[1];
  const out = [];
  const seen = new Set();
  const push = (v) => { if (v != null && !seen.has(v)) { seen.add(v); out.push(v); } };
  for (const m of args.matchAll(/"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'/g)) {
    const raw = m[1] !== undefined ? m[1] : m[2];
    const dec = raw.replace(/\\x([0-9a-fA-F]{2})|\\(\d{1,3})/g, (w, x, d) => String.fromCharCode(x ? parseInt(x, 16) : parseInt(d, 10)));
    if (dec.length && dec.length < 500 && !/^[0-9A-F]{40,}$/.test(dec)) push(JSON.stringify(dec));
  }
  for (const m of args.matchAll(/\b(getfenv|setfenv|loadstring|load|pcall|xpcall|coroutine|task|wait|spawn|string|table|math|bit32|buffer|debug|game|workspace|rawget|rawset|rawequal|rawlen|setmetatable|getmetatable|select|unpack|tonumber|tostring|type|pairs|ipairs|next|print|error|assert|require|identifyexecutor|getexecutor|hookfunction|newcclosure|getgenv|getrenv|_ENV|_G)\b/g)) push(m[1]);
  for (const m of args.matchAll(/\b(\d{1,20})\b/g)) push(m[1]);
  return out;
}

// The giant encoded instruction stream — a dense hex/alnum blob (Luraph's
// `"LPH#<bytecode>"` payload — LPH# magic then ~200KB alnum) or a long \ddd
// escape run. Report magic + size + offset.
function encodedBlob(src) {
  let best = null;
  // `MAGIC#<alnum>` — Luraph/Soteria-style tagged bytecode blobs
  for (const m of src.matchAll(/([A-Z]{2,6}#?)([0-9A-Za-z]{400,})/g)) if (!best || m[2].length > best.bytes) best = { offset: m.index, bytes: m[2].length, magic: m[1] };
  for (const m of src.matchAll(/([0-9A-Za-z]{1000,})/g)) if (!best || m[1].length > best.bytes) best = { offset: m.index, bytes: m[1].length };
  for (const m of src.matchAll(/"((?:\\x[0-9a-fA-F]{2}|\\\d{1,3}){100,})"/g)) {
    const b = (m[1].match(/\\/g) || []).length;
    if (!best || b > best.bytes) best = { offset: m.index, bytes: b };
  }
  return best;
}

function apiSurface(strings) {
  const api = strings.filter((s) => /^(getfenv|setfenv|loadstring|load|pcall|xpcall|coroutine|task|string|table|math|bit32|buffer|debug|game|workspace|identifyexecutor|getexecutor|isfunctionhooked|restorefunction|hookfunction|getrenv|getgenv|GetJobsInfo|GetService|HttpGet|require|rawget|rawset|setmetatable|getmetatable|newcclosure|checkcaller|getidentity|setidentity|tick|os\.time|wait|spawn)/i.test(s) || /^[a-zA-Z_]\w*\.[a-zA-Z_]\w*$/.test(s));
  return api;
}

// Recover the opcode-handler dispatch — interpreter functions the VM calls
// per opcode. Shapes seen in the wild: `X=function(`, `local function X(`,
// and method-table entries `key=function(self,` / `key=function(v,`.
function opcodeHandlers(src) {
  const names = new Set();
  for (const m of src.matchAll(/[,{]\s*([A-Za-z_]\w?)\s*=\s*function\s*\(/g)) names.add(m[1]);
  for (const m of src.matchAll(/local\s+function\s+([A-Za-z_]\w?)\s*\(/g)) names.add(m[1]);
  for (const m of src.matchAll(/[,{]\s*([A-Za-z_]\w+)\s*=\s*function\s*\(\s*(?:self|v|s|a|e)\b/g)) names.add(m[1]);
  return [...names];
}

// Locate the dense escaped regions — the compiled instruction streams the VM
// deserializes (the program's actual body, encoded).
function instructionBlobs(src) {
  const blobs = [];
  const re = /"((?:\\x[0-9a-fA-F]{2}|\\\d{1,3}){20,})"/g;
  let m;
  while ((m = re.exec(src))) blobs.push({ offset: m.index, bytes: (m[1].match(/\\/g) || []).length });
  return blobs;
}

function deobfuscate(source) {
  const src = typeof source === 'string' ? source : '';
  if (!src.trim()) throw new Error('empty input');
  const fam = detectVmFamily(src);
  const tag = fam.length ? fam[0].tag : 'compile-to-VM Lua obfuscator';
  const strings = extractStrings(src);
  const api = apiSurface(strings);
  const handlers = opcodeHandlers(src);
  const blobs = instructionBlobs(src);
  const callArgs = callArgConstants(src);
  const blob = encodedBlob(src);
  // prefer the call-arg constant list (the real VM constant pool) when present
  const constants = callArgs.length ? callArgs : strings;
  const notes = [
    `${tag}: this obfuscator compiles the real program into a custom bytecode/register VM — the original .lua source is not stored in the file. Recovered the decoded constant pool + structure (best-effort; full devirtualization requires the VM deserializer trace).`,
  ];
  if (callArgs.length) notes.push(`Recovered ${callArgs.length} call-argument constants (the VM's constant pool): ${callArgs.slice(0, 24).join(', ')}${callArgs.length > 24 ? ', …' : ''}`);
  if (api.length) notes.push(`Recovered ${strings.length} constant-pool strings (${api.length} API surface): ${api.slice(0, 24).join(', ')}${api.length > 24 ? ', …' : ''}`);
  if (handlers.length) notes.push(`Opcode-handler dispatch table: ${handlers.length} handler methods (${handlers.slice(0, 16).join(', ')}${handlers.length > 16 ? ', …' : ''}) — the VM's decoded instruction surface.`);
  if (blob) notes.push(`Encoded instruction stream located: ${blob.magic ? blob.magic + ' ' : ''}${blob.bytes}B @ offset ${blob.offset} — the compiled program body the VM deserializes.`);
  else if (blobs.length) notes.push(`${blobs.length} encoded instruction stream(s) located (${blobs.map((b) => b.bytes + 'B').join(', ')}) — the compiled program body the VM deserializes.`);
  const head = [
    `-- Devirtualized (best-effort) from: ${tag}`,
    `-- This obfuscator ships a bytecode/register-VM, not source. Below is the recovered`,
    `-- constant pool + dispatch structure + API surface — the program's real logic.`,
    ``,
    `-- opcode-handler dispatch (${handlers.length} handlers):`,
    ...handlers.slice(0, 40).map((h, i) => `--   op_${i}: handler '${h}'`),
    ``,
    blob ? `-- encoded instruction stream: ${blob.magic || ''} ${blob.bytes}B @ offset ${blob.offset}` : `-- encoded instruction streams: ${blobs.map((b) => `${b.bytes}B@off${b.offset}`).join(', ') || 'none'}`,
    ``,
    `local recovered_constants = {`,
    ...constants.slice(0, 200).map((s) => `  ${/^[\d"']/.test(s) ? s : JSON.stringify(s)},`),
    `}`,
    ``,
    `-- API surface detected:`,
    ...api.slice(0, 80).map((s) => `--   ${s}`),
  ].join('\n');
  return { output: head, notes, recovered: head, partial: true };
}

function detect(src) {
  const fam = detectVmFamily(src);
  return { name: fam.length ? fam[0].tag.split(' ')[0] : 'VM-family obfuscator', confidence: fam.length ? 70 : 0, signals: fam.map((f) => f.tag) };
}

module.exports = { deobfuscate, detect, detectVmFamily };
