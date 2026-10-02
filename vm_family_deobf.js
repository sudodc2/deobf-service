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

// Extract printable string runs >=4 from a decoded/escaped blob (constant pool).
function extractStrings(src) {
  // gather long-bracket string literals and escaped runs
  const out = new Set();
  const litRe = /\[(=*)\[([\s\S]*?)\]\1\]/g;
  let m;
  while ((m = litRe.exec(src))) {
    const body = m[2];
    for (const mm of body.matchAll(/[ -~]{6,}/g)) out.add(mm[0]);
  }
  const escRe = /"((?:\\x[0-9a-fA-F]{2}|\\\d{1,3}|[ -~]){8,})"/g;
  while ((m = escRe.exec(src))) {
    const dec = m[1].replace(/\\x([0-9a-fA-F]{2})|\\(\d{1,3})/g, (w, x, d) => String.fromCharCode(x ? parseInt(x, 16) : parseInt(d, 10)));
    for (const mm of dec.matchAll(/[ -~]{6,}/g)) out.add(mm[0]);
  }
  return [...out].filter((s) => s.length >= 6 && !/^\d+$/.test(s)).slice(0, 400);
}

function apiSurface(strings) {
  const api = strings.filter((s) => /^(getfenv|setfenv|loadstring|load|pcall|xpcall|coroutine|task|string|table|math|bit32|buffer|debug|game|workspace|identifyexecutor|getexecutor|isfunctionhooked|restorefunction|hookfunction|getrenv|getgenv|GetJobsInfo|GetService|HttpGet|require|rawget|rawset|setmetatable|getmetatable|newcclosure|checkcaller|getidentity|setidentity|tick|os\.time|wait|spawn)/i.test(s) || /^[a-zA-Z_]\w*\.[a-zA-Z_]\w*$/.test(s));
  return api;
}

// Recover the opcode-handler dispatch table — the `X=function(a,b) ... end`
// methods the VM's interpreter loop calls per opcode. This is the program's
// decoded instruction set surface (same shape MoonSec's disasm exposes).
function opcodeHandlers(src) {
  const names = new Set();
  for (const m of src.slice(0, 60000).matchAll(/[,{]\s*([A-Za-z_]\w?)\s*=\s*function\s*\(/g)) names.add(m[1]);
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
  const notes = [
    `${tag}: this obfuscator compiles the real program into a custom bytecode/register VM — the original .lua source is not stored in the file. Recovered the decoded constant pool + structure (best-effort; full devirtualization requires the VM deserializer trace).`,
  ];
  if (api.length) notes.push(`Recovered ${strings.length} constant-pool strings (${api.length} API surface): ${api.slice(0, 24).join(', ')}${api.length > 24 ? ', …' : ''}`);
  if (handlers.length) notes.push(`Opcode-handler dispatch table: ${handlers.length} handler methods (${handlers.slice(0, 16).join(', ')}${handlers.length > 16 ? ', …' : ''}) — the VM's decoded instruction surface.`);
  if (blobs.length) notes.push(`${blobs.length} encoded instruction stream(s) located (${blobs.map((b) => b.bytes + 'B').join(', ')}) — the compiled program body the VM deserializes.`);
  const head = [
    `-- Devirtualized (best-effort) from: ${tag}`,
    `-- This obfuscator ships a bytecode/register-VM, not source. Below is the recovered`,
    `-- constant pool + dispatch structure + API surface — the program's real logic.`,
    ``,
    `-- opcode-handler dispatch (${handlers.length} handlers):`,
    ...handlers.slice(0, 40).map((h, i) => `--   op_${i}: handler '${h}'`),
    ``,
    `-- encoded instruction streams: ${blobs.map((b) => `${b.bytes}B@off${b.offset}`).join(', ') || 'none'}`,
    ``,
    `local recovered_constants = {`,
    ...strings.slice(0, 200).map((s) => `  ${JSON.stringify(s)},`),
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
