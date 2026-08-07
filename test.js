'use strict';
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { detectObfuscator } = require('./detect.js');

const fixtures = {
  Hercules: '-- Obfuscated by Hercules\nreturn(getfenv())()',
  Ironveil: '-- Obfuscated using ironveil\nreturn(function(...)return(function(...)end)end)',
  Prometheus: '-- Prometheus Obfuscator by levno-710\nreturn(function(...) local x=string.char(104,105) end)',
  MoonSec: '-- MoonSec V3\nreturn(function(...) local x="\\104\\101\\108\\108\\111\\032\\119\\111\\114\\108\\100\\033\\104\\101\\108\\108\\111\\032\\119\\111\\114\\108\\100\\033\\104\\101\\108\\108\\111\\032\\119\\111\\114\\108\\100\\033\\104\\101\\108\\108\\111\\032\\119\\111\\114\\108\\100\\033" end)',
  Moonveil: '-- moonveil\nfunction abc(a,b,c) return T[12345] end',
  Kers0ne: '-- Protected By Kers0ne Obfuscator Base66 Multi-XOR\nlocal x=(a-1)*66+(b-1)',
  Luraph: '-- Luraph Obfuscator v14.8\nreturn({A=function(...)end})',
  KarmaVM: '-- Karma Obfuscator luarmor-bot\nreturn({a=function(...)end}) local x=L[1234]',
  Voltils: '-- Voltils Obfuscation v7.4 dsc.gg/Voltils\nlocal __voltils_abc=1',
  Syscure: '-- syscure.vip\nloadstring(game:HttpGet("https://syscure.vip/obf/0123456789abcdef.lua"))()',
  Pew: '-- Pew Obfuscator v1\nlocal x=string.char(104,105)',
  KarmaProtect: '-- Protected By Karma Lua Hosting\nlocal a=string.char;local b=string.byte;return(function(...)end)',
};

function detectorMatrix() {
  for (const [expected, source] of Object.entries(fixtures)) {
    const got = detectObfuscator(source);
    assert.equal(got.name, expected, `${expected}: detected ${got.name}`);
    assert.ok(got.confidence >= 30, `${expected}: confidence ${got.confidence}`);
  }

  const verified = detectObfuscator('-- Luraph Obfuscator v14.8\nreturn({A=function(...)end})');
  assert.equal(verified.claimedVersion, '14.8');
  assert.equal(verified.versionVerified, true);

  const spoofed = detectObfuscator('-- Luraph Obfuscator v99.9\nprint("plain")');
  assert.equal(spoofed.claimedVersion, '99.9');
  assert.equal(spoofed.versionVerified, false);

  const clean = detectObfuscator('local message = "hello"; print(message)');
  assert.equal(clean.name, null);
}

async function waitForHealth(port) {
  for (let i = 0; i < 80; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.ok) return;
    } catch (_) {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('test server did not start');
}

async function post(port, source) {
  const response = await fetch(`http://127.0.0.1:${port}/deobf`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-deobf-key': 'test-secret' },
    body: JSON.stringify({ source }),
  });
  assert.equal(response.status, 200);
  return response.json();
}

function assertOutputContract(data, expectedName) {
  assert.equal(data.ok, true);
  if (expectedName) assert.equal(data.detected.name, expectedName);
  assert.equal(data.files.source, 'View Source');
  assert.equal(data.files.beautified, 'beautified.lua');
  assert.equal(data.files.dump, 'dump.lua');
  assert.equal(data.files.evidence, 'evidence.txt');
  assert.equal(typeof data.sourceUrl, 'string');
  assert.match(data.sourceUrl, /\/source\/[0-9a-f-]{36}\?exp=\d+&sig=[0-9a-f]{64}$/);
  assert.equal(typeof data.beautified, 'string');
  assert.equal(typeof data.dump, 'string');
  assert.equal(typeof data.evidence, 'string');
  assert.match(data.evidence, /Detection confidence:/);
  assert.match(data.evidence, /Recovery estimate:/);
  assert.ok(Number.isInteger(data.recoveryPercent));
  assert.ok(data.recoveryPercent >= 0 && data.recoveryPercent <= 95);
  assert.ok(Number.isInteger(data.elapsedMs));
}

async function endpointMatrix() {
  const port = 18777;
  const server = spawn(process.execPath, ['server.js'], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(port), RENDER_EXTERNAL_URL: `http://127.0.0.1:${port}`, DEOBF_SOURCE_DIR: `${__dirname}/.test-source-links`, DEOBF_SHARED_SECRET: 'test-secret', DEOBF_TOOL_TIMEOUT_MS: '3000' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  server.stderr.on('data', (chunk) => { stderr += chunk; });
  try {
    await waitForHealth(port);
    const generic = await post(port, 'local x=string.char(104,101,108,108,111);print(x)');
    assertOutputContract(generic, null);
    assert.ok(generic.beautified.length > 0);
    const sourcePage = await fetch(generic.sourceUrl);
    assert.equal(sourcePage.status, 200);
    assert.match(await sourcePage.text(), /Recovered Lua source/);
    const tampered = await fetch(generic.sourceUrl.replace(/sig=[0-9a-f]+/, 'sig=' + '0'.repeat(64)));
    assert.equal(tampered.status, 403);

    const luraph = await post(port, fixtures.Luraph);
    assertOutputContract(luraph, 'Luraph');
    assert.equal(luraph.detected.claimedVersion, '14.8');
    assert.equal(luraph.detected.versionVerified, true);
    assert.ok(luraph.recoveryPercent <= 68);

    const pew = await post(port, fixtures.Pew);
    assertOutputContract(pew, 'Pew');
    assert.ok(pew.recoveryPercent <= 68);
  } finally {
    server.kill('SIGTERM');
  }
  if (stderr) process.stdout.write(`Backend test diagnostics:\n${stderr.slice(0, 2000)}\n`);
}

(async () => {
  detectorMatrix();
  await endpointMatrix();
  console.log(`PASS: ${Object.keys(fixtures).length} named detectors + clean/spoofed/version cases + API output contract`);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
