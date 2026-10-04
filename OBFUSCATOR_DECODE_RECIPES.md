# Obfuscator Decode Recipes — Agent Knowledge Base

How to recognize and reconstruct source from each major Roblox Luau obfuscator. Built from real devirtualization work (Soteria fully cracked end-to-end). Use this to identify the engine, then apply the matching recipe.

---

## Universal recon checklist (run first on ANY obfuscated blob)

1. **VM vs source-encryption.** If you see a giant interpreter table / `while true` state machines / `string.pack`/register ops → it's a custom VM (Soteria, Luraph, PSU, IronBrew). If it's just encoded strings + `loadstring` → it's source-encryption (weak).
2. **Find the payload container.** Look for a big literal blob (`"SOTR..."`, base91/base64, `\x..` escapes, or a long printable string). That blob is the compiled program.
3. **Find the loader.** The outer code decodes the blob then `loadstring`s / `task.spawn`s / coroutine-resumes it. Capture the decoded bytes BEFORE exec.
4. **Extract constants.** The string/const pool lists every API the payload calls — grep it for `identifyexecutor`, `GetJobsInfo`, `isfunctionhooked`, `debug.info`, `task.wait`, `bit32`, `loadstring` to fingerprint anti-tamper vs payload.
5. **Don't re-run the VM blindly.** Dump the program data (consts, proto schema, instruction words, cipher key) to files — then either lift the executed opcode stream to readable Lua OR port the byte-decoder offline.

---

## Soteria (soteria.rip) — FULLY CRACKED

**ID markers:** `SOTR_*` macro SDK, `SOTR\x01`+`b@FVK` stream header, `SOTR$!!(` encoded blob, `l:`/`a`/`jc`/`om`/`zM`/`TW`/`Mu`/`sn`/`om_*`/`HJ` identifiers, presets BALANCED/SECURE/SECURE_MAX, TRANSFORMs EXTRACT/CONTROL_FLOW/REWRITE_NAMECALLS.

**Pipeline:** `w`-decode → LZMA → 373KB L2 interpreter → `jc`/`nstream` (`SOTR\x01`, 55907B) → proto-deserializer → `function(jc)` exec-init → `a`/`l:I`/`Q:B`/`G:J`/`lc`/`dq`/`Mu`/`W`/`C`/`Md`/`T`/`X`/`b` element decoder → `om`/`zM`/`TW`/`Mu` offset-encoded maps → `nf=zM[zq]`/`Fu=om[nf]-nf` outer dispatch → `sn[((X[b][i]-i)/9)](reg_t,reg_M)` register-VM.

**ISA:** 12 `sn` opcode handlers. Register operands `e`/`t`/`M`/`b`; `op = floor((X[b][i]-i)/9)` (base-9 packed word → opcode). `reg_e` dest, `reg_t`/`reg_M` sources; `const_pool[op+v]` for constants; `reg_t[reg_M]` table index.

**Anti-tamper suite (decoded):** executor-name fetch + `Volt`/`Potassium` blacklist; `isfunctionhooked`/`restorefunction`/`debug.info` `[C]`-frame fingerprint; `getrenv`/`getgenv`/`getsenv`/`getfenv`/`setfenv`; `getidentity`/`setidentity`/`threadidentity`; `getcallingscript`; `Game:GetJobsInfo` compare battery; `loadstring` honesty probes (`2^64` wrap + `table.pack` rebuild); `task.wait(0.0001)` timing; `pcall`/`xpcall`/`error`/`traceback`; `bit32` band/bor/bxor/lshift/rshift/byteswap/extract + `string.pack` + 16-byte `Bq` rolling key.

**Recipe:** (1) w-decode + LZMA → interpreter. (2) Dump `l`'s field map (534 fields) + `Cw`/`Fh`/`sn`/`sp`/`Ws`/`Zt`/`my`/`Bq`/`om`/`zM`/`TW`/`Mu`/`jc`/`bk`. (3) The payload = anti-tamper wrapper + real script — lift the executed opcode stream OR port `lc`/`J`/`G`/`F`/`dq`/`Mu`/`jc`/`nstream` offline. The `om`/`zM`/`TW`/`Mu` maps are `__index`-lazy descriptors: `rawget` returns nil; they only resolve via the `a`/`l:I` decode. **Field-index fraction fix:** `math.floor` every `((OBJ[FLD][IDX]-IDX)/9)` site (opcode + cursor strides) — ~30 sites.

---

## Luraph (luraph.obfuscator.xyz / luraph.xyz)

**ID markers:** `Luraph`/`LPH` env, `["\\108\\117\\114\\97\\112\\104"]` string, `CRSV`/`___SERVO` constants, `protect`/`virfunc`/`obfuscate` markers, `Luraph_obfuscated` comment header, heavy `constant array` + register-VM interpreter, `VM_PROTECT`/`Luraph_vX`.

**Pipeline:** outer `loadstring`/`pcall` wrapper → giant constant array → deserializer → custom LuaVM bytecode → `vm_call` exec. Uses a ~huge interpreter table with opcode dispatch.

**Recipe:** (1) Find the `LPH`-prefixed env table + constant pool. (2) The deserializer builds a `script` env mirror (custom `Instance.new`, `game`, `workspace` etc.) — stub those. (3) Dump `opcodes`/`constants`/`protos` from the VM table. (4) Luraph applies `constant encryption` — each constant is XOR/transformed at load; intercept the constant-read to dump decoded values. (5) Lift the VM's register ops to Lua.

**Gotchas:** `getfenv`/`setfenv`/`getmetatable` probes; `LPH_OBFUSCATED` flag; syscall-like `LuraphVM` exec layer; string/table encoding.

---

## PSU (psu.obfuscator.xyz / PSU Obfuscator)

**ID markers:** `-- [[ PSU-Obfuscator ]]`, `psu`/`PSU`/`Protected by PSU` headers, `loadstring`+`return{...}` data tables, `4f8`/`bf`/`md`-style table indexes, `local a=string.byte`, `loadstring(...)()`.

**Pipeline:** outer chunk → encoded string → `loadstring` decode → interpreter → encoded `chunkData`/`bytecode` table → VM exec.

**Recipe:** (1) Locate the `return {...}` / `a=loadstring` decode loop. (2) Extract the numeric data table (the compiled program). (3) PSU builds a `luaVM`/`instr`/`consts`/`globals`/`stacks` interpreter — dump `stack`/`registers`/`instructions`/`constants`. (4) Decode instruction words (PSU uses `bit32`-packed operands). (5) `loadstring`-based: intercept `loadstring` to catch decoded chunks.

**Gotchas:** `args`/`env` confusion, `loadstring`-re-entrant layers, `setfenv` env mirrors.

---

## IronBrew 2 (IronBrew / ironbrew)

**ID markers:** `IronBrew`, `IB2`, `IronBrew:tm`, `EXE_WRAPPER`, `instr`/`opcode`/`constants`/`stacks`/`locals`/`env`/`data` fields, `emergency_exit`/`func`/`subp`/`bit_`/`string_`/`math_`/`table_`/`mem_from_top` tables.

**Pipeline:** `EXE_WRAPPER`/`vm` builder → opcode-decoder `while` loop → `instr`/`constants`/`data`/`stacks`/`locals`/`env` → `vm_execute` register VM. Deserializer reads an encoded `pc`/`instr` table; each instruction has `op/A/B/C/D` fields.

**Recipe:** (1) Dump `stacks`/`locals`/`constants`/`instr`/`data`/`env`. (2) IronBrew instructions are `op + A,B,C,D` — decode via the `opcode` field map. (3) The `mem_from_top`/`stack`/`top`/`stack_references` tables = register file — dump them. (4) `wrapper`/`IB2_OBFUSCATED` env fns. (5) Lift each instruction to Lua via the opcode table.

**Gotchas:** `const_use`/`unpacked_consts`/`nups`/`use_const`/`reference`/`local` mirror tables; `bit32`/`bit`-family field packing; `N_UP`/`UPVAL`/`upval`/`RETURN`-type opcodes.

---

## MoonSec / MoonSec-v3 (moonsec.rip)

**ID markers:** `MoonSec`/`MSV`/`-5f`/`Errordetect`/`kill`/`killerfunc`/`hookmetamethod`/`newcclosure`, `math.random`/`bit`/`table`/`string` field splits, `LVM`/`Generate`/`Warn`/`Coolmessage` tables, `watermark`/`v3`.

**Pipeline:** `obfuscate` wrapper → `Generate` → `killerfunc`/`Errordetect` → `LVM` interpreter. Encodes numbers via `bit`-library ops + `math.random` noise; `hookmetamethod`-based anti-hook.

**Recipe:** (1) `Generate`/`Errordetect`/`kill` are the loader/decoy fns — trace which builds the real chunk. (2) MoonSec splits the program into per-line `bit`-encoded chunks; intercept the `bit`-decode to dump real values. (3) `hookmetamethod`/`newcclosure` wrap env reads — stub them. (4) The `LVM`/`interpreter`/`exec`/`states` table = the VM; dump `instructions`/`constants`/`stack`.

**Gotchas:** `Errordetect`/`kill`/`Warn` decoys, `math.random` noise constants, `hookmetamethod` env interception, `newcclosure` C-side checks.

---

## XenitH / XenitH Protector (xenith)

**ID markers:** `XenitH`/`XNT`/`Protected`/`antihook`/`antidebug`/`antiinstance`/`Flow`/`Encrypt`/`Syscall`/`Precedence`/`identifier` fields, `~>`/`->` arrows, `metamethod`/`namecall`/`getnamecallmethod` interception.

**Pipeline:** `antihook`/`antidebug`/`Flow`/`Encrypt`/`Syscall`/`identifier` → `Precedence` interpreter → `metamethod`/`namecall` interception → instruction table.

**Recipe:** (1) `Flow`/`Encrypt`/`Syscall`/`identifier`/`Precedence`/`antihook`/`antidebug`/`antiinstance`/`antimemorydump`/`antidecompile`/`antispy` are the loader+protection fns — isolate the decoder. (2) XenitH uses `metamethod`/`namecall`/`getnamecallmethod` interception — hook `getnamecallmethod` to capture real calls. (3) Dump `Flow`/`Instructions`/`Precedence`/`stack`/`data`/`args`.

**Gotchas:** `namecall`/`metamethod`/`getnamecallmethod` hooks, `identifier`/`Precedence`/`Syscall` layers, `anti`-prefix protection fns.

---

## Weaker systems (string/byte-encryption only — trivial)

- **`obfuscator.net`/basic base64/byte-encoded:** just `loadstring`+`string.char`/`string.byte` loops — capture the decoded string before `loadstring` runs it.
- **`w0y`/`Sweetie`/`sweetie`/`Protect`:** env-mirror + string-encrypt; `getfenv`/`setfenv` probes; intercept `loadstring`/`getfenv`.
- **`Byte`/`byt`/`byte`-encoders:** hex/byte-array → `string.char` — decode the table directly.
- **`IronBrew-Lite`/`PSU-Lite`/`PxT`/`Puzzle`/`fake`:** source-encryption not full VM — intercept the `loadstring` decode.

---

## Cross-cutting technique: env/stub stubs for exec

To run any VM payload past its env checks, stub the executor surface before exec:
```lua
identifyexecutor/getexecutorname -> "Synapse X"/"Krnl" (a non-blacklisted name)
getrenv/getgenv/getsenv/getfenv -> real env (return {} for custom mirrors)
setfenv -> true; isfunctionhooked -> false; restorefunction -> fn
debug.info -> fake clean frames (no [C] on the checked index)
task.wait/coroutine.* -> synchronous shim (Lune/sandbox schedulers panic otherwise)
Game:GetJobsInfo -> the expected job-name/value battery (see decoded pool)
loadstring -> intercept: dump the decoded chunk BEFORE returning the loader
bit32/buffer/string.pack -> real impls
```

## The decisive deliverable = program data, not just pretty source

For proving an obfuscator broke: the decoded interpreter + the complete constant pool + proto/instruction schema + cipher key + the anti-tamper suite are byte-exact proof. The literal per-opcode table is the deepest mile (a flattened register-VM deserializer) — offline port of the element decoder, not a runtime fix.

---

## Lua Obscura (luaobscura.com) — Vega/Atlas virtualization

**ID markers:** `Obscura`/`Vega`/`Atlas` engine names, `Θ` theta markers, "protected virtual machine" / "devirtualization ladder" framing, per-function protection ("Vega" general VM, "Atlas" heavy VM on cold paths), `ModuleScript-safe`/`loadstring-free` static Luau output, pinned `seed` for byte-identical builds.

**Pipeline:** source → engine selection (Vega general VM / Atlas heavy VM) → per-function protection → self-contained artifact (no external VM pkg) → custom VM interpreter. Atlas adds a "devirtualization ladder" — graduated static protection on sensitive paths.

**Recipe:** (1) Identify engine (Vega vs Atlas) from the artifact's VM shape — Atlas is the heavier/per-function one. (2) Dump the VM's constant pool + opcode table + instruction stream like any register-VM. (3) The per-function model means each protected fn is a separate small VM proto — enumerate them all. (4) `seed`-pinned builds are byte-identical — a recovered seed reproduces the exact VM.

**Gotchas:** per-function split (many small protos), "devirtualization ladder" layered protection, native/static Luau output (no `loadstring` to hook — capture the artifact file instead).

## LuaLock (lualock.dev) — register bytecode VM, per-build remap

**ID markers:** `LuaLock`, "register-based bytecode", "opcode remapping per build", "affine byte permutation", "encrypted constant pool with call-site validation", "tamper-detection guards", "self-contained script", Lua 5.1/5.3/5.4/LuaJIT/Luau targets.

**Pipeline:** source → custom register bytecode → per-build opcode remapping + affine byte permutation of the byte stream → encrypted constant pool → generated VM → tamper-detection/anti-introspection guards.

**Recipe:** (1) The opcode table is remapped PER BUILD — don't hardcode opcodes; recover the runtime opcode map from the VM's dispatch table, not a fixed list. (2) The byte stream has an affine permutation — decode `y=(a*x+b) mod 256` per byte. (3) Const pool is encrypted + validated at call site — intercept the call-site decryption to dump plaintext constants. (4) Tamper guards corrupt execution on patch — prefer passive dumps to live patching.

**Gotchas:** opcode remap (not a fixed ISA), affine permutation, call-site const validation, active tamper detection (avoid patching the VM; dump state instead).

## MoonVeil (moonveil.cc) — Luau VM + IR folding

**ID markers:** `MoonVeil`, "custom virtual machine bundle" per script, "state machine" control-flow flattening, "IR toolchain" constant folding + dead-code elim, "selection of implementations".

**Pipeline:** source → IR fold/DCE optimize → custom VM bundle (per-script implementation choice) → state-machine-flattened branches/loops → interpreter.

**Recipe:** (1) Pre-folded IR means constants are already folded — the const pool reflects folded values. (2) State-machine-flattened control flow — same `while true do if STATE` recognition; decode the state-var transition table. (3) VM implementation varies per script — fingerprint which variant from the interpreter shape.

**Gotchas:** IR folding shifts constants, per-script VM variant selection, flattened control flow obscures branch structure.

## Prometheus (prometheus-lua) — open-source, transform-based

**ID markers:** `-- [[ Prometheus ]]`/`obfuscated by prometheus`, `Prometheus`/`MaGZclcBH`/`local A=`, step names (`EncryptStrings`/`ConstantArray`/`NumbersToExpressions`/`AntiTamper`/`Vmify`/`EncryptVarNames`/`NumbersToExpressions`/`WrapInFunction`/`SplitStrings`/`DynamicData`).

**Pipeline:** source → AST transforms (`EncryptStrings`→string-encrypt loop, `ConstantArray`→const pool, `Vmify`→optional VM, `AntiTamper`→integrity checks, `NumbersToExpressions`→arith-obfuscated numbers, `DynamicData`/`SplitStrings`).

**Recipe:** (1) Open-source — read the transform list in the `Prometheus` config; each is a known step. (2) `EncryptStrings`/`ConstantArray`/`DynamicData`/`SplitStrings` are reversible — decode the arrays directly. (3) `Vmify`→a generated register VM — dump it like Soteria (dispatch loop, opcode table, const pool). (4) `AntiTamper`→`pcall`/`error`/`debug` checks — stub them.

**Gotchas:** it's Lua-target (PUC/lua5.x) more than Roblox-specific; `Vmify` is the only VM step — string/number transforms alone are trivially reversible.

## AztupBrew / Aztup / w0y / others (community/forked)

**ID markers:** `AztupBrew`/`Aztup`, `w0y`/`Sweetie`/`sweetie`, `Protected`/`Watermark`/`protectme`, `obfuscate`/`Protect` wrappers, `GetFenv`/`SetFenv`/`HookFunction` env probes, `IronBrew`-derivative `instr`/`stacks`/`locals`/`mem_from_top` tables.

**Pipeline:** mostly IronBrew/PSU derivatives — env-mirror + register VM + string encryption.

**Recipe:** apply the IronBrew/PSU recipe (they fork the same interpreter shape). Community forks add `getfenv`/`hookfunction`/watermark wrappers — stub and unwrap.

## Generic signature for "unknown" engines

When the engine isn't recognized, fingerprint via:
- **Container shape:** one big literal blob → VM; scattered small strings → transform-based.
- **Dispatch form:** `while true do if STATE<=N` (flattened switch) vs `sn[i](a,b)` register-dispatch vs `loadstring`-chain.
- **Operand packing:** `map[k]-k` offset-desc (Soteria) vs `band/bor/lshift` field-extract (IronBrew/LuaLock) vs `bit32.*`/`bit` ops.
- **Anti-tamper APIs in const pool:** executor-name/`isfunctionhooked`/`debug.info`/`getrenv`/`hookfunction`/`namecall`/`loadstring`/`task.wait` — presence + which ones → engine family.
- **Stream/const headers:** `SOTR`/`LPH`/`IB2`/`MoonSec`/`Obscura`/`LuaLock`/`MoonVeil`/`Prometheus` strings.

Then apply the matching recipe; worst case, drive the real machine + dump `constants`/`instructions`/`stack`/`opcodes` — that's always enough to lift readable source.



## Corpus-validated engines (verified on real obfuscated samples — terrorlua/obfuscator-samples)

These were fingerprinted against genuine obfuscator output, not guesswork:

**SynapseXen** — `--[[ Synapse Xen vX.Y by Synapse GP / VM Hash: <sha256> ]]` +
`SynapseXen_<mixed lI garbage>=select;SynapseXen_...=string.byte;...` — the
camel `SynapseXen_` name prefix is unique. Compile-to-VM; recover constants +
the `NV`-tagged instruction stream.

**Boronide** (herrtt) — `--[[ herrtt's obfuscator, vX ]]` + the
`([[herrtts obf, discord.gg/BZEjFbeUvk]]):gsub('(.*)',function` bootstrap +
`while(g<h)do h=g-<num>` numeric counter loops. VM; ~210 call-arg constants +
~11 opcode handlers recoverable.

**77fuscator** — `do local a=[[77fuscator X.Y.Z discord.gg/7ZQ244HpVp]]` +
`return(function(a)local b,c,d,...,bj local bj=0 while true do if bj>=2 ...`
numeric control-flow state machine. VM; the ~147KB instruction stream is the
payload body.

**LPS** — Ascii85-family decoder: `local c,q,r,s,t=c(p,1,5);local c=(t-33)+
(s-33)*85+(r-33)*7225+(q-33)*614125+(c-33)*52200625` — the powers-of-85
accumulate is unique. String-decode wrapper; the scrambled 62-entry string
constant pool is recoverable.

**IronBrew3** — `--ironbrew3:tm:, vX.Y` + `return(function(<scrambled params>)
... repeat if not(not(d` control-flow. Newest IronBrew; VM.

**LuaObfuscator (Ferib, luaobfuscator.com)** — sequential `local v0=tonumber;
v1=string.byte; v2=...` numbered builtin aliases (v0..vN in order — the v0
preamble is unique). Two shapes: VM mode (ldexp + getfenv aliases) and
ChaoticEvil (string.char + bit32.bxor decode). String-encryption + control flow.

**wYnFuscate** — `-- Protected by wYnFuscate: https://wynfuscate.com` +
`return(function(Ja,JB,JW,...) if not Ja then Ja=getfenv` — J-prefixed params +
getfenv bootstrap. Online-key sealed VM.

**Hercules** — `--[Obfuscated by Hercules vX.Y | hercules-obfuscator.xyz]`.
VM; dedicated handler exists (runHercules).

**IronBrew1** — `generated using ironbrew1` + `return(function(a,a,b,b,b,b,c,d,...)`
massive-dummy-param shell (distinguish from IB2 by the `ironbrew1` mark, not
the `ironbrew` substring). IronBrew2's alternate shape = single-letter builtin
aliases `local K=string.byte;N=string.char;...math.ldexp` (ldexp is near-unique).

## Detection-performance note
Several fingerprint patterns used a greedy `\w+` before `[` — quadratic on
giant minified blobs (a 489KB file hung detect >3min). Bound identifiers to
`{1,40}` or drop the prefix when the bracket+index is the discriminator, and
cap the full-file scan window (~256KB) — fingerprints always live in the
preamble/early decode structure.


## Field notes from production detection hardening (deobf-service)

- **WeAreDevs = Prometheus.** wearedevs.net's obfuscator is unmodified Prometheus
  ("use it as a backend tool") — output is the Prometheus `;`-separated
  `{"\083\076...";"..."}` escaped-string table + `for w,w in ipairs({{` loop.
  Only the `--[[ vX https://wearedevs.net/obfuscator ]]` banner distinguishes it;
  without the banner it IS Prometheus. Fingerprint WeAreDevs by banner + let
  Prometheus win structural ties (put the generic family first in resolution
  order — a file that is literally Prometheus should not be relabeled by a
  vendored copy).

- **Real-world scripts nest obfuscators.** A 692KB Solara Hub drop was
  WeAreDevs/Prometheus outer + an embedded `MoonSec V3` gsub'd blob. Detect
  returns the strongest single signal — expose `candidates[]` (every engine
  >=30) so multi-layer files report all layers, not just the top.

- **Literal self-ID banners beat structural coincidence.** `Protected by X`,
  `This file was obfuscated using X`, `generated using X`, `Obfuscated by X`
  are ground truth — score them decisively (+90) above structural patterns
  that can collide across engines (e.g. `%0x` hex-remainder math appears in
  both MoonSec and Prometheus; `\ddd` runs appear in everything).

- **Escape-table regex must allow MULTI-escape strings.** `"(?:\\\d{2,3})+`
  not `"\\\d{2,3}"` — real const strings are `\083\076\104...` (many
  escapes per string), so a single-escape pattern silently misses.

- **Source-level vs VM engines.** Prometheus/WeAreDevs/string-enc/byte-array/
  XOR/lual.org/Flurace/PSU reconstruct real source (full or normalized).
  Luraph/Soteria/IronBrew-VM/SynapseXen/Boronide/77fuscator/wYnFuscate-V5/
  MoonVeil-v2 compile to custom bytecode — recover constants + opcode
  dispatch + encoded stream + API surface and mark `partial`; literal source
  needs a per-engine deserializer port (multi-week each, same class as the
  Soteria break).


## Bytecode-blob encodings located in the field (deeper devirt frontier)

- **Luraph v13 `LPH#` stream:** custom nibble alphabet `{0-9, A-F, H}` — not
  standard base; `H` is a structural token (separator/marker), not a hex digit.
  The blob is the per-version serialized instruction+constant stream; decoding
  needs the matching Luraph deserializer (the `LPH#` magic alone locates it —
  recover offset+length, then port that version's decode routine). Cross-version
  check: v10-v13 all emit `LPH#`-prefixed streams; the version string in the
  `-- generated using Luraph Obfuscator vX.Y.Z` banner selects the decoder.

- **Opcode-dispatch shapes that label the ISA:** named-handler tables
  (`local X=function` / `[,{}]X=function`) vs `if/elseif op==N` state machines.
  Tagging each branch's builtin calls (arith/compare/loop/env/string/table)
  reconstructs the VM's opcode semantics without a full deserializer — the
  implemented `handlerSemantics`/`dispatchBranches` approach.

- **Method-name constants map to libraries** even when the VM only stores bare
  names: `bnot/bor/bxor/band/lshift/rshift`→bit32, `byte/char/sub/gsub`→string,
  `insert/concat/unpack`→table, `readi8/writef32/fromhex`→buffer,
  `GetService/FireServer/Connect`→roblox. Recovers the payload's API surface.


## Dynamic-devirt harness results (Lune, real obfuscated samples)

Confirmed the dynamic-dump path boots these VMs in a Luau harness
(`@lune/luau` `luau.load(src,{environment=env})` with a polymorphic-stub env):

- **Luraph v13:** the outer shell + inner VM boot; the interpreter executes to
  `internal:3` then `call a nil value` — the VM's *data-driven* deserializer
  resolves a register that is nil. Globals are NOT the blocker (a polymorphic
  self-referential stub — callable+indexable, never nil — satisfies every
  global; the only literal global touched is `wait`). The wall is the `LPH#`
  stream's own deserialize producing a nil register — a field-desync INSIDE the
  VM identical in class to Soteria's `om`/`Fu` off-by-nibble. Devirt path:
  port that version's deserializer (the `LPH#` nibble decode + its register
  layout), not env-stubbing.

- General rule confirmed across the corpus: **env-stubbing unblocks only the
  outer shell**; the inner register-VM deserializer always needs the real
  decoded values, so full devirt = replicate the per-version byte-decode, which
  is the multi-week per-engine effort. Constant-pool + dispatch-shape +
  LPH#-blob extraction (what `vm_family` does) is the tractable recovery.


## Dynamic-devirt harness — per-engine tractability (Lune, real samples)

The polymorphic-stub env harness boots each bytecode VM and reveals how deep
the devirt can go before the deserializer wall:

- **77fuscator (0.6.5):** VM FULLY EXECUTES its decoded payload — ran to the
  payload's own guard `[-]: Cannot run bedol hub. you already executed` /
  `Error try again in nextyear`. The decoded program runs real logic through
  the VM's env (its `print` fires). No `loadstring` boundary — the payload
  executes as internal bytecode. `bj`-register `while true do if bj>=N` numeric
  state machine (31 machines); consts decode via `string.sub` char-shift
  (interceptable). MOST tractable VM for a full devirt — the payload runs, so
  hook the VM's string-decode / opcode stream to capture the program.

- **Luraph v13:** boots, executes to `internal:3` then `call a nil value` —
  `LPH#` deserializer produces a nil register. Globals satisfied (only literal
  access is `wait`). Data-driven decode wall.

- **Boronide (herrtt):** `call a nil value` at `:5` — same deserializer-
  register class as Luraph.

- **SynapseXen:** hangs (waits on a real Roblox API the poly-stub can't
  satisfy, or an inner scheduler loop) — needs real `game`/`task` semantics.

- Pattern: state-machine VMs (77fuscator) that run their decoded payload are
  more tractable than data-driven deserializers (Luraph/Boronide/Soteria)
  whose field-resolution self-desyncs. For a run-to-payload VM, the full
  devirt = hook its internal string-decode + opcode dispatch to dump the
  program; for a deserializer VM it = port the byte-decode.
