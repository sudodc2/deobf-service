# Reverse-Engineering Methodology — Devirtualizing Luau/Lua VM Obfuscators

Real techniques for cracking VM-based obfuscators. Grounded in a full devirtualization of Soteria (3-layer custom VM). Written for the agents — follow this order.

## Core mindset

- A VM obfuscator does NOT store the original `.lua` text. The program ships as compiled bytecode in a custom ISA. "Deobfuscation" = recover the program: decode the container → dump the program data (constants, schema, instruction words, cipher key) → lift the executed instruction stream back to readable Lua. You are reconstructing source, not decrypting a file.
- Everything the program does is recoverable from the constant pool + instruction data, even when the deepest opcode-by-opcode listing is the last thing to fall.
- Work outside-in: container → interpreter → deserializer → exec. Never try to read the obfuscated source linearly — drive the real machine under a harness and dump its state.

## Step 1 — Fingerprint the engine

Match the blob's surface to a known engine before doing any work (see `OBFUSCATOR_DECODE_RECIPES.md`). Markers: SDK macros (`SOTR_*`, `LPH`, `IB2`, `MoonSec`), stream headers (`SOTR\x01`, `SOTR$!!(`), interpreter-table shape, constant-pool API names, preset/transform names.

## Step 2 — Build a runnable harness, not a reader

- Get a Luau/Lune runtime. Load the outer chunk; capture the decoded layer via `loadstring`/`fs.writeFile` hooks (write decoded bytes to `.bin`/`.txt` — sandbox stdout is usually buffered and lost on kill).
- The payload almost always runs under a scheduler (coroutine/task). Sandboxed schedulers panic on resume — shim `coroutine.*`/`task.*` to run synchronously or the machine dies before it starts.
- Stub the env mirror (`getrenv`/`getgenv`/`getfenv`/`setfenv`/`identifyexecutor`/`getcallingscript`/`getidentity`/Roblox globals) BEFORE the VM reads them, or it errors into a silent pcall-swallow that looks exactly like a control-flow hang.

## Step 3 — Dump program data early and often

- The interpreter object (here `l`) carries the whole decode chain as fields/methods. Enumerate it (`pairs`) and dump: constant pool (`Cw`/`Ws`), proto schema (`Fh`), opcode handlers (`sn`), permutation/`sp`, instruction-word positions (`Zt`/`my`), cipher key (`Bq`), the raw instruction stream (`jc`/`bk`/`nstream`), the descriptor maps (`om`/`zM`/`TW`/`Mu`/`HJ`).
- `__index`-lazy descriptor tables return nil on `rawget` and flood/empty on `pairs` — read them via metatable access (`t.x`), and only after the decode that populates them.

## Step 4 — Decode the ISA

- Find the dispatch loop: `nf=stream[cursor]` → `opcode=map[nf]-nf` → `handler`. The opcode is usually packed into an instruction word — look for the extraction expression and reverse it.
- Soteria's trick (generalizes): `word = index + value` — `om[nf]` returns `nf+op`, so `op = om[nf]-nf`. Operands ride the low digit of a base-N packed word: `sn[(word-index)/N]`, `reg[pos-index]`. A `(x-index)/N` lookup that yields a non-integer (`op + digit/N`) is THE desync signature — `math.floor` it.
- Register files: `dest = reg_e`, `src1 = reg_t`, `src2 = reg_M`, `opcode = reg_b`; `const_pool[op+v]`; `reg_t[reg_M]` for indexing.

## Step 5 — Handle control-flow flattening + state machines

- The deserializer/interpreter is `while true do if STATE<=N then ... continue/return ... end end` chains — a flattened switch over a state var. It "hangs" only if a state transition desyncs on bad input data, not because the loop is infinite.
- If it truly spins: rewrite every `while true do`/`while(not(false))do`/`repeat` to a bounded `for _=1,N do` to force-return — then dump whatever state got populated and salvage.
- If there's no `debug.sethook`/`getlocal` (sandboxes like Lune lack them), you cannot inspect live local state vars — the only deterministic route is a static port of the decoder, which is real multi-week work. Prefer dumping the *output* state (maps/populated tables) over tracing the loop.

## Step 6 — Anti-tamper & anti-analysis

- Decoded constant pool reveals the whole suite: executor-name blacklist (`Volt`/`Potassium`/etc), `isfunctionhooked`/`restorefunction`/`debug.info` `[C]`-frame fingerprinting, env/identity/callingscript reads, `Game:GetJobsInfo` compare batteries, `loadstring` honesty probes, timing seeds (`os.time`/`task.wait`), `pcall`/`error`/`traceback` control flow, `bit32`/`buffer`/`string.pack` + a rolling cipher key.
- Counter each by stubbing the *check*, not the whole VM: return a non-blacklisted executor name, a clean `debug.info` frame, `isfunctionhooked→false`, the expected job values, real `bit32`/`buffer`/`string.pack`.

## Step 7 — Lift to source

- With opcodes + operands + constants decoded, emit readable Lua: registers → locals, `sn[op]` handlers → statements, `const_pool` refs → literals, `reg_t[reg_M]` → indexing, control ops → `if`/`while`/`for`/`goto`.
- Deliver the byte-exact artifacts (decoded interpreter, constant pool, instruction words, cipher key, anti-tamper suite) alongside the reconstruction — those are the proof-of-break, and they're undeniable.

## Hard-won rules

- Timeouts kill buffered output — dump to files via `fs.writeFile`, never rely on stdout.
- Instrumentation changes behavior: heavy `__index`/`__newindex`+file-I/O loggers on hundreds of fields stall the deserialize. Prefer post-hoc dumps over live logging.
- A pcall-swallowed env/API error is indistinguishable from a hang — always run the raw layer first and fix the first hard error before assuming control-flow trouble.
- `local` counters inside a `while` body reset each iteration — bounded-loop rewrites must put the counter outside (`for _=1,N do`).
- The literal per-opcode table is the deepest layer — budget for a multi-week static port, not a runtime fix, when the deserializer self-describes its own operand maps.
