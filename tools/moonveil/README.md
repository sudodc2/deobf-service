# Moonveil Deobfuscator Discord Bot



# WARNING: U NEED LUAU INSTALLED ON UR MACHINE.


Moonveil is **environment-locked**: its VM only decrypts correctly inside a real
Roblox environment (the decrypt key derives from real `game` object properties).
So deobfuscation is a **two-phase** flow driven from Discord.

## Flow

> You can run `.moonveil`, `.decompile` or `.trace` three ways: **attach** the
> file, **reply** to a message that already has it, or pass a **URL**
> (`.decompile https://.../script.lua`) — the bot fetches the content and runs
> the same flow. URL fetches are size-capped and refuse private/internal
> addresses (SSRF guard).

**Step 1 — `.moonveil` (attach the Moonveil `.lua`/`.luau`, or reply to one)**
- The bot builds a trace harness tailored to that exact build and sends back
  `moonveil_roblox_trace.luau`, with an **Abort trace** button.
- Run it in your Roblox executor (inside a game). It writes `moonveil_trace.txt`
  to your executor's workspace folder (auto-flush ~10s; opening the script's UI
  / triggering its branches before the flush raises coverage).
- If the trace isn't working, press **Abort trace** to cancel the pending
  session, then `.moonveil` again for a fresh one.

> **Merging traces:** send `.trace` several times for the same build (or attach
> several trace files at once). The bot **accumulates and merges** them per
> session, so each run/branch you exercise in-game raises coverage of the
> reconstruction.

**Step 2 — `.trace` (attach the `moonveil_trace.txt` the harness produced)**
- The bot matches it with your last `.moonveil` upload, runs the register-lifter
  reconstruction, and returns `moonveil_devirtualized.lua` — the executed paths
  rebuilt into real Lua (calls, methods, args, comparison conditions,
  service locals, control flow). Untraced branches are collapsed.
- You can also reply to the message containing the trace with `.trace`.

## Extra commands
- `.decompile` (attach a `.lua`) — the static/luau pipeline (strings, disasm,
  structured CFG). Partial without a trace, but needs no executor. If the file
  isn't a recognized Moonveil build it says so and returns nothing (no stale
  output from another run is ever surfaced).
- `.config` / `.cfg` — interactive **buttons** to toggle which `.decompile`
  artifacts are sent (`strings`, `opcodes`, `disasm`, `devirtualized`,
  `decompiled`), plus a Reset. Also `.cfg <key>` (toggle), `.cfg <key> on|off`,
  `.cfg reset`.
- `.status` — show your pending trace session (file + age).
- `.abort` — cancel your pending trace session.
- `.help` — command overview.

Every command has a slash `/` equivalent (`/moonveil`, `/trace`, `/decompile`,
`/config`, `/status`, `/help`).

##  isolation
- Filesystem paths are stripped from everything the bot posts (logs, errors) —
  only basenames are shown, never `C:\Users\...` or temp dirs.
- Each run writes its fixed-name artifacts into an isolated per-run temp dir
  (`MOONVEIL_OUT_DIR`), so a failed or non-moonveil input can never pick up
  another file's leftover output.

## Setup
1. `pip install -r moonveil_bot_requirements.txt`
2. Put `DISCORD_TOKEN=...` in a `.env` next to the script (or in the environment).
3. Enable the **MESSAGE CONTENT** intent in the Discord Developer Portal (for the
   `.` prefix commands).
4. `python moonveil_bot.py`

Sessions (your uploaded `.lua` awaiting a trace) are kept per user under
`mvbot_sessions/`.

*Moonveil deobfuscator made by 2zvh*
