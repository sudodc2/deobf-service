"""Discord bot for the Moonveil deobfuscator.

Moonveil is environment-locked: its VM only decrypts correctly inside a real
Roblox environment (the decrypt key derives from real `game` object props). So
the deobfuscation is a TWO-PHASE flow driven from Discord:

  Phase 1  .moonveil  (attach a .lua/.luau)
             -> the bot builds a trace harness for that build and sends it back.
             -> you run the harness in your Roblox executor; it writes
                `moonveil_trace.txt` (via writefile).
  Phase 2  .trace     (attach the moonveil_trace.txt the harness produced)
             -> the bot matches it with your last .moonveil upload, runs the
                register-lifter reconstruction and returns the devirtualized Lua.

Any of .moonveil/.decompile/.trace also accept a URL (`.decompile <url>`) or a
reply to a message with the file, not just a direct attachment.

Extra:
  .decompile (attach a .lua)  -> the static/luau pipeline (strings, disasm,
                                 structured CFG) — partial without a trace.
  .config / .cfg              -> interactive toggles for which .decompile
                                 artifacts are sent (buttons + `.cfg <key>`).
  .status                     -> show your pending trace session.
  .abort                      -> cancel your pending trace session.
  .help                       -> command overview.
  (every command has a slash `/` equivalent.)

Setup: put DISCORD_TOKEN in a .env next to this script and
`pip install -r moonveil_bot_requirements.txt`. Enable the MESSAGE CONTENT
intent in the Developer Portal for the `.` prefix commands.
"""

import asyncio
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

import discord
from discord import app_commands
from discord.ext import commands

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "moonveil_bot_config.json")
SESSIONS_DIR = os.path.join(BASE, "mvbot_sessions")
MAX_INPUT = 16 * 1024 * 1024
MAX_TRACE = 48 * 1024 * 1024
MAX_UPLOAD = 24 * 1024 * 1024
PROC_TIMEOUT = 320

JOB_DELAY = float(os.environ.get("MOONVEIL_JOB_DELAY", "4"))
MAX_QUEUE = int(os.environ.get("MOONVEIL_MAX_QUEUE", "25"))

OWNER_IDS = {1057422089025486918}
OWNER_IDS |= {int(x) for x in os.environ.get("MOONVEIL_OWNER_IDS", "").replace(",", " ").split()
              if x.strip().isdigit()}


def _is_owner(scope_id):
    try:
        return int(scope_id) in OWNER_IDS
    except (TypeError, ValueError):
        return False


class QueueFull(Exception):
    """Raised when the backlog is at MAX_QUEUE; the caller just returns."""


class _JobQueue:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.waiting = 0
        self.busy = False

    @property
    def depth(self):
        return self.waiting + (1 if self.busy else 0)


QUEUE = _JobQueue()


@contextlib.asynccontextmanager
async def queued(send=None, scope_id=None):
    """Serialise heavy pipeline work through QUEUE. Tells the user their queue
    position if others are ahead, rejects with QueueFull past MAX_QUEUE, and
    sleeps JOB_DELAY after each job so the VPS gets breathing room. Owners
    (OWNER_IDS) bypass the queue, cap and cooldown entirely."""
    if _is_owner(scope_id):
        yield
        return
    q = QUEUE
    if q.depth >= MAX_QUEUE:
        if send:
            await send(content="Queue is full (%d jobs waiting). Please try again in a bit."
                               % MAX_QUEUE)
        raise QueueFull()
    ahead = q.depth
    q.waiting += 1
    got = False
    try:
        if ahead > 0 and send:
            await send(content="Queued - you're #%d in line. I'll post your result here "
                               "when it's your turn." % (ahead + 1))
        await q.lock.acquire()
        got = True
        q.waiting -= 1
        q.busy = True
        yield
    finally:
        if got:
            if JOB_DELAY > 0:
                await asyncio.sleep(JOB_DELAY)
            q.busy = False
            q.lock.release()
        else:
            q.waiting -= 1

OPTIONS = {
    "strings":      ("strings.txt",     "extracted strings",                 "auto"),
    "opcodes":      ("opcodes.txt",     "opcode + transition map",           "decompile"),
    "disasm":       ("disasm.txt",      "static disassembly (all branches)", "decompile"),
    "deobfuscated": ("deobfuscated.lua", "clean reconstructed Lua (calls, if/else/for)", "decompile"),
    "no_antitamper": (None,             "strip the anti-tamper from the output", "flag"),
}
ALIASES = {"str": "strings", "string": "strings", "ops": "opcodes", "op": "opcodes",
           "dis": "disasm", "disassembly": "disasm", "devirt": "deobfuscated",
           "structured": "deobfuscated", "struct": "deobfuscated", "deob": "deobfuscated",
           "deobf": "deobfuscated", "output": "deobfuscated",
           "noat": "no_antitamper", "antitamper": "no_antitamper", "stripat": "no_antitamper"}
DEFAULTS = {"strings": True, "opcodes": False, "disasm": False,
            "deobfuscated": True, "no_antitamper": False}
DECOMPILE_OUTPUTS = {
    "opcodes": "moonveil_opcodes.txt",
    "disasm": "moonveil_disasm.txt",
    "deobfuscated": "moonveil_structured.lua",
}


def load_env(path=os.path.join(BASE, ".env")):
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def load_configs():
    if os.path.exists(CONFIG_PATH):
        try:
            return json.load(open(CONFIG_PATH, encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_configs(cfgs):
    with open(CONFIG_PATH, "w", encoding="utf-8") as h:
        json.dump(cfgs, h, indent=2)


CONFIGS = load_configs()


def get_config(scope_id):
    cfg = dict(DEFAULTS)
    cfg.update(CONFIGS.get(str(scope_id), {}))
    return cfg


def set_config(scope_id, key, value):
    sid = str(scope_id)
    CONFIGS.setdefault(sid, {})[key] = value
    save_configs(CONFIGS)


def _session_dir(scope_id):
    d = os.path.join(SESSIONS_DIR, str(scope_id))
    os.makedirs(d, exist_ok=True)
    return d


def save_session(scope_id, filename, data):
    d = _session_dir(scope_id)
    with open(os.path.join(d, "input.lua"), "wb") as h:
        h.write(data)
    meta = {"filename": filename, "ts": time.time()}
    with open(os.path.join(d, "meta.json"), "w", encoding="utf-8") as h:
        json.dump(meta, h)


def load_session(scope_id):
    d = os.path.join(SESSIONS_DIR, str(scope_id))
    ip = os.path.join(d, "input.lua")
    if not os.path.exists(ip):
        return None
    meta = {}
    mp = os.path.join(d, "meta.json")
    if os.path.exists(mp):
        try:
            meta = json.load(open(mp, encoding="utf-8"))
        except Exception:
            meta = {}
    return {"input": ip, "filename": meta.get("filename", "input.lua"), "ts": meta.get("ts", 0)}


def clear_session(scope_id):
    d = os.path.join(SESSIONS_DIR, str(scope_id))
    existed = os.path.exists(os.path.join(d, "input.lua"))
    shutil.rmtree(d, ignore_errors=True)
    return existed


ACCUM_CAP = 64 * 1024 * 1024


def append_traces(scope_id, datas):
    """Append trace uploads to this session's accumulated trace file. Since the
    trace format is line-based and parse_trace groups by block across the whole
    text, concatenating multiple traces = merging them -> coverage grows with
    each run/branch the user exercises. Returns (accum_path, num_merged)."""
    d = _session_dir(scope_id)
    accum = os.path.join(d, "trace_accum.txt")
    with open(accum, "ab") as h:
        for data in datas:
            h.write(data)
            if not data.endswith(b"\n"):
                h.write(b"\n")
    if os.path.getsize(accum) > ACCUM_CAP:
        with open(accum, "rb") as h:
            h.seek(-ACCUM_CAP, os.SEEK_END)
            tail = h.read()
        with open(accum, "wb") as h:
            h.write(tail)
    cnt_path = os.path.join(d, "trace_count")
    n = 0
    if os.path.exists(cnt_path):
        try:
            n = int(open(cnt_path).read().strip() or "0")
        except ValueError:
            n = 0
    n += len(datas)
    open(cnt_path, "w").write(str(n))
    return accum, n


load_env()
TOKEN = os.environ.get("DISCORD_TOKEN", "")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=".", intents=intents, help_command=None)


import re as _re

_PATH_RE = _re.compile(
    r'(?<![:\w])[A-Za-z]:[\\/][\w.~+\-\\/]+'
    r'|(?<![:\w/])/[\w.~+\-]+(?:/[\w.~+\-]+)+')


def _scrub(text):
    """Strip absolute filesystem paths from anything shown to users: replace a
    path with just its basename so we never leak `C:\\Users\\...` or temp dirs.
    URLs (`scheme://...`) are left intact."""
    if not text:
        return text
    return _PATH_RE.sub(lambda m: os.path.basename(m.group(0).replace("\\", "/")), text)


_LUAU_HELP = ("luau is not installed on this server. It is REQUIRED (Moonveil runs "
              "its deserializer under Luau). Install the Luau CLI and make sure "
              "`luau` is on PATH, then retry. Linux: grab a release from "
              "github.com/luau-lang/luau/releases (or build it) and put it in /usr/local/bin.")


def _luau_ready():
    import shutil as _sh
    for cand in (os.environ.get("MOONVEIL_LUAU"), os.environ.get("LUAU_BIN")):
        if cand and (os.path.isfile(cand) or _sh.which(cand)):
            return True
    if _sh.which("luau"):
        return True
    return any(os.path.isfile(p) for p in ("/home/container/luau", "./luau"))


def _run(cmd, timeout, env=None):
    runenv = None
    if env:
        runenv = dict(os.environ)
        runenv.update(env)
    return subprocess.run(cmd, cwd=BASE, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, env=runenv)


import ipaddress
import socket
from urllib.parse import urlparse

FETCH_TIMEOUT = 30
_URL_RE = _re.compile(r"^https?://", _re.IGNORECASE)


def _looks_url(s):
    return bool(s) and bool(_URL_RE.match(s.strip()))


def _host_allowed(host):
    """SSRF guard: refuse to fetch internal / private / loopback addresses since
    the fetch runs on the bot's host. Resolves the name and checks every IP."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


async def fetch_url(url):
    """Download a script from a URL. Returns (filename, data, error)."""
    url = url.strip().strip("<>")
    if not _looks_url(url):
        return None, None, "not an http(s) URL"
    u = urlparse(url)
    if not _host_allowed(u.hostname):
        return None, None, "refusing to fetch that host (private/internal address)"
    import aiohttp
    timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT)
    headers = {"User-Agent": "MoonveilBot/1.0 (+deobfuscator)"}
    try:
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            async with sess.get(url, headers=headers, allow_redirects=True,
                                 max_redirects=3) as resp:
                if not _host_allowed(urlparse(str(resp.url)).hostname):
                    return None, None, "redirect pointed at a private address"
                if resp.status != 200:
                    return None, None, "HTTP %d fetching the URL" % resp.status
                data = b""
                async for chunk in resp.content.iter_chunked(65536):
                    data += chunk
                    if len(data) > MAX_INPUT:
                        return None, None, "file too large (> %d MB)" % (MAX_INPUT // (1024 * 1024))
    except aiohttp.ClientError as e:
        return None, None, _scrub(str(e)[:200]) or "fetch failed"
    except asyncio.TimeoutError:
        return None, None, "fetch timed out (>%ds)" % FETCH_TIMEOUT
    if not data:
        return None, None, "the URL returned no content"
    name = os.path.basename(u.path) or "input.lua"
    if not name.lower().endswith((".lua", ".luau", ".txt")):
        name += ".lua"
    return name, data, None


def _gen_harness(input_path, out_luau):
    """Blocking. Returns (ok, log, fields)."""
    log = []
    try:
        r = _run([sys.executable, "gen_roblox_trace.py", input_path, out_luau], 120)
        for line in (r.stdout or "").strip().splitlines():
            if line.startswith("[*]") or line.startswith("[!]"):
                log.append(_scrub(line))
        ok = os.path.exists(out_luau) and os.path.getsize(out_luau) > 0
        if not ok:
            log.append(_scrub((r.stderr or "").strip()[-400:]) or "harness not produced")
        return ok, log
    except subprocess.TimeoutExpired:
        return False, ["harness generation timed out"]
    except Exception as e:
        return False, [_scrub("error: " + str(e)[:300])]


def _reconstruct(input_path, trace_path, out_lua, no_antitamper=False):
    """Blocking. Runs reconstruct_from_trace.py; copies the devirt output out.
    Returns (ok, log, stats)."""
    log = []
    stats = {}
    if not _luau_ready():
        return False, [_LUAU_HELP], stats
    outdir = os.path.dirname(out_lua)
    produced = os.path.join(outdir, "moonveil_trace_devirt.lua")
    try:
        if os.path.exists(produced):
            os.remove(produced)
    except OSError:
        pass
    renv = {"MOONVEIL_OUT_DIR": outdir}
    if no_antitamper:
        renv["MOONVEIL_NO_ANTITAMPER"] = "1"
    try:
        r = _run([sys.executable, "reconstruct_from_trace.py", input_path, trace_path],
                 PROC_TIMEOUT, env=renv)
        out = r.stdout or ""
        for line in out.strip().splitlines():
            if line.startswith("[*]") or line.startswith("[!]"):
                log.append(_scrub(line))
        m = _re.search(r"parsed (\d+) trace blocks, (\d+) total entries", out)
        if m:
            stats["blocks"], stats["entries"] = m.group(1), m.group(2)
        m = _re.search(r"learned (\d+) opcodes, (\d+) transitions", out)
        if m:
            stats["opcodes"], stats["transitions"] = m.group(1), m.group(2)
        covs = _re.findall(r"proto_(\d+): \d+ instrs, \d+ traced pcs \((\d+)% coverage\)", out)
        if covs:
            stats["covered"] = ", ".join("p%s %s%%" % (a, b) for a, b in covs[:6])
        if os.path.exists(produced) and os.path.getsize(produced) > 0:
            if produced != out_lua:
                shutil.copyfile(produced, out_lua)
            return True, log, stats
        log.append(_scrub((r.stderr or "").strip()[-400:]) or "no devirtualized output produced")
        return False, log, stats
    except subprocess.TimeoutExpired:
        return False, ["reconstruction timed out (>%ds)" % PROC_TIMEOUT], stats
    except Exception as e:
        return False, [_scrub("error: " + str(e)[:300])], stats


def _process(input_path, out_dir, cfg):
    log, artifacts, ok = [], {}, False
    if cfg.get("strings"):
        try:
            _run([sys.executable, "moonveil_auto.py", input_path], 200)
            sp = os.path.splitext(input_path)[0] + "_strings.txt"
            if os.path.exists(sp) and os.path.getsize(sp) > 0:
                artifacts["strings.txt"] = sp
                ok = True
        except Exception as e:
            log.append(_scrub("[strings] " + str(e)[:150]))
    if any(cfg.get(k) for k in DECOMPILE_OUTPUTS):
        if not _luau_ready():
            log.append(_LUAU_HELP)
            return {"ok": ok, "artifacts": artifacts, "log": log}
        dec_out = os.path.join(out_dir, "moonveil_decompiled.lua")
        denv = {"MOONVEIL_OUT_DIR": out_dir}
        if cfg.get("no_antitamper"):
            denv["MOONVEIL_NO_ANTITAMPER"] = "1"
        try:
            r = _run([sys.executable, "moonveil_decompile.py", input_path, dec_out],
                     PROC_TIMEOUT, env=denv)
            out = r.stdout or ""
            err = r.stderr or ""
            detected = "could not detect the interpreter" not in out
            for line in out.strip().splitlines():
                if line.startswith("[*]") or line.startswith("[!]"):
                    log.append(_scrub(line))
            if "luau not on PATH" in out or "luau not on PATH" in err:
                log.append(_LUAU_HELP)
            elif not detected:
                log.append("this file is not a recognized Moonveil build - nothing produced")
            else:
                for key, src_name in DECOMPILE_OUTPUTS.items():
                    if not cfg.get(key):
                        continue
                    src = os.path.join(out_dir, src_name)
                    if os.path.exists(src) and os.path.getsize(src) > 0:
                        dst = os.path.join(out_dir, OPTIONS[key][0])
                        if src != dst:
                            shutil.copyfile(src, dst)
                        artifacts[OPTIONS[key][0]] = dst
                        ok = True
                if not artifacts and err.strip():
                    log.append(_scrub(err.strip()[-300:]))
        except Exception as e:
            log.append(_scrub("[decompile] " + str(e)[:150]))
    return {"ok": ok, "artifacts": artifacts, "log": log}


class AbortView(discord.ui.View):
    """Abort button on the phase-1 message: cancels the pending trace session so
    the user can start a fresh `.moonveil` if the current trace isn't working."""

    def __init__(self, scope_id):
        super().__init__(timeout=1800)
        self.scope_id = scope_id
        self.owner_id = scope_id

    @discord.ui.button(label="Abort trace", style=discord.ButtonStyle.danger)
    async def abort(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message(
                "Only the person who started this trace can abort it.", ephemeral=True)
            return
        clear_session(self.scope_id)
        button.disabled = True
        button.label = "Aborted"
        self.stop()
        em = discord.Embed(
            title="Moonveil - trace aborted",
            color=discord.Color.light_grey(),
            description="Pending trace cancelled. Run `.moonveil` with a `.lua` "
                        "again to start a new trace.")
        em.set_footer(text="Moonveil deobfuscator made by 2zvh")
        await interaction.response.edit_message(embed=em, view=self)

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True


def _phase1_embed(filename, log, ok):
    em = discord.Embed(
        title="Moonveil - step 1/2: run this in your executor",
        color=discord.Color.green() if ok else discord.Color.red())
    em.add_field(name="input", value="`%s`" % filename[:80], inline=False)
    if ok:
        em.description = (
            "Moonveil is **environment-locked** (it only decrypts inside real "
            "Roblox), so I built a trace harness for this exact build.\n\n"
            "**1.** Run the attached `moonveil_roblox_trace.luau` in your Roblox "
            "executor (inside a game).\n"
            "**2.** It writes `moonveil_trace.txt` to your executor's workspace "
            "folder (auto-flush ~10s).\n"
            "**3.** Send it back here with `.trace` (attach `moonveil_trace.txt`).\n\n"
            "Tip: open the script's UI / trigger its branches before the flush "
            "for higher coverage.")
    else:
        em.description = "```\n" + "\n".join(log[-6:])[:1500] + "\n```"
    em.set_footer(text="Moonveil deobfuscator made by 2zvh")
    return em


def _phase2_embed(filename, stats, log, ok):
    em = discord.Embed(
        title="Moonveil - step 2/2: deobfuscated",
        color=discord.Color.green() if ok else discord.Color.red())
    em.add_field(name="trace", value="`%s`" % filename[:80], inline=True)
    if "blocks" in stats:
        em.add_field(name="traced", value="%s blk / %s ins" % (stats["blocks"], stats.get("entries", "?")), inline=True)
    if "transitions" in stats:
        em.add_field(name="learned", value="%s op / %s tr" % (stats.get("opcodes", "?"), stats["transitions"]), inline=True)
    if stats.get("merged", 0) > 1:
        em.add_field(name="merged", value="%d traces" % stats["merged"], inline=True)
    if stats.get("covered"):
        em.add_field(name="coverage", value=stats["covered"][:1000], inline=False)
    if not ok and log:
        em.description = "```\n" + "\n".join(log[-6:])[:1500] + "\n```"
    elif ok:
        em.description = ("Reconstructed the executed paths (calls, methods, args, conditions). "
                          "Untraced branches are collapsed.\nSend more `.trace` files for this "
                          "build (or attach several at once) and I'll **merge** them to raise coverage.")
    em.set_footer(text="Moonveil deobfuscator made by 2zvh")
    return em


def _config_embed(cfg):
    em = discord.Embed(
        title="Moonveil .decompile config", color=discord.Color.blurple(),
        description="Which artifacts `.decompile` sends back. Tap a button below "
                    "to toggle, or use `.cfg <key>` / `.cfg <key> on|off`.")
    for key, (fname, desc, _t) in OPTIONS.items():
        mark = "\N{WHITE HEAVY CHECK MARK}" if cfg.get(key) else "\N{WHITE LARGE SQUARE}"
        val = ("`%s` - %s" % (fname, desc)) if fname else desc
        em.add_field(name="%s  %s" % (mark, key), value=val, inline=False)
    em.set_footer(text="Moonveil deobfuscator made by 2zvh")
    return em


class ConfigView(discord.ui.View):
    """Interactive toggles for the `.decompile` artifact config. Each button
    flips one option and live-updates the embed; Reset restores defaults."""

    def __init__(self, scope_id):
        super().__init__(timeout=300)
        self.scope_id = scope_id
        self.owner_id = scope_id
        self._build()

    def _build(self):
        self.clear_items()
        cfg = get_config(self.scope_id)
        for key in OPTIONS:
            on = cfg.get(key)
            btn = discord.ui.Button(
                label=key, row=0 if list(OPTIONS).index(key) < 5 else 1,
                style=discord.ButtonStyle.success if on else discord.ButtonStyle.secondary)
            btn.callback = self._toggle_cb(key)
            self.add_item(btn)
        reset = discord.ui.Button(label="Reset defaults", style=discord.ButtonStyle.danger, row=1)
        reset.callback = self._reset_cb
        self.add_item(reset)

    async def _guard(self, interaction):
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message(
                "This config panel isn't yours - run `.config` to open your own.",
                ephemeral=True)
            return False
        return True

    def _toggle_cb(self, key):
        async def cb(interaction: discord.Interaction):
            if not await self._guard(interaction):
                return
            set_config(self.scope_id, key, not get_config(self.scope_id).get(key))
            self._build()
            await interaction.response.edit_message(
                embed=_config_embed(get_config(self.scope_id)), view=self)
        return cb

    async def _reset_cb(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        for k, v in DEFAULTS.items():
            set_config(self.scope_id, k, v)
        self._build()
        await interaction.response.edit_message(
            embed=_config_embed(get_config(self.scope_id)), view=self)

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True


def _help_embed():
    em = discord.Embed(
        title="Moonveil deobfuscator - commands",
        color=discord.Color.blurple(),
        description="Moonveil is **environment-locked** (its VM only decrypts inside "
                    "real Roblox), so the main flow is two steps.")
    em.add_field(
        name="Main flow",
        value="**`.moonveil`** *(attach `.lua`/`.luau`)* - step 1: build a Roblox "
              "trace harness.\n"
              "**`.trace`** *(attach `moonveil_trace.txt`)* - step 2: devirtualize "
              "from the runtime trace.\n"
              "You can run any of these by **replying** to a message that has the "
              "file, or by passing a **URL** (`.decompile <url>`) instead of "
              "uploading it.",
        inline=False)
    em.add_field(
        name="Extra",
        value="**`.decompile`** *(attach `.lua`)* - static pipeline (strings / "
              "disasm / structured), partial without a trace.\n"
              "**`.config`** - toggle which `.decompile` files come back.\n"
              "**`.status`** - show your pending trace session.\n"
              "**`.queue`** - show how many jobs are waiting.\n"
              "**`.help`** - this message.",
        inline=False)
    em.add_field(
        name="Tip",
        value="Open the script's UI and trigger its branches in-game before the "
              "harness flushes (~10s) for higher trace coverage.",
        inline=False)
    em.set_footer(text="Moonveil deobfuscator made by 2zvh - slash (/) equivalents exist too")
    return em


def _status_embed(sess):
    if not sess:
        em = discord.Embed(title="Moonveil - no pending session",
                           color=discord.Color.light_grey(),
                           description="Run `.moonveil` with a `.lua` to start.")
    else:
        age = max(0, int(time.time() - sess.get("ts", 0)))
        em = discord.Embed(title="Moonveil - pending trace session",
                           color=discord.Color.green(),
                           description="Send the harness output back with `.trace`.")
        em.add_field(name="file", value="`%s`" % sess["filename"][:80], inline=True)
        em.add_field(name="age", value="%dm %ds" % (age // 60, age % 60), inline=True)
    depth = QUEUE.depth
    em.add_field(name="queue",
                 value=("idle" if depth == 0
                        else "%d job%s ahead" % (depth, "" if depth == 1 else "s")),
                 inline=True)
    em.set_footer(text="Moonveil deobfuscator made by 2zvh")
    return em


def _queue_embed():
    depth = QUEUE.depth
    if depth == 0:
        desc = "Idle - your job would start right away."
        color = discord.Color.green()
    else:
        running = "one job is running" if QUEUE.busy else "no job running"
        desc = ("%d job%s in the pipeline (%s, %d waiting). New jobs run one at a "
                "time with a %.0fs cooldown between them." %
                (depth, "" if depth == 1 else "s", running, QUEUE.waiting, JOB_DELAY))
        color = discord.Color.orange()
    em = discord.Embed(title="Moonveil - queue", color=color, description=desc)
    em.add_field(name="capacity", value="%d / %d" % (depth, MAX_QUEUE), inline=True)
    em.add_field(name="cooldown", value="%.0fs" % JOB_DELAY, inline=True)
    em.set_footer(text="Moonveil deobfuscator made by 2zvh")
    return em


async def handle_moonveil(scope_id, filename, data, send):
    low = filename.lower()
    if not (low.endswith(".lua") or low.endswith(".luau") or low.endswith(".txt")):
        await send(content="Attach a Moonveil `.lua` / `.luau` file.")
        return
    if len(data) > MAX_INPUT:
        await send(content="File too large (max %d MB)." % (MAX_INPUT // (1024 * 1024)))
        return
    save_session(scope_id, filename, data)
    tmp = tempfile.mkdtemp(prefix="mvbot_")
    try:
        input_path = os.path.join(tmp, "input.lua")
        with open(input_path, "wb") as h:
            h.write(data)
        out_luau = os.path.join(tmp, "moonveil_roblox_trace.luau")
        loop = asyncio.get_running_loop()
        async with queued(send, scope_id):
            ok, log = await asyncio.wait_for(
                loop.run_in_executor(None, _gen_harness, input_path, out_luau), timeout=150)
        files = []
        if ok and os.path.getsize(out_luau) <= MAX_UPLOAD:
            files.append(discord.File(out_luau, filename="moonveil_roblox_trace.luau"))
        kw = {"embed": _phase1_embed(filename, log, ok), "files": files}
        if ok:
            kw["view"] = AbortView(scope_id)
        await send(**kw)
    except QueueFull:
        return
    except asyncio.TimeoutError:
        await send(content="Timed out building the harness.")
    except Exception:
        await send(content="```\n" + _scrub(traceback.format_exc()[-1800:]) + "\n```")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def handle_trace(scope_id, filename, datas, send):
    if isinstance(datas, (bytes, bytearray)):
        datas = [datas]
    if sum(len(d) for d in datas) > MAX_TRACE:
        await send(content="Trace too large (max %d MB)." % (MAX_TRACE // (1024 * 1024)))
        return
    sess = load_session(scope_id)
    if not sess:
        await send(content="No pending Moonveil file. Run `.moonveil` with your `.lua` first, "
                           "then send the trace here.")
        return
    accum, merged = append_traces(scope_id, datas)
    no_at = bool(get_config(scope_id).get("no_antitamper"))
    tmp = tempfile.mkdtemp(prefix="mvtrace_")
    try:
        trace_path = os.path.join(tmp, "trace.txt")
        shutil.copyfile(accum, trace_path)
        out_lua = os.path.join(tmp, "moonveil_trace_devirt.lua")
        loop = asyncio.get_running_loop()
        async with queued(send, scope_id):
            ok, log, stats = await asyncio.wait_for(
                loop.run_in_executor(None, _reconstruct, sess["input"], trace_path, out_lua, no_at),
                timeout=PROC_TIMEOUT + 40)
        stats["merged"] = merged
        files = []
        if ok and os.path.getsize(out_lua) <= MAX_UPLOAD:
            files.append(discord.File(out_lua, filename="moonveil_deobfuscated.lua"))
        await send(embed=_phase2_embed(filename, stats, log, ok), files=files)
    except QueueFull:
        return
    except asyncio.TimeoutError:
        await send(content="Timed out reconstructing from the trace.")
    except Exception:
        await send(content="```\n" + _scrub(traceback.format_exc()[-1800:]) + "\n```")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def handle_decompile(scope_id, filename, data, send):
    low = filename.lower()
    if not (low.endswith(".lua") or low.endswith(".luau") or low.endswith(".txt")):
        await send(content="Attach a Moonveil `.lua` / `.luau` file.")
        return
    if len(data) > MAX_INPUT:
        await send(content="File too large.")
        return
    cfg = get_config(scope_id)
    tmp = tempfile.mkdtemp(prefix="mvdec_")
    try:
        input_path = os.path.join(tmp, "input.lua")
        with open(input_path, "wb") as h:
            h.write(data)
        loop = asyncio.get_running_loop()
        async with queued(send, scope_id):
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _process, input_path, tmp, cfg), timeout=PROC_TIMEOUT + 40)
        files = [discord.File(p, filename=n) for n, p in result["artifacts"].items()
                 if os.path.getsize(p) <= MAX_UPLOAD]
        em = discord.Embed(title="Moonveil .decompile (static/partial)",
                           color=discord.Color.green() if result["ok"] else discord.Color.red())
        em.add_field(name="files", value=", ".join(result["artifacts"].keys()) or "none", inline=False)
        want = ["strings.txt"] if cfg.get("strings") else []
        want += [OPTIONS[k][0] for k in DECOMPILE_OUTPUTS if cfg.get(k)]
        skipped = [n for n in want if n not in result["artifacts"]]
        if skipped:
            em.add_field(name="not produced", value=", ".join(skipped), inline=False)
        em.add_field(name="tip", value="For complete output use the trace flow: "
                     "`.moonveil` -> run harness -> `.trace`.", inline=False)
        if result["log"]:
            em.description = "```\n" + "\n".join(result["log"][-8:])[:1800] + "\n```"
        em.set_footer(text="Moonveil deobfuscator made by 2zvh")
        await send(embed=em, files=files)
    except QueueFull:
        return
    except Exception:
        await send(content="```\n" + _scrub(traceback.format_exc()[-1800:]) + "\n```")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _resolve_key(key):
    key = key.lower()
    return key if key in OPTIONS else ALIASES.get(key)


def _scope(ctx_or_i):
    if isinstance(ctx_or_i, discord.Interaction):
        return ctx_or_i.user.id
    return ctx_or_i.author.id


async def _resolve_attachment(ctx):
    """The first attachment on the command message, or - if the command is a
    reply - the first attachment on the message being replied to. Lets you run
    `.moonveil` / `.decompile` / `.trace` by replying to someone's file."""
    if ctx.message.attachments:
        return ctx.message.attachments[0]
    ref = ctx.message.reference
    if ref is not None:
        msg = ref.resolved if isinstance(ref.resolved, discord.Message) else None
        if msg is None:
            try:
                msg = await ctx.channel.fetch_message(ref.message_id)
            except Exception:
                msg = None
        if msg and msg.attachments:
            return msg.attachments[0]
    return None


async def _slash_input(file, url):
    """Slash-command input: an attachment or a URL. Returns (filename, data, err)."""
    if file is not None:
        return file.filename, await file.read(), None
    if url and _looks_url(url):
        return await fetch_url(url)
    return None, None, None


async def _resolve_one(ctx, arg):
    """A single input for .moonveil/.decompile: an attachment (own message or a
    reply) or a URL given as the command argument. Returns (filename, data, err)."""
    att = await _resolve_attachment(ctx)
    if att is not None:
        return att.filename, await att.read(), None
    if arg and _looks_url(arg):
        return await fetch_url(arg)
    return None, None, None


async def _resolve_attachments(ctx):
    """All attachments on the command message, or those on the replied-to
    message. Used by `.trace` so several trace files merge in one command."""
    if ctx.message.attachments:
        return list(ctx.message.attachments)
    ref = ctx.message.reference
    if ref is not None:
        msg = ref.resolved if isinstance(ref.resolved, discord.Message) else None
        if msg is None:
            try:
                msg = await ctx.channel.fetch_message(ref.message_id)
            except Exception:
                msg = None
        if msg and msg.attachments:
            return list(msg.attachments)
    return []


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    try:
        await ctx.reply("error: ```\n%s\n```" % _scrub(str(error)[:1500]))
    except Exception:
        pass


@bot.event
async def on_ready():
    try:
        synced = await bot.tree.sync()
        print("synced %d slash commands" % len(synced))
    except Exception as e:
        print("slash sync failed:", e)
    if not _luau_ready():
        print("[!] WARNING: `luau` is NOT on PATH. .decompile and .trace will not "
              "work until you install the Luau CLI. (.moonveil harness gen still works.)")
    print("logged in as %s (%s)" % (bot.user, bot.user.id))


@bot.command(name="moonveil", aliases=["mv"])
async def moonveil_prefix(ctx, *, arg: str = None):
    async with ctx.typing():
        filename, data, err = await _resolve_one(ctx, arg)
    if err:
        await ctx.reply("Couldn't fetch that URL: %s" % err)
        return
    if data is None:
        await ctx.reply("Attach a Moonveil `.lua` file, give a URL "
                        "(`.moonveil <url>`), or reply to a message that has one.")
        return
    async with ctx.typing():
        await handle_moonveil(_scope(ctx), filename, data, lambda **kw: ctx.reply(**kw))


@bot.command(name="trace", aliases=["mvtrace", "t"])
async def trace_prefix(ctx, *, arg: str = None):
    atts = await _resolve_attachments(ctx)
    if atts:
        datas = [await a.read() for a in atts]
        name = atts[0].filename
    elif arg and _looks_url(arg):
        async with ctx.typing():
            name, data, err = await fetch_url(arg)
        if err:
            await ctx.reply("Couldn't fetch that URL: %s" % err)
            return
        datas = [data]
    else:
        await ctx.reply("Attach the `moonveil_trace.txt` your harness produced "
                        "(several to merge them), give a URL, or reply to the "
                        "message that has it.")
        return
    async with ctx.typing():
        await handle_trace(_scope(ctx), name, datas, lambda **kw: ctx.reply(**kw))


@bot.command(name="decompile", aliases=["dec"])
async def decompile_prefix(ctx, *, arg: str = None):
    async with ctx.typing():
        filename, data, err = await _resolve_one(ctx, arg)
    if err:
        await ctx.reply("Couldn't fetch that URL: %s" % err)
        return
    if data is None:
        await ctx.reply("Attach a Moonveil `.lua` file, give a URL "
                        "(`.decompile <url>`), or reply to a message that has one.")
        return
    async with ctx.typing():
        await handle_decompile(_scope(ctx), filename, data, lambda **kw: ctx.reply(**kw))


@bot.command(name="config", aliases=["cfg"])
async def cfg_prefix(ctx, key: str = None, value: str = None):
    scope = _scope(ctx)
    if key is None:
        await ctx.reply(embed=_config_embed(get_config(scope)), view=ConfigView(scope))
        return
    if key.lower() == "reset":
        for k, v in DEFAULTS.items():
            set_config(scope, k, v)
        await ctx.reply(embed=_config_embed(get_config(scope)), view=ConfigView(scope))
        return
    rk = _resolve_key(key)
    if rk is None:
        await ctx.reply("Unknown key. Options: " + ", ".join(OPTIONS) + " (or `reset`).")
        return
    if value is None:
        newval = not get_config(scope).get(rk)
    else:
        newval = value.lower() in ("on", "true", "1", "yes", "y", "enable", "enabled")
    set_config(scope, rk, newval)
    await ctx.reply(embed=_config_embed(get_config(scope)), view=ConfigView(scope))


@bot.command(name="help", aliases=["h", "commands"])
async def help_prefix(ctx):
    await ctx.reply(embed=_help_embed())


@bot.command(name="status", aliases=["session"])
async def status_prefix(ctx):
    await ctx.reply(embed=_status_embed(load_session(_scope(ctx))))


@bot.command(name="queue", aliases=["q"])
async def queue_prefix(ctx):
    await ctx.reply(embed=_queue_embed())


@bot.command(name="abort", aliases=["cancel"])
async def abort_prefix(ctx):
    existed = clear_session(_scope(ctx))
    await ctx.reply("Pending trace cancelled." if existed else "No pending session to cancel.")


@bot.tree.command(name="moonveil", description="Step 1: build a Roblox trace harness for a Moonveil file")
@app_commands.describe(file="The Moonveil .lua/.luau file", url="or a URL to fetch it from")
async def moonveil_slash(interaction: discord.Interaction,
                         file: discord.Attachment = None, url: str = None):
    await interaction.response.defer(thinking=True)
    fn, data, err = await _slash_input(file, url)
    if err or data is None:
        await interaction.followup.send(err or "Provide a `file` or a `url`.")
        return
    await handle_moonveil(interaction.user.id, fn, data,
                          lambda **kw: interaction.followup.send(**kw))


@bot.tree.command(name="trace", description="Step 2: reconstruct from the moonveil_trace.txt")
@app_commands.describe(file="The moonveil_trace.txt the harness produced", url="or a URL to fetch it from")
async def trace_slash(interaction: discord.Interaction,
                      file: discord.Attachment = None, url: str = None):
    await interaction.response.defer(thinking=True)
    fn, data, err = await _slash_input(file, url)
    if err or data is None:
        await interaction.followup.send(err or "Provide a `file` or a `url`.")
        return
    await handle_trace(interaction.user.id, fn, [data],
                       lambda **kw: interaction.followup.send(**kw))


@bot.tree.command(name="decompile", description="Static/partial pipeline (no trace needed)")
@app_commands.describe(file="The Moonveil .lua/.luau file", url="or a URL to fetch it from")
async def decompile_slash(interaction: discord.Interaction,
                          file: discord.Attachment = None, url: str = None):
    await interaction.response.defer(thinking=True)
    fn, data, err = await _slash_input(file, url)
    if err or data is None:
        await interaction.followup.send(err or "Provide a `file` or a `url`.")
        return
    await handle_decompile(interaction.user.id, fn, data,
                           lambda **kw: interaction.followup.send(**kw))


@bot.tree.command(name="config", description="Toggle which .decompile artifacts are returned")
async def config_slash(interaction: discord.Interaction):
    scope = interaction.user.id
    await interaction.response.send_message(
        embed=_config_embed(get_config(scope)), view=ConfigView(scope))


@bot.tree.command(name="help", description="Show the Moonveil bot commands")
async def help_slash(interaction: discord.Interaction):
    await interaction.response.send_message(embed=_help_embed())


@bot.tree.command(name="status", description="Show your pending Moonveil trace session")
async def status_slash(interaction: discord.Interaction):
    await interaction.response.send_message(
        embed=_status_embed(load_session(interaction.user.id)))


@bot.tree.command(name="queue", description="Show how many jobs are waiting in the pipeline")
async def queue_slash(interaction: discord.Interaction):
    await interaction.response.send_message(embed=_queue_embed())


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("No DISCORD_TOKEN found (set it in .env next to this script or the environment).")
    bot.run(TOKEN)
