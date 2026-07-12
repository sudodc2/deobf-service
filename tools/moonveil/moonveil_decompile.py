import math
import os
import re
import shutil
import struct
import subprocess
import sys

import moonveil_auto as mauto
import register_lifter

sys.stdout.reconfigure(encoding="utf-8")


def _resolve_luau():
    """Locate the Luau CLI: MOONVEIL_LUAU env var, then PATH, then the common
    container path. Lets it work on a VPS where luau isn't on PATH."""
    for cand in (os.environ.get("MOONVEIL_LUAU"), os.environ.get("LUAU_BIN")):
        if cand and (os.path.isfile(cand) or shutil.which(cand)):
            return cand
    found = shutil.which("luau")
    if found:
        return found
    for cand in ("/home/container/luau", "./luau"):
        if os.path.isfile(cand):
            return cand
    return "luau"


LUAU = _resolve_luau()


def detect(src):
    best = None
    for m in re.finditer(r"function (\w+)\(([\w,]+)\)", src):
        params = m.group(2).split(",")
        if not (3 <= len(params) <= 6):
            continue
        body = src[m.end():m.end() + 9000]
        score = len(re.findall(r"\w+\[\d{4,5}\]", body))
        if best is None or score > best[0]:
            best = (score, params, m.end())
    if not best or best[0] < 8:
        return None
    params, body = best[1], src[best[2]:best[2] + 45000]

    candidates = {}
    for fm in re.finditer(r"(\w+)=(\w+)\[(\w+)\]", body):
        instr, code, pc = fm.group(1), fm.group(2), fm.group(3)
        if code in params and instr not in params:
            refs = len(re.findall(re.escape(instr) + r"\[\d{4,5}\]", body))
            if refs > candidates.get((instr, code, pc), 0):
                candidates[(instr, code, pc)] = refs
    if not candidates:
        return None
    (instr, code, pc), _ = max(candidates.items(), key=lambda kv: kv[1])

    regs = max(params, key=lambda p: (len(re.findall(re.escape(p) + r"\[" + re.escape(instr) + r"\[", body)),
                                      len(re.findall(re.escape(p) + r"\[[^\]]{1,24}\]=", body))))
    return {"regs": regs, "instr": instr, "code": code, "pc": pc}


LOGGER = r"""
do
    local _type, _rawget, _setmt, _osclock = type, rawget, setmetatable, os.clock
    local _table, _buffer = table, buffer
    local ok,g = pcall(getfenv)
    if not ok or _type(g)~="table" then g=_G end


    local mkproxy
    mkproxy = function(d)
        if d<=0 then return "" end
        local mt={}
        local p=_setmt({},mt)
        local function child() return mkproxy(d-1) end
        mt.__index=child
        mt.__call=child
        mt.__namecall=child        -- luau method dispatch (obj:Method())
        mt.__newindex=function() end
        mt.__concat=function() return "" end
        mt.__tostring=function() return "" end
        mt.__len=function() return 0 end
        mt.__eq=function() return false end
        mt.__lt=function() return false end
        mt.__le=function() return false end
        mt.__add=function() return 0 end
        mt.__sub=function() return 0 end
        mt.__mul=function() return 0 end
        mt.__div=function() return 0 end
        mt.__mod=function() return 0 end
        mt.__pow=function() return 0 end
        mt.__unm=function() return 0 end
        return p
    end
    local function proxyfn() return mkproxy(48) end


    rawset(g,'tick', function() return _osclock() end)
    rawset(g,'wait', function() return 0 end)
    rawset(g,'warn', function(...) return print(...) end)
    rawset(g,'task', _setmt({},{__index=function(_,k)
        if MV_STUB and (k=="spawn" or k=="defer" or k=="delay") then
            return function(f,...) if _type(f)=="function" then pcall(f,...) end end
        end
        return function() return 0 end
    end}))

    if _type(_table)=="table" and _type(_table.create)=="function" then
        local realc=_table.create
        rawset(g,'table', _setmt({create=function(n,...)
            if _type(n)~="number" or n~=n or n<1 then n=1 elseif n>1048576 then n=1048576 end
            return realc(n,...)
        end}, {__index=_table}))
    end
    if _type(_buffer)=="table" and _type(_buffer.create)=="function" then
        local realc=_buffer.create
        rawset(g,'buffer', _setmt({create=function(n,...)
            if _type(n)~="number" or n~=n or n<1 then n=1 elseif n>1073741824 then n=1073741824 end
            return realc(n,...)
        end}, {__index=_buffer}))
    end

    if MV_STUB then
        rawset(g,'delay', function() return 0 end)
        rawset(g,'spawn', function(f,...) if _type(f)=="function" then pcall(f,...) end end)

        rawset(g,'loadstring', function() return function() return mkproxy(48) end end)
        rawset(g,'require', proxyfn)
        rawset(g,'collectgarbage', function() return 0 end)

    
        local gmt=getmetatable(g)
        local oldidx=gmt and gmt.__index
        local oldnew=gmt and gmt.__newindex
        local newmt={
            __index=function(t,k)
                local v
                if _type(oldidx)=="function" then v=oldidx(t,k)
                elseif _type(oldidx)=="table" then v=_rawget(oldidx,k) end
                if v~=nil then return v end
                return mkproxy(48)
            end,
        }
        if oldnew~=nil then newmt.__newindex=oldnew end
        pcall(_setmt, g, newmt)
    end
end
local __thex=function(s) return (s:gsub('.',function(c) return string.format('%02x',string.byte(c)) end)) end
local __bid,__bn,__cnt={},0,{}
function __MV(pc,ins,regs,code)
    if not __bid[code] then __bn=__bn+1; __bid[code]=__bn end
    local id=__bid[code]
    local key=id*100000+pc
    __cnt[key]=(__cnt[key] or 0)+1
    if __cnt[key]>8 then return end
    local fs={}
    for k,v in pairs(ins) do
        if type(k)=="number" then
            if type(v)=="number" then fs[#fs+1]=k..'=#'..tostring(v)
            elseif type(v)=="string" then fs[#fs+1]=k..'=$'..__thex(v) end
        end
    end
    local rs={}
    for k,v in pairs(regs) do
        if type(k)=="number" then
            local t=type(v)
            local r
            if t=="number" then r='#'..tostring(v)
            elseif t=="string" then r='$'..__thex(v)
            elseif t=="boolean" then r='b'..tostring(v)
            elseif t=="function" then r='fn'
            elseif t=="table" then r='tb'
            else r='?' end
            rs[#rs+1]=k..'='..r
        end
    end
    print('I '..id..' '..pc..'|'..table.concat(fs,',')..'|'..table.concat(rs,','))
end
"""


def build_harness(src, d, stub=True):
    fetch = "{0}={1}[{2}]".format(d["instr"], d["code"], d["pc"])
    inject = fetch + ";__MV({0},{1},{2},{3})".format(d["pc"], d["instr"], d["regs"], d["code"])
    body = src.replace(fetch, inject, 1)
    flag = "MV_STUB=%s\n" % ("true" if stub else "false")
    return flag + LOGGER + "\n" + body


BEHAVIOR = r"""
do
  local _print,_type,_rawget,_rawset,_setmt,_select,_tostring,_format,_sub,_concat,_byte,_gsub,_osclock,_pcall,_error =
    print,type,rawget,rawset,setmetatable,select,tostring,string.format,string.sub,table.concat,string.byte,string.gsub,os.clock,pcall,error
  local ok,g=_pcall(getfenv); if not ok or _type(g)~="table" then g=_G end
  local function hex(s) return (_gsub(s,'.',function(c) return _format('%02x',_byte(c)) end)) end
  local function fmt(v)
    local t=_type(v)
    if t=='string' then return 's\2'..hex(v)
    elseif t=='number' then return 'n\2'.._tostring(v)
    elseif t=='boolean' then return 'b\2'.._tostring(v)
    elseif t=='nil' then return 'z\2' else return 'o\2'..t end
  end
  local function logc(name,...)
    local n=_select('#',...); local parts={}
    for i=1,n do parts[i]=fmt((_select(i,...))) end
    _print('__BHV\1'..name..'\1'.._concat(parts,'\1'))
  end
  local mkproxy
  mkproxy=function(d)
    if d<=0 then return "" end
    local mt={}; local p=_setmt({},mt)
    local function child() return mkproxy(d-1) end
    mt.__index=child; mt.__call=child; mt.__namecall=child
    mt.__newindex=function() end; mt.__concat=function() return "" end
    mt.__tostring=function() return "" end; mt.__len=function() return 0 end
    mt.__eq=function() return false end; mt.__lt=function() return false end
    mt.__le=function() return false end; mt.__add=function() return 0 end
    mt.__sub=function() return 0 end; mt.__mul=function() return 0 end
    mt.__div=function() return 0 end; mt.__mod=function() return 0 end
    mt.__pow=function() return 0 end; mt.__unm=function() return 0 end
    return p
  end
  local function proxyfn() return mkproxy(48) end

  local function clampn(n, hi)
    if _type(n)~='number' then return 0 end
    if n<0 then return 0 end
    if n>hi then return hi end
    return n
  end
  local function wraplib(real, hi)
    local c=real.create
    local w=_setmt({},{__index=real})
    _rawset(w,'create', function(n,v) return c(clampn(n,hi),v) end)
    return w
  end
  if _type(table)=='table' and _type(table.create)=='function' then _rawset(g,'table', wraplib(table, 1048576)) end
  if _type(buffer)=='table' and _type(buffer.create)=='function' then _rawset(g,'buffer', wraplib(buffer, 0x3fffffff)) end
  local genv={}
  local function loud(name,ret)
    return function(...) logc(name,...) if ret then return ret() end end
  end
  _rawset(g,'print', loud('print'))
  _rawset(g,'warn', loud('warn'))
  _rawset(g,'error', function(...) logc('error',...) return _error(...) end)  -- log then preserve throw semantics
  _rawset(g,'setclipboard', loud('setclipboard'))
  _rawset(g,'toclipboard', loud('setclipboard'))
  _rawset(g,'writefile', loud('writefile'))
  _rawset(g,'appendfile', loud('appendfile'))
  _rawset(g,'makefolder', loud('makefolder'))
  _rawset(g,'request', loud('request', function() return mkproxy(8) end))
  _rawset(g,'http_request', loud('request', function() return mkproxy(8) end))
  _rawset(g,'hookfunction', loud('hookfunction', function() return function() end end))
  _rawset(g,'hookmetamethod', loud('hookmetamethod', function() return function() end end))
  _rawset(g,'newcclosure', function(f) return f end)
  _rawset(g,'getconnections', loud('getconnections', function() return mkproxy(8) end))
  _rawset(g,'firetouchinterest', loud('firetouchinterest'))
  _rawset(g,'fireclickdetector', loud('fireclickdetector'))
  _rawset(g,'queueonteleport', loud('queueonteleport'))
  _rawset(g,'queue_on_teleport', loud('queueonteleport'))
  _rawset(g,'loadstring', function(s,...) logc('loadstring',s) return function() return mkproxy(48) end end)
  _rawset(g,'require', loud('require', proxyfn))
  _rawset(g,'getgenv', function() return genv end)
  _rawset(g,'getrenv', function() return genv end)
  _rawset(g,'identifyexecutor', function() return 'luau-trace','v1' end)
  _rawset(g,'getexecutorname', function() return 'luau-trace' end)
  _rawset(g,'tick', function() return _osclock() end)
  _rawset(g,'time', function() return _osclock() end)
  _rawset(g,'wait', function() return 0 end)
  _rawset(g,'delay', function() return 0 end)
  _rawset(g,'spawn', function(f,...) if _type(f)=='function' then _pcall(f,...) end end)
  _rawset(g,'collectgarbage', function() return 0 end)
  _rawset(g,'task', _setmt({},{__index=function(_,k)
    if k=='spawn' or k=='defer' or k=='delay' then
      return function(f,...) if _type(f)=='function' then _pcall(f,...) end end end
    return function() return 0 end end}))
  local gmt=getmetatable(g); local oldidx=gmt and gmt.__index
  local newmt={__index=function(t,k)
    local v
    if _type(oldidx)=='function' then v=oldidx(t,k)
    elseif _type(oldidx)=='table' then v=_rawget(oldidx,k) end
    if v~=nil then return v end
    return mkproxy(48)
  end}
  _pcall(_setmt,g,newmt)
end
"""


def run_behavior(src, timeout=25):
    """Run the script under luau with logging shims; return the ordered list of
    captured high-level calls as (name, [args]) where each arg is a python value
    (str/float/bool/None) or ('obj', typename)."""
    out = run_luau(BEHAVIOR + "\n" + src, timeout)
    calls = []
    for line in out.splitlines():
        if not line.startswith("__BHV\x01"):
            continue
        parts = line.split("\x01")
        name = parts[1] if len(parts) > 1 else "?"
        args = []
        for raw in parts[2:]:
            tag, _, val = raw.partition("\x02")
            if tag == "s":
                try:
                    args.append(bytes.fromhex(val).decode("utf-8", "replace"))
                except ValueError:
                    args.append("")
            elif tag == "n":
                args.append(val)
            elif tag == "b":
                args.append(val == "true")
            elif tag == "z":
                args.append(None)
            else:
                args.append(("obj", val))
        calls.append((name, args))
    return calls


def trace_blocks(src, d):
    """Trace twice and union the blocks: the stubbed pass runs the loader far
    past the Roblox API calls, the un-stubbed pass exercises the executor /
    anti-tamper fallback branches (taken when those globals are nil). Merging
    both gives strictly broader opcode / transition coverage than either."""
    blocks = parse_trace(run_luau(build_harness(src, d, True), 60))
    try:
        extra = parse_trace(run_luau(build_harness(src, d, False), 60))
    except RuntimeError:
        extra = {}
    if extra:
        offset = (max(blocks) if blocks else 0) + 1
        for bid, entries in extra.items():
            blocks[offset + bid] = entries
    return blocks


def run_luau(source, timeout):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_mv_dec.luau")
    with open(path, "w", encoding="latin-1") as h:
        h.write(source)
    try:
        res = subprocess.run([LUAU, "_mv_dec.luau"], cwd=os.path.dirname(path),
                             capture_output=True, text=True, encoding="latin-1", timeout=timeout)
        out = res.stdout or ""
    except FileNotFoundError:
        raise RuntimeError("luau not on PATH")
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("latin-1", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
    finally:
        if os.path.exists(path):
            os.remove(path)
    return out


def parse_regs(blob):
    regs = {}
    for part in blob.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        try:
            regs[int(k)] = v
        except ValueError:
            pass
    return regs


def parse_fields(blob):
    out = {}
    for part in blob.split(","):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        try:
            key = int(k)
        except ValueError:
            continue
        if v.startswith("$"):
            try:
                out[key] = bytes.fromhex(v[1:])
            except ValueError:
                pass
        elif v.startswith("#"):
            out[key] = ("num", v[1:])
    return out


def parse_trace(text):
    blocks = {}
    for line in text.splitlines():
        if not line.startswith("I "):
            continue
        head, _, rest = line.partition("|")
        fields_blob, _, regs_blob = rest.partition("|")
        _, bid, pc = head.split(" ")[:3] if len(head.split(" ")) >= 3 else (None, None, None)
        try:
            bid, pc = int(bid), int(pc)
        except (TypeError, ValueError):
            continue
        entry = {"pc": pc, "fields": parse_fields(fields_blob), "regs": parse_regs(regs_blob)}
        blocks.setdefault(bid, []).append(entry)
    return blocks


def is_ident(s):
    return bool(re.match(r"^[A-Za-z_]\w*$", s))


def is_text(b):
    return len(b) >= 1 and all(32 <= x < 127 or x in (9, 10, 13) for x in b)


def lua_string(b):
    s = b.decode("utf-8", "replace")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'


def reg_value(rep):
    if rep is None:
        return None
    if rep.startswith("$"):
        try:
            return ("str", bytes.fromhex(rep[1:]))
        except ValueError:
            return None
    if rep.startswith("#"):
        return ("num", rep[1:])
    if rep == "fn":
        return ("fn",)
    if rep == "tb":
        return ("tb",)
    if rep.startswith("b"):
        return ("bool", rep[1:])
    return None


def fmt_num(s):
    try:
        f = float(s)
        return str(int(f)) if f.is_integer() else repr(f)
    except ValueError:
        return s


def as_number(rep):
    if rep and rep.startswith("#"):
        try:
            return float(rep[1:])
        except ValueError:
            return None
    return None


def as_string(rep):
    if rep and rep.startswith("$"):
        try:
            return bytes.fromhex(rep[1:])
        except ValueError:
            return None
    return None


ARITH = [("+", lambda a, b: a + b), ("-", lambda a, b: a - b),
         ("*", lambda a, b: a * b), ("/", lambda a, b: a / b if b else None),
         ("%", lambda a, b: a - (a // b) * b if b else None),
         ("^", lambda a, b: a ** b if abs(b) < 64 else None)]


def match_arith(result, numregs):
    for ai, (an, av) in numregs:
        for bi, (bn, bv) in numregs:
            for op, fn in ARITH:
                try:
                    r = fn(av, bv)
                except (OverflowError, ZeroDivisionError, ValueError):
                    r = None
                if r is not None and abs(r - result) < 1e-9:
                    return ai, op, bi
    return None


def match_concat(result, before, sym):
    cands = []
    for idx in before:
        v = reg_value(before[idx])
        if v is None or idx not in sym:
            continue
        if v[0] == "str":
            cands.append((idx, v[1]))
        elif v[0] == "num":
            cands.append((idx, fmt_num(v[1]).encode()))
    for ai, ab in cands:
        for bi, bb in cands:
            if ai != bi and ab + bb == result:
                return [sym[ai], sym[bi]], {ai, bi}
    return None


def detect_loop(seq):
    pcs = [e["pc"] for e in seq]
    n = len(pcs)
    for i in range(n):
        for L in range(1, (n - i) // 2 + 1):
            if pcs[i:i + L] == pcs[i + L:i + 2 * L]:
                reps = 2
                while pcs[i + reps * L:i + (reps + 1) * L] == pcs[i:i + L]:
                    reps += 1
                return i, L, reps
    return None


def find_counter(seq, i, L):
    a, b = seq[i]["regs"], seq[i + L]["regs"]
    for idx in a:
        av, bv = as_number(a.get(idx)), as_number(b.get(idx))
        if av is not None and bv is not None and bv - av != 0 and abs(bv - av) < 1e6:
            return idx, av, bv - av
    return None


def lift_block(entries, const_field):
    seq = []
    for e in entries:
        if seq and seq[-1]["pc"] == e["pc"]:
            seq[-1] = e
        else:
            seq.append(e)

    loop = detect_loop(seq)
    loop_start = loop_end = None
    skip = set()
    counter = None
    if loop:
        i, L, reps = loop
        loop_start, loop_end = i, i + L
        skip = set(range(i + L, i + reps * L))
        counter = find_counter(seq, i, L)

    writes = {}
    for i, e in enumerate(seq):
        after = seq[i + 1]["regs"] if i + 1 < len(seq) else {}
        for idx in after:
            if after.get(idx) != e["regs"].get(idx):
                writes[idx] = writes.get(idx, 0) + 1
    var_regs = {idx for idx, n in writes.items() if n > 1}

    sym = {}
    consumed = set()
    declared = set()
    callable_idx = set()
    stmts = []
    indent = ""

    def name(idx):
        return sym.get(idx, "v" + str(idx))

    def assign(idx, expr):
        if idx in var_regs:
            kw = "local " if idx not in declared else ""
            declared.add(idx)
            stmts.append(indent + "{0}v{1} = {2}".format(kw, idx, expr))
            sym[idx] = "v" + str(idx)
        else:
            sym[idx] = expr

    for i, e in enumerate(seq):
        if i in skip:
            continue
        if loop_start is not None and i == loop_start:
            if counter:
                cidx, start, step = counter
                declared.add(cidx)
                limit = next((name(k) for k in sorted(sym) if as_number(seq[i]["regs"].get(k)) and
                              as_number(seq[i]["regs"].get(k)) >= start + step), None)
                hdr = "for v{0} = {1}, {2}{3} do".format(
                    cidx, fmt_num(str(start)), limit or "0 --[[?]]",
                    "" if step == 1 else ", " + fmt_num(str(step)))
                sym[cidx] = "v" + str(cidx)
            else:
                hdr = "while true do"
            stmts.append(hdr)
            indent = "  "

        before = e["regs"]
        after = seq[i + 1]["regs"] if i + 1 < len(seq) else {}
        text_consts = [v for v in e["fields"].values() if isinstance(v, (bytes, bytearray)) and is_text(v)]
        ident_const = next((c.decode("utf-8", "replace") for c in text_consts
                            if is_ident(c.decode("utf-8", "replace"))), None)
        kfield = e["fields"].get(const_field)
        kconst = float(kfield[1]) if isinstance(kfield, tuple) and kfield[0] == "num" else None

        changed = {idx: after[idx] for idx in after if after.get(idx) != before.get(idx)}
        removed = sorted(idx for idx in before if before.get(idx) is not None and idx not in after)
        numregs = [(idx, as_number(before[idx])) for idx in before if as_number(before[idx]) is not None]

        for idx in sorted(changed):
            v = reg_value(changed[idx])
            if v is None:
                continue

            if idx in callable_idx and v[0] != "fn":
                fnname = sym.get(idx, "v" + str(idx))
                if fnname == "{}":
                    callable_idx.discard(idx)
                else:
                    args = []
                    a = idx + 1
                    while a in sym and a in before and reg_value(before.get(a)) is not None:
                        if a not in consumed:
                            args.append(name(a))
                            consumed.add(a)
                        a += 1
                    callable_idx.discard(idx)
                    assign(idx, "{0}({1})".format(fnname, ", ".join(args)))
                    continue

            if v[0] == "fn":
                if ident_const:
                    sym[idx] = ident_const
                elif idx - 1 in sym and text_consts:
                    sym[idx] = "{0}:{1}".format(sym[idx - 1], text_consts[0].decode("utf-8", "replace"))
                else:
                    sym[idx] = name(idx)
                callable_idx.add(idx)
            elif v[0] == "num":
                n = float(v[1])
                expr = None
                for bi, brep in before.items():
                    bs = as_string(brep)
                    if bs is not None and len(bs) == n and bi in sym and n > 0:
                        expr = "#" + name(bi)
                        break
                if expr is None and kconst is not None and kconst not in (0.0, 1.0):
                    for ai, av in numregs:
                        for op, fn in ARITH:
                            if op in ("*", "^") and (av == 0 or kconst == 0):
                                continue
                            try:
                                r = fn(av, kconst)
                            except (ZeroDivisionError, OverflowError, ValueError):
                                r = None
                            if r is not None and abs(r - n) < 1e-9:
                                expr = "{0} {1} {2}".format(name(ai), op, fmt_num(str(kconst)))
                                break
                        if expr:
                            break
                if expr is None:
                    for ai, av in numregs:
                        for bi, bv in numregs:
                            if av == 0 or bv == 0 or av == 1 or bv == 1:
                                continue
                            for op, fn in ARITH:
                                try:
                                    r = fn(av, bv)
                                except (ZeroDivisionError, OverflowError, ValueError):
                                    r = None
                                if r is not None and abs(r - n) < 1e-9 and (ai == idx or bi == idx):
                                    expr = "{0} {1} {2}".format(name(ai), op, name(bi))
                                    break
                            if expr:
                                break
                        if expr:
                            break
                if expr is None:
                    mv = next((j for j, jv in numregs if abs(jv - n) < 1e-9 and j != idx), None)
                    if mv is not None:
                        expr = name(mv)
                assign(idx, expr if expr else fmt_num(v[1]))
            elif v[0] == "str":
                s = v[1]
                if any(c == s for c in text_consts):
                    assign(idx, lua_string(s))
                else:
                    cc = match_concat(s, before, sym)
                    if cc:
                        consumed.update(cc[1])
                        assign(idx, " .. ".join(cc[0]))
                    else:
                        src = next((j for j in before if before[j] == changed[idx] and j != idx), None)
                        assign(idx, sym[src] if src in sym else lua_string(s))
            elif v[0] == "tb":
                assign(idx, "{}")
            elif v[0] == "bool":
                assign(idx, v[1])

        if removed:
            fn_idx = removed[0] - 1
            if (fn_idx in callable_idx or fn_idx in sym) and name(fn_idx) != "{}":
                args = [name(a) for a in range(removed[0], removed[-1] + 1) if a not in consumed]
                call = "{0}({1})".format(name(fn_idx), ", ".join(args))
                if reg_value(after.get(fn_idx)) is not None:
                    sym[fn_idx] = call
                else:
                    stmts.append(indent + call)
                    callable_idx.discard(fn_idx)

        if loop_end is not None and i == loop_end - 1:
            indent = ""
            stmts.append("end")

    return stmts


def is_noise(stmt):
    if "\ufffd" in stmt or "_mv_dec" in stmt or ".luau" in stmt:
        return True
    if re.match(r"^v\d+\(", stmt) or re.match(r"^v\d+:\w+\(", stmt):
        return True
    longest = max((len(m) for m in re.findall(r'"((?:[^"\\]|\\.)*)"', stmt)), default=0)
    return longest > 160


def detect_const_field(blocks):
    counts = {}
    for entries in blocks.values():
        for e in entries:
            for k, v in e["fields"].items():
                if isinstance(v, (bytes, bytearray)):
                    counts[k] = counts.get(k, 0) + 1
    return max(counts, key=counts.get) if counts else 0


def detect_fields(blocks):
    present = {}
    distinct = {}
    negative = set()
    for entries in blocks.values():
        for e in entries:
            for k, v in e["fields"].items():
                if isinstance(v, tuple) and v[0] == "num":
                    fv = float(v[1])
                    present[k] = present.get(k, 0) + 1
                    distinct.setdefault(k, set()).add(fv)
                    if fv < 0 or fv > 60000:
                        negative.add(k)
    total = sum(len(e) for e in blocks.values())
    tag = None
    best = -1
    for k, cnt in present.items():
        vals = distinct[k]
        opish = [x for x in vals if 0 <= x <= 255]
        score = len(opish) if cnt > total * 0.5 else 0
        if score > best:
            best, tag = score, k
    sbx = None
    bestn = -1
    for k in negative:
        neg = sum(1 for x in distinct[k] if x < 0)
        if neg > bestn:
            bestn, sbx = neg, k
    return tag, sbx


def detect_fields_src(src, d):
    instr = re.escape(d["instr"])
    pcv = re.escape(d["pc"])
    lits = re.findall(r"\{\[(\d+)\]=\d+[^{}]*\}", src)
    tag = None
    if lits:
        from collections import Counter
        tag = int(Counter(lits).most_common(1)[0][0])
    operands = []
    keys = {}
    op_field = None
    if tag is not None:
        for lit in re.findall(r"\{\[" + str(tag) + r"\]=\d+[^{}]*\}", src):
            nt = int(re.match(r"\{\[\d+\]=(\d+)", lit).group(1))
            kd = {}
            for f, sf, k in re.findall(r"\[(\d+)\]=\w+\(" + instr + r"\[(\d+)\],(\d+)\)", lit):
                if f == sf:
                    if int(f) not in operands:
                        operands.append(int(f))
                    kd[int(f)] = int(k)
            if kd:
                keys[nt] = kd
            for f, val in re.findall(r"\[(\d+)\]=(\d+)\b", lit):
                fi = int(f)
                if fi != tag and fi not in operands and int(val) == 0:
                    op_field = fi
    jumps = re.findall(pcv + r"[-+]=" + instr + r"\[(\d+)\]", src)
    sbx = int(jumps[0]) if jumps else None
    return {"tag": tag, "operands": operands, "sbx": sbx, "keys": keys, "op": op_field}


def classify_occurrence(before, after, fields, const_field, tag_field, sbx):
    changed = {i: after[i] for i in after if after.get(i) != before.get(i)}
    removed = [i for i in before if before.get(i) is not None and i not in after]
    sbx_val = fields.get(sbx)
    has_jump = isinstance(sbx_val, tuple) and sbx_val[0] == "num" and float(sbx_val[1]) != 0
    kf = fields.get(const_field)
    kconst = float(kf[1]) if isinstance(kf, tuple) and kf[0] == "num" else None

    if removed:
        if (removed[0] - 1) in before or (removed[0] - 1) in after:
            return "CALL"
        return "CALL"

    if not changed:
        if has_jump and float(sbx_val[1]) < 0:
            return "FORLOOP/JMPBACK"
        if has_jump:
            return "JMP"
        return "TEST"

    if len(changed) == 1:
        idx = next(iter(changed))
        nv = reg_value(changed[idx])
        ov = reg_value(before.get(idx))
        if nv is None:
            return "?"
        if ov is not None and ov[0] == "fn" and nv[0] != "fn":
            return "CALL"
        if nv[0] == "fn":
            return "GETGLOBAL"
        if nv[0] == "tb":
            return "NEWTABLE"
        if nv[0] == "bool":
            return "LOADBOOL"
        if nv[0] == "num":
            n = float(nv[1])
            for j, r in before.items():
                s = as_string(r)
                if s is not None and len(s) == n and n > 0:
                    return "LEN"
            nums = [(j, as_number(before[j])) for j in before if as_number(before[j]) is not None]
            for ai, av in nums:
                for bi, bv in nums:
                    if av in (0, 1) or bv in (0, 1):
                        continue
                    for op, fn in ARITH:
                        try:
                            if abs(fn(av, bv) - n) < 1e-9 and (ai == idx or bi == idx):
                                return {"+" : "ADD", "-": "SUB", "*": "MUL",
                                        "/": "DIV", "%": "MOD", "^": "POW"}[op]
                        except (ZeroDivisionError, OverflowError, ValueError, TypeError):
                            pass
            if kconst is not None and any(abs(av - n) > 1e-9 for _, av in nums):
                for ai, av in nums:
                    for op, fn in ARITH:
                        try:
                            if abs(fn(av, kconst) - n) < 1e-9:
                                return {"+" : "ADDK", "-": "SUBK", "*": "MULK",
                                        "/": "DIVK", "%": "MODK", "^": "POWK"}[op]
                        except (ZeroDivisionError, OverflowError, ValueError, TypeError):
                            pass
            if any(abs(as_number(before[j]) - n) < 1e-9 for j in before
                   if j != idx and as_number(before[j]) is not None):
                return "MOVE"
            return "LOADN"
        if nv[0] == "str":
            s = nv[1]
            if kf == s:
                return "LOADK"
            if match_concat(s, before, {j: "x" for j in before}):
                return "CONCAT"
            return "LOADK"
    if len(changed) >= 2:
        return "MULTI"
    return "?"


BINOP = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%", "POW": "^",
         "ADDK": "+", "SUBK": "-", "MULK": "*", "DIVK": "/", "MODK": "%", "POWK": "^"}


def stmt_of(ins, opmap):
    op = opmap.get(ins["tag"], "OP_%s" % ins["tag"])
    A, B, K = ins["A"], ins["B"], ins["K"]
    rA = "R%s" % A if A is not None else "R?"
    rB = "R%s" % B if B is not None else "R?"
    if op in ("LOADK", "LOADN"):
        return "%s = %s" % (rA, repr(K) if K is not None else "<const>")
    if op == "GETGLOBAL":
        return "%s = %s" % (rA, K if K else "<global>")
    if op == "MOVE":
        return "%s = %s" % (rA, rB)
    if op == "LEN":
        return "%s = #%s" % (rA, rB)
    if op in BINOP:
        return "%s = %s %s %s" % (rA, rA, BINOP[op], rB)
    if op == "CONCAT":
        return "%s = %s .. %s" % (rA, rA, rB)
    if op == "NEWTABLE":
        return "%s = {}" % rA
    if op == "CALL":
        return "%s = %s(...)" % (rA, rA)
    if op == "RETURN":
        return "return"
    extra = "  K=%r" % K if K is not None else ""
    return "-- %s A=%s B=%s%s" % (op, A, B, extra)


def structure_proto(code, opmap, jump_tags):
    n = len(code)

    def target_idx(ins):
        t = ins["pc"] + (ins["sBx"] or 0) + 1
        for k, c in enumerate(code):
            if c["pc"] >= t:
                return k
        return n

    def is_jump(ins):
        return ins["tag"] in jump_tags and ins["sBx"]

    loops = {}
    for k, ins in enumerate(code):
        if is_jump(ins) and ins["sBx"] < 0:
            loops[target_idx(ins)] = k

    sym = {}
    declared = set()
    out = []

    def name(r):
        return sym.get(r, "v%s" % r)

    def setexpr(r, e, line, ind):
        if r in declared:
            out.append(ind + "v%s = %s" % (r, e))
            sym[r] = "v%s" % r
        else:
            sym[r] = e

    def materialize(r, ind):
        if r in declared:
            return
        e = sym.get(r)
        if e is not None and e != "v%s" % r:
            out.append(ind + "local v%s = %s" % (r, e))
        declared.add(r)
        sym[r] = "v%s" % r

    def do_stmt(ins, ind):
        op = opmap.get(ins["tag"], "OP_%s" % ins["tag"])
        A, B, K = ins["A"], ins["B"], ins["K"]
        if op == "CALL":
            fn = name(A) if A is not None else "?"
            out.append(ind + "%s(...)" % fn)
            return
        if op == "RETURN":
            out.append(ind + "return")
            return
        if K is not None:
            ident = bool(re.match(r"^[A-Za-z_]\w*$", str(K)))
            sym[A if A is not None else 0] = K if (op == "GETGLOBAL" or ident) else repr(K)
            return
        if op == "MOVE" and A is not None and B is not None:
            sym[A] = name(B)
        elif op == "LEN" and A is not None and B is not None:
            sym[A] = "#" + name(B)
        elif op in BINOP and A is not None and B is not None:
            materialize(A, ind)
            out.append(ind + "v%s = v%s %s %s" % (A, A, BINOP[op], name(B)))
        elif op == "CONCAT" and A is not None and B is not None:
            sym[A] = "%s .. %s" % (name(A), name(B))
        elif op == "NEWTABLE":
            sym[A] = "{}"
        else:
            out.append(ind + "-- %s" % op)

    def emit(i, j, ind, depth=0):
        if depth > 300:
            out.append(ind + "-- [reconstruction depth limit reached]")
            return
        while i < j:
            ins = code[i]
            if i in loops and loops[i] < j:
                end = loops[i]
                cv = code[end].get("A")
                out.append(ind + "for v%s = <start>, <limit> do" % (cv if cv is not None else "i"))
                emit(i, end, ind + "  ", depth + 1)
                out.append(ind + "end")
                i = end + 1
                continue
            if is_jump(ins) and ins["sBx"] > 0:
                tgt = target_idx(ins)
                prev = code[tgt - 1] if 0 < tgt <= n else None
                if prev is not None and is_jump(prev) and prev["sBx"] > 0 and target_idx(prev) > tgt:
                    els = target_idx(prev)
                    out.append(ind + "if <cond> then")
                    emit(i + 1, tgt - 1, ind + "  ", depth + 1)
                    out.append(ind + "else")
                    emit(tgt, els, ind + "  ", depth + 1)
                    out.append(ind + "end")
                    i = els
                else:
                    out.append(ind + "if <cond> then")
                    emit(i + 1, tgt, ind + "  ", depth + 1)
                    out.append(ind + "else")
                    emit(tgt, j, ind + "  ", depth + 1)
                    out.append(ind + "end")
                    i = j
                continue
            do_stmt(ins, ind)
            i += 1

    emit(0, n, "")
    return out


def learn_transitions(blocks, tag_field, op_field):
    def gnum(e, k):
        v = e["fields"].get(k)
        return int(float(v[1])) if isinstance(v, tuple) and v[0] == "num" else None
    votes = {}
    for entries in blocks.values():
        for j in range(len(entries) - 1):
            a, b = entries[j], entries[j + 1]
            if a["pc"] != b["pc"]:
                continue
            ta, tb = gnum(a, tag_field), gnum(b, tag_field)
            oa = gnum(a, op_field) if op_field is not None else None
            if ta is None or tb is None or ta == tb:
                continue
            votes.setdefault((ta, oa), {}).setdefault(tb, 0)
            votes[(ta, oa)][tb] += 1
    return {k: max(v, key=v.get) for k, v in votes.items()}


def _f32(raw):
    iv = int(raw) & 0xFFFFFFFF
    try:
        return struct.unpack("<f", struct.pack("<I", iv))[0]
    except (struct.error, ValueError):
        return None


def _num_literal(raw, allow_zero=False):
    """Moonveil stores numeric literals as the little-endian float32 bit pattern
    in a dedicated instruction field. Decode only genuine floats (normal
    exponent, sane magnitude) so register-index fields and marker words like
    0x80000001 are not mistaken for numbers. `allow_zero` lets a real 0/0.0
    literal through (exp==0), used only where the opcode is a numeric load so a
    field that merely happens to be 0 elsewhere is not turned into a number."""
    if not isinstance(raw, (int, float)):
        return None
    if isinstance(raw, float) and not math.isfinite(raw):
        return None
    iv = int(raw) & 0xFFFFFFFF
    exp = (iv >> 23) & 0xFF
    if exp == 0:
        return 0.0 if (allow_zero and (iv & 0x7FFFFFFF) == 0) else None
    if exp == 0xFF:
        return None
    f = _f32(iv)
    if f is None or abs(f) >= 1e9 or (f != 0 and abs(f) < 1e-4):
        return None
    return f


def _discover_protos(tables):
    """Tree-aware proto discovery. Returns (real_order, code, pindex,
    children_idx, numfield):
      - real_order: ordered code-table ids of the *real* protos (the child-list
        tables, which find_code_arrays wrongly accepts because proto headers
        carry >=6 integer fields, are excluded).
      - code:       {code_tid: instruction sequence}
      - pindex:     {code_tid: global proto index}
      - children_idx: {proto index: [child proto index, ...]} in source order.
      - numfield:   the instruction field carrying float32 numeric literals."""
    from collections import Counter
    code, order = {}, []
    for tid, node in tables.items():
        seq = mauto.as_sequence(node, tables)
        if not seq:
            continue
        good = sum(1 for e in seq if mauto.looks_like_instruction(e))
        if good >= max(1, len(seq) * 0.6):
            code[tid] = seq
            order.append(tid)
    codeset = set(code)

    def is_childlist(seq):
        hits = sum(1 for e in seq if isinstance(e, dict) and any(
            isinstance(v, tuple) and v[0] == "ref" and v[1] in codeset
            for v in e.values()))
        return bool(seq) and hits >= max(1, len(seq) * 0.6)

    childlists = {tid for tid in code if is_childlist(code[tid])}
    real_order = [tid for tid in order if tid not in childlists]
    real_set = set(real_order)
    pindex = {tid: i for i, tid in enumerate(real_order)}

    headers = {}
    for tid, node in tables.items():
        if tid in code:
            continue
        for k, v in node.items():
            if isinstance(v, tuple) and v[0] == "ref" and v[1] in real_set:
                headers[tid] = v[1]
                break
    header_of_code = {c: h for h, c in headers.items()}

    childfield_votes = Counter()
    for htid in headers:
        for k, v in tables[htid].items():
            if isinstance(v, tuple) and v[0] == "ref" and v[1] in childlists:
                childfield_votes[k] += 1
    childfield = childfield_votes.most_common(1)[0][0] if childfield_votes else None

    children_idx = {}
    if childfield is not None:
        for code_tid in real_order:
            h = header_of_code.get(code_tid)
            if h is None:
                continue
            ref = tables[h].get(childfield)
            if not (isinstance(ref, tuple) and ref[0] == "ref"):
                continue
            lst = tables.get(ref[1])
            seq = mauto.as_sequence(lst, tables) if lst else None
            if not seq:
                continue
            kids = []
            for i in range(1, len(seq) + 1):
                r = lst.get(i)
                if isinstance(r, tuple) and r[0] == "ref" and r[1] in headers:
                    ck = headers[r[1]]
                    if ck in pindex:
                        kids.append(pindex[ck])
            children_idx[pindex[code_tid]] = list(reversed(kids))

    numhits = Counter()
    for tid in real_order:
        for ins in code[tid]:
            if not isinstance(ins, dict):
                continue
            for k, v in ins.items():
                if _num_literal(v) is not None:
                    numhits[k] += 1
    numfield = numhits.most_common(1)[0][0] if numhits else None

    return real_order, code, pindex, children_idx, numfield


def static_protos(src, d, fl, opmap, transitions):
    dd = mauto.find_deserializer(src)
    if not dd:
        return []
    tables = mauto.parse_dump(mauto.run_luau(mauto.build_harness(src, *dd), 60))
    real_order, code, pindex, children_idx, numfield = _discover_protos(tables)
    arrays = [code[tid] for tid in real_order]
    sfields = mauto.string_fields(arrays)
    src_salts = mauto.extract_salts(src)
    best = None
    for field in sfields[:5]:
        for forward in (True, False):
            pairs = mauto.gather_pairs(arrays, field, forward)
            if len(pairs) < 1:
                continue
            cands = list(mauto.salt_votes(pairs).keys()) + [mauto.freq_salt(pairs)] + list(src_salts)
            for salt in cands:
                if not salt:
                    continue
                rank = mauto.score_salt(pairs, salt)
                if salt in src_salts and rank[1] > 0:
                    rank = (rank[0] + 100000, rank[1])
                if best is None or rank > best[0]:
                    best = (rank, field, forward, salt)
    if not best:
        return []
    _, dfield, forward, salt = best

    def fieldnum(ins, key):
        v = ins.get(key)
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, tuple) and v[0] == "num":
            return int(float(v[1]))
        return None

    TAG, OPA, OPB, SBX, OPF = fl["tag"], fl["operands"][0], fl["operands"][1], fl["sbx"], fl["op"]
    keys = fl["keys"]
    protos = []
    for gi, a in enumerate(arrays):
        decoded = []
        texts = []
        for i, ins in enumerate(a):
            if not isinstance(ins, dict):
                continue
            cur = ins.get(dfield)
            nxt = a[i + 1].get(dfield) if i + 1 < len(a) and isinstance(a[i + 1], dict) else None
            plain = None
            if isinstance(cur, (bytes, bytearray)) and isinstance(nxt, (bytes, bytearray)):
                cipher, keymat = (nxt, cur) if forward else (cur, nxt)
                p = mauto.xor_repeat(bytes(cipher), salt + bytes(keymat))
                if mauto.is_text(p):
                    plain = p.decode("utf-8", "replace")
                    texts.append(plain)
            tag = fieldnum(ins, TAG)
            opv = fieldnum(ins, OPF)
            A = fieldnum(ins, OPA)
            B = fieldnum(ins, OPB)
            nt = transitions.get((tag, opv))
            if nt is not None and nt in keys:
                kk = keys[nt]
                if A is not None and OPA in kk:
                    A ^= kk[OPA]
                if B is not None and OPB in kk:
                    B ^= kk[OPB]
                tag = nt
            if plain is None and isinstance(cur, (bytes, bytearray)) and salt:
                p2 = mauto.xor_repeat(bytes(cur), salt)
                if mauto.is_text(p2) and re.fullmatch(r"[A-Za-z_]\w*", p2.decode("utf-8", "replace") or ""):
                    plain = p2.decode("utf-8", "replace")
                    texts.append(plain)
            if plain is None and numfield is not None:
                numop = opmap.get(tag, "") in ("LOADN", "LOADK", "ADDK", "SUBK",
                                               "MULK", "DIVK", "MODK", "POWK")
                nlit = _num_literal(ins.get(numfield), allow_zero=numop)
                if nlit is not None:
                    plain = int(nlit) if float(nlit).is_integer() else float("%.7g" % nlit)
            decoded.append({"pc": i + 1, "tag": tag, "A": A, "B": B,
                            "sBx": fieldnum(ins, SBX), "K": plain})
        strtexts = [t for t in texts if isinstance(t, str)]
        is_user = bool(strtexts) and any(re.search(r"[A-Za-z]{3,}", t or "") for t in strtexts) and \
            not all(len(t or "") > 40 for t in strtexts)
        protos.append({"code": decoded, "is_user": is_user, "index": gi,
                       "children": children_idx.get(gi, [])})
    return protos


def _is_name(s):
    return isinstance(s, str) and bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", s)) and 1 <= len(s) <= 64


def _var_from_title(title, base):
    """Local name for a UI container bound from its title: "Combat" + "Tab" ->
    `combatTab`; "Main Menu" -> `mainMenuTab`; no usable title -> the base type."""
    if isinstance(title, str) and title.strip():
        words = re.findall(r"[A-Za-z][A-Za-z0-9]*", title)
        if words and sum(len(w) for w in words) <= 22:
            name = words[0].lower() + "".join(w[:1].upper() + w[1:] for w in words[1:])
            if name.lower() != base.lower():
                return name + base
    return base


def _qarg(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'



_KNOWN_METHODS = {
    "HttpGet", "HttpGetAsync", "HttpPost", "HttpPostAsync", "GetService",
    "FindFirstChild", "FindFirstChildOfClass", "FindFirstChildWhichIsA",
    "FindFirstAncestor", "WaitForChild", "GetObjects", "GetChildren",
    "GetDescendants", "Connect", "Once", "Disconnect", "Wait", "Fire",
    "FireServer", "FireClient", "FireAllClients", "InvokeServer", "InvokeClient",
    "Invoke", "Destroy", "Clone", "IsA", "Kick", "JSONDecode", "JSONEncode",
    "UrlEncode", "GenerateGUID", "RequestAsync", "GetPlayers",
    "GetAsync", "SetAsync", "UpdateAsync", "IncrementAsync", "RemoveAsync",
    "GetSortedAsync", "GetItem", "SetItem",
    "MoveTo", "PivotTo", "GetPivot", "Raycast", "GetTouchingParts",
    "SetPrimaryPartCFrame", "BreakJoints", "MakeJoints", "GetMass",
    "GetPlayerFromCharacter", "LoadCharacter", "BindToClose",
    "GetPropertyChangedSignal", "OnChanged", "SetValues", "Play", "Pause",
    "Cancel", "Create", "IsKeyDown", "GetMouseLocation", "GetFocusedTextBox",
    "PlayEmote", "request",
    "Notify", "MakeNotification", "CreateWindow", "MakeWindow", "CreateLib",
    "CreateTab", "MakeTab", "NewTab", "AddTab", "CreateButton", "AddButton",
    "NewButton", "CreateToggle", "AddToggle", "NewToggle", "CreateSlider",
    "AddSlider", "NewSlider", "CreateDropdown", "AddDropdown", "NewDropdown",
    "CreateColorPicker", "AddColorPicker", "AddColorpicker", "NewColorPicker",
    "CreateKeybind", "AddKeybind", "AddKeyPicker", "NewKeybind", "CreateInput",
    "AddInput", "AddTextbox", "NewTextBox", "CreateParagraph", "AddParagraph",
    "CreateSection", "AddSection", "NewSection", "CreateLabel", "AddLabel",
    "NewLabel", "CreateDivider", "AddDivider", "AddLeftGroupbox",
    "AddRightGroupbox", "AddLeftTabbox", "AddRightTabbox", "LoadConfiguration",
    "SetTheme", "AddTheme", "Init",
}



_ARITY1 = {"tostring", "tonumber", "type", "typeof"}


_NAME_ARG_METHODS = {
    "GetService", "FindFirstChild", "FindFirstChildOfClass", "WaitForChild",
    "FindFirstChildWhichIsA", "GetPropertyChangedSignal", "IsA",
}


def reconstruct_proto(code):
    """Best-effort, human-readable reconstruction of one proto from the VM
    constant stream. Returns (loader_lines, call_lines):
      - loader_lines: genuinely runnable entrypoints (loadstring/HttpGet idiom)
      - call_lines:   the ordered API name + string-arg sequence (approximate;
                      the flattened control flow loses exact call grouping).
    String literals are attached to the next identifier-name they precede,
    which matches how the VM loads args before the method constant."""
    tokens = []
    for ins in code:
        K = ins.get("K")
        if not isinstance(K, str) or K == "":
            continue
        tokens.append(("name", K) if _is_name(K) else ("lit", K))

    calls = []
    pend = []
    i = 0
    while i < len(tokens):
        kind, val = tokens[i]
        if kind == "lit":
            pend.append(val)
            i += 1
            continue
        if (i + 1 < len(tokens) and tokens[i + 1][0] == "name"
                and tokens[i + 1][1] in _NAME_ARG_METHODS):
            calls.append((tokens[i + 1][1], pend + [val], "method"))
            pend = []
            i += 2
            continue
        if val in ("HttpGet", "HttpGetAsync"):
            calls.append((val, pend, "loader"))
        elif val in _KNOWN_METHODS:
            calls.append((val, pend, "method"))
        else:
            calls.append((val, pend, "prop"))
        pend = []
        i += 1
    if pend:
        calls.append((None, pend, "lit"))

    loader_lines, call_lines = [], []
    for name, args, kind in calls:
        qargs = ", ".join(_qarg(a) for a in args)
        if kind == "loader" and args:
            url = next((a for a in args if a.startswith("http")), args[0])
            loader_lines.append('loadstring(game:%s(%s))()' % (name, _qarg(url)))
            call_lines.append('game:%s(%s)' % (name, _qarg(url)))
        elif kind == "lit":
            if args:
                call_lines.append("-- literals: " + qargs)
        elif kind == "method":
            call_lines.append(':%s(%s)' % (name, qargs))
        else:
            call_lines.append('.%s%s' % (name, ("  -- " + qargs) if qargs else ""))
    return loader_lines, call_lines



_KNOWN_OPNAMES = {"JMP", "CALL", "GETGLOBAL", "TEST", "NEWTABLE", "LOADK",
                  "LOADN", "CONCAT", "LEN", "FORLOOP", "ADDK", "SUBK", "MULK",
                  "MOVE", "RETURN"}

_GLOBAL_FUNCS = {"loadstring", "pcall", "xpcall", "print", "warn", "error",
                 "require", "pairs", "ipairs", "type", "typeof", "select",
                 "tostring", "tonumber", "setclipboard", "toclipboard",
                 "getgenv", "identifyexecutor", "request", "next", "rawget",
                 "rawset", "assert", "unpack", "wait", "task", "spawn"}

_SNAP_GLOBALS = {"tick", "wait", "print", "warn", "error", "spawn", "delay",
                 "pairs", "ipairs", "next", "type", "typeof", "pcall", "xpcall",
                 "select", "unpack", "require", "assert", "tostring", "tonumber",
                 "loadstring", "setmetatable", "getmetatable", "rawget", "rawset",
                 "rawequal", "newproxy", "collectgarbage", "getgenv"}


def _snap_global(name):
    if not name or name in _SNAP_GLOBALS or not re.match(r"^[A-Za-z_]\w*$", name):
        return name

    def shared(a, b):
        n = 0
        for x, y in zip(a, b):
            if x != y:
                break
            n += 1
        return n

    cands = [g for g in _SNAP_GLOBALS
             if len(g) == len(name) and shared(g, name) >= max(2, len(name) // 2)]
    return cands[0] if len(cands) == 1 else name

_GAME_METHODS = {"GetService", "HttpGet", "HttpGetAsync", "HttpPost",
                 "HttpPostAsync", "GetObjects", "FindService"}

_GAME_ANY = {"HttpGet", "HttpGetAsync", "HttpPost", "HttpPostAsync", "GetObjects"}

_UI_METHODS = {
    "Notify", "CreateWindow", "AddTheme", "SetTheme", "Tab", "AddTab", "Select",
    "Paragraph", "Button", "AddButton", "Toggle", "AddToggle", "Slider",
    "AddSlider", "Dropdown", "AddDropdown", "Section", "AddSection", "Input",
    "AddInput", "Label", "AddLabel", "Divider", "AddDivider", "ToggleTransparency",
    "Keybind", "AddKeybind", "ColorPicker", "AddColorPicker",
    "CreateTab", "CreateButton", "CreateToggle", "CreateSlider", "CreateDropdown",
    "CreateColorPicker", "CreateKeybind", "CreateInput", "CreateParagraph",
    "CreateSection", "CreateLabel", "CreateDivider", "LoadConfiguration",
    "MakeWindow", "MakeTab", "MakeNotification", "AddBind", "AddTextbox",
    "AddColorpicker", "Init",
    "AddParagraph", "AddKeyPicker",
    "CreateLib", "NewTab", "NewSection", "NewButton", "NewToggle", "NewSlider",
    "NewKeybind", "NewLabel", "NewTextBox", "NewColorPicker", "NewDropdown",
    "AddLeftGroupbox", "AddRightGroupbox", "AddLeftTabbox", "AddRightTabbox",
    "AddDependencyBox",
}

_CONTAINER_METHODS = {
    "CreateWindow": "Window", "Window": "Window", "MakeWindow": "Window",
    "CreateLib": "Window",
    "Tab": "Tab", "AddTab": "Tab", "CreateTab": "Tab", "MakeTab": "Tab",
    "NewTab": "Tab",
    "AddSection": "Section", "Section": "Section", "CreateSection": "Section",
    "NewSection": "Section",
    "AddGroupbox": "Groupbox", "AddLeftGroupbox": "Groupbox",
    "AddRightGroupbox": "Groupbox",
    "Dialog": "Dialog", "AddLeftTabbox": "Tabbox", "AddRightTabbox": "Tabbox",
}

_LEAF_METHODS = {
    "SetItem", "GetItem", "RemoveItem", "UpdateItem", "SetAsync", "GetAsync",
    "UpdateAsync", "IncrementAsync", "RemoveAsync", "Base64Encode", "Base64Decode",
    "CompressBuffer", "DecompressBuffer", "ComputeStringHash", "ComputeBufferHash",
    "GetDecompressedBufferSize", "JSONEncode", "JSONDecode", "Fire", "FireServer",
    "FireAllClients", "InvokeServer", "Destroy", "Remove", "Kick", "Notify",
    "Play", "Stop", "Pause", "Disconnect", "Wait", "MoveTo", "PivotTo",
    "BreakJoints", "SetPrimaryPartCFrame",
}

_LIBRARY_SIGS = [
    ("Rayfield", {"Rayfield", "sirius.menu", "Rayfield Library", "LoadConfiguration"}),
    ("OrionLib", {"OrionLib", "MakeWindow", "Orion", "OrionLibrary", "MakeNotification"}),
    ("Fluent", {"Fluent", "InterfaceManager", "SaveManager", "AddKeyPicker"}),
    ("Library", {"Linoria", "LinoriaLib", "AddLeftGroupbox", "AddRightGroupbox", "Obsidian"}),
    ("Kavo", {"Kavo", "CreateLib", "NewTab", "NewSection"}),
    ("WindUI", {"WindUI", "AddTheme", "ToggleTransparency"}),
]


def detect_library(protos):
    """Guess the UI library a build uses from its string constants and return the
    handle to use as the default receiver (`Rayfield`, `OrionLib`, `Fluent`,
    `Library`, `Kavo`, `WindUI`). Falls back to a neutral `Library`."""
    blob = "\n".join(k for p in protos for ins in p["code"]
                     for k in (ins.get("K"),) if isinstance(k, str) and k).lower()
    best, score = None, 0
    for handle, sigs in _LIBRARY_SIGS:
        hits = sum(1 for s in sigs if s.lower() in blob)
        if hits > score:
            best, score = handle, hits
    return best

_ANTITAMPER_HINTS = {"traceback", "gmatch", "getinfo", "info", "debug",
                     "checkcaller", "hookfunction", "getfenv", "islclosure",
                     "getgc", "gethiddenproperty", "getrawmetatable", "setreadonly"}

_DESTROY_METHODS = {"Destroy", "Remove", "Disconnect", "ClearAllChildren",
                    "Kick", "Clear"}

_NAMESPACE_GLOBALS = {"game", "Enum", "workspace", "string", "table", "math",
                      "os", "buffer", "coroutine", "utf8", "bit32", "Instance",
                      "script", "shared", "debug", "task", "Players"}

_ROBLOX_SERVICES = {
    "Players", "Workspace", "Lighting", "ReplicatedStorage", "ReplicatedFirst",
    "ServerStorage", "ServerScriptService", "StarterGui", "StarterPack",
    "StarterPlayer", "StarterPlayerScripts", "StarterCharacterScripts", "CoreGui",
    "RunService", "UserInputService", "ContextActionService", "TweenService",
    "HttpService", "TeleportService", "MarketplaceService", "DataStoreService",
    "MemoryStoreService", "MemStorageService", "MessagingService", "EncodingService",
    "PathfindingService", "PhysicsService", "CollectionService", "Debris",
    "SoundService", "TextChatService", "Chat", "GuiService", "HapticService",
    "VRService", "VirtualInputManager", "VirtualUser", "Stats", "LogService",
    "Teams", "GroupService", "BadgeService", "GamePassService", "PolicyService",
    "LocalizationService", "TextService", "ProximityPromptService", "InsertService",
    "AssetService", "AvatarEditorService", "SocialService", "AnalyticsService",
    "NotificationService", "GamepadService", "TouchInputService", "VoiceChatService",
    "ContentProvider", "CaptureService", "ScriptContext", "PlayerGui", "PlayerScripts",
    "GenerationService", "SerializationService", "TextBoxService", "KeyboardService",
    "MouseService", "PluginGuiService", "StudioService",
}

_DATATYPE_CTORS = {
    "Instance", "Color3", "ColorSequence", "ColorSequenceKeypoint", "UDim",
    "UDim2", "Vector2", "Vector2int16", "Vector3", "Vector3int16", "CFrame",
    "Rect", "Region3", "Region3int16", "Ray", "NumberRange", "NumberSequence",
    "NumberSequenceKeypoint", "TweenInfo", "BrickColor", "Random", "Font",
    "PhysicalProperties", "RaycastParams", "OverlapParams", "PathWaypoint",
    "DateTime", "Faces", "Axes",
}

_CTOR_METHODS = {
    "new", "fromRGB", "fromHSV", "fromHex", "fromScale", "fromOffset",
    "fromNormalized", "fromName", "fromNumber", "fromWrap", "fromCharacter",
    "Angles", "fromAxisAngle", "fromMatrix", "fromEulerAnglesXYZ",
    "fromEulerAnglesYXZ", "fromEulerAngles", "lookAt", "identity", "palette",
    "fromKeyCode", "fromEnum", "now", "fromUnixTimestamp",
    "fromUnixTimestampMillis", "fromIsoDate", "fromLocalTime", "fromUniversalTime",
}

_PROPERTIES = {
    "Parent", "Name", "ClassName", "Position", "CFrame", "Size", "Orientation",
    "Rotation", "Anchored", "Transparency", "Color", "BrickColor", "Material",
    "CanCollide", "CanTouch", "CanQuery", "Velocity", "AssemblyLinearVelocity",
    "Massless", "CollisionGroup", "Health", "MaxHealth", "WalkSpeed", "JumpPower",
    "JumpHeight", "Character", "Humanoid", "HumanoidRootPart", "PrimaryPart",
    "Torso", "Head", "Backpack", "PlayerGui", "LocalPlayer",
    "Value", "Text", "Visible", "Enabled", "Active", "Adornee", "Locked",
    "UserId", "DisplayName", "AccountAge", "Team", "TeamColor",
    "CurrentCamera", "CameraType", "FieldOfView", "Focus", "ViewportSize",
    "Origin", "Direction", "Magnitude", "Unit", "LookVector", "RightVector",
    "UpVector", "Completed", "Touched", "Changed", "Mouse", "MouseButton1Click",
    "Activated", "PlayerAdded", "CharacterAdded", "Heartbeat", "RenderStepped",
    "Stepped", "InputBegan", "InputEnded", "InputChanged",
}

_VOWELS = set("aeiouAEIOU")


def _looks_random(s):
    """Per-build random identifier (variable/marker names like VuEcXXyNjiRvlE or
    DeXTiH_krU_pAM); allows underscores/digits between the camel humps."""
    core = s.replace("_", "")
    ups = sum(1 for c in core if c.isupper())
    return len(s) >= 9 and ups >= 3 and core.isalnum() and not core.isupper()


def _is_word(s):
    return (3 <= len(s) <= 30 and s.isalpha() and any(c in _VOWELS for c in s)
            and not _looks_random(s))


def proto_role(code):
    """Classify a proto: the actual user 'loader', the 'antitamper' stack-trace
    check, or a 'helper' (per-build string-decryptor lookup). Build-independent:
    keys on constant content, not hardcoded names."""
    consts = [c for ins in code for c in (ins["K"],) if isinstance(c, str) and c]
    if not consts:
        return "runtime"
    api = _KNOWN_METHODS | _GAME_METHODS | _UI_METHODS | _GLOBAL_FUNCS | _ROBLOX_SERVICES
    at = sum(1 for c in consts if c in _ANTITAMPER_HINTS)
    meaningful = [c for c in consts if c not in _ANTITAMPER_HINTS
                  and (" " in c or c.startswith("http") or c in api or _is_word(c))]
    from collections import Counter
    idents = Counter(c for c in consts if _looks_random(c))
    dominated = bool(idents) and idents.most_common(1)[0][1] >= 2
    distinct_mf = len(set(meaningful))
    if at >= 1 and distinct_mf <= 1:
        return "antitamper"
    if at >= 2 and distinct_mf <= 12:
        return "antitamper"
    if (dominated or idents) and distinct_mf <= 1:
        return "helper"
    return "loader"


def proto_summary(code):
    """A short human hint of what a proto does, from its own constants (reliable,
    content-based) -> shown as a comment so callbacks are navigable."""
    strs = [ins["K"] for ins in code if isinstance(ins["K"], str) and ins["K"]]
    url = next((s for s in strs if s.startswith("http")), None)
    if url:
        return 'loads %s' % (url[:60] + ("..." if len(url) > 60 else ""))
    win = next((s for s in strs if s in ("CreateWindow", "MakeWindow", "CreateLib")), None)
    if win:
        title = next((s for s in strs if " " in s and not s.startswith("http")), None)
        return ('builds the UI window "%s"' % title) if title else "builds the UI window"
    tab = next((s for s in strs if s in ("CreateTab", "MakeTab", "NewTab", "AddTab", "Tab")), None)
    if tab:
        title = next((s for s in strs if " " in s and not s.startswith("http")), None)
        return ('builds UI tab "%s"' % title) if title else "builds a UI tab"
    if any(s == "Notify" or s == "MakeNotification" for s in strs):
        title = next((s for s in strs if " " in s or (s[:1].isupper() and not _is_name(s))), None)
        return ('shows notification "%s"' % title) if title else "shows a notification"
    methods = [s for s in strs if s in _DESTROY_METHODS]
    if methods:
        return "%s the UI" % "/".join(dict.fromkeys(m.lower() for m in methods))
    svcs = list(dict.fromkeys(s for s in strs if s in _ROBLOX_SERVICES))
    if svcs:
        return "uses " + ", ".join(svcs[:4]) + ("..." if len(svcs) > 4 else "")
    quoted = next((s for s in strs if " " in s or s.startswith("@") or "/" in s), None)
    if quoted:
        return 'uses "%s"' % (quoted[:50])
    return ""


_LUA_TYPES = {"string", "number", "boolean", "table", "function", "nil",
              "userdata", "thread", "buffer", "vector", "Instance", "EnumItem",
              "CFrame", "Vector3", "Vector2", "Color3", "UDim2", "UDim",
              "BrickColor", "Ray", "Region3", "TweenInfo", "RBXScriptSignal",
              "RBXScriptConnection"}


_STOPWORDS = {"the", "and", "for", "you", "use", "this", "your", "here", "with",
              "are", "not", "from", "was", "but", "all", "can", "now", "get",
              "loadstring", "game", "httpget", "www", "https", "http", "com",
              "follow", "copied", "copy", "link", "loader"}


def _words(s):
    return {w for w in re.findall(r"[a-z]+", s.lower())
            if len(w) >= 3 and w not in _STOPWORDS}


def proto_words(code):
    """Significant words a proto mentions -> used to match a button to the child
    closure that actually implements it (content-based callback pairing)."""
    out = set()
    for ins in code:
        if isinstance(ins["K"], str):
            out |= _words(ins["K"])
    return out


_ANTITAMPER_APIS = {"traceback", "gmatch", "info", "find", "sub"}


def reconstruct_antitamper(code):
    ks = [ins["K"] for ins in code if isinstance(ins["K"], str) and ins["K"]]
    names = set(ks)
    if not ({"traceback", "gmatch", "info"} <= names):
        return None
    marker = None
    seen_tb = False
    for k in ks:
        if k == "traceback":
            seen_tb = True
            continue
        if seen_tb and _looks_random(k) and k not in _ANTITAMPER_APIS:
            marker = k
            break
    if marker is None:
        marker = next((k for k in ks if _looks_random(k)), None)
    mk = '"%s"' % marker if marker else "<per-build marker>"
    lines = [
        "-- Moonveil anti-tamper (fully devirtualized).",
        "local traceback, info = debug.traceback, debug.info",
        "local find, sub, gmatch = string.find, string.sub, string.gmatch",
        "",
        "local MARKER = %s" % mk,
        "",
        "local function integrity_check()",
        "    local tb = traceback()",
        "    local at = find(tb, MARKER)",
        "    if not at then",
        "        return false            -- marker missing => stack was tampered",
        "    end",
        "    local reported = {}",
        "    for n in gmatch(sub(tb, at), \":(%d*)\\n\") do",
        "        reported[#reported + 1] = tonumber(n)",
        "    end",
        "    local actual = info(2, \"l\")   -- real current line",
        "    if reported[1] ~= actual then",
        "        return false            -- line numbers disagree => tampered",
        "    end",
        "    return true",
        "end",
        "",
        "-- the VM gates the payload on this: `if not integrity_check() then return end`",
        "local _ = integrity_check",
    ]
    return lines


def detect_static_ops(protos, opmap):
    """Augment the trace-learned opmap with the opcodes the trace never voted
    on, recovered from the *static* instruction structure. Most important is
    SETTABLE (builds every option table); also SETGLOBAL and CLOSURE-capture."""
    op2 = dict(opmap)

    def nm(tag):
        return op2.get(tag, "OP_%s" % tag)

    settable_votes = {}
    setglobal_votes = {}
    for p in protos:
        code = p["code"]
        for i, ins in enumerate(code):
            name = nm(ins["tag"])
            if name in _KNOWN_OPNAMES or ins["K"] is not None:
                continue
            keyk = None
            for b in range(1, 4):
                if i - b < 0:
                    break
                pk = code[i - b]["K"]
                if isinstance(pk, str) and pk:
                    keyk = pk
                    break
            if keyk is None or not _is_name(keyk):
                continue
            settable_votes[ins["tag"]] = settable_votes.get(ins["tag"], 0) + 1
            if keyk in _GLOBAL_FUNCS:
                setglobal_votes[ins["tag"]] = setglobal_votes.get(ins["tag"], 0) + 1

    ks_votes = {}
    for p in protos:
        seen_newtable = False
        for ins in p["code"]:
            nmv = nm(ins["tag"])
            if nmv == "NEWTABLE":
                seen_newtable = True
            if nmv in _KNOWN_OPNAMES:
                continue
            if seen_newtable and isinstance(ins["K"], str) and _is_name(ins["K"]):
                ks_votes[ins["tag"]] = ks_votes.get(ins["tag"], 0) + 1

    settable = max(settable_votes, key=settable_votes.get) if settable_votes else None
    if settable is not None:
        op2[settable] = "SETTABLE"
        setglobal_votes.pop(settable, None)
    settable_ks = max(ks_votes, key=ks_votes.get) if ks_votes else None
    if settable_ks is not None and ks_votes[settable_ks] >= 2 and settable_ks != settable:
        op2[settable_ks] = "SETTABLE"
        setglobal_votes.pop(settable_ks, None)


    setglobal = max(setglobal_votes, key=setglobal_votes.get) if setglobal_votes else None
    if setglobal is not None and setglobal_votes[setglobal] >= 2:
        op2[setglobal] = "SETGLOBAL"
    return op2, settable


def _render_token(tok):
    k = tok["kind"]
    if k == "str":
        return _qarg(tok["val"])
    if k == "num":
        return str(tok["val"])
    if k == "expr":
        return tok["val"]
    if k == "table":
        return _render_table(tok["val"])
    return "nil"


def _render_table(fields):
    if not fields:
        return "{}"
    parts = []
    for key, val in fields:
        v = _render_token(val) if val is not None else "nil --[[?]]"
        if key is None:
            parts.append(v)
        elif key["kind"] == "str" and _is_name(key["val"]):
            parts.append("%s = %s" % (key["val"], v))
        else:
            parts.append("[%s] = %s" % (_render_token(key), v))
    return "{ " + ", ".join(parts) + " }"


def _const_token(K):
    if isinstance(K, (int, float)):
        return {"kind": "num", "val": K}
    return {"kind": "str", "val": K}


def _is_stmt_call(s):
    """A Lua expression-statement must be a function/method call. Reject bare
    value expressions (top-level concat/length/arithmetic) that parse only as
    values, so the emitted reconstruction is always valid Luau."""
    s = s.strip()
    if not s.endswith(")") or "(" not in s:
        return False
    if s.startswith("#") or s.startswith("("):
        pass
    depth = 0
    i = 0
    while i < len(s):
        c = s[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and c == "." and i + 1 < len(s) and s[i + 1] == ".":
            return False
        i += 1
    return True


def synth_statements(insns, opmap2, settable, child_q=None, child_words=None,
                     resolved=None, ui_recv="Library"):
    """Synthesize readable Lua statements from one straight-line run of
    instructions, using the constant stream + opcode classes. Call results are
    pushed back as expression tokens so method chains like
    game:GetService("X"):GetChildren() collapse naturally. All `pending` edits
    mutate the list in place so chained receivers resolve correctly.
    `child_q` (a mutable list) supplies child-proto indices for Callback slots."""
    pending = []
    out = []
    if child_q is None:
        child_q = []
    if child_words is None:
        child_words = {}
    if resolved is None:
        resolved = {}
    namecnt = {}
    services = {}

    def fresh(base):
        namecnt[base] = namecnt.get(base, 0) + 1
        return base if namecnt[base] == 1 else "%s%d" % (base, namecnt[base])

    _CLOSURE_KEYS = {"Callback", "Handler", "Function", "Click", "OnClick",
                     "Changed", "OnChanged", "Activated", "Run"}

    def opname(ins):
        return opmap2.get(ins["tag"], "OP_%s" % ins["tag"])

    def cur_table_index():
        for j in range(len(pending) - 1, -1, -1):
            if pending[j]["kind"] == "table":
                return j
        return None

    def emit_call():
        gtoks = [t for t in pending if t["kind"] == "global"]
        has_global = bool(gtoks)
        gname = next((t.get("val") for t in gtoks if t.get("val")), None)
        gname = _snap_global(gname)
        if has_global:
            pending[:] = [t for t in pending if t["kind"] != "global"]
        gidx = None
        for j, t in enumerate(pending):
            if t["kind"] == "str" and t["val"] in _GLOBAL_FUNCS:
                gidx = j
                break
        if gidx is not None:
            for t in pending[:gidx]:
                if t["kind"] == "expr":
                    out.append(t["val"])
            fn = pending[gidx]["val"]
            args = pending[gidx + 1:]
            arg_toks = [a for a in args
                        if a["kind"] != "num" and not (a["kind"] == "table" and not a["val"])]
            if fn in _ARITY1 and len(arg_toks) > 1:
                arg_toks = arg_toks[:1]
            expr = "%s(%s)" % (fn, ", ".join(_render_token(a) for a in arg_toks))
            pending[:] = [{"kind": "expr", "val": expr}]
            return

        if has_global:
            strs = [t for t in pending if t["kind"] == "str"]
            has_recv = any(t["kind"] == "expr" for t in pending)
            known_method = any(
                s["val"] in _GAME_METHODS or s["val"] in _UI_METHODS
                or s["val"] in _CONTAINER_METHODS or s["val"] in _KNOWN_METHODS
                for s in strs)
            if not has_recv and not known_method:
                arg_toks = [t for t in pending
                            if t["kind"] in ("str", "table")
                            and not (t["kind"] == "table" and not t["val"])]
                callee = gname
                if callee == "Enum":
                    idents = [a["val"] for a in arg_toks
                              if a["kind"] == "str" and _is_name(a["val"])]
                    if idents:
                        pending[:] = [{"kind": "expr",
                                       "val": "Enum." + ".".join(idents[:2])}]
                        return
                if callee in _DATATYPE_CTORS:
                    mi = next((j for j, t in enumerate(pending)
                               if t["kind"] == "str" and _is_name(t["val"])), None)
                    if mi is not None:
                        member = pending[mi]["val"]
                        rest = [t for t in pending[mi + 1:]
                                if t["kind"] in ("str", "num", "table")
                                and not (t["kind"] == "table" and not t["val"])]
                        if rest or member in _CTOR_METHODS:
                            expr = "%s.%s(%s)" % (callee, member,
                                                  ", ".join(_render_token(a) for a in rest))
                        else:
                            expr = "%s.%s" % (callee, member)
                        pending[:] = [{"kind": "expr", "val": expr}]
                        return
                if callee in _NAMESPACE_GLOBALS:
                    idents = [a["val"] for a in arg_toks
                              if a["kind"] == "str" and _is_name(a["val"])]
                    if len(arg_toks) == 1 and len(idents) == 1:
                        pending[:] = [{"kind": "expr", "val": "%s.%s" % (callee, idents[0])}]
                        return
                if callee is None and strs:
                    m = strs[0]["val"]
                    if (len(arg_toks) == 1 and (" " in m or len(m) >= 10)
                            and not m.startswith("http") and "loadstring" not in m
                            and "game:" not in m and "@" not in m and "/" not in m):
                        callee = "print"
                if callee is not None:
                    expr = "%s(%s)" % (callee, ", ".join(_render_token(a) for a in arg_toks))
                    pending[:] = [{"kind": "expr", "val": expr}]
                    return

        midx = None
        for j in range(len(pending) - 1, -1, -1):
            if pending[j]["kind"] == "str":
                midx = j
                break
        if midx is None:
            if pending and pending[-1]["kind"] == "expr" and "(" in pending[-1]["val"]:
                out.append(pending.pop()["val"])
            return
        method = pending[midx]["val"]
        recv = None
        start = 0
        args = pending[:midx]
        for j in range(midx - 1, -1, -1):
            if pending[j]["kind"] == "expr":
                recv = pending[j]["val"]
                start = j
                args = pending[j + 1:midx]
                break
        if not _is_name(method):
            all_args = pending[start:midx + 1] if recv is None else pending[start + 1:midx + 1]
            arg_toks = [a for a in all_args
                        if a["kind"] != "num" and not (a["kind"] == "table" and not a["val"])]
            argstr = ", ".join(_render_token(a) for a in arg_toks)
            realname = None
            note = "  -- (function name not recovered)"
            for a in arg_toks:
                if a["kind"] == "str" and a["val"] in resolved:
                    realname = resolved[a["val"]]
                    note = "  -- resolved from runtime trace"
                    break
            if realname is None:
                strs = [a["val"] for a in arg_toks if a["kind"] == "str"]
                if (len(arg_toks) == 1 and len(strs) == 1
                        and (" " in strs[0] or len(strs[0]) >= 10)
                        and not strs[0].startswith("http")
                        and "loadstring" not in strs[0] and "game:" not in strs[0]
                        and "@" not in strs[0] and "/" not in strs[0]):
                    realname = "print"
                    note = "  -- inferred (global call with a message string)"
            if recv is not None:
                out.append("%s(...)  -- chained call, name not recovered" % recv)
            if realname:
                out.append("%s(%s)%s" % (realname, argstr, note))
            else:
                out.append("fn(%s)%s" % (argstr, note))
            pending[start:] = []
            return
        arg_toks = [a for a in args
                    if a["kind"] != "num" and not (a["kind"] == "table" and not a["val"])]
        argstr = ", ".join(_render_token(a) for a in arg_toks)
        if recv is not None and re.match(r"(print|warn|error|assert)\(", recv):
            out.append(recv)
            recv = None
        if recv is not None and not arg_toks and method in _PROPERTIES:
            pending[start:midx + 1] = [{"kind": "expr", "val": "%s.%s" % (recv, method)}]
            return
        if recv is not None:
            receiver = recv
        elif method in _GAME_METHODS:
            receiver = "game"
        elif method in _UI_METHODS:
            receiver = ui_recv
        else:
            receiver = gname or "obj"
        if (method in _LEAF_METHODS and services
                and not re.match(r"^[A-Za-z_][\w.]*$", receiver)):
            receiver = list(services.values())[-1]
        expr = "%s:%s(%s)" % (receiver, method, argstr)

        if method in ("HttpGet", "HttpGetAsync"):
            url = next((a["val"] for a in arg_toks
                        if a["kind"] == "str" and a["val"].startswith("http")), None)
            if url is not None:
                expr = 'game:%s("%s")' % (method, url)
            expr = "loadstring(%s)()" % expr

        if method == "GetService" and arg_toks and arg_toks[0]["kind"] == "str" \
                and _is_name(arg_toks[0]["val"]):
            svc = arg_toks[0]["val"]
            if svc in services:
                var = services[svc]
            else:
                var = fresh(svc)
                services[svc] = var
                out.append("local %s = %s" % (var, expr))
            pending[start:midx + 1] = [{"kind": "expr", "val": var}]
        elif method in _CONTAINER_METHODS:
            base = _CONTAINER_METHODS[method]
            title = next((a["val"] for a in arg_toks if a["kind"] == "str"), None)
            var = fresh(_var_from_title(title, base))
            out.append("local %s = %s" % (var, expr))
            pending[start:midx + 1] = [{"kind": "expr", "val": var}]
        elif method in _UI_METHODS or method in _LEAF_METHODS:
            out.append(expr)
            pending[start:midx + 1] = [{"kind": "expr", "val": receiver}]
        else:
            pending[start:midx + 1] = [{"kind": "expr", "val": expr}]

    for ins in insns:
        o = opname(ins)
        K = ins["K"]
        if o == "GETGLOBAL":
            if isinstance(K, str) and (K in _KNOWN_METHODS or K in _CTOR_METHODS):
                if not (pending and pending[-1].get("kind") == "str"
                        and pending[-1].get("val") == K):
                    pending.append({"kind": "str", "val": K})
            else:
                pending.append({"kind": "global", "val": K if (isinstance(K, str) and K) else None})
            continue
        if o == "SETTABLE" or ins["tag"] == settable:
            ti = cur_table_index()
            above = pending[ti + 1:] if ti is not None else pending[:]
            own_key = K if (isinstance(K, str) and _is_name(K)) else None
            key = val = None
            if own_key is not None:
                key = {"kind": "str", "val": own_key}
                for t in reversed(above):
                    if t["kind"] in ("str", "num", "table", "expr"):
                        if t["kind"] == "str" and t["val"] == own_key:
                            continue
                        val = t
                        break
            elif above:
                key = above[-1] if above[-1]["kind"] == "str" else None
                val = above[-2] if len(above) >= 2 and above[-2]["kind"] in ("str", "num", "table", "expr") else None
            if (key is not None and val is None and child_q
                    and key["val"] in _CLOSURE_KEYS):
                tb_now = pending[ti]["val"] if ti is not None else []
                ctx = set()
                for _k, _v in tb_now:
                    if _v and _v.get("kind") == "str":
                        ctx |= _words(_v["val"])
                best, bestscore = None, 0
                for ci in child_q:
                    sc = len(ctx & child_words.get(ci, set()))
                    if sc > bestscore:
                        best, bestscore = ci, sc
                pick = best if best is not None else child_q[0]
                child_q.remove(pick)
                val = {"kind": "expr", "val": "proto_%d" % pick}
            if key is not None and ti is not None:
                pending[ti]["val"].append((key, val))
            if ti is not None:
                del pending[ti + 1:]
            else:
                pending.clear()
            continue
        if K is not None and K != "":
            tok = _const_token(K)
            if (tok["kind"] == "str" and pending
                    and pending[-1].get("kind") == "str"
                    and pending[-1].get("val") == tok["val"]):
                continue
            pending.append(tok)
            continue
        if o == "NEWTABLE":
            pending.append({"kind": "table", "val": []})
            continue
        if o == "SETGLOBAL":
            if pending and pending[-1]["kind"] == "str":
                g = pending.pop()
                out.append("%s = function() end  -- (loader overwrites this global)" % g["val"])
            continue
        if o == "CONCAT":
            if len(pending) >= 2:
                b = pending.pop()
                a = pending.pop()
                pending.append({"kind": "expr",
                                "val": "%s .. %s" % (_render_token(a), _render_token(b))})
            continue
        if o == "LEN":
            if pending:
                a = pending.pop()
                pending.append({"kind": "expr", "val": "#" + _render_token(a)})
            continue
        if o == "CALL":
            emit_call()
            continue
    for tok in pending:
        if tok["kind"] == "expr":
            s = tok["val"]
            if s.startswith("#"):
                s = s[1:]
            if _is_stmt_call(s):
                out.append(s)
    return out


def _last_string_before(code, idx):
    for j in range(idx - 1, max(idx - 4, -1), -1):
        if isinstance(code[j]["K"], str):
            return code[j]["K"]
    return None


def _strings_before(code, idx, count, window=8):
    found = []
    for j in range(idx - 1, max(idx - window, -1), -1):
        K = code[j]["K"]
        if isinstance(K, str) and K:
            found.append(K)
            if len(found) >= count:
                break
    return found


def _match_cleanup_loop(code, start, end, opname, is_jump):
    """Recognize the near-universal Roblox loader idiom of destroying children
    whose Name matches one of a few values:
        for _, v in pairs(...) do
            if v.Name == "A" or v.Name == "B" then v:Destroy() end
        end
    The flattened jumps otherwise reconstruct as wrongly-nested ifs."""
    prop = None
    names = []
    method = None
    for k in range(start, end):
        ins = code[k]
        if is_jump(ins) and ins["sBx"] and ins["sBx"] > 0:
            pair = _strings_before(code, k, 2)
            if pair:
                names.append(pair[0])
                if len(pair) >= 2 and prop is None and _is_name(pair[1]):
                    prop = pair[1]
        if opname(ins) == "CALL":
            mv = _last_string_before(code, k)
            if mv in _DESTROY_METHODS:
                method = mv
    if names and method:
        seen = []
        for nm in names:
            if nm not in seen and nm != prop:
                seen.append(nm)
        return prop or "Name", seen, method
    return None


_TRACE_BOUNDARY_NOTE = ("-- below here: rebuilt from the constant stream "
                        "(not execution-traced); receivers & args best-effort")


def clean_proto(code, opmap2, settable, jump_tags, children=None, child_words=None,
                resolved=None, conds=None, trace_facts=None, traced_max_pc=None,
                ui_recv="Library"):
    """Reconstruct one proto into clean Lua with loop/branch structure.
    `children` are this proto's child-proto indices in source order; they are
    consumed into the `Callback`-style table slots, paired by content when
    possible (`child_words`). `resolved` maps an argument string to the runtime
    function name captured by the behavioral trace (resolves `fn(...)`).
    `conds` maps a branch pc to a trace-recovered comparison {op, const}."""
    n = len(code)
    child_q = list(children or [])
    child_words = child_words or {}
    resolved = resolved or {}
    conds = conds or {}
    trace_facts = dict(trace_facts or {})
    ret_tag = code[-1]["tag"] if code and code[-1].get("tag") not in jump_tags else None

    marked = [traced_max_pc is None]

    def opname(ins):
        return opmap2.get(ins["tag"], "OP_%s" % ins["tag"])

    def is_jump(ins):
        return ins["tag"] in jump_tags and ins["sBx"]

    def is_forloop(ins):
        return opname(ins) == "FORLOOP"

    def target_idx(ins):
        t = ins["pc"] + (ins["sBx"] or 0) + 1
        for k, c in enumerate(code):
            if c["pc"] >= t:
                return k
        return n

    out = []

    def flush(run, ind, hold_last=False):
        """Synthesize `run` into statements. If hold_last, the trailing call
        expression is returned (not emitted) so the caller can use it as a
        loop iterable / condition subject."""
        if not run:
            return None
        stmts = [s for s in synth_statements(run, opmap2, settable, child_q,
                                             child_words, resolved, ui_recv) if s.strip()]
        run.clear()
        tail = None
        if hold_last and stmts and "(" in stmts[-1]:
            tail = stmts.pop()
        for s in stmts:
            out.append(ind + s)
        return tail

    def emit(i, j, ind, depth=0, in_loop=False):
        run = []
        if depth > 200:
            flush(run, ind)
            return
        loops = {}
        for k in range(i, j):
            if is_forloop(code[k]) and code[k]["sBx"] and code[k]["sBx"] < 0:
                loops[target_idx(code[k])] = k
        while i < j:
            ins = code[i]
            if not marked[0] and ind == "" and not loops and ins["pc"] > traced_max_pc:
                flush(run, ind)
                out.append(_TRACE_BOUNDARY_NOTE)
                marked[0] = True
            if i in loops and loops[i] < j:
                iexpr = flush(run, ind, hold_last=True)
                end = loops[i]
                cleanup = _match_cleanup_loop(code, i, end, opname, is_jump)
                iterable = trace_facts.pop("iterable", None) or iexpr or "..."
                out.append(ind + "for _, v in pairs(%s) do" % iterable)
                if cleanup:
                    prop, names, method = cleanup
                    cond = " or ".join('v.%s == "%s"' % (prop, nm) for nm in names)
                    out.append(ind + "    if %s then" % cond)
                    out.append(ind + "        v:%s()" % method)
                    out.append(ind + "    end")
                else:
                    emit(i, end, ind + "    ", depth + 1, in_loop=True)
                out.append(ind + "end")
                i = end + 1
                if not marked[0] and ind == "":
                    out.append(_TRACE_BOUNDARY_NOTE)
                    marked[0] = True
                continue
            if is_jump(ins) and ins["sBx"] and ins["sBx"] > 0:
                cinfo = conds.get(ins["pc"])
                subj = flush(run, ind, hold_last=True)
                tgt = target_idx(ins)
                cmpv = _last_string_before(code, i)
                subj_used = False
                if cinfo:
                    lhs = subj if subj else "COND"
                    cond = "%s %s %s" % (lhs, cinfo["op"], _fmt_num_literal(cinfo["const"]))
                    subj_used = True
                elif (cmpv in _LUA_TYPES and subj
                      and re.match(r"(typeof|type)\(", subj)):
                    cond = '%s == "%s"' % (subj, cmpv)
                    subj_used = True
                elif in_loop and cmpv:
                    cond = 'v.Name == "%s"' % cmpv
                elif cmpv:
                    cond = 'COND --[[ branches on "%s" ]]' % cmpv
                else:
                    cond = "COND"
                if subj and not subj_used:
                    out.append(ind + subj)
                then_hi = min(tgt, j)
                else_hi = None
                then_body_hi = then_hi
                last_then = then_hi - 1
                if not in_loop and i < last_then < n:
                    lt = code[last_then]
                    if is_jump(lt) and lt["sBx"] and lt["sBx"] > 0:
                        else_hi = min(target_idx(lt), j)
                        then_body_hi = last_then
                    elif ret_tag is not None and lt["tag"] == ret_tag and tgt < j:
                        else_hi = j
                out.append(ind + "if %s then" % cond)
                emit(i + 1, then_body_hi, ind + "    ", depth + 1, in_loop=in_loop)
                if else_hi is not None and else_hi > tgt:
                    out.append(ind + "else")
                    emit(tgt, else_hi, ind + "    ", depth + 1, in_loop=in_loop)
                    out.append(ind + "end")
                    i = else_hi
                else:
                    out.append(ind + "end")
                    i = tgt if tgt > i else i + 1
                continue
            run.append(ins)
            i += 1
        flush(run, ind)

    emit(0, n, "")

    def strip_empty(lines):
        changed = True
        while changed:
            changed = False
            res, i = [], 0
            while i < len(lines):
                cur = lines[i].strip()
                if (i + 1 < len(lines) and (cur.startswith("if ") or cur.startswith("for "))
                        and lines[i + 1].strip() == "end"):
                    i += 2
                    changed = True
                    continue
                res.append(lines[i])
                i += 1
            lines = res
        return lines

    out2 = strip_empty(out)
    meaningful = any(("(" in l or " = " in l or l.strip().startswith("local "))
                     and not l.strip().startswith("--") for l in out2)
    if not meaningful:
        if children:
            return ["-- (creates the closures listed above)"]
        return ["-- failed to decompile"]
    return out2


def _fmt_num_literal(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return str(int(f)) if f.is_integer() else repr(f)


def _cmp_operator(subj_val, const_val, cond_true):
    """Infer a comparison operator from the runtime operand values and whether
    the (skip-if-false) branch fell through to its then-body. A single execution
    cannot separate < from <= etc., so the strict form is chosen; annotated as
    runtime-derived by the caller."""
    if subj_val > const_val:
        return ">" if cond_true else "<="
    if subj_val < const_val:
        return "<" if cond_true else ">="
    return "==" if cond_true else "~="


def _match_trace_block(proto, blocks, tag_field):
    """Find the traced execution block whose pcs/tags belong to this proto."""
    ppcs = set(ins["pc"] for ins in proto["code"])
    ptag = {ins["pc"]: ins["tag"] for ins in proto["code"]}
    best = None
    for entries in blocks.values():
        bpcs = [e["pc"] for e in entries]
        if not bpcs or not set(bpcs) <= ppcs:
            continue
        total = agree = 0
        for e in entries:
            tf = e["fields"].get(tag_field)
            if isinstance(tf, tuple) and tf[0] == "num":
                total += 1
                if int(float(tf[1])) == ptag.get(e["pc"]):
                    agree += 1
        if total and agree >= total * 0.6:
            if best is None or len(entries) > len(best):
                best = entries
    return best


def learn_trace_semantics(protos, blocks, tag_field, opmap2, jump_tags):
    """Recover exact branch conditions (and numeric literals) from the runtime
    trace. At a comparison-and-jump the operand fields A/B index the two
    compared registers; the trace holds their real values and the branch
    outcome, which together give `<subject> <op> <const>`. This is ground truth
    (the VM actually ran), not a static heuristic."""
    result = {}
    if not blocks or tag_field is None:
        return result
    for p in protos:
        entries = _match_trace_block(p, blocks, tag_field)
        if not entries:
            continue
        conds = {}
        for i, e in enumerate(entries):
            tf = e["fields"].get(tag_field)
            tag = int(float(tf[1])) if isinstance(tf, tuple) and tf[0] == "num" else None
            if tag not in jump_tags:
                continue
            sins = next((x for x in p["code"] if x["pc"] == e["pc"]), None)
            if not sins or not sins.get("sBx") or sins["sBx"] <= 0:
                continue
            A, B = sins.get("A"), sins.get("B")
            va, vb = as_number(e["regs"].get(A)), as_number(e["regs"].get(B))
            if va is None or vb is None:
                continue
            target = e["pc"] + sins["sBx"] + 1
            nxt = entries[i + 1]["pc"] if i + 1 < len(entries) else None
            cond_true = nxt is not None and nxt != target
            a_int, b_int = float(va).is_integer(), float(vb).is_integer()
            if a_int and not b_int:
                const_val, subj_val = va, vb
            elif b_int and not a_int:
                const_val, subj_val = vb, va
            elif abs(va) <= abs(vb):
                const_val, subj_val = va, vb
            else:
                const_val, subj_val = vb, va
            conds[e["pc"]] = {"op": _cmp_operator(subj_val, const_val, cond_true),
                              "const": const_val}
        if conds:
            result[p["index"]] = {"conds": conds}
    return result


_LUAU_GLOBALS = {
    "print", "warn", "error", "assert", "pairs", "ipairs", "next", "select",
    "type", "typeof", "tostring", "tonumber", "pcall", "xpcall", "rawget",
    "rawset", "rawequal", "rawlen", "setmetatable", "getmetatable", "unpack",
    "require", "loadstring", "collectgarbage", "gcinfo", "newproxy", "getfenv",
    "setfenv", "string", "table", "math", "os", "coroutine", "bit32", "buffer",
    "utf8", "debug", "vector", "task", "game", "workspace", "Enum", "Instance",
    "tick", "wait", "spawn", "delay", "_G", "shared", "_VERSION", "v",
}


def _unknown_globals(body_lines):
    """Names used in call/index position that are neither luau builtins nor
    locals/loop-vars defined in the body. Declared as `any` so the best-effort
    reconstruction always type-checks (e.g. a global whose name decoded only
    partially like `tiRJ`)."""
    body = "\n".join((l[:l.find("--")] if "--" in l else l) for l in body_lines)
    body = re.sub(r'"(?:\\.|[^"\\])*"', '""', body)
    defined = set()
    for m in re.finditer(r'\blocal\s+(?:function\s+)?([\w,\s]+)', body):
        defined |= set(re.findall(r'[A-Za-z_]\w*', m.group(1)))
    defined |= set(re.findall(r'\bfunction\s+(\w+)', body))
    for m in re.finditer(r'\bfor\s+(.+?)\s+in\b', body):
        defined |= set(re.findall(r'\w+', m.group(1)))
    for m in re.finditer(r'\bfor\s+(\w+)\s*=', body):
        defined.add(m.group(1))
    names = set(re.findall(r'(?<![.:\w])([A-Za-z_]\w*)\s*[(.:]', body))
    return sorted(n for n in names
                  if n not in _LUAU_GLOBALS and n not in defined
                  and not n[0].isdigit())


def reconstruct_clean(protos, opmap2, settable, jump_tags, behavior=None,
                      blocks=None, tag_field=None, fl=None, opmap=None,
                      drop_antitamper=None):
    if drop_antitamper is None:
        drop_antitamper = bool(os.environ.get("MOONVEIL_NO_ANTITAMPER"))
    behavior = behavior or []
    detected_lib = detect_library(protos)
    ui_lib = detected_lib or "Library"
    trace_sem = learn_trace_semantics(protos, blocks, tag_field, opmap2, jump_tags)
    resolved = {}
    for name, args in behavior:
        if name in ("print", "warn", "setclipboard", "loadstring", "writefile",
                    "appendfile", "require", "hookfunction"):
            for a in args:
                if isinstance(a, str) and a:
                    resolved.setdefault(a, name)
    out = []
    out.append("--!nocheck")
    out.append("-- Moonveil reconstruction by 2zvh")
    if detected_lib:
        out.append("-- detected UI library: %s (receiver of unbound UI calls)" % detected_lib)
    svc_used = sorted({ins["K"] for p in protos for ins in p["code"]
                       if isinstance(ins.get("K"), str) and ins["K"] in _ROBLOX_SERVICES})
    if svc_used:
        out.append("-- Roblox services referenced: %s" % ", ".join(svc_used))
    allstrs = [ins["K"] for p in protos for ins in p["code"] if isinstance(ins.get("K"), str)]
    urls = list(dict.fromkeys(s for s in allstrs if s.startswith("http")))
    parts = []
    if urls:
        parts.append("loads " + ", ".join(u[:55] + ("..." if len(u) > 55 else "") for u in urls[:2]))
    if detected_lib:
        parts.append("builds a UI with %s" % detected_lib)
    if svc_used:
        parts.append("uses " + ", ".join(svc_used[:4]) + ("..." if len(svc_used) > 4 else ""))
    if parts:
        out.append("-- This script: " + "; ".join(parts) + ".")
    out.append("")


    if behavior:
        out.append("-- BEHAVIORAL TRACE  (actual calls captured by running under luau)")
        for name, args in behavior:
            parts = []
            for a in args:
                if isinstance(a, str):
                    parts.append(_qarg(a))
                elif isinstance(a, tuple):
                    parts.append("<%s>" % a[1])
                else:
                    parts.append(str(a))
            call = "%s(%s)" % (name, ", ".join(parts))
            if name == "loadstring":
                call += "()"
            out.append(call)
        out.append("")

    roles = {p["index"]: proto_role(p["code"]) for p in protos}
    pmap = {p["index"]: p for p in protos}
    child_words = {p["index"]: proto_words(p["code"]) for p in protos}

    real = set()
    stack = [i for i, r in roles.items() if r == "loader"]
    while stack:
        i = stack.pop()
        if i in real or i not in pmap:
            continue
        real.add(i)
        for c in pmap[i].get("children") or []:
            if roles.get(c) != "antitamper" and c not in real:
                stack.append(c)

    def emit_proto(nidx, p, role, collapse=False):
        kids = p.get("children") or []
        if collapse:
            label = {"antitamper": "anti-tamper (stack-trace integrity check)",
                     "helper": "per-build string-decryptor helper"}.get(
                role, "VM runtime / obfuscator helper")
            out.append("function proto_%d(...)  --[[ %s; body omitted ]] end" % (nidx, label))
            out.append("")
            return
        note = ""
        summary = proto_summary(p["code"])
        if summary:
            note = "  -- " + summary
        out.append("function proto_%d(...)%s" % (nidx, note))
        if kids:
            out.append("    -- closures defined here: %s"
                       % ", ".join("proto_%d" % c for c in kids))
        conds = (trace_sem.get(p["index"], {}) or {}).get("conds")
        trace_facts = {}
        traced_max_pc = None
        try:
            entries = _match_trace_block(p, blocks, tag_field) if blocks else None
            if entries:
                lifter_ctx = {"opmap": opmap, "tag_field": tag_field, "fl": fl}
                trace_facts = register_lifter.recover_facts(p["code"], entries, lifter_ctx)
                if len(p["code"]) >= register_lifter.MIN_PROTO_SIZE:
                    tmax = max(e["pc"] for e in entries)
                    if tmax < max(ins["pc"] for ins in p["code"]):
                        traced_max_pc = tmax
        except (RecursionError, RuntimeError):
            trace_facts = {}
        try:
            lines = clean_proto(p["code"], opmap2, settable, jump_tags, list(kids),
                                child_words, resolved, conds, trace_facts, traced_max_pc,
                                ui_lib)
        except (RecursionError, RuntimeError):
            lines = ["    -- [reconstruction failed for this proto]"]
        if not lines:
            lines = ["    -- (only creates closures / no direct statements)" if kids
                     else "    -- (no statements recovered)"]
        for ln in lines:
            out.append(("    " + ln).rstrip() if ln.strip() else "")
        out.append("end")
        out.append("")

    real_list = [p for p in protos if p["index"] in real]
    junk_list = [p for p in protos if p["index"] not in real]

    at_done = set()
    at_sections = []
    if drop_antitamper:
        junk_list = [p for p in junk_list if roles[p["index"]] != "antitamper"]
    else:
        for p in protos:
            if roles[p["index"]] == "antitamper":
                recon = reconstruct_antitamper(p["code"])
                if recon:
                    at_sections.append((p["index"], recon))
                    at_done.add(p["index"])
        junk_list = [p for p in junk_list if p["index"] not in at_done]

    if real_list:
        out.append("-- real shi")
        out.append("")
        for p in real_list:
            emit_proto(p["index"], p, roles[p["index"]])

    if at_sections:
        out.append("-- antitamper boi:")
        out.append("")
        for idx, recon in at_sections:
            out.append("-- proto_%d:" % idx)
            out.extend(recon)
            out.append("")

    if junk_list:
        out.append("-- obfuscator junk (string decryptor / VM helpers; bodies omitted)")
        out.append("")
        for p in junk_list:
            emit_proto(p["index"], p, roles[p["index"]], collapse=True)
    allidx = sorted(p["index"] for p in protos if p["index"] not in at_done)
    out.append("")
    out.append("-- proto table (the VM entry point is proto_0)")
    out.append("return { %s }" % ", ".join("proto_%d" % i for i in allidx))
    return "\n".join(out).rstrip() + "\n"


def reconstruct_source(user_protos):
    """Assemble the best-effort reconstruction across all user protos."""
    out = []
    out.append("-- Moonveil Reconstruction by 2zvh.")
    out.append("-- Enable other options from the bot to get disassemble output, opcodes and strings.")
    out.append("")

    all_loaders = []
    for p in user_protos:
        ld, _ = reconstruct_proto(p["code"])
        for line in ld:
            if line not in all_loaders:
                all_loaders.append(line)
    if all_loaders:
        out.append("-- runnable loader entrypoint(s)")
        out.extend(all_loaders)
        out.append("")

    out.append("-- reconstructed API call sequence")
    for n, p in enumerate(user_protos):
        _, calls = reconstruct_proto(p["code"])
        if not calls:
            continue
        out.append("-- proto_%d:" % n)
        for line in calls:
            out.append("--   " + line)
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def disasm_proto(proto, opmap, jump_tags):
    lines = []
    for ins in proto["code"]:
        mn = opmap.get(ins["tag"], "OP_%s" % ins["tag"])
        parts = []
        for f in ("A", "B"):
            if ins[f]:
                parts.append("%s=%s" % (f, ins[f]))
        if ins["tag"] in jump_tags and ins["sBx"]:
            parts.append("-> %d" % (ins["pc"] + ins["sBx"] + 1))
        if ins["K"] is not None:
            parts.append("K=%r" % ins["K"])
        lines.append("  %3d  %-12s %s" % (ins["pc"], mn, "  ".join(parts)))
    return "\n".join(lines)


def learn_opcodes(blocks, const_field, tag_field, sbx):
    votes = {}
    jump_hits = {}
    jump_total = {}
    back = {}
    for entries in blocks.values():
        seq = []
        for e in entries:
            if seq and seq[-1]["pc"] == e["pc"]:
                seq[-1] = e
            else:
                seq.append(e)
        for i, e in enumerate(seq):
            after = seq[i + 1]["regs"] if i + 1 < len(seq) else {}
            tf = e["fields"].get(tag_field)
            if not (isinstance(tf, tuple) and tf[0] == "num"):
                continue
            tag = int(float(tf[1]))
            sv = e["fields"].get(sbx)
            sval = int(float(sv[1])) if isinstance(sv, tuple) and sv[0] == "num" else 0
            if sval != 0 and i + 1 < len(seq):
                jump_total[tag] = jump_total.get(tag, 0) + 1
                if seq[i + 1]["pc"] == e["pc"] + sval + 1:
                    jump_hits[tag] = jump_hits.get(tag, 0) + 1
                    if sval < 0:
                        back[tag] = back.get(tag, 0) + 1
            label = classify_occurrence(e["regs"], after, e["fields"], const_field, tag_field, sbx)
            votes.setdefault(tag, {})
            votes[tag][label] = votes[tag].get(label, 0) + 1
    jump_tags = {}
    for tag, total in jump_total.items():
        if jump_hits.get(tag, 0) >= max(1, total * 0.4):
            jump_tags[tag] = "FORLOOP" if back.get(tag, 0) >= 1 else "JMP"
    opmap = {}
    for tag, vs in votes.items():
        if tag in jump_tags:
            opmap[tag] = jump_tags[tag]
        else:
            opmap[tag] = max((k for k in vs if k not in ("?", "MULTI", "JMP", "FORLOOP/JMPBACK", "TEST")),
                             key=vs.get, default=max(vs, key=vs.get))
    return opmap, jump_tags


_BETA_DUMP = (
    "local __seen,__n={},0\n"
    "local function __id(t) if __seen[t] then return __seen[t] end __n=__n+1 __seen[t]=__n return __n end\n"
    "local function __hex(s) return (s:gsub('.',function(c) return string.format('%02x',string.byte(c)) end)) end\n"
    "local __em={}\n"
    "local function __emit(t,tag) if __em[t] then return end __em[t]=true local r={tag..'T'..__id(t)}"
    " for k,v in pairs(t) do if type(k)=='number' then local tv=type(v)"
    " if tv=='number' then r[#r+1]=k..'=#'..v elseif tv=='string' then r[#r+1]=k..'=$'..__hex(v)"
    " elseif tv=='table' then r[#r+1]=k..'=@'..__id(v) elseif tv=='function' then r[#r+1]=k..'=F'"
    " elseif tv=='boolean' then r[#r+1]=k..'=b'..tostring(v) end end end print('\\1'..table.concat(r,'|')) end\n"
    "local function __deep(t,tag,d) if type(t)~='table' or d<0 then return end if __em[t] then return end"
    " __emit(t,tag) for _,v in pairs(t) do if type(v)=='table' then __deep(v,tag,d-1) end end end\n"
    "function __WRAP(T) for _,key in ipairs({'B','w','z'}) do local orig=T[key]"
    " if type(orig)=='function' then T[key]=function(a,c) local inner=orig(a,c)"
    " if type(c)=='table' then __deep(c,'C',4) end"
    " return function(...) for _,g in ipairs({...}) do if type(g)=='table' then __deep(g,'G',3) end end"
    " return inner(...) end end end end"
    " local oo=T.o if type(oo)=='function' then T.o=function(_,a) local dec=oo(_,a)"
    " return function(ca) local r=dec(ca)"
    " if type(ca)=='string' and type(r)=='string' then print('\\1D'..__hex(ca)..'='..__hex(r)) end"
    " return r end end end end\n"
)


def beta_detect(src):
    body = src
    if body.startswith("--"):
        body = body.split("\n", 1)[1] if "\n" in body else body
    body = body.strip()
    return (bool(re.match(r"return\s*\(\s*\{", body))
            and bool(re.search(r"\}\s*\)\s*:\s*\w+\s*\(\s*\.\.\.\s*\)\s*;?\s*$", body)))


def beta_harvest(src, timeout=120):
    """Run the beta under luau with the interpreter factories wrapped so the
    decrypted instruction arrays + constant pools are dumped. Returns
    (tables, payload_lines)."""
    body = src.split("\n", 1)[1].strip() if src.startswith("--") else src.strip()
    m = re.search(r":\s*(\w+)\s*\(\s*\.\.\.\s*\)\s*;?\s*$", body)
    entry = m.group(1) if m else "H"
    tablepart = body[len("return"):m.start()] if m else body[len("return"):]
    factory_keys = sorted(set(re.findall(
        r"(\w+)\s*=\s*function\s*\([^)]*\)\s*return\s+function", body)))
    keylist = "{" + ",".join("'%s'" % k for k in factory_keys) + "}"
    dump = _BETA_DUMP.replace("{'B','w','z'}", keylist) if factory_keys else _BETA_DUMP
    harness = dump + "local __T=" + tablepart + "\n__WRAP(__T)\nreturn __T:" + entry + "(...)\n"
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_mv_beta.luau")
    with open(path, "w", encoding="latin-1") as h:
        h.write(harness)
    try:
        res = subprocess.run([LUAU, "_mv_beta.luau"], cwd=os.path.dirname(path),
                             capture_output=True, text=True, encoding="latin-1", timeout=timeout)
        out = res.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("latin-1", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
    finally:
        if os.path.exists(path):
            os.remove(path)
    tables = {}
    payload = []
    decomp = {}
    for line in out.splitlines():
        if not line.startswith("\1"):
            payload.append(line)
            continue
        row = line[1:]
        if row.startswith("D"):
            body = row[1:]
            if "=" in body:
                ca, ea = body.split("=", 1)
                try:
                    decomp[bytes.fromhex(ca)] = bytes.fromhex(ea)
                except ValueError:
                    pass
            continue
        parts = row.split("|")
        head = parts[0]
        kind, tid = head[0], int(head[2:])
        fields = {}
        for chunk in parts[1:]:
            if "=" not in chunk:
                continue
            k, v = chunk.split("=", 1)
            try:
                k = int(k)
            except ValueError:
                continue
            if not v:
                continue
            m, payloadv = v[0], v[1:]
            if m == "#":
                try:
                    fields[k] = float(payloadv)
                except ValueError:
                    pass
            elif m == "$":
                try:
                    fields[k] = bytes.fromhex(payloadv)
                except ValueError:
                    pass
            elif m == "@":
                fields[k] = ("ref", int(payloadv))
            elif m == "F":
                fields[k] = ("fn",)
            elif m == "b":
                fields[k] = (payloadv == "true")
        tables[tid] = {"kind": kind, "fields": fields}
    return tables, payload, decomp


_BETA_OPCODE_FIELD = 734


def _beta_boxval(tables, tid):
    """A constant box is {[1]=3,[2]=self,[3]=value}; return its real value."""
    node = tables.get(tid)
    if not node:
        return None
    f = node["fields"]
    if f.get(1) == 3.0 and 3 in f:
        return f[3]
    return None


def _beta_str(v):
    if isinstance(v, (bytes, bytearray)) and len(v) >= 1 and all(
            32 <= b < 127 or b in (9, 10, 13) for b in v):
        return bytes(v).decode("latin-1")
    return None


def _beta_opcode_field(tables):
    """Detect the per-build opcode field. Instruction records carry several
    "random big" numeric field keys; group them by field signature, take the
    largest cluster (the dominant instruction shape), and pick the opcode field:
    present across the cluster, >=3 distinct values, with the widest value range
    (opcodes span a larger range than 0-based register/index operands)."""
    from collections import defaultdict
    big = [n for n in tables.values()
           if sum(1 for k in n["fields"] if isinstance(k, int) and k > 500) >= 3]
    if not big:
        return None
    clusters = defaultdict(list)
    for n in big:
        clusters[frozenset(k for k in n["fields"] if isinstance(k, int) and k > 500)].append(n)
    group = max(clusters.values(), key=len)
    vals = defaultdict(list)
    for n in group:
        for k, v in n["fields"].items():
            if isinstance(k, int) and isinstance(v, float) and v.is_integer():
                vals[k].append(int(v))
    best, best_max = None, -1
    for k, vs in vals.items():
        if len(vs) < len(group) * 0.8 or len(set(vs)) < 3:
            continue
        if max(vs) > best_max:
            best, best_max = k, max(vs)
    return best


def beta_devirt(src):
    tables, payload, decomp = beta_harvest(src)
    if not tables:
        return None

    opf = _beta_opcode_field(tables) or _BETA_OPCODE_FIELD
    instr_ids = {tid for tid, n in tables.items() if opf in n["fields"]}
    strings = []
    seen = set()
    for tid, n in tables.items():
        for v in n["fields"].values():
            s = _beta_str(v)
            if s is None and isinstance(v, (bytes, bytearray)):
                s = _beta_str(decomp.get(bytes(v)))
            if (s and s not in seen and any(c.isalpha() for c in s)
                    and "_mv_beta" not in s and not s.startswith("./")
                    and not re.match(r"^\.?[/\\].*:\d+", s)):
                seen.add(s)
                strings.append(s)

    def is_code_array(node):
        f = node["fields"]
        seq = [f[i] for i in range(1, len(f) + 1) if i in f]
        if len(seq) < 1 or len(seq) != len([k for k in f if isinstance(k, int)]):
            return False
        good = sum(1 for e in seq if isinstance(e, tuple) and e[0] == "ref"
                   and e[1] in instr_ids)
        return good >= max(1, len(seq) * 0.6)

    arrays = []
    for tid, n in tables.items():
        if is_code_array(n):
            seq = [n["fields"][i][1] for i in range(1, len(n["fields"]) + 1)
                   if i in n["fields"] and isinstance(n["fields"][i], tuple)
                   and n["fields"][i][0] == "ref"]
            arrays.append((tid, seq))

    from collections import Counter
    keyfreq = Counter()
    for tid in instr_ids:
        for k in tables[tid]["fields"]:
            keyfreq[k] += 1
    operand_fields = [k for k, _ in keyfreq.most_common() if k != opf][:9]

    def fmt_field(v):
        if isinstance(v, float):
            return str(int(v)) if v.is_integer() else str(v)
        if isinstance(v, tuple) and v[0] == "ref":
            bv = _beta_boxval(tables, v[1])
            s = _beta_str(bv) if bv is not None else None
            if s is not None:
                return '"%s"' % s
            if isinstance(bv, float):
                return str(int(bv)) if bv.is_integer() else str(bv)
            return "@%d" % v[1]
        if isinstance(v, tuple) and v[0] == "fn":
            return "<fn>"
        s = _beta_str(v)
        if s is not None:
            return '"%s"' % s
        if isinstance(v, (bytes, bytearray)):
            plain = decomp.get(bytes(v))
            ps = _beta_str(plain) if plain is not None else None
            if ps is not None:
                return '"%s"' % ps
            if plain is not None:
                return "decompress(%dB)" % len(plain)
            return "enc<%dB %s>" % (len(v), bytes(v)[:6].hex())
        return repr(v)

    def disasm_array(seq):
        lines = []
        for pc, iid in enumerate(seq, 1):
            f = tables[iid]["fields"]
            op = f.get(opf)
            op = int(op) if isinstance(op, float) else op
            parts = []
            for k in operand_fields:
                if k in f:
                    parts.append("%d=%s" % (k, fmt_field(f[k])))
            lines.append("  %4d  OP_%-6s %s" % (pc, op, "  ".join(parts)))
        return lines

    at_markers = {"traceback", "find", "userdata", "debug", "getfenv", "info"}

    def array_strings(seq):
        out = set()
        for iid in seq:
            for v in tables[iid]["fields"].values():
                if isinstance(v, tuple) and v[0] == "ref":
                    s = _beta_str(_beta_boxval(tables, v[1]))
                    if s:
                        out.add(s)
                elif isinstance(v, (bytes, bytearray)):
                    s = _beta_str(v) or _beta_str(decomp.get(bytes(v)))
                    if s:
                        out.add(s)
                else:
                    s = _beta_str(v)
                    if s:
                        out.add(s)
        return out

    return {"tables": tables, "payload": payload, "arrays": arrays,
            "strings": strings, "operand_fields": operand_fields,
            "disasm_array": disasm_array, "array_strings": array_strings,
            "at_markers": at_markers, "decomp": decomp, "opcode_field": opf}


def beta_main(base, src):
    print("[*] MoonVeil beta build detected -> devirtualizing")
    info = beta_devirt(src)
    if not info:
        print("[!] beta harvest failed (luau dump empty)")
        return
    arrays = info["arrays"]
    print("[*] harvested {0} decrypted tables | {1} code arrays | {2} strings".format(
        len(info["tables"]), len(arrays), len(info["strings"])))
    dec = info.get("decomp") or {}
    if dec:
        decoded = sorted({_beta_str(v) for v in dec.values() if _beta_str(v)})
        print("[*] LZ-decompressed {0} blob constant(s) -> {1} distinct strings".format(
            len(dec), len(decoded)))

    disasm_path = os.path.join(base, "moonveil_beta_disasm.txt")
    with open(disasm_path, "w", encoding="utf-8") as h:
        h.write("-- MoonVeil beta devirtualizer by 2zvh\n")
        h.write("-- opcode field=%s  operand fields=%s\n\n" % (
            info["opcode_field"], info["operand_fields"]))
        for n, (tid, seq) in enumerate(sorted(arrays, key=lambda a: -len(a[1]))):
            strs = info["array_strings"](seq)
            role = ""
            if len(info["at_markers"] & {s for s in strs}) >= 2:
                role = "   ; ANTI-TAMPER"
            h.write("function fn%d  (%d instructions)%s\n" % (n, len(seq), role))
            for line in info["disasm_array"](seq):
                h.write(line + "\n")
            if strs:
                readable = sorted(s for s in strs if any(c.isalpha() for c in s))
                if readable:
                    h.write("  ; strings: %s\n" % ", ".join(repr(s) for s in readable[:12]))
            h.write("end\n\n")
    print("[*] beta disasm -> " + disasm_path)

    at_arrays = [(tid, seq) for tid, seq in arrays
                 if len(info["at_markers"] & info["array_strings"](seq)) >= 2]
    marker = None
    strings_path = os.path.join(base, "moonveil_beta_strings.txt")
    with open(strings_path, "w", encoding="utf-8") as h:
        h.write("\n".join(info["strings"]))
    print("[*] beta strings -> " + strings_path)

    for s in info["strings"]:
        if _looks_random(s):
            marker = s
            break
    print("[*] anti-tamper: {0} candidate function(s), marker={1}".format(
        len(at_arrays), ('"%s"' % marker) if marker else "?"))
    if info["payload"]:
        print("[*] (payload emitted %d lines at runtime)" % len(info["payload"]))


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    outdir = os.environ.get("MOONVEIL_OUT_DIR") or base
    os.makedirs(outdir, exist_ok=True)
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(base, "moonveil.lua")
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(outdir, "moonveil_decompiled.lua")
    src = open(target, encoding="latin-1").read()

    if not (os.path.isfile(LUAU) or shutil.which(LUAU)):
        print("[!] luau not found (looked for %r) — it is REQUIRED (Moonveil is "
              "deserialized by running it under Luau). Set MOONVEIL_LUAU to the "
              "binary path or put luau on PATH." % LUAU)
        return

    if beta_detect(src):
        beta_main(outdir, src)
        return

    d = detect(src)
    if not d:
        print("[!] could not detect the interpreter")
        return
    print("[*] interpreter: regs={regs} code={code} pc={pc} instr={instr}".format(**d))

    blocks = trace_blocks(src, d)
    const_field = detect_const_field(blocks)
    fl = detect_fields_src(src, d)
    tag_field = fl["tag"]
    if tag_field is None:
        tag_field, _ = detect_fields(blocks)
    opmap, jump_tags = learn_opcodes(blocks, const_field, tag_field, fl["sbx"])
    transitions = learn_transitions(blocks, tag_field, fl["op"])
    print("[*] traced {0} blocks | tag={1} operands={2} sbx={3} op={4}".format(
        len(blocks), tag_field, fl["operands"], fl["sbx"], fl["op"]))
    print("[*] learned {0} opcodes, {1} jumps, {2} macro-keys, {3} transitions".format(
        len(opmap), len(jump_tags), len(fl["keys"]), len(transitions)))

    op_path = os.path.join(outdir, "moonveil_opcodes.txt")
    with open(op_path, "w", encoding="utf-8") as h:
        h.write("-- opcode mapper made by 2zvh\n")
        h.write("tag={0}  operands={1}  sbx={2}  const={3}\n\n".format(
            tag_field, fl["operands"], fl["sbx"], const_field))
        for tag in sorted(opmap):
            h.write("op {0:<5} {1}\n".format(tag, opmap[tag]))
    print("[*] wrote opcode map -> " + op_path)

    if len(fl["operands"]) < 2 or fl["sbx"] is None or not blocks:
        print("[!] field detection incomplete for this build "
              "(operands={0}, sbx={1}, traced {2} blocks) -> can't do a full "
              "opcode devirtualization with the v1.4.x model.".format(
                  fl["operands"], fl["sbx"], len(blocks)))
        print("[*] falling back to string extraction via the deserializer...")
        try:
            res, err = mauto.process(target, 60)
        except (RuntimeError, OSError) as e:
            res, err = None, str(e)
        if res:
            spath = os.path.join(outdir, "moonveil_strings.txt")
            with open(spath, "w", encoding="utf-8") as h:
                h.write("-- string extractor (fallback) made by 2zvh\n")
                h.write("\n".join(res["strings"]))
            print("[*] recovered {0} strings ({1} proto tables) -> {2}".format(
                len(res["strings"]), res["tables"], spath))
        else:
            print("[!] string extraction failed: " + (err or "unknown"))
        return

    protos = static_protos(src, d, fl, opmap, transitions)
    user_protos = [p for p in protos if p["is_user"]]
    opmap2, settable = detect_static_ops(protos, opmap)
    try:
        behavior = run_behavior(src)
    except (RuntimeError, OSError):
        behavior = []
    def _is_runtime_noise(n, a):
        if n != "error":
            return False
        msg = a[0] if a and isinstance(a[0], str) else ""
        return bool(re.search(r"_mv_dec|\.luau|argument|overflow|attempt to|out of range|nil", msg))
    behavior = [(n, a) for n, a in behavior if not _is_runtime_noise(n, a)]
    print("[*] behavioral trace: {0} high-level calls captured".format(len(behavior)))
    disasm_path = os.path.join(outdir, "moonveil_disasm.txt")
    with open(disasm_path, "w", encoding="utf-8") as h:
        h.write("-- disassembler made by 2zvh\n\n")
        for p in protos:
            kids = (" children=%s" % p["children"]) if p.get("children") else ""
            h.write("function proto_{0}  ({1} instructions){2}\n".format(
                p["index"], len(p["code"]), kids))
            h.write(disasm_proto(p, opmap, jump_tags) + "\nend\n\n")
    print("[*] static disasm: {0} protos ({1} user) -> {2}".format(
        len(protos), len(user_protos), disasm_path))

    struct_path = os.path.join(outdir, "moonveil_structured.lua")
    with open(struct_path, "w", encoding="utf-8") as h:
        h.write(reconstruct_clean(protos, opmap2, settable, jump_tags, behavior,
                                  blocks=blocks, tag_field=tag_field, fl=fl, opmap=opmap))
    print("[*] clean reconstruction (table literals + call chains) -> " + struct_path)

    sections = []
    for bid in sorted(blocks):
        stmts = [s for s in lift_block(blocks[bid], const_field) if not is_noise(s)]
        named = any(re.search(r"(?:^|[^.\w])([a-z]\w*)\(", s) and " = " not in s for s in stmts)
        if stmts:
            sections.append((bid, stmts, named))

    user = [(b, s) for b, s, n in sections if n] or [(b, s) for b, s, n in sections]
    out_lines = []
    for bid, stmts in user:
        out_lines.extend(stmts)
        out_lines.append("")
    text = "\n".join(out_lines).strip() if out_lines else "-- nothing reconstructed"

    recon = reconstruct_source(user_protos)
    prelude = "\n".join("local %s: any = nil" % g for g in _unknown_globals(recon.splitlines()))
    raw = text.replace("]==]", "] ==]")
    with open(out_path, "w", encoding="utf-8") as h:
        if prelude:
            h.write(prelude + "\n\n")
        h.write(recon)
        h.write("\n\n--[==[ register-level reconstruction (raw, best-effort; reference only)\n")
        h.write(raw + "\n")
        h.write("]==]\n")
    loaders = sum(len(reconstruct_proto(p["code"])[0]) for p in user_protos)
    print("[*] reconstruction ({0} runnable loader line(s)) -> {1}".format(loaders, out_path))


if __name__ == "__main__":
    main()
