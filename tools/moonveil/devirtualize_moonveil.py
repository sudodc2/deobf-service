import os
import shutil
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")


def _resolve_luau():
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
SALT = b"S+"

KBX = 50053
KC = 28201
F_CODE = 36476

DUMPER = r"""
local __seen, __n, __emitted = {}, 0, {}
local function __id(t)
    if __seen[t] then return __seen[t] end
    __n = __n + 1
    __seen[t] = __n
    return __n
end
local function __hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end
local function __emit(t)
    local row = {"T" .. __id(t)}
    for k, v in pairs(t) do
        if type(k) == "number" then
            local tv = type(v)
            if tv == "number" then
                row[#row + 1] = k .. "=#" .. tostring(v)
            elseif tv == "string" then
                row[#row + 1] = k .. "=$" .. __hex(v)
            elseif tv == "table" then
                row[#row + 1] = k .. "=@" .. __id(v)
            end
        end
    end
    print(table.concat(row, "|"))
end
function __MV_DUMP(root)
    local stack, queued = {root}, {[root] = true}
    while #stack > 0 do
        local t = table.remove(stack)
        if not __emitted[t] then
            __emitted[t] = true
            __emit(t)
        end
        for _, v in pairs(t) do
            if type(v) == "table" and not queued[v] then
                queued[v] = true
                stack[#stack + 1] = v
            end
        end
    end
end
"""


def build_harness(src):
    hook = ("local __mv_re = re_\n"
            "re_ = function(oc) local r = __mv_re(oc); if type(r) == \"table\" then __MV_DUMP(r) end; return r end\n")
    body = src.replace("local de = (function(Xc, wf)", hook + "local de = (function(Xc, wf)", 1)
    return DUMPER + "\n" + body


def run_luau(source, timeout):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_mv_dump.luau")
    with open(path, "w", encoding="latin-1") as h:
        h.write(source)
    try:
        res = subprocess.run([LUAU, "_mv_dump.luau"], cwd=os.path.dirname(path),
                             capture_output=True, text=True, encoding="latin-1", timeout=timeout)
        out = res.stdout or ""
    except FileNotFoundError:
        raise RuntimeError("luau was not found on PATH")
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("latin-1", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
    finally:
        if os.path.exists(path):
            os.remove(path)
    return out


def parse_dump(text):
    tables = {}
    for line in text.splitlines():
        if not line.startswith("T") or "|" not in line:
            continue
        parts = line.split("|")
        tid = int(parts[0][1:])
        fields = {}
        for chunk in parts[1:]:
            if "=" not in chunk:
                continue
            key, val = chunk.split("=", 1)
            key = int(key)
            mark = val[0]
            if mark == "$":
                fields[key] = bytes.fromhex(val[1:])
            elif mark == "@":
                fields[key] = ("ref", int(val[1:]))
            elif mark == "#":
                fields[key] = float(val[1:])
        tables[tid] = fields
    return tables


def deref(value, tables):
    if isinstance(value, tuple) and value[0] == "ref":
        return tables.get(value[1])
    return value


def code_of(node, tables):
    body = deref(node.get(F_CODE), tables)
    if not isinstance(body, dict):
        return []
    out, i = [], 1
    while i in body:
        out.append(deref(body[i], tables))
        i += 1
    return out


def xor_repeat(cipher, key):
    return bytes(cipher[i] ^ key[i % len(key)] for i in range(len(cipher)))


def is_text(data):
    if len(data) < 2:
        return False
    if not all(32 <= b < 127 or b in (9, 10, 13) for b in data):
        return False
    letters = sum(1 for b in data if 65 <= b <= 90 or 97 <= b <= 122 or b == 95)
    return letters * 2 >= len(data)


def field_bytes(instr, key):
    v = instr.get(key) if isinstance(instr, dict) else None
    return bytes(v) if isinstance(v, (bytes, bytearray)) else None


def collect_strings(tables):
    seen = set()
    ordered = []

    def add(blob):
        if isinstance(blob, (bytes, bytearray)) and is_text(blob):
            s = bytes(blob).decode("utf-8", "replace")
            if s not in seen:
                seen.add(s)
                ordered.append(s)

    for node in tables.values():
        if not isinstance(node, dict) or F_CODE not in node:
            continue
        code = code_of(node, tables)
        for i in range(len(code)):
            for fk in (KBX, KC):
                cur = field_bytes(code[i], fk)
                if cur and is_text(cur):
                    add(cur)
                if i + 1 < len(code):
                    nxt = field_bytes(code[i + 1], fk)
                    if cur is not None and nxt is not None:
                        add(xor_repeat(nxt, SALT + cur))
    return ordered


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(base, "moonveil.lua")
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(base, "moonveil_strings.txt")
    src = open(target, encoding="latin-1").read()

    tables = parse_dump(run_luau(build_harness(src), 60))
    if not tables:
        print("[!] failed to harvest prototypes")
        return

    strings = collect_strings(tables)
    for s in strings:
        print(s)
    with open(out_path, "w", encoding="utf-8") as h:
        h.write("\n".join(strings))


if __name__ == "__main__":
    main()
