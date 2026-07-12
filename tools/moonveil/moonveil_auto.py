import os
import re
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
    if type(root) ~= "table" then return end
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


def find_deserializer(src):
    candidates = []
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\(\s*\1\s*\)", src):
        var, func = m.group(1), m.group(2)
        if var == func:
            continue
        if re.search(r"\blocal\s+" + re.escape(func) + r"\s*=\s*\(?\s*function\b", src):
            candidates.append((var, func, m.start()))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[2])
    return candidates[0][0], candidates[0][1]


def build_harness(src, var, func):
    wrapper = ("do local __r = {0}; {0} = function(o) local v = __r(o); "
               "__MV_DUMP(v); return v end end\n").format(func)
    pat = re.compile(r"(\b" + re.escape(var) + r"\s*=\s*" + re.escape(func) + r"\(\s*" + re.escape(var) + r"\s*\))")
    body = pat.sub(wrapper + r"\1", src, count=1)
    return DUMPER + "\n" + body


def run_luau(source, timeout):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_mv_auto.luau")
    with open(path, "w", encoding="latin-1") as h:
        h.write(source)
    try:
        res = subprocess.run([LUAU, "_mv_auto.luau"], cwd=os.path.dirname(path),
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
        try:
            tid = int(parts[0][1:])
        except ValueError:
            continue
        fields = {}
        for chunk in parts[1:]:
            if "=" not in chunk:
                continue
            key, val = chunk.split("=", 1)
            try:
                key = int(key)
            except ValueError:
                continue
            if not val:
                continue
            mark, payload = val[0], val[1:]
            if mark == "$":
                try:
                    fields[key] = bytes.fromhex(payload)
                except ValueError:
                    pass
            elif mark == "@":
                fields[key] = ("ref", int(payload))
            elif mark == "#":
                fields[key] = float(payload)
        tables[tid] = fields
    return tables


def deref(value, tables):
    if isinstance(value, tuple) and value[0] == "ref":
        return tables.get(value[1])
    return value


def as_sequence(node, tables):
    if not isinstance(node, dict):
        return None
    i, out = 1, []
    while i in node:
        out.append(deref(node[i], tables))
        i += 1
    if len(out) < 1 or len(node) != len(out):
        return None
    return out


def looks_like_instruction(node):
    if not isinstance(node, dict):
        return False
    ints = [k for k in node if isinstance(k, int)]
    return len(ints) >= 6


def find_code_arrays(tables):
    arrays = []
    for node in tables.values():
        seq = as_sequence(node, tables)
        if not seq:
            continue
        good = sum(1 for e in seq if looks_like_instruction(e))
        if good >= max(1, len(seq) * 0.6):
            arrays.append(seq)
    return arrays


def string_fields(arrays):
    counts = {}
    for seq in arrays:
        for instr in seq:
            if not isinstance(instr, dict):
                continue
            for k, v in instr.items():
                if isinstance(v, (bytes, bytearray)):
                    counts[k] = counts.get(k, 0) + 1
    return [k for k, _ in sorted(counts.items(), key=lambda x: -x[1])]


CLEAN = set(range(48, 58)) | set(range(65, 91)) | set(range(97, 123))
CLEAN |= set(b" _-./:%()'\",!?=#@&+;[]<>*\n\r")


def is_text(data):
    if len(data) < 3:
        return False
    if not all(32 <= b < 127 or b in (10, 13) for b in data):
        return False
    letters = sum(1 for b in data if 65 <= b <= 90 or 97 <= b <= 122)
    if letters == 0:
        return False
    clean = sum(1 for b in data if b in CLEAN)
    return clean >= len(data) * 0.85 and letters * 2 >= len(data)


def xor_repeat(cipher, key):
    if not key:
        return cipher
    return bytes(cipher[i] ^ key[i % len(key)] for i in range(len(cipher)))


def gather_pairs(arrays, field, forward):
    pairs = []
    for seq in arrays:
        for i in range(len(seq) - 1):
            a = seq[i] if isinstance(seq[i], dict) else {}
            b = seq[i + 1] if isinstance(seq[i + 1], dict) else {}
            ka = a.get(field)
            kb = b.get(field)
            if isinstance(ka, (bytes, bytearray)) and isinstance(kb, (bytes, bytearray)):
                if forward:
                    pairs.append((bytes(kb), bytes(ka)))
                else:
                    pairs.append((bytes(ka), bytes(kb)))
    return pairs


ANCHORS = [
    "GetService", "FindFirstChild", "FindFirstChildOfClass", "userdata",
    "traceback", "gmatch", "FireServer", "Humanoid", "workspace", "Players",
    "LocalPlayer", "WaitForChild", "GetChildren", "Character", "Parent",
    "string", "table", "GetState", "Position", "Activate",
]
ANCHOR_BYTES = [w.encode() for w in ANCHORS]
ANCHOR_SET = set(ANCHORS)


def salt_votes(pairs):
    votes = {}
    for cipher, keymat in pairs:
        for w in ANCHOR_BYTES:
            if len(w) != len(cipher) or len(cipher) < 5:
                continue
            x = bytes(a ^ b for a, b in zip(cipher, w))
            for length in range(1, min(len(x), 7) + 1):
                tail = len(x) - length
                if 2 <= tail <= len(keymat) and x[length:] == keymat[:tail]:
                    votes[x[:length]] = votes.get(x[:length], 0) + 1
    for salt, count in cyclic_salt_votes(pairs).items():
        votes[salt] = votes.get(salt, 0) + count
    return votes


def cyclic_salt_votes(pairs, max_salt=8):
    """Derive the salt from anchor words while honoring the cyclic key.

    The Moonveil string cipher is ``plaintext = xor(cipher, salt + keymat)``
    where the ``salt + keymat`` key is *repeated cyclically* over the whole
    ciphertext. When a decoded string is longer than ``salt + keymat`` the key
    wraps back to the salt, so the salt bytes appear again past the keymat
    region. For every known anchor word of the same length as a ciphertext we
    reconstruct the full required key (``cipher xor anchor``) and accept it only
    if the ``keymat`` sits right after an ``L``-byte prefix and the whole key is
    periodic with period ``L + len(keymat)`` -> then the salt is that prefix.
    """
    votes = {}
    for cipher, keymat in pairs:
        if len(cipher) < 3 or not keymat:
            continue
        for w in ANCHOR_BYTES:
            if len(w) != len(cipher):
                continue
            key = bytes(cipher[i] ^ w[i] for i in range(len(w)))
            upper = min(max_salt, len(key) - len(keymat))
            for length in range(1, upper + 1):
                period = length + len(keymat)
                span = min(len(keymat), len(key) - length)
                if key[length:length + span] != keymat[:span]:
                    continue
                if all(key[i] == key[i % period] for i in range(len(key))):
                    votes[key[:length]] = votes.get(key[:length], 0) + 1
    return votes


def score_salt(pairs, salt):
    anchors = set()
    good = 0
    for cipher, keymat in pairs:
        pt = xor_repeat(cipher, salt + keymat)
        if is_text(pt):
            good += 1
            s = pt.decode("utf-8", "replace")
            if s in ANCHOR_SET:
                anchors.add(s)
    return len(anchors), good


def freq_salt(pairs):
    best = None
    for length in range(1, 9):
        salt = bytearray()
        for j in range(length):
            column = [c[j] for c, _ in pairs if len(c) > j]
            if not column:
                salt.append(0)
                continue
            pick, score = 0, -1
            for s in range(256):
                cnt = 0
                for x in column:
                    y = x ^ s
                    if 97 <= y <= 122:
                        cnt += 3
                    elif y == 32 or y == 47 or 48 <= y <= 57:
                        cnt += 2
                    elif 65 <= y <= 90 or y == 95 or y == 58 or y == 46:
                        cnt += 1
                if cnt > score:
                    score, pick = cnt, s
            salt.append(pick)
        salt = bytes(salt)
        good = sum(1 for c, k in pairs if is_text(xor_repeat(c, salt + k)))
        if best is None or good > best[0]:
            best = (good, salt)
    return best[1] if best else b""


def parse_lua_str(lit):
    body = lit[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            e = body[i + 1]
            simple = {"n": 10, "t": 9, "r": 13, "a": 7, "b": 8, "f": 12, "v": 11,
                      "\\": 92, '"': 34, "'": 39, "0": 0}
            if e == "x" and i + 3 < len(body):
                out.append(int(body[i + 2:i + 4], 16))
                i += 4
            elif e.isdigit():
                j, num = i + 1, ""
                while j < len(body) and body[j].isdigit() and len(num) < 3:
                    num += body[j]
                    j += 1
                out.append(int(num) & 0xFF)
                i = j
            elif e in simple:
                out.append(simple[e])
                i += 2
            else:
                out.append(ord(e) & 0xFF)
                i += 2
        else:
            out.append(ord(c) & 0xFF)
            i += 1
    return bytes(out)


def extract_salts(src):
    pat = r"\w+\(('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"),('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")\)\.\."
    salts = []
    for m in re.finditer(pat, src):
        try:
            a, b = parse_lua_str(m.group(1)), parse_lua_str(m.group(2))
        except (ValueError, IndexError):
            continue
        if 1 <= len(a) <= 12 and b:
            salt = bytes(a[i] ^ b[i % len(b)] for i in range(len(a)))
            if salt not in salts:
                salts.append(salt)
    return salts


def recover_strings(tables, src_salts=()):
    arrays = find_code_arrays(tables)
    fields = string_fields(arrays)
    seen = set()
    plain = []

    def add(blob, sink):
        if isinstance(blob, (bytes, bytearray)) and is_text(blob):
            s = bytes(blob).decode("utf-8", "replace")
            if s not in seen:
                seen.add(s)
                sink.append(s)

    for seq in arrays:
        for instr in seq:
            if isinstance(instr, dict):
                for v in instr.values():
                    add(v, plain)

    best = None
    for field in fields[:6]:
        for forward in (True, False):
            pairs = gather_pairs(arrays, field, forward)
            if len(pairs) < 1:
                continue
            candidates = list(salt_votes(pairs).keys())
            candidates.append(freq_salt(pairs))
            candidates.extend(src_salts)
            for salt in candidates:
                if not salt:
                    continue
                hits, good = score_salt(pairs, salt)
                rank = (hits, good)
                if best is None or rank > best[0]:
                    best = (rank, field, forward, salt, pairs)

    decrypted = []
    info = None
    if best:
        rank, field, forward, salt, pairs = best
        for cipher, keymat in pairs:
            add(xor_repeat(cipher, salt + keymat), decrypted)
        info = {"field": field, "forward": forward, "salt": salt,
                "anchors": rank[0], "matches": rank[1]}
    return plain + decrypted, info


def process(path, timeout):
    src = open(path, encoding="latin-1").read()
    found = find_deserializer(src)
    if not found:
        return None, "could not locate the deserializer pattern"
    var, func = found
    out = run_luau(build_harness(src, var, func), timeout)
    tables = parse_dump(out)
    if not tables:
        return None, "no prototypes harvested (luau ran but produced no dump)"
    strings, info = recover_strings(tables, extract_salts(src))
    return {"strings": strings, "info": info, "tables": len(tables), "deser": func}, None


def iter_targets(arg):
    if os.path.isdir(arg):
        for root, _, files in os.walk(arg):
            for f in files:
                if f.endswith((".lua", ".luau")):
                    yield os.path.join(root, f)
    elif os.path.isfile(arg):
        yield arg


def main():
    args = sys.argv[1:]
    if not args:
        args = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "moonveil.lua")]
    targets = []
    for a in args:
        targets.extend(iter_targets(a))
    if not targets:
        print("no input files found")
        return
    for path in targets:
        print("[*] " + os.path.basename(path))
        try:
            result, err = process(path, 60)
        except RuntimeError as e:
            print("    error: " + str(e))
            continue
        if err:
            print("    skipped: " + err)
            continue
        info = result["info"]
        out_path = os.path.splitext(path)[0] + "_strings.txt"
        with open(out_path, "w", encoding="utf-8") as h:
            h.write("-- string extractor made by 2zvh\n")
            h.write("\n".join(result["strings"]))
        if info:
            print("    deserializer={0}  field={1}  dir={2}  salt={3}  anchors={4}  protos={5}".format(
                result["deser"], info["field"], "next" if info["forward"] else "prev",
                info["salt"].hex(), info["anchors"], result["tables"]))
        print("    {0} strings -> {1}".format(len(result["strings"]), os.path.basename(out_path)))


if __name__ == "__main__":
    main()
