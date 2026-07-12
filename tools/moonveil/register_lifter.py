import re

MIN_PROTO_SIZE = 120

_ARITY1 = {"tostring", "tonumber", "type", "typeof"}


def _should_attempt(code, entries):
    if not code or not entries:
        return False
    if len(code) < MIN_PROTO_SIZE:
        return False
    return any(e.get("regs") for e in entries)


def _lua_string(b):
    b = bytes(b)
    printable = sum(1 for x in b if 32 <= x <= 126 or x in (9, 10, 13))
    truncate = len(b) > 24 and printable < len(b) * 0.75
    data = b[:24] if truncate else b
    out = []
    for byte in data:
        if byte == 0x5C:
            out.append("\\\\")
        elif byte == 0x22:
            out.append('\\"')
        elif byte == 0x0A:
            out.append("\\n")
        elif byte == 0x09:
            out.append("\\t")
        elif byte == 0x0D:
            out.append("\\r")
        elif 32 <= byte <= 126:
            out.append(chr(byte))
        else:
            out.append("\\%03d" % byte)
    if truncate:
        out.append("...[%d bytes]" % len(b))
    return '"' + "".join(out) + '"'


def sym_from_repr(rep):
    if rep is None:
        return None
    if rep.startswith("$"):
        try:
            b = bytes.fromhex(rep[1:])
        except ValueError:
            return {"kind": "unknown"}
        return {"kind": "str", "expr": _lua_string(b),
                "text": b.decode("utf-8", "replace")}
    if rep.startswith("#"):
        return {"kind": "num", "expr": rep[1:]}
    if rep == "fn":
        return {"kind": "fn"}
    if rep == "tb":
        return {"kind": "table"}
    if rep.startswith("b"):
        return {"kind": "bool", "expr": "true" if rep[1:].lower().startswith("t") else "false"}
    return {"kind": "unknown"}


def _longest_string_run(regs):
    best, cur = [], []
    for r in sorted(regs):
        sv = sym_from_repr(regs[r])
        ok = sv and sv["kind"] == "str" and "\ufffd" not in sv["text"]
        if ok and (not cur or r == cur[-1][0] + 1):
            cur.append((r, sv))
        elif ok:
            cur = [(r, sv)]
        else:
            cur = []
        if len(cur) > len(best):
            best = list(cur)
    return best


def recover_array_literal(entries):
    best = []
    for e in entries:
        run = _longest_string_run(e.get("regs", {}))
        if len(run) > len(best):
            best = run
    if len(best) < 3:
        return None
    return "{ %s }" % ", ".join(sv["expr"] for _, sv in best)


def recover_facts(code, entries, ctx):
    if not _should_attempt(code, entries):
        return {}
    facts = {}
    arr = recover_array_literal(entries)
    if arr:
        facts["iterable"] = arr
    return facts


_NS_GLOBALS = {"game", "workspace", "Enum", "Instance", "string", "table",
               "math", "os", "buffer", "coroutine", "task", "Players", "bit32"}

_STRING_METHODS = {"find", "match", "gmatch", "gsub", "sub", "format", "byte",
                   "char", "rep", "lower", "upper", "len", "split", "reverse"}

_SERVICE_METHODS = {"Base64Encode", "Base64Decode", "CompressBuffer",
                    "DecompressBuffer", "ComputeStringHash", "ComputeBufferHash",
                    "GetDecompressedBufferSize", "SetItem", "GetItem", "RemoveItem",
                    "UpdateItem", "GetAsync", "SetAsync", "UpdateAsync",
                    "IncrementAsync", "RemoveAsync", "JSONEncode", "JSONDecode",
                    "GenerateGUID", "RequestAsync", "GetService", "HttpGet",
                    "HttpGetAsync"}

_GLOBALS = {"print", "warn", "error", "pairs", "ipairs", "next", "type", "typeof",
            "tostring", "tonumber", "pcall", "xpcall", "select", "rawget", "rawset",
            "rawequal", "rawlen", "setmetatable", "getmetatable", "assert", "unpack",
            "require", "loadstring", "game", "workspace", "buffer", "math", "table",
            "string", "os", "task", "bit32", "coroutine", "Instance", "Enum",
            "Players", "tick", "wait", "spawn", "delay", "collectgarbage", "newproxy"}


def _rexpr(regs_expr, r):
    e = regs_expr.get(r)
    return e if e else "nil"


def _snap_name(rep):
    sv = sym_from_repr(rep)
    if sv is None:
        return None
    return sv.get("expr")


def learn_call_keys(code, entries, opmap2):
    from collections import Counter
    code_by_pc = {ins["pc"]: ins for ins in code}
    kb = Counter()
    call_A = []
    for i in range(len(entries) - 1):
        e, nxt = entries[i], entries[i + 1]
        ins = code_by_pc.get(e["pc"], {})
        if opmap2.get(ins.get("tag")) != "CALL":
            continue
        before, after = e.get("regs", {}), nxt.get("regs", {})
        writes = [r for r in after if before.get(r) != after.get(r)]
        A, B = ins.get("A"), ins.get("B")
        if A is not None:
            call_A.append(A)
        if writes and B is not None:
            base = min(writes)
            if 0 <= base <= 40:
                kb[B ^ base] += 1
    key_B = kb.most_common(1)[0][0] if kb else None
    ka = Counter()
    if key_B is not None:
        for i in range(len(entries) - 1):
            e = entries[i]
            ins = code_by_pc.get(e["pc"], {})
            if opmap2.get(ins.get("tag")) != "CALL":
                continue
            A, B = ins.get("A"), ins.get("B")
            if A is None or B is None:
                continue
            base = B ^ key_B
            before = e.get("regs", {})
            if not (0 <= base <= 40) or base not in before:
                continue
            top = base
            while (top + 1) in before:
                top += 1
            lo = min(before)
            if top - base <= 5 and lo >= base:
                ka[A ^ (top - base + 1)] += 1
    key_A = ka.most_common(1)[0][0] if ka else None
    return key_B, key_A


def lift_from_trace(code, entries, ctx):
    return _lift_core(code, entries, ctx)[0]


def _cmp_op(subj, const, cond_true):
    try:
        if subj > const:
            return ">" if cond_true else "<="
        if subj < const:
            return "<" if cond_true else ">="
    except TypeError:
        pass
    return "==" if cond_true else "~="


def _lift_core(code, entries, ctx):
    opmap = (ctx or {}).get("opmap") or {}
    opmap2 = (ctx or {}).get("opmap2") or opmap
    jump_tags = (ctx or {}).get("jump_tags") or set()
    key_B = (ctx or {}).get("key_B")
    key_A = (ctx or {}).get("key_A")
    if key_B is None or key_A is None:
        key_B, key_A = learn_call_keys(code, entries, opmap2)
    code_by_pc = {ins["pc"]: ins for ins in code}
    regs_expr = {}
    method = {}
    method_meta = {}
    services = set()
    last_service = None
    prev_ident = None
    pending_method = None
    lines = []
    pc_lines = {}
    cond_map = {}
    cond_expr = {}
    nvar = [0]

    def snap_expr(rep):
        sv = sym_from_repr(rep)
        if sv is None:
            return None
        return sv.get("expr")

    def fresh_var():
        nvar[0] += 1
        return "v" + str(nvar[0])

    def call_frame(ins, regs):
        B, A = ins.get("B"), ins.get("A")
        if B is None or A is None or key_B is None or key_A is None:
            return None
        base = B ^ key_B
        b_lua = A ^ key_A
        if b_lua >= 1:
            nargs = b_lua - 1
        else:
            top = base
            while (top + 1) in regs:
                top += 1
            nargs = min(top - base, 12)
        if 0 <= base <= 250 and 0 <= nargs <= 40:
            return base, nargs
        return None

    reused = set()
    for i in range(1, len(entries)):
        e = entries[i - 1]
        ins = code_by_pc.get(e["pc"], {})
        if opmap2.get(ins.get("tag"), opmap.get(ins.get("tag"))) != "CALL":
            continue
        fr = call_frame(ins, e.get("regs", {}))
        if fr:
            base, nargs = fr
            for r in range(base + 1, base + 1 + nargs):
                reused.add(r)

    for i in range(1, len(entries)):
        prev_e, cur_e = entries[i - 1], entries[i]
        prev_regs, cur_regs = prev_e.get("regs", {}), cur_e.get("regs", {})
        pc = prev_e["pc"]
        ins = code_by_pc.get(pc, {})
        op = opmap2.get(ins.get("tag"), opmap.get(ins.get("tag"), "?"))
        K = ins.get("K")
        writes = [r for r, rep in cur_regs.items() if prev_regs.get(r) != rep]

        is_ident = isinstance(K, str) and K.isidentifier()
        is_self = (len(writes) == 2 and sorted(writes)[1] == sorted(writes)[0] + 1)
        mname = K if is_ident else (prev_ident if op != "CALL" else None)
        if op in ("GETGLOBAL", "GETTABLE", "SELF") and is_ident and K not in _GLOBALS:
            pending_method = K

        if ins.get("tag") in jump_tags and (ins.get("sBx") or 0) > 0 and pc not in cond_map:
            A2 = ins.get("A")
            ea = cond_expr.get(A2) or regs_expr.get(A2)
            cond_true = cur_e["pc"] != (pc + ins["sBx"] + 1)
            eq = "==" if cond_true else "~="
            if ea and "(" in ea and isinstance(K, str) and K:
                cond_map[pc] = "%s %s %s" % (ea, eq, _lua_string(K.encode("utf-8", "replace")))
            elif ea and "(" in ea and isinstance(K, (int, float)):
                cond_map[pc] = "%s %s %s" % (ea, eq, K)
            elif ea and "(" in ea:
                cond_map[pc] = ea if cond_true else "not (%s)" % ea

        if op != "CALL" and is_self and mname:
            r = min(writes)
            method_meta[r] = (regs_expr.get(r), mname)
            regs_expr[r] = None
            method[r] = True
        elif op == "GETGLOBAL" and len(writes) == 1:
            r = writes[0]
            if is_ident and K not in _GLOBALS:
                method_meta[r] = (None, K)
                regs_expr[r] = None
                method[r] = True
            else:
                regs_expr[r] = K if isinstance(K, str) else None
                method[r] = False
        elif op in ("LOADK", "LOADN") and len(writes) == 1:
            r = writes[0]
            regs_expr[r] = snap_expr(cur_regs[r])
            cond_expr.pop(r, None)
            method.pop(r, None)
        elif op == "NEWTABLE" and len(writes) == 1:
            regs_expr[writes[0]] = "{}"
            method.pop(writes[0], None)
        elif op != "CALL" and len(writes) >= 1 and is_ident:
            r = min(writes)
            if K in _GLOBALS:
                regs_expr[r] = K
                method[r] = False
            else:
                method_meta[r] = (None, K)
                regs_expr[r] = None
                method[r] = True
        elif op == "CALL" and key_B is not None and key_A is not None:
            _ls = len(lines)
            B, A = ins.get("B"), ins.get("A")
            if B is None or A is None:
                prev_ident = K if is_ident else None
                continue
            base = B ^ key_B
            b_lua = A ^ key_A
            if b_lua >= 1:
                nargs = b_lua - 1
            else:
                top = base
                while (top + 1) in prev_regs:
                    top += 1
                nargs = min(top - base, 12)
            if not (0 <= base <= 250 and 0 <= nargs <= 40):
                continue
            def argexpr(r):
                if regs_expr.get(r):
                    return regs_expr[r]
                sv = sym_from_repr(prev_regs.get(r))
                if sv and sv.get("expr"):
                    return sv["expr"]
                if sv and sv["kind"] in ("fn", "table"):
                    return "obj" if sv["kind"] == "table" else "fn"
                return "nil"

            arg_regs = list(range(base + 1, base + 1 + nargs))
            result_expr = None
            meta = method_meta.get(base)
            if meta is None and pending_method and arg_regs:
                meta = (None, pending_method)
            if meta and arg_regs:
                recv, mname = meta
                if not recv or recv == "nil":
                    a0 = argexpr(arg_regs[0]) if arg_regs else "obj"
                    if a0 not in ("nil", "obj"):
                        recv = a0
                    elif last_service and mname not in _STRING_METHODS:
                        recv = last_service
                    else:
                        recv = "obj"
                if (mname in _SERVICE_METHODS and last_service
                        and (recv in ("obj", "nil") or re.match(r"^v\d+$", recv or ""))):
                    recv = last_service
                if recv == "nil":
                    recv = "obj"
                if recv.startswith('"'):
                    recv = "(%s)" % recv
                rest = [argexpr(r) for r in arg_regs[1:]]
                call = "%s:%s(%s)" % (recv, mname, ", ".join(rest))
                if mname == "GetService" and rest and rest[0].startswith('"'):
                    svc = rest[0].strip('"')
                    if svc.isidentifier():
                        if svc not in services:
                            services.add(svc)
                            lines.append("local %s = %s" % (svc, call))
                            call = None
                        else:
                            call = None
                        result_expr = svc
                        last_service = svc
            else:
                fname = regs_expr.get(base) or _snap_name(prev_regs.get(base)) or "fn"
                args = [argexpr(r) for r in arg_regs]
                if fname == "fn" and len(args) == 1 and args[0].startswith('"'):
                    fname = "print"
                if fname in _ARITY1 and len(args) > 1:
                    args = args[:1]
                if fname == "buffer" and len(args) == 1:
                    if args[0].startswith('"'):
                        fname = "buffer.fromstring"
                    elif re.match(r"^-?[\d.]", args[0]):
                        fname = "buffer.create"
                call = "%s(%s)" % (fname, ", ".join(args))
            if call is not None:
                if result_expr is None and base in reused and "(" in call:
                    var = fresh_var()
                    lines.append("local %s = %s" % (var, call))
                    result_expr = var
                else:
                    lines.append(call)
            if pc not in pc_lines and len(lines) > _ls:
                pc_lines[pc] = list(lines[_ls:])
            regs_expr[base] = result_expr
            cond_expr[base] = call if call is not None else result_expr
            for r in list(cond_expr):
                if r > base:
                    cond_expr.pop(r, None)
            pending_method = None
            method.pop(base, None)
            method_meta.pop(base, None)
            for r in list(regs_expr):
                if r > base:
                    regs_expr.pop(r, None)
                    method.pop(r, None)
                    method_meta.pop(r, None)
        prev_ident = K if is_ident else None
    return lines, pc_lines, cond_map


def lift_structured(code, entries, ctx, jump_tags):
    opmap2 = (ctx or {}).get("opmap2") or (ctx or {}).get("opmap") or {}
    ctx = dict(ctx or {})
    ctx.setdefault("jump_tags", jump_tags)
    _flat, pc_lines, cond_map = _lift_core(code, entries, ctx)
    n = len(code)
    iterable = recover_array_literal(entries)
    out = []

    def opname(ins):
        return opmap2.get(ins["tag"], "OP_%s" % ins["tag"])

    def is_jump(ins):
        return ins["tag"] in jump_tags and ins.get("sBx")

    def is_forloop(ins):
        return opname(ins) == "FORLOOP"

    def target_idx(ins):
        t = ins["pc"] + (ins.get("sBx") or 0) + 1
        for k, c in enumerate(code):
            if c["pc"] >= t:
                return k
        return n

    used_iter = [False]

    def emit(i, j, ind, depth=0):
        if depth > 60:
            return
        loops = {}
        for k in range(i, j):
            if is_forloop(code[k]) and code[k].get("sBx") and code[k]["sBx"] < 0:
                loops[target_idx(code[k])] = k
        while i < j:
            ins = code[i]
            pc = ins["pc"]
            if i in loops and loops[i] < j:
                end = loops[i]
                it = (iterable if (iterable and not used_iter[0]) else "...")
                used_iter[0] = True
                out.append(ind + "for _, v in pairs(%s) do" % it)
                emit(i + 1, end, ind + "    ", depth + 1)
                out.append(ind + "end")
                i = end + 1
                continue
            if is_jump(ins) and ins["sBx"] > 0:
                tgt = target_idx(ins)
                cond = cond_map.get(pc, "COND")
                out.append(ind + "if %s then" % cond)
                emit(i + 1, min(tgt, j), ind + "    ", depth + 1)
                out.append(ind + "end")
                i = tgt if tgt > i else i + 1
                continue
            if pc in pc_lines:
                for ln in pc_lines[pc]:
                    sep = ";" if ln[:1] in '("' else ""
                    out.append(ind + sep + ln)
            i += 1

    emit(0, n, "")
    for idx, ln in enumerate(out):
        m = re.match(r"^(\s*)local (\w+) = (.+)$", ln)
        if m:
            name, expr = m.group(2), m.group(3)
            rest = "\n".join(out[idx + 1:])
            if not re.search(r"(?<![.:\w])" + name + r"\b", rest):
                out[idx] = m.group(1) + expr
    changed = True
    while changed:
        changed = False
        res, k = [], 0
        while k < len(out):
            cur = out[k].strip()
            if (k + 1 < len(out) and (cur.startswith("if ") or cur.startswith("for "))
                    and out[k + 1].strip() == "end"):
                k += 2
                changed = True
                continue
            res.append(out[k])
            k += 1
        out = res
    return out


def build_regmap(code, entries, ctx):
    opmap = (ctx or {}).get("opmap") or {}
    code_by_pc = {ins["pc"]: ins for ins in code}
    steps = []
    for i in range(1, len(entries)):
        prev_e, cur_e = entries[i - 1], entries[i]
        prev_regs, cur_regs = prev_e.get("regs", {}), cur_e.get("regs", {})
        pc = prev_e["pc"]
        ins = code_by_pc.get(pc, {})
        writes = {}
        for r, rep in cur_regs.items():
            if prev_regs.get(r) != rep:
                writes[r] = sym_from_repr(rep)
        steps.append({
            "pc": pc, "tag": ins.get("tag"),
            "opname": opmap.get(ins.get("tag"), "?"),
            "A": ins.get("A"), "B": ins.get("B"), "K": ins.get("K"),
            "writes": writes,
            "before": {r: sym_from_repr(v) for r, v in prev_regs.items()},
            "after": {r: sym_from_repr(v) for r, v in cur_regs.items()},
        })
    return steps


def _qstr(s):
    return '"' + (str(s).replace("\\", "\\\\").replace('"', '\\"')
                  .replace("\n", "\\n").replace("\t", "\\t")) + '"'


def _reg_ok(v, n):
    return isinstance(v, int) and 0 <= v <= n


def _loadk_value(code, i):
    k = code[i].get("K")
    if isinstance(k, (str, int, float)):
        return k
    if i > 0:
        pk = code[i - 1].get("K")
        if isinstance(pk, (str, int, float)):
            return pk
    return None


def build_static_regmap(code, ctx):
    opmap = (ctx or {}).get("opmap2") or (ctx or {}).get("opmap") or {}
    nregs = 60
    regs = {}
    steps = []
    for i, ins in enumerate(code):
        op = opmap.get(ins.get("tag"), "OP_%s" % ins.get("tag"))
        A = ins.get("A")
        wrote = None
        if op == "LOADK" and _reg_ok(A, nregs):
            v = _loadk_value(code, i)
            if isinstance(v, str):
                regs[A] = {"kind": "str", "expr": _qstr(v), "text": v}
                wrote = A
            elif isinstance(v, (int, float)):
                regs[A] = {"kind": "num", "expr": repr(v) if isinstance(v, float) else str(v)}
                wrote = A
        elif op == "LOADN" and _reg_ok(A, nregs):
            v = _loadk_value(code, i)
            if isinstance(v, (int, float)):
                regs[A] = {"kind": "num", "expr": repr(v) if isinstance(v, float) else str(v)}
                wrote = A
        elif op == "GETGLOBAL" and _reg_ok(A, nregs):
            name = ins.get("K") if isinstance(ins.get("K"), str) else None
            regs[A] = {"kind": "global", "expr": name, "name": name}
            wrote = A
        elif op == "NEWTABLE" and _reg_ok(A, nregs):
            regs[A] = {"kind": "table", "expr": None}
            wrote = A
        steps.append({"pc": ins.get("pc"), "op": op, "A": A, "B": ins.get("B"),
                      "K": ins.get("K"), "wrote": wrote,
                      "regs": {r: dict(v) for r, v in regs.items()}})
    return steps


def static_call_sequence(code, ctx):
    steps = build_static_regmap(code, ctx)
    calls = []
    func = None
    args = []
    for s in steps:
        op = s["op"]
        if op == "GETGLOBAL" and s["wrote"] is not None:
            func = s["regs"][s["wrote"]].get("name")
            args = []
        elif op in ("LOADK", "LOADN") and s["wrote"] is not None and func is not None:
            args.append(s["regs"][s["wrote"]].get("expr"))
        elif op == "CALL":
            if func is not None:
                calls.append((func, [a for a in args if a]))
            func, args = None, []
    return calls
