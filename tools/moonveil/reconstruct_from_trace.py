import sys
import moonveil_decompile as dec
import register_lifter as rl

SAMPLE = sys.argv[1] if len(sys.argv) > 1 else "moonveil_2.lua"
TRACE = sys.argv[2] if len(sys.argv) > 2 else "moonveil_trace.txt"

src = open(SAMPLE, encoding="utf-8", errors="replace").read()
d = dec.detect(src)
trace_text = open(TRACE, encoding="utf-8", errors="replace").read()
blocks = dec.parse_trace(trace_text)
print("[*] parsed %d trace blocks, %d total entries" %
      (len(blocks), sum(len(v) for v in blocks.values())))

const_field = dec.detect_const_field(blocks)
fl = dec.detect_fields_src(src, d)
tag_field = fl["tag"] or dec.detect_fields(blocks)[0]
opmap, jump_tags = dec.learn_opcodes(blocks, const_field, tag_field, fl["sbx"])
transitions = dec.learn_transitions(blocks, tag_field, fl["op"])
print("[*] learned %d opcodes, %d transitions (was ~8 from luau)" %
      (len(opmap), len(transitions)))
protos = dec.static_protos(src, d, fl, opmap, transitions)
opmap2, settable = dec.detect_static_ops(protos, opmap)

for p in protos:
    entries = dec._match_trace_block(p, blocks, tag_field)
    if not entries:
        continue
    ppcs = set(i["pc"] for i in p["code"])
    tpcs = set(e["pc"] for e in entries)
    cov = len(tpcs & ppcs)
    if len(p["code"]) > 40:
        print("  proto_%d: %d instrs, %d traced pcs (%.0f%% coverage), %d entries" % (
            p["index"], len(p["code"]), cov, 100 * cov / len(ppcs), len(entries)))

trace_sem = dec.learn_trace_semantics(protos, blocks, tag_field, opmap2, jump_tags)
child_words = {p["index"]: dec.proto_words(p["code"]) for p in protos}
ui_lib = dec.detect_library(protos) or "Library"


def reconstruct_proto(p, entries):
    """Big flattened protos -> trace-driven lift (real CALL args/receivers).
    Small protos -> the proven clean_proto path (comparisons, else, print)."""
    if len(p["code"]) >= rl.MIN_PROTO_SIZE:
        ctx = {"opmap": opmap, "opmap2": opmap2}
        return rl.lift_structured(p["code"], entries, ctx, jump_tags)
    conds = (trace_sem.get(p["index"], {}) or {}).get("conds")
    return dec.clean_proto(p["code"], opmap2, settable, jump_tags,
                           list(p.get("children") or []), child_words,
                           conds=conds, ui_recv=ui_lib)


TARGET = int(sys.argv[3]) if len(sys.argv) > 3 else None
if TARGET is not None:
    p = next(pp for pp in protos if pp["index"] == TARGET)
    entries = dec._match_trace_block(p, blocks, tag_field)
    kb, ka = rl.learn_call_keys(p["code"], entries, opmap2)
    print("\n=== proto_%d reconstructed from real trace (key_B=%s key_A=%s) ===" %
          (TARGET, kb, ka))
    for line in reconstruct_proto(p, entries):
        print("    " + line)
    sys.exit(0)

_RISKY = ["game", "workspace", "Enum", "Instance", "task", "typeof", "buffer",
          "print", "pcall", "xpcall", "tostring", "type", "debug", "pairs", "math"]

import os as _os
_DROP_AT = bool(_os.environ.get("MOONVEIL_NO_ANTITAMPER"))

body = []
allidx = []
for p in protos:
    idx = p["index"]
    entries = dec._match_trace_block(p, blocks, tag_field)
    role = dec.proto_role(p["code"])
    ppcs = set(i["pc"] for i in p["code"])
    cov = len(set(e["pc"] for e in entries) & ppcs) if entries else 0
    lines = reconstruct_proto(p, entries) if (entries and cov >= 3) else []
    real = [l for l in lines if l.strip() and not l.strip().lstrip(";").startswith("--")]
    if _DROP_AT and role == "antitamper" and not real:
        continue
    allidx.append(idx)
    if real:
        note = "  -- reconstructed from trace (%.0f%% of pcs executed)" % (100 * cov / len(ppcs))
        body.append("function proto_%d(...)%s" % (idx, note))
        for ln in lines:
            body.append(("    " + ln).rstrip() if ln.strip() else "")
        body.append("end")
    elif role == "antitamper":
        body.append("function proto_%d(...)  --[[ anti-tamper; body omitted ]] end" % idx)
    else:
        body.append("function proto_%d(...)  --[[ %s runtime/helper; body omitted ]] end"
                     % (idx, role))
    body.append("")

out = ["--!nocheck", "-- Moonveil devirtualized from Roblox trace by 2zvh", ""]
out += body
out.append("")
out.append("return { %s }" % ", ".join("proto_%d" % i for i in allidx))

_outdir = _os.environ.get("MOONVEIL_OUT_DIR") or _os.path.dirname(_os.path.abspath(__file__))
_os.makedirs(_outdir, exist_ok=True)
out_path = _os.path.join(_outdir, "moonveil_trace_devirt.lua")
open(out_path, "w", encoding="utf-8").write("\n".join(out) + "\n")
print("[*] wrote full devirtualized output -> %s" % out_path)
