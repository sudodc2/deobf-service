import sys
import moonveil_decompile as dec

SAMPLE = sys.argv[1] if len(sys.argv) > 1 else "moonveil_2.lua"
OUT = sys.argv[2] if len(sys.argv) > 2 else "moonveil_roblox_trace.luau"

src = open(SAMPLE, encoding="utf-8", errors="replace").read()
d = dec.detect(src)
if not d:
    print("[!] could not detect interpreter fields in", SAMPLE)
    sys.exit(1)

fetch = "{0}={1}[{2}]".format(d["instr"], d["code"], d["pc"])
inject = fetch + ";__MV({0},{1},{2},{3})".format(d["pc"], d["instr"], d["regs"], d["code"])
if fetch not in src:
    print("[!] fetch pattern not found:", fetch)
    sys.exit(1)
body = src.replace(fetch, inject, 1)

PRELUDE = r"""-- Moonveil trace harness (run in a Roblox executor). Writes moonveil_trace.txt.
local __lines, __n, __cap, __done = {}, 0, 400000, false
local __bid, __bn, __cnt = {}, 0, {}
local __thex = function(s) return (s:gsub('.', function(c) return string.format('%02x', string.byte(c)) end)) end
local function __flush(why)
    if __done then return end
    __done = true
    local blob = table.concat(__lines, "\n")
    local wf = writefile or (syn and syn.writefile)
    if wf then pcall(wf, "moonveil_trace.txt", blob) end
    warn("[MV] trace written ("..why.."): "..#__lines.." lines, "..#blob.." bytes")
end
function __MV(pc, ins, regs, code)
    if __done then return end
    if not __bid[code] then __bn = __bn + 1; __bid[code] = __bn end
    local id = __bid[code]
    local key = id * 100000 + pc
    __cnt[key] = (__cnt[key] or 0) + 1
    if __cnt[key] > 8 then return end
    local fs = {}
    for k, v in pairs(ins) do
        if type(k) == "number" then
            if type(v) == "number" then fs[#fs+1] = k..'=#'..tostring(v)
            elseif type(v) == "string" then fs[#fs+1] = k..'=$'..__thex(v) end
        end
    end
    local rs = {}
    for k, v in pairs(regs) do
        if type(k) == "number" then
            local t = type(v)
            local r
            if t == "number" then r = '#'..tostring(v)
            elseif t == "string" then r = '$'..__thex(v)
            elseif t == "boolean" then r = 'b'..tostring(v)
            elseif t == "function" then r = 'fn'
            elseif t == "table" then r = 'tb'
            else r = '?' end
            rs[#rs+1] = k..'='..r
        end
    end
    __lines[#__lines+1] = 'I '..id..' '..pc..'|'..table.concat(fs, ',')..'|'..table.concat(rs, ',')
    __n = __n + 1
    if __n >= __cap then __flush("cap") end
end
task.spawn(function() task.wait(10); __flush("timer") end)
pcall(function(...)
"""

EPILOGUE = r"""
end, ...)
__flush("end")
"""

harness = PRELUDE + body + EPILOGUE
with open(OUT, "w", encoding="utf-8", errors="replace") as h:
    h.write(harness)
print("[*] wrote Roblox trace harness -> %s" % OUT)
print("[*] interpreter fields: instr=%s code=%s pc=%s regs=%s" %
      (d["instr"], d["code"], d["pc"], d["regs"]))
print("[*] run it in your executor; it writes moonveil_trace.txt (workspace folder).")
