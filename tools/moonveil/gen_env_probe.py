"""Record every environment interaction moonveil makes under standalone luau,
up to the point it diverges/fails. The log = the exact Roblox API surface we
must emulate (per Roblox docs) to run it standalone/automated.
"""
import sys, os, subprocess
import moonveil_decompile as dec

SAMPLE = sys.argv[1] if len(sys.argv) > 1 else "moonveil_2.lua"
src = open(SAMPLE, encoding="utf-8", errors="replace").read()
d = dec.detect(src)
if not d:
    print("[!] detect failed"); sys.exit(1)
body = src

PRELUDE = r"""
local _rawset, _setmt, _type, _tostring, _concat = rawset, setmetatable, type, tostring, table.concat
local ok, g = pcall(getfenv)
if not ok or _type(g) ~= "table" then g = _G end
local seen = {}
local function rec(path)
    if not seen[path] then seen[path] = true; print("ENV " .. path) end
end
-- recording proxy: logs the access path of every index/call/method.
local mkrec
mkrec = function(path, depth)
    if depth <= 0 then return "" end
    return _setmt({}, {
        __index = function(_, k) rec(path .. "." .. _tostring(k)); return mkrec(path .. "." .. _tostring(k), depth - 1) end,
        __call = function(_, ...) rec(path .. "()"); return mkrec(path .. "()", depth - 1) end,
        __namecall = function(_, ...)
            -- luau: the invoked method name is not directly available here in std
            rec(path .. ":<method>"); return mkrec(path .. ":m", depth - 1)
        end,
        __newindex = function() end,
        __tostring = function() return "" end,
        __concat = function() return "" end,
        __len = function() return 0 end,
    })
end
-- install recording values for the Roblox globals moonveil might use.
local roblox_globals = {"game","workspace","Instance","Enum","task","Vector3",
    "Vector2","CFrame","Color3","UDim2","UDim","Ray","Region3","TweenInfo",
    "BrickColor","NumberSequence","ColorSequence","Rect","PhysicalProperties",
    "Random","DateTime","OverlapParams","RaycastParams","Font","Content"}
for _, name in ipairs(roblox_globals) do
    _rawset(g, name, mkrec(name, 8))
end
-- also record known executor globals
local exec_globals = {"getgenv","getrenv","getreg","getgc","hookfunction","hookmetamethod",
    "getrawmetatable","setrawmetatable","setreadonly","isreadonly","newcclosure",
    "identifyexecutor","request","http_request","syn","fluxus","getexecutorname",
    "readfile","writefile","isfile","listfiles","loadstring","getcustomasset",
    "setclipboard","queue_on_teleport","firesignal","getconnections"}
for _, name in ipairs(exec_globals) do
    _rawset(g, name, mkrec(name, 8))
end
-- wrap string/table/buffer/bit32/os/math indexing to record which members are used
for _, libname in ipairs({"buffer","bit32","utf8","os","debug","coroutine"}) do
    local lib = g[libname] or (_type(_G[libname]) == "table" and _G[libname])
    if _type(lib) == "table" then
        local real = lib
        _rawset(g, libname, _setmt({}, {__index = function(_, k)
            rec(libname .. "." .. _tostring(k)); return real[k]
        end}))
    end
end
"""

harness = PRELUDE + "\n" + body
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_mv_env.luau")
with open(path, "w", encoding="latin-1", errors="replace") as h:
    h.write(harness)
res = subprocess.run([dec.LUAU, "_mv_env.luau"], cwd=os.path.dirname(path),
                     capture_output=True, text=True, encoding="latin-1", timeout=30)
env = sorted(set(l[4:] for l in (res.stdout or "").splitlines() if l.startswith("ENV ")))
print("[*] environment accesses moonveil made (%d):" % len(env))
for e in env:
    print("   " + e)
print("---- STDERR (first 500) ----")
print((res.stderr or "")[:500])
os.remove(path)
