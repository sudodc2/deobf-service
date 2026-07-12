# deobf-service

Deobfuscation backend for the Sudo Discord bot. Bundles the real per-obfuscator
tools behind one HTTP API so the Cloudflare-hosted bot (which can't run
Python/.NET/Java/Luau) can deobfuscate uploads and loadstring links.

## Supported (only these five)

| Obfuscator | Engine | Recovery |
|---|---|---|
| Hercules   | Python (static)        | Full source |
| Ironveil   | Node                   | Full source |
| MoonSec V3 | .NET → bytecode + unluac | Source via bytecode decompile (disasm fallback) |
| Prometheus | in-house (from Vmify source) | Static layers reversed; VM devirt WIP |
| Moonveil   | Python + Luau (two-phase) | Partial static; full needs an executor trace |

## API

`POST /deobf`
```json
{ "source": "<obfuscated lua>", "url": "optional remote", "type": "optional force" }
```
Returns `{ ok, detected:{name,confidence,signals}, tool, fetchedFrom, output, notes, partial }`.

`GET /health` → `{ ok: true }`

Auth: if `DEOBF_SHARED_SECRET` is set, requests must send `x-deobf-key: <secret>`.

Loadstring/HttpGet stubs are followed to the real payload with an SSRF guard
(scheme allowlist, private/loopback address block, size cap). Fetched code is
**never executed** — analysis is static (except Moonveil's opt-in trace flow).

## Run

```bash
npm install
node server.js         # :8080
```

## Deploy (Render)

`render.yaml` builds the Docker image (Node + Python + .NET 9 + JRE + Luau),
compiles the MoonSec tool, and fetches unluac. Set `DEOBF_SHARED_SECRET`.
