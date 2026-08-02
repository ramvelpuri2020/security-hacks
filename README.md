# PATCH 🔧

**Paste a GitHub repo URL → clone → scan for real vulnerabilities → cross-reference live CVE data → generate working patches.**

A static-analysis + AI-patching service. Detection is **deterministic** (regex + dependency parsing — verifiable, not hallucinated); the LLM is narrowed to what it's good at: explaining findings clearly and generating the fix diff.

## Architecture

```
Frontend (your existing app)
   │  GET /api/scan?url=https://github.com/owner/repo   (Server-Sent Events)
   ▼
Express backend ── runPipeline ──┬─ 1. clone   (git clone --depth 1, temp dir, auto-cleanup)
                                 ├─ 2. scan    ├─ secrets    (AWS, GitHub, OpenAI, Slack, Stripe, private keys…)
                                 │              ├─ injection  (SQL concat, eval, exec, shell=True, XSS sinks…)
                                 │              └─ deps       (package.json + requirements.txt)
                                 ├─ 3. CVE     (Tavily search restricted to nvd.nist.gov + cve.org)
                                 └─ 4. patch   (Qwen via DashScope — OpenAI-compatible; deterministic fallback)
```

**Streamed events:** `start` → `step` → `scan` → `finding`* → `cve`* → `patch`* → `done` | `error`

## Quickstart

```bash
npm install
cp .env.example .env   # add TAVILY_API_KEY and LLM_API_KEY (optional but recommended)
npm run dev            # http://localhost:4000
```

### Try it without a browser

```bash
node scripts/local-scan.js ./test-fixtures/vulnerable-app
```

or stream live over HTTP:

```bash
curl -N "http://localhost:4000/api/scan?url=https://github.com/octocat/Hello-World"
```

## Deploy to Render

The repo includes a `render.yaml` Blueprint that deploys the backend as a managed web service.

1. Push this repo to GitHub
2. Create a free account at https://render.com
3. **New → Blueprint** → connect the GitHub repo — `render.yaml` defines the backend service
4. Fill in the two secret env vars it prompts for: `TAVILY_API_KEY` and `LLM_API_KEY` (also settable anytime in Dashboard → Environment)
5. Deploy → live URL → `GET https://<your-app>.onrender.com/api/health` should return `{ "ok": true }`

Notes:
- The **free tier spins the service down after ~15 min idle** — the first request after sleep has a cold-start delay of a few seconds. A paid plan keeps it always-on.
- CORS is open (hackathon-friendly), so the frontend can call the backend from anywhere.
- Background workers / Render Workflows (the full pipeline-as-workflow upgrade) require a paid plan — see Roadmap.

## API

| Endpoint | Description |
| --- | --- |
| `GET /api/health` | JSON health + which capabilities are enabled |
| `GET /api/scan?url=<repo-url>` | SSE stream of the full pipeline. `url` must be a GitHub/GitLab/Bitbucket repo URL. |

SSE payloads are `event: <type>\ndata: <json>\n\n` — the browser-native `EventSource` API reads them directly.

## Environment

| Var | Purpose | Required |
| --- | --- | --- |
| `TAVILY_API_KEY` | Live CVE lookup via Tavily (1,000 free credits/mo) | optional |
| `LLM_API_KEY` | AI patch generation (Qwen/DashScope or OpenRouter) | optional |
| `LLM_BASE_URL` | OpenAI-compatible base URL (defaults to DashScope) | optional |
| `LLM_MODEL` | Model name (default `qwen-plus`) | optional |
| `PORT` | Server port (default 4000) | optional |
| `MAX_SCAN_BYTES` / `MAX_SCAN_FILES` | Caps so giant repos can't hang the demo | optional |

## Safety & scoping

- **Shallow clone** (`--depth 1 --single-branch`) into a temp dir, **deleted after the run**.
- `git` is spawned with an **args array** (never a shell string) → the URL can't inject commands.
- Only source extensions are scanned; `node_modules`, `.git`, build output, minified bundles, and >512 KB files are skipped.
- Hard caps on total scanned bytes/files.
- **No GitHub write access** — patches are generated diffs shown in the UI (with a "copy fix" option), never pushed.

## Testing fixture

`test-fixtures/vulnerable-app/` is a deliberately vulnerable sample app (fake secrets + SQL concat + eval + command injection + XSS + outdated packages with real known CVEs). Use it to verify the pipeline deterministically. Push a copy to GitHub as your demo safety net.

## Roadmap

- [ ] Frontend integration (URL input → live pipeline → severity-ranked results with expandable diffs)
- [ ] Planted demo repo on GitHub
- [ ] Optional: swap the in-process pipeline for a real Render Workflow (TS/Python SDK), triggered via `POST /v1/task-runs`
