# PATCH 🔧

**Paste a GitHub repo URL → get a real security scan, live CVE intel, and working patches.**

No signup walls, no static report PDFs. PATCH clones any public repo, hunts for real
vulnerabilities, cross-checks them against live CVE data, and writes the fix for each one —
all streamed to your browser in real time.

---

## How it works (the short version)

1. **Clone** — the repo is downloaded (GitHub repos come down as a tarball, no `git` needed; GitLab/Bitbucket use a shallow `git clone`).
2. **Scan** — four passes hunt for problems:
   - 🔑 **Secrets** — hardcoded AWS keys, GitHub tokens, private keys, crypto material…
   - 🧨 **Injection** — SQL concat, `eval`, `exec`, `shell=True`, XSS sinks, NoSQL…
   - 📦 **Dependencies** — parses *any* manifest (`package.json`, `requirements.txt`, `go.mod`, `Gemfile`, `Cargo.toml`, `pom.xml`, `build.gradle`, `composer.json`…)
   - 🧠 **AI semantic analysis** — an LLM actually *reads the source* (in any language) and finds vulnerabilities a regex list could never catch.
3. **CVE research** — live Tavily search per dependency, restricted to NVD + cve.org so you get real, package-relevant CVEs.
4. **Patch** — AI-generated unified diff for every finding (with a deterministic fallback if no AI key is configured).

The whole pipeline streams as server-sent events:
`start` → `step` → `scan` → `finding`* → `cve`* → `patch`* → `done` | `error`

---

## Quickstart

**You need:** Node.js ≥ 20.3.

```bash
npm install
cp .env.example .env   # optional: add your TAVILY_API_KEY and LLM_API_KEY
npm run dev            # → http://localhost:4000
```

That runs the **backend API**. Want the pretty UI too? The repo ships with a full
Next.js frontend:

```bash
cd frontend
npm install
npm run dev            # → http://localhost:3000
```

By default the frontend points at `http://localhost:4000` (the local backend).
To use a deployed backend instead, create `frontend/.env.local`:

```
NEXT_PUBLIC_API_BASE=https://your-backend.onrender.com
```

---

## Try it without a browser

Scan a local folder (no cloning, no network — great for testing):

```bash
node scripts/local-scan.js ./test-fixtures/vulnerable-app
```

Or stream a live scan of any public repo over HTTP:

```bash
curl -N "http://localhost:4000/api/scan?url=https://github.com/octocat/Hello-World"
```

---

## Deploy to Render

The repo includes a `render.yaml` Blueprint that deploys the backend as a managed web service.

1. Push this repo to GitHub
2. Create a free account at [render.com](https://render.com)
3. **New → Blueprint** → connect the GitHub repo
4. Fill in the secret env vars it prompts for — you *need* `TAVILY_API_KEY` and
   `LLM_API_KEY`; the two `RENDER_*` vars are optional (only if you use Workflows)
5. Deploy → hit `GET https://<your-app>.onrender.com/api/health` → expect `{ "ok": true }`

**Heads-up:** the free tier puts the service to sleep after ~15 min idle, so the
first request after a nap has a few seconds of cold-start lag. A paid plan keeps it always-on.
CORS is open (hackathon-friendly), so the frontend can call it from anywhere.

### Render Workflows (optional "Best Use of Render" upgrade)

The same scan can run as a managed workflow task instead of streaming in-process.
`render.yaml` can't define workflows (blueprints don't support them yet), so create it in
the dashboard: **New → Workflow** → build `npm ci` → start `node workflow/index.js`.
Then set `RENDER_API_KEY` + `RENDER_WORKFLOW_TASK` (e.g. `patch-scan/scan_repo`) on the
web service to enable `POST /api/scan/workflow` (kick off) and
`GET /api/scan/workflow/:id` (poll results).

---

## API

| Endpoint | Description |
| --- | --- |
| `GET /api/health` | JSON health check + which capabilities are enabled |
| `GET /api/scan?url=<repo-url>` | SSE stream of the full pipeline (`url` = GitHub/GitLab/Bitbucket repo) |
| `GET /api/history` | Last 20 scans (in-memory — resets on deploy) |
| `GET /api/history/:id` | Full results of one scan |
| `POST /api/scan/workflow` | Kick off a scan as a Render Workflow run `{ "url": "…" }` |
| `GET /api/scan/workflow/:taskRunId` | Poll a workflow run's status/results |

SSE payloads are plain `event: <type>\ndata: <json>\n\n` — the browser-native
`EventSource` API reads them directly, no dependencies needed.

---

## Environment variables

| Var | Purpose | Default |
| --- | --- | --- |
| `TAVILY_API_KEY` | Live CVE lookup via Tavily (1,000 free credits/mo) | *off* |
| `LLM_API_KEY` | AI patches + AI semantic analysis (Qwen/DashScope or OpenRouter) | *off* |
| `DASHSCOPE_API_KEY` | Alias for the LLM key (DashScope's canonical env var — either works) | *off* |
| `LLM_BASE_URL` | OpenAI-compatible base URL | DashScope compatible-mode v1 |
| `LLM_MODEL` | Model name | `qwen-plus` |
| `LLM_TIMEOUT_MS` | Per-patch LLM timeout (thinking models are slow) | `45000` |
| `LLM_ANALYSIS_TIMEOUT_MS` | Timeout for the AI semantic-analysis pass | `120000` |
| `PORT` | Server port | `4000` |
| `MAX_SCAN_BYTES` / `MAX_SCAN_FILES` | Caps so giant repos can't hang the demo | `20000000` / `10000` |
| `RENDER_API_KEY` / `RENDER_WORKFLOW_TASK` | Render Workflows trigger | *off* |

Everything is optional except the server itself — PATCH works end-to-end with zero keys
(deterministic patches, skipped CVE lookup), it just gets smarter the more you add.

---

## Safety & scoping

- **GitHub repos come down as tarballs** via the GitHub API (`api.github.com/repos/{owner}/{repo}/tarball`)
  into a temp dir that's **deleted after the run** — no `git clone`, which dodges
  git's smart-HTTP auth quirks on cloud/datacenter IPs. GitLab/Bitbucket fall back to a
  shallow `git clone --depth 1`.
- Any subprocess (`git`) is spawned with an **args array, never a shell string** → the
  URL can't inject commands.
- Only source extensions are scanned; `node_modules`, `.git`, build output, minified
  bundles, lockfiles, and files >512 KB are skipped.
- Hard caps on total scanned bytes/files (configurable above).
- **No GitHub write access, ever** — patches are diffs shown in the UI with a
  "copy fix" option. Nothing is pushed.

---

## Testing fixture

`test-fixtures/vulnerable-app/` is a deliberately vulnerable sample app — fake secrets,
SQL concatenation, `eval`, command injection, XSS, and outdated packages with real known
CVEs. It's the deterministic test bed for the pipeline. Push a copy to GitHub if you want
a demo repo you can scan over HTTP.

---

## Roadmap

- [x] Frontend — URL input → live pipeline → severity-ranked results with expandable diffs
- [ ] Planted demo repo on GitHub
- [x] Render Workflow support (SDK task + runner, `/api/scan/workflow`)

---

Built for hackathons, by people who like working code. 🚀
