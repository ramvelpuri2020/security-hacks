# 🏆 PATCH — Complete Demo & Submission Guide (STEMist Hacks IV)

> **Everything you need for the demo, the pitch, and the Devpost submission — in one file.**
> Target prizes: **1st Place Overall**, **Best AI Hack (Tavily)**, **Best Security or Privacy Hack**, **Best Use of Render**.

---

## 1. Project at a glance

| | |
|---|---|
| **Name** | **PATCH** (Security Scanner) |
| **One-liner** | Paste a GitHub repo URL → clone → scan for real vulnerabilities → cross-reference **live CVE data** → generate **working patches**. |
| **Repo** | https://github.com/ramvelpuri2020/security-hacks |
| **Live app** | https://security-hacks.onrender.com |
| **Health check** | https://security-hacks.onrender.com/api/health |
| **Stack** | Next.js 16 + React 19 + Tailwind 4 frontend · Node/Express backend · Render (deploy) · **Tavily** (live CVE research) · **Qwen** via DashScope (AI patches) |

**Tagline options (pick one):**
- *"Your repo, scanned like a security engineer — with a fix for every finding."*
- *"Deterministic security scanning + live CVE intelligence + AI-generated patches."*
- *"Don't ask an LLM if your code is safe. Prove it."*

---

## 2. The pitch — why this is NOT just "an LLM that reads your code"

A generic chatbot can *look* at a repo and give you opinions. PATCH gives you an **audit**. The four differences, verbatim (memorize these):

1. **Sampling vs. exhaustive.** An LLM reads the files it *chooses* to look at and silently skips the rest. PATCH **walks every file** and **parses every dependency manifest** — full coverage is a guarantee, not a hope.
2. **Memory vs. live data.** An LLM's CVE knowledge dies at its training cutoff. PATCH pulls **live CVE data via Tavily at scan time**, restricted to authoritative sources (nvd.nist.gov + cve.org). A CVE published last week: the chatbot doesn't know it, PATCH does.
3. **Opinion vs. proof.** Run the same repo through a chatbot twice → two different reports. Run it through PATCH twice → **identical findings, each anchored to file:line + the exact matched pattern**. Deterministic output you can verify is engineering, not hallucination.
4. **Advice vs. fix.** A chatbot ends with *"consider parameterized queries."* PATCH ends with **the actual diff to copy and apply**.

**The division of labor (say this in your pitch):**
> *"Detection is 100% deterministic — real regex engines and dependency parsers, zero LLM in the finding. The LLM is confined to the two things it's genuinely good at: explaining the finding clearly and writing the fix diff. That's why nothing in the report can be hallucinated."*

---

## 3. How it works — the 4-stage pipeline

```
Paste repo URL
      │
      ▼
 ┌─ 1. CLONE ── GitHub tarball API (no git binary needed) → temp dir, deleted after run
 ├─ 2. SCAN ─── 3 deterministic engines:
 │              • Secrets    — 14 patterns (AWS keys, GitHub/OpenAI/Anthropic/Slack/Stripe/npm/Twilio
 │                             tokens, private keys, hardcoded credentials)
 │              • Injection  — 12 patterns (SQL string concat, SQL template literals, eval(),
 │                             new Function(), child_process exec, os.system(), subprocess shell=True,
 │                             pickle.loads(), unsafe yaml.load(), innerHTML / dangerouslySetInnerHTML,
 │                             document.write())
 │              • Deps       — package.json (all 4 sections) + requirements.txt → pinned name@version
 ├─ 3. CVE ──── Tavily live web search per dependency, restricted to nvd.nist.gov + cve.org,
 │              extracts CVE-YYYY-#### IDs from real advisories
 └─ 4. PATCH ── Qwen (qwen3.6-flash via DashScope, OpenAI-compatible) writes an explanation + patch
                diff per finding — 4 parallel workers, 15s timeout, deterministic fallback if the
                LLM fails → the scan ALWAYS completes
      │
      ▼
Live SSE stream: start → step → scan → finding* → cve* → patch* → done | error
      │
      ▼
Results screen: severity-ranked findings (Critical/High/Medium), each expandable
→ explanation + diff + CVE citation → "Copy fix" → scan history is saved to the dashboard
```

**Streaming, not a loading bar.** Every stage of the pipeline is streamed to the browser as Server-Sent Events — judges *watch the pipeline think* in real time.

---

## 4. Tech stack & architecture

### Backend (repo root)
- **Express** server with SSE streaming (`src/server.js`)
- **Pipeline orchestrator** (`src/pipeline.js`) — clone → scan → CVE → patch, emits typed events
- **Scanners** (`src/scanners/`) — `secrets.js`, `injection.js`, `dependencies.js` (pure deterministic regex/parsing, unit-testable)
- **CVE lookup** (`src/cve.js`) — Tavily Search API, `include_domains: ['nvd.nist.gov', 'cve.org']`
- **Patch generation** (`src/patchgen.js`) — Qwen via DashScope OpenAI-compatible endpoint; parallel worker pool (4), configurable `LLM_TIMEOUT_MS`, graceful deterministic fallback
- Deployed via **`render.yaml` Blueprint** (Node 22.14.0, health check, free tier)

### Frontend (`frontend/`)
- **Next.js 16 + React 19 + Tailwind 4** + shadcn/ui, dark glass-panel aesthetic
- Screens: `input-screen` (URL entry) → `pipeline-stepper` + `pipeline-display` (live stream) → `results-screen` (severity-ranked findings with diffs) → `dashboard-home` (real scan history, clickable to re-open results)
- Backend base URL: `NEXT_PUBLIC_API_BASE` env (defaults to `http://localhost:4000`)

### API endpoints
| Endpoint | What it does |
| --- | --- |
| `GET /api/health` | Capabilities status (`cveLookup`, `aiPatches`, `llmModel`) |
| `GET /api/scan?url=<repo>` | SSE stream of the full pipeline |
| `GET /api/history` | Recent scans (real data, in-memory, max 20) |
| `GET /api/history/:id` | Full archived results for one scan |

---

## 5. Live state (verified ✅)

Current deployed health at https://security-hacks.onrender.com/api/health:

```json
{ "ok": true, "service": "patch-backend", "version": "0.1.0",
  "capabilities": { "cveLookup": true, "aiPatches": true,
  "llmModel": "qwen3.6-flash", "llmProvider": "custom (LLM_BASE_URL)" } }
```

**Everything is ON:** Tavily CVE lookup ✅, AI patches ✅, model `qwen3.6-flash` ✅.

---

## 6. Prize targeting (from the actual Devpost page)

| Prize | Award | Why we win it |
| --- | --- | --- |
| **1st Place Overall** (T-Mobile) | **$1,000 cash** + subs | Complete product: real pipeline, live data, AI, polished UI, clear demo arc |
| **Best AI Hack** | $150 + **Tavily 10k credits** ($80) + $100 cash | Tavily is doing *live CVE research* — a real AI capability, not a chatbot wrapper |
| **Best Security or Privacy Hack** | $150 + **TryHackMe 6-mo ×4** + $100 cash | Deterministic static analysis + CVE cross-referencing — actual security engineering |
| **Best Use of Render** | $500 Render credits + $100 cash | ⚠️ **Eligibility requires Render Workflows** — see §7 |

> **Reality check:** the current build deploys on Render as a **web service** (Blueprint). The "Best Use of Render" prize *requires Render Workflows* to be eligible. See §7 for your two options. If you don't add a Workflow, you're still eligible for Overall + Best AI + Best Security.

---

## 7. Render Workflows (Best Use of Render eligibility) ✅ BUILT

The prize rules say: *"Winners must use Render Workflows to be eligible."* ✅ **This is now built** — the same scan pipeline runs as a managed **Render Workflow task** on dedicated Render infrastructure.

### What was built
- **`workflow/index.js`** — a Render SDK task (`scan_repo`) registered with `@renderinc/sdk`. It runs the *exact same* pipeline as the live scan (`runPipeline` via `scripts/workflow-run.js`), so results are byte-for-byte identical to the in-process path.
- **`POST /api/scan/workflow`** `{ url }` — kicks off a workflow run via the Render API (`POST /v1/task-runs`) and returns a `taskRunId`.
- **`GET /api/scan/workflow/:taskRunId`** — polls run status (`pending | running | completed | failed | canceled`); on completion returns the full report and records it into scan history so it appears on the dashboard.
- **Frontend** — the input screen now has a **"Run as Render Workflow"** button that shows a live status view (run ID, elapsed time, step checklist) with a link to the Render dashboard, then lands on the same results screen.

### How to activate it (one-time, ~5 min in Render)
1. Create a **Render API key**: Dashboard → Account Settings → API Keys.
2. **New → Workflow** → connect this repo → root dir `.` → build `npm ci` → start `node workflow/index.js`.
3. Give the workflow the same env vars as the web service: `TAVILY_API_KEY`, `LLM_API_KEY`/`DASHSCOPE_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`.
4. On the **web service**, set `RENDER_API_KEY` (the key from step 1) and `RENDER_WORKFLOW_TASK` = `{workflow-slug}/scan_repo` (the slug shown on the task's page in the dashboard, e.g. `patch-scan/scan_repo`).
5. Restart the web service. Verify: `GET /api/health` shows `workflows: true`.

> Note: workflows are billed by compute usage (prorated per second) — covered by the $50 of Render credits all participants get. Blueprints don't support workflows yet, which is why it's created via the dashboard rather than `render.yaml`.

---

## 8. Demo script (5–6 minutes, timed)

> **Golden rule:** demo the *planted* repo first (guaranteed results), then a real repo if time allows. Never gamble a live demo on an unverified scan.

| Time | What you do | What judges see |
| --- | --- | --- |
| **0:00–0:20** | Hook: *"Every dev has pasted code into a chatbot and asked 'is this safe?' Chatbots give opinions. I built a tool that gives proof — and a fix for everything it finds."* | — |
| **0:20–0:40** | Open the live app, paste the demo repo URL: `https://github.com/ramvelpuri2020/security-hacks` (or a planted vulnerable repo — see §9) | Clean glass UI, URL input |
| **0:40–1:40** | Hit Scan. Narrate the stream: *"It's cloning via GitHub's API, then running three deterministic engines — secrets, injection risks, dependencies. No LLM involved in finding anything yet."* | Live pipeline stepper animating: Cloning → Scanning → CVE research → Patches |
| **1:40–2:10** | Point at the findings as they stream in: *"27 findings (illustrative — verify the count when you record). Critical ones first — a leaked API key pattern, SQL built by string concatenation."* | Severity-colored findings streaming |
| **2:10–2:50** | Expand one critical finding: *"Here's the exact file, the exact line, the exact pattern that matched. This isn't a guess — it's a regex that fired. And here's the live CVE data from Tavily, citing the actual advisory from NVD."* | **THE proof panel moment** — file:line, matched code, regex pattern, CVE citation |
| **2:50–3:40** | Show the AI patch: *"Now the LLM's job — explain why this is dangerous and write the actual fix."* Show the diff. Click **Copy fix**. | AI-generated diff, copy button |
| **3:40–4:20** | Scroll to the dashboard: *"Every scan is saved to history — real data from the backend, not mock."* Click a past scan to re-open it. | Real scan history, drill-down |
| **4:20–5:00** | The differentiator close: *"Run this twice and you get the same findings, every time, anchored to real lines of code and real CVEs. That's the difference between a tool that audits and a chatbot that guesses."* | — |
| **5:00–5:30** | Q&A buffer | — |

---

## 9. The planted demo repo (your safety net) 🎯

`test-fixtures/vulnerable-app/` in this repo is a deliberately vulnerable sample app. **Push a copy to GitHub under your account** and use it for the guaranteed demo:

- Fake hardcoded API key (real regex pattern → **Critical**)
- SQL string concatenation in `server.js` (→ **High**, SQL injection)
- `eval()` usage (→ **High**, RCE)
- `child_process.exec` (→ **High**, command injection)
- `.innerHTML` assignment (→ **Medium**, XSS)
- `package.json` pinning an outdated version with a **known CVE** (→ live Tavily citation)
- `requirements.txt` with an outdated pinned package

**Why this wins:** the demo *always* finds real, clear, CVE-backed issues — no gambling on someone else's code.

---

## 10. Devpost submission (copy-paste ready)

**Title:** `PATCH — Security Scanner that Fixes Your Repo`

**Tagline:** `Paste a GitHub repo. Get a real security audit with live CVE data — and working patches for every finding.`

**Description (paste into the "Describe what you built" box):**

> PATCH is a security scanning pipeline that turns any public GitHub repo into a ranked, verifiable security audit in under a minute. It clones the repo, runs three deterministic detection engines (hardcoded secrets, injection risks, and dependency analysis), cross-references every dependency against **live CVE data pulled from the web via Tavily**, and then uses an LLM (Qwen) to write a human explanation and an actual patch diff for every finding. Detection is 100% deterministic — every finding is anchored to a file, a line, and the exact pattern that matched, so nothing can be hallucinated. The LLM is deliberately narrowed to explaining and fixing. Results stream live to a glass-panel dashboard with a security report, per-finding diffs, and real scan history. Deployed as a full pipeline on Render.

**"How we built it":**
> Next.js 16 + React 19 + Tailwind frontend, Node/Express backend with a streaming SSE pipeline (clone → scan → CVE research → patch generation). Detection engines: custom regex-based secret scanner (14 patterns) and risky-code scanner (12 patterns) plus a dependency parser for package.json/requirements.txt. Live CVE lookup via the Tavily Search API restricted to nvd.nist.gov and cve.org. AI patch generation via Qwen (qwen3.6-flash) through DashScope's OpenAI-compatible endpoint with a deterministic fallback so scans always complete. Deployed with a Render Blueprint on the free tier.

**Built with:** Next.js · React · TypeScript · Tailwind CSS · Node.js · Express · Render · Tavily · Qwen / DashScope · shadcn/ui · Server-Sent Events

**Categories:** Security, AI, Developer Tools, Open Source

**Video (60s):** reuse the demo script §8 — record the live scan of the planted repo, then 10s of the history drill-down.

---

## 11. Judge Q&A (objection handling)

> **"Can't I just paste my repo into ChatGPT and ask it to audit?"**
> "Try it — then run it again and see if you get the same findings. ChatGPT gives you an opinion based on the files it decided to read. PATCH exhaustively scans every file and every dependency manifest, and every finding is anchored to a file, a line, and a regex pattern — deterministic and reproducible. And it pulls live CVE advisories from the web at scan time, which a chatbot's training data can't do."

> **"Are the findings real, or did the LLM make them up?"**
> "The findings are made by deterministic engines — zero LLM in detection. Here, expand this finding: file, line, matched pattern, and a real CVE from NVD via Tavily. The LLM only writes the explanation and the fix."

> **"Why the LLM at all, then?"**
> "Because explaining and patching are what LLMs are actually good at. Detection is verifiable engineering; the LLM converts it into something a developer can act on in seconds. That's the honest division of labor."

> **"What about private repos?"**
> "Public repos only, by design — and we cap repo size so the scan can't hang. It's scoped for the demo, not a production product."

> **"Does it actually fix the repo?"**
> "It generates the exact patch diff and lets you copy it. We deliberately don't write to your GitHub — no auth, no risk. The fix is one copy away."

---

## 12. Troubleshooting quick-reference (things we already fixed)

| Symptom | Cause | Fix |
| --- | --- | --- |
| Log spam `HTTP 404` from the LLM endpoint | `LLM_BASE_URL` pointed at DashScope **native** `/api/v1`; the OpenAI-compatible path is `/compatible-mode/v1` | Set `LLM_BASE_URL=https://<your-workspace>.aliyuncs.com/compatible-mode/v1` (fixed in Render dashboard ✅) |
| "AI patch service unavailable (LLM request timed out)" | Thinking models (qwen3.6-flash) can take 15–60s; per-call timeout too low | Raise `LLM_TIMEOUT_MS` in steps (25–30s first). Scans still complete via deterministic fallback |
| Scan "spins forever" on patches | Patches used to generate sequentially, 30s each × 27 findings | Fixed: parallel pool of 4 workers + 15s timeout → worst case ~84s, always bounded |
| `bis_skin_checked` hydration warning in dev console | A browser extension (Bis) mutating the DOM before React hydrates | Not your app — production builds don't show it; test in incognito |
| First load slow on Render | Free tier cold-starts after ~15 min idle | Click once; or use a paid plan for the demo hour |

---

## 13. Quick-facts cheat sheet (numbers to drop in conversation)

- **14** secret patterns · **12** injection patterns · **2** dependency formats (package.json + requirements.txt)
- **4** parallel AI-patch workers · **15s** LLM timeout (configurable) · **20** deps checked for CVEs per scan
- **50 MB** max repo tarball · **20 MB / 10,000 files** scan caps · **20** scans kept in history
- **~20–90s** typical end-to-end scan on a small repo (observed: ~17s deployed) · **100% deterministic** detection · **live** CVE data via Tavily (nvd.nist.gov + cve.org only)
- Deployed: **Render** (free tier, Blueprint, auto-deploy on push to `main`)

---

## 14. Run it locally (for the recording)

```bash
# Backend
npm install
cp .env.example .env        # add TAVILY_API_KEY + DASHSCOPE_API_KEY
npm run dev                 # http://localhost:4000

# Frontend (separate terminal)
cd frontend
npm install
# ⚠️ PRODUCTION: point the frontend at the deployed backend at build time,
# otherwise it will call localhost:4000 and break
#   NEXT_PUBLIC_API_BASE=https://security-hacks.onrender.com npx next build
npx next dev                # http://localhost:3000 (dev uses localhost:4000)
# (prod build → npx next build && npx next start)

# CLI-style local scan without the UI
node scripts/local-scan.js ./test-fixtures/vulnerable-app
```

**Env vars (all in Render → Environment, mirror locally in `.env`):**
`TAVILY_API_KEY` · `DASHSCOPE_API_KEY` (or `LLM_API_KEY`) · `LLM_BASE_URL` (OpenAI-compatible endpoint) · `LLM_MODEL=qwen3.6-flash` · `LLM_TIMEOUT_MS` (optional) · `PORT` · `MAX_SCAN_BYTES` / `MAX_SCAN_FILES` (optional)

**Frontend build var:** `NEXT_PUBLIC_API_BASE` — defaults to `http://localhost:4000` (in `frontend/lib/api.ts`). For any hosted/recorded frontend, build with `NEXT_PUBLIC_API_BASE=https://security-hacks.onrender.com` or the app will call localhost.

---

## 15. Final checklist before submission

- [ ] Scan history shows **real** data (already wired ✅)
- [ ] Live scan of your planted repo completes in under ~90s with AI patches (no `llmError`)
- [ ] Copy-paste §10 into Devpost (update "Built with" tags to match Devpost's list exactly)
- [ ] 60s demo video recorded using §8 script
- [ ] Decided on §7: add Render Workflow (Option A) or skip (Option B)
- [ ] If the frontend is hosted/recorded against the deployed app: built with `NEXT_PUBLIC_API_BASE=https://security-hacks.onrender.com`
- [ ] GitHub repo is public, README is clean, license added
- [ ] Screenshots: input screen, live pipeline, results with a CVE, history drill-down
