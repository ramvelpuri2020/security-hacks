// Render Workflow task definitions — STEMist Hacks IV
//
// Render Workflows is a separate Render service (NOT a render.yaml resource —
// blueprints don't support workflows yet). You create it from the dashboard:
//
//   New → Workflow → connect this repo (root dir: .) → build: `npm ci`
//   start: `node workflow/index.js`
//   env: same keys as the web service (TAVILY_API_KEY, LLM_*/DASHSCOPE_API_KEY)
//
// The start command imports this file, which registers every task. Runs are
// triggered from the backend via POST /v1/task-runs (see /api/scan/workflow)
// with a task slug like `patch-scan/scan_repo`.
//
// Each task run executes on its own instance. This task shells out to
// scripts/workflow-run.js — the exact same pipeline the live scan uses — so
// detection, CVE research and patch generation are byte-for-byte identical
// to the SSE path, just running on dedicated Render infrastructure.
// The task() registration factory lives on the /workflows subpath (the root
// @renderinc/sdk export is the Render REST client). Per the SDK README:
//   import { task } from '@renderinc/sdk/workflows';
import { task } from '@renderinc/sdk/workflows';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

// Resolve the job runner relative to THIS module so it works regardless of the
// workflow service's working directory (never assume cwd == repo root).
const WORKFLOW_RUNNER = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'workflow-run.js');

const execFileAsync = promisify(execFile);

/**
 * scan_repo(url) — full security scan as a managed workflow run.
 * Returns the complete report object (meta, summary, findings, dependencies,
 * cves) which the Render API exposes as results[0] on the task run.
 */
export const scan_repo = task(
  {
    name: 'scan_repo',
    timeoutSeconds: 1800, // 30 min cap — well above any real scan
    plan: 'standard', // 1 CPU / 2 GB — enough for clone + scan + LLM patches
    retry: { maxRetries: 1, waitDurationMs: 2000, backoffScaling: 1.5 },
  },
  async (repoUrl) => {
    if (typeof repoUrl !== 'string' || !repoUrl.trim()) {
      throw new Error('scan_repo requires a repo URL string as input, e.g. ["https://github.com/owner/repo"]');
    }
    const { stdout } = await execFileAsync(
      process.execPath,
      [WORKFLOW_RUNNER, repoUrl.trim()],
      { maxBuffer: 128 * 1024 * 1024, env: process.env }
    );
    const m = stdout.match(/REPORT_START\n([\s\S]*?)\nREPORT_END/);
    if (!m) throw new Error('workflow-run.js finished without producing a report');
    return JSON.parse(m[1]);
  }
);
