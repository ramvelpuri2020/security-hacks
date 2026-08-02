import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

import { runPipeline, validateRepoUrl } from './pipeline.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// In-memory scan history (demo scope — resets on deploy/restart).
// Recorded on every completed/failed scan and served via GET /api/history
// so the dashboard can render real data instead of mock rows.
const scanHistory = [];
// id -> full results (findings + patches) so a dashboard row can be re-opened.
const scanDetails = new Map();
const MAX_HISTORY = 20;

function recordScan(entry, fullResults) {
  scanHistory.unshift(entry);
  if (fullResults) scanDetails.set(entry.id, fullResults);
  if (scanHistory.length > MAX_HISTORY) {
    const removed = scanHistory.pop();
    if (removed) scanDetails.delete(removed.id);
  }
}

app.get('/api/history', (_req, res) => {
  res.json({ scans: scanHistory });
});

app.get('/api/history/:id', (req, res) => {
  const detail = scanDetails.get(req.params.id);
  if (!detail) return res.status(404).json({ error: 'Scan not found' });
  res.json({ scan: detail });
});

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'patch-backend',
    version: '0.1.0',
    capabilities: {
      cveLookup: Boolean(process.env.TAVILY_API_KEY),
      aiPatches: Boolean(process.env.LLM_API_KEY || process.env.DASHSCOPE_API_KEY),
      llmModel: process.env.LLM_MODEL || 'qwen-plus (default)',
      llmProvider: process.env.LLM_BASE_URL ? 'custom (LLM_BASE_URL)' : 'dashscope (default)',
      workflows: Boolean(process.env.RENDER_API_KEY && process.env.RENDER_WORKFLOW_TASK),
      workflowTask: process.env.RENDER_WORKFLOW_TASK || null,
    },
  });
});

/**
 * SSE endpoint — streams pipeline progress as server-sent events:
 *   event: step    | { step, message }
 *   event: scan    | { filesScanned, secrets, injection, dependencies }
 *   event: finding | { finding }
 *   event: cve     | { dep, status, cves, ... }
 *   event: patch   | { findingId, patch, explanation }
 *   event: done    | { results }
 *   event: error   | { message }
 */
app.get('/api/scan', async (req, res) => {
  const { url } = req.query;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const aborted = { current: false };
  const controller = new AbortController();
  req.on('close', () => {
    // Stop gating writes AND abort the pipeline so it stops burning compute.
    aborted.current = true;
    controller.abort();
  });

  const emit = (type, data) => {
    if (aborted.current) return;
    res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
    if (type === 'done' && data?.results) {
      const r = data.results;
      recordScan(
        {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          repo: r.meta?.repo || url || 'unknown',
          date: new Date().toISOString(),
          status: 'completed',
          summary: {
            totalFindings: r.summary?.totalFindings ?? 0,
            bySeverity: r.summary?.bySeverity ?? {},
            secrets: r.summary?.secrets ?? 0,
            injection: r.summary?.injection ?? 0,
            dependencies: r.summary?.dependencies ?? 0,
          },
        },
        r
      );
    } else if (type === 'error' && typeof url === 'string' && url) {
      // Only record real scan failures — skip the missing-param validation error.
      recordScan({
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        repo: url,
        date: new Date().toISOString(),
        status: 'failed',
        error: String(data?.message || 'unknown error').slice(0, 200),
      });
    }
  };

  emit('start', { url: url || null, ts: Date.now() });

  if (!url || typeof url !== 'string') {
    emit('error', { message: 'Missing required query param: url (e.g. https://github.com/owner/repo)' });
    return res.end();
  }

  try {
    await runPipeline({ url, emit, signal: controller.signal });
  } catch {
    // The pipeline already emitted the `error` event — nothing more to stream.
  } finally {
    res.end();
  }
});

// ----------------------------------------------------------------
// Render Workflows support (optional) — "Best Use of Render" path.
//
// The scan pipeline also runs as a managed Render Workflow task
// (workflow/index.js + scripts/workflow-run.js). When RENDER_API_KEY and
// RENDER_WORKFLOW_TASK are set, clients can POST /api/scan/workflow to kick
// off a workflow run instead of streaming in-process, then poll its status.
// ----------------------------------------------------------------
const RENDER_API_BASE = 'https://api.render.com/v1';
const RENDER_API_KEY = process.env.RENDER_API_KEY || '';
const RENDER_WORKFLOW_TASK = process.env.RENDER_WORKFLOW_TASK || ''; // e.g. patch-scan/scan_repo

async function renderApi(path, options = {}) {
  const res = await fetch(`${RENDER_API_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${RENDER_API_KEY}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

/**
 * POST /api/scan/workflow — start a scan as a Render Workflow task run.
 * Body: { url }
 * Response: { taskRunId, task, status }
 * The run executes on its own Render instance; poll with GET below.
 */
app.post('/api/scan/workflow', async (req, res) => {
  if (!RENDER_API_KEY || !RENDER_WORKFLOW_TASK) {
    return res.status(503).json({
      error: 'Render Workflows not configured — set RENDER_API_KEY and RENDER_WORKFLOW_TASK',
    });
  }
  const url = req.body && req.body.url;
  if (typeof url !== 'string' || !url.trim()) {
    return res.status(400).json({ error: 'Missing required body field: url' });
  }
  try {
    validateRepoUrl(url);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  try {
    const { status, body } = await renderApi('/task-runs', {
      method: 'POST',
      body: JSON.stringify({ task: RENDER_WORKFLOW_TASK, input: [url.trim()] }),
    });
    if (status !== 201 && status !== 200) {
      return res.status(502).json({ error: `Render API ${status}: ${JSON.stringify(body).slice(0, 300)}` });
    }
    const taskRunId = body.taskRunId || body.id;
    if (!taskRunId) {
      return res.status(502).json({ error: `Render API returned no run id: ${JSON.stringify(body).slice(0, 300)}` });
    }
    res.json({ taskRunId, task: RENDER_WORKFLOW_TASK, status: body.status || 'pending' });
  } catch (err) {
    res.status(502).json({ error: `Render API unreachable: ${err.message}` });
  }
});

/**
 * GET /api/scan/workflow/:taskRunId — poll a workflow run.
 * Response: { taskRunId, status, results?, error? }
 * status: pending | running | completed | failed | canceled
 * When completed, results is the full scan report and the run is recorded
 * into scan history so it appears on the dashboard.
 */
app.get('/api/scan/workflow/:taskRunId', async (req, res) => {
  if (!RENDER_API_KEY || !RENDER_WORKFLOW_TASK) {
    return res.status(503).json({ error: 'Render Workflows not configured' });
  }
  try {
    const { status, body } = await renderApi(`/task-runs/${req.params.taskRunId}`);
    if (status !== 200) {
      return res.status(502).json({ error: `Render API ${status}: ${JSON.stringify(body).slice(0, 300)}` });
    }
    const results = Array.isArray(body.results) ? body.results[0] : null;
    if (body.status === 'completed' && results && !scanDetails.has(`wf-${req.params.taskRunId}`)) {
      recordScan(
        {
          id: `wf-${req.params.taskRunId}`,
          repo: (Array.isArray(body.input) ? body.input[0] : null) || results.meta?.repo || 'workflow',
          date: body.completedAt || new Date().toISOString(),
          status: 'completed',
          summary: {
            totalFindings: results.summary?.totalFindings ?? 0,
            bySeverity: results.summary?.bySeverity ?? {},
            secrets: results.summary?.secrets ?? 0,
            injection: results.summary?.injection ?? 0,
            dependencies: results.summary?.dependencies ?? 0,
          },
        },
        results
      );
    }
    res.json({
      taskRunId: req.params.taskRunId,
      status: body.status,
      results: body.status === 'completed' ? results : undefined,
      error: body.error || undefined,
    });
  } catch (err) {
    res.status(502).json({ error: `Render API unreachable: ${err.message}` });
  }
});

const port = Number(process.env.PORT) || 4000;
app.listen(port, () => {
  console.log(`PATCH backend listening on http://localhost:${port}`);
  console.log(`  CVE lookup:   ${process.env.TAVILY_API_KEY ? 'ON (Tavily)' : 'OFF — set TAVILY_API_KEY'}`);
  console.log(`  AI patches:   ${process.env.LLM_API_KEY || process.env.DASHSCOPE_API_KEY ? 'ON' : 'OFF (deterministic fallback) — set LLM_API_KEY or DASHSCOPE_API_KEY'}`);
  console.log(`  Workflows:    ${RENDER_API_KEY && RENDER_WORKFLOW_TASK ? `ON (${RENDER_WORKFLOW_TASK})` : 'OFF — set RENDER_API_KEY + RENDER_WORKFLOW_TASK'}`);
});
