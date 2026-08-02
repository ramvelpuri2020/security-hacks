import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

import { runPipeline } from './pipeline.js';

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

const port = Number(process.env.PORT) || 4000;
app.listen(port, () => {
  console.log(`PATCH backend listening on http://localhost:${port}`);
  console.log(`  CVE lookup:   ${process.env.TAVILY_API_KEY ? 'ON (Tavily)' : 'OFF — set TAVILY_API_KEY'}`);
  console.log(`  AI patches:   ${process.env.LLM_API_KEY || process.env.DASHSCOPE_API_KEY ? 'ON' : 'OFF (deterministic fallback) — set LLM_API_KEY or DASHSCOPE_API_KEY'}`);
});
