import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';

import { runPipeline } from './pipeline.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

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
