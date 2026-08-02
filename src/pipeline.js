import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

import { walkFiles } from './util.js';
import { scanForSecrets } from './scanners/secrets.js';
import { scanForInjection } from './scanners/injection.js';
import { extractDependencies } from './scanners/dependencies.js';
import { lookupDepCVE } from './cve.js';
import { generatePatch } from './patchgen.js';

const GIT_URL_RE =
  /^https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)\/[A-Za-z0-9_.\-]+\/[A-Za-z0-9_.\-]+(?:\/)?$/;

function throwIfAborted(signal) {
  if (signal && signal.aborted) {
    const err = new Error('Scan aborted by client');
    err.name = 'AbortError';
    throw err;
  }
}

export function validateRepoUrl(url) {
  if (typeof url !== 'string' || !GIT_URL_RE.test(url.trim())) {
    throw new Error(
      'Invalid repo URL. Expected a GitHub/GitLab/Bitbucket repository URL, e.g. https://github.com/owner/repo'
    );
  }
}

function runGitClone(url, dest) {
  return new Promise((resolve, reject) => {
    // Args array (never a shell string) — prevents any command injection from the URL.
    const args = ['clone', '--depth', '1', '--single-branch', '--quiet', url.trim(), dest];
    const proc = spawn('git', args, { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    proc.stderr.on('data', (d) => (stderr += d));
    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      reject(new Error('Clone timed out after 30s'));
    }, 30000);
    proc.on('error', (err) => {
      clearTimeout(timer);
      reject(new Error(`git binary unavailable: ${err.message}`));
    });
    proc.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`Clone failed (exit ${code}): ${stderr.slice(0, 400)}`));
    });
  });
}

/** Collect scannable files with hard caps so giant repos can't hang the demo. */
function collectFiles(root, limits) {
  const out = [];
  let bytes = 0;
  for (const entry of walkFiles(root)) {
    if (out.length >= limits.maxFiles) break;
    if (bytes + entry.size > limits.maxBytes) break;
    bytes += entry.size;
    out.push(entry);
  }
  return out;
}

/**
 * Run the full pipeline: clone -> scan -> CVE lookup -> patch generation.
 * Emits SSE-style events via `emit(type, data)`:
 *   step, scan, finding, cve, patch, done, error
 */
export async function runPipeline({
  url,
  localPath,
  emit = () => {},
  env = process.env,
  signal,
} = {}) {
  const limits = {
    maxBytes: Number(env.MAX_SCAN_BYTES) || 20_000_000,
    maxFiles: Number(env.MAX_SCAN_FILES) || 10_000,
  };

  let tmpDir = null;
  let scanRoot = null;
  const cveResults = [];

  try {
    // ---------- 1. CLONE ----------
    if (localPath) {
      scanRoot = path.resolve(localPath);
      emit('step', { step: 'clone', message: `Scanning local path: ${scanRoot}` });
    } else {
      validateRepoUrl(url);
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'patch-'));
      scanRoot = path.join(tmpDir, 'repo');
      emit('step', { step: 'clone', message: `Cloning ${url.trim()} (shallow clone)…` });
      await runGitClone(url, scanRoot);
      throwIfAborted(signal);
      emit('step', { step: 'clone', message: 'Clone complete' });
    }

    // ---------- 2. SCAN ----------
    throwIfAborted(signal);
    emit('step', { step: 'scan', message: 'Walking source tree…' });
    const files = collectFiles(scanRoot, limits);
    const secrets = scanForSecrets(files);
    const injection = scanForInjection(files);
    const deps = extractDependencies(scanRoot);
    const findings = [...secrets, ...injection];

    emit('scan', {
      filesScanned: files.length,
      secrets: secrets.length,
      injection: injection.length,
      dependencies: deps.length,
    });
    for (const f of findings) emit('finding', f);

    // ---------- 3. CVE RESEARCH ----------
    const tavilyKey = env.TAVILY_API_KEY;
    if (deps.length > 0) {
      emit('step', {
        step: 'cve',
        message: tavilyKey
          ? `Looking up live CVEs for ${Math.min(deps.length, 20)} of ${deps.length} dependencies…`
          : 'Skipping CVE lookup — set TAVILY_API_KEY to enable live CVE research',
      });
      for (const dep of deps.slice(0, 20)) {
        throwIfAborted(signal);
        const result = await lookupDepCVE(dep, tavilyKey, { signal });
        cveResults.push(result);
        emit('cve', result);
        if (!tavilyKey) break; // no key → emit the skip notice once and move on
      }
    } else {
      cveResults.push({ status: 'none', message: 'No pinned dependencies found to check' });
      emit('cve', { status: 'none', message: 'No pinned dependencies found to check' });
    }

    // ---------- 4. PATCH GENERATION ----------
    const llm = {
      apiKey: env.LLM_API_KEY,
      baseUrl: env.LLM_BASE_URL,
      model: env.LLM_MODEL,
    };
    emit('step', {
      step: 'patch',
      message: llm.apiKey
        ? `Generating patches for ${findings.length} finding${findings.length === 1 ? '' : 's'}…`
        : `Generating suggested fixes for ${findings.length} finding${findings.length === 1 ? '' : 's'} (deterministic mode — set LLM_API_KEY for AI patches)`,
    });

    for (let i = 0; i < findings.length; i++) {
      throwIfAborted(signal);
      const finding = findings[i];
      const patch = await generatePatch(finding, llm, signal);
      finding.patch = patch.patch;
      finding.explanation = patch.explanation;
      if (patch.llmError) finding.llmError = patch.llmError;
      emit('patch', {
        findingId: finding.id,
        index: i,
        total: findings.length,
        patch: patch.patch,
        explanation: patch.explanation,
        llmError: patch.llmError || null,
      });
    }

    // ---------- 5. ASSEMBLE ----------
    const bySeverity = {};
    for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    const results = {
      meta: {
        repo: localPath ? `local:${scanRoot}` : url.trim(),
        filesScanned: files.length,
        scannedBytes: files.reduce((a, f) => a + f.size, 0),
        scannedAt: new Date().toISOString(),
        llmMode: llm.apiKey ? 'ai' : 'deterministic',
        llmModel: llm.apiKey ? llm.model || 'default' : null,
        cveLookup: tavilyKey ? 'tavily' : 'off',
      },
      summary: {
        totalFindings: findings.length,
        bySeverity,
        secrets: secrets.length,
        injection: injection.length,
        dependencies: deps.length,
      },
      findings,
      dependencies: deps,
      cves: cveResults,
    };
    emit('done', { results });
    return results;
  } catch (err) {
    emit('error', { message: err && err.message || String(err) });
    throw err;
  } finally {
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
