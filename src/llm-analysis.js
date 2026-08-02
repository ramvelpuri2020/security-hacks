/**
 * Universal semantic vulnerability analysis.
 *
 * The deterministic regex scanners (secrets.js / injection.js) can never be
 * universal — every language has its own syntax (Python f-strings, Kotlin,
 * Go, PHP, Ruby…). Instead of writing a regex per language (an endless
 * whack-a-mole), this module sends the repository's actual source code to an
 * LLM and asks it to find vulnerabilities. The LLM understands every
 * language, so the SAME code path works for ANY repo.
 *
 * Findings are validated against the real file contents (file must exist,
 * line must be in range, the reported snippet must appear near that line) so
 * hallucinated findings get dropped.
 */
import fs from 'node:fs';
import path from 'node:path';
import { extractJson, normalizeBaseUrl } from './patchgen.js';

/** Max source characters sent to the LLM per analysis call (~100k tokens budget, kept safe). */
const MAX_ANALYSIS_CHARS = 90_000;

/** Cap on how many findings a single analysis pass may return. */
const MAX_FINDINGS = 12;

/** Files likely to contain interesting code — prioritize these when sampling. */
const PRIORITY_HINT = /(auth|login|password|token|secret|key|user|admin|api|route|controller|db|database|sql|query|upload|download|config|config\.|server|index|app|main|exec|shell|eval|deserialize|pickle|session|cookie)/i;

/** File extensions we consider "code worth sending to the LLM". */
const ANALYSIS_EXTS = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.py', '.rb', '.php', '.go', '.java', '.kt', '.kts', '.c', '.h', '.cpp', '.hpp', '.cs',
  '.sh', '.bash', '.zsh', '.ps1', '.html', '.htm', '.vue', '.sql',
  '.yaml', '.yml', '.toml', '.json', '.xml', '.ini', '.properties', '.gradle', '.env', '.txt', '.md',
]);

/** Build a line-numbered, length-capped view of a repo's source for the LLM. */
export function sampleSource(files, maxChars = MAX_ANALYSIS_CHARS) {
  // Prioritize code files by (1) priority hint in path, (2) smaller files first.
  const codeFiles = files
    .filter((f) => ANALYSIS_EXTS.has(f.ext) && !/lockfile|package-lock|yarn\.lock|pnpm-lock|\.min\./i.test(f.name))
    .sort((a, b) => {
      const pa = PRIORITY_HINT.test(a.rel) ? 1 : 0;
      const pb = PRIORITY_HINT.test(b.rel) ? 1 : 0;
      if (pa !== pb) return pb - pa;
      return a.size - b.size;
    });

  const out = [];
  let used = 0;
  for (const f of codeFiles) {
    if (used >= maxChars || out.length >= 40) break;
    let content;
    try {
      content = fs.readFileSync(f.full, 'utf8');
    } catch {
      continue;
    }
    const slice = content.slice(0, maxChars - used);
    out.push({ rel: f.rel, content: slice });
    used += slice.length;
  }
  return out;
}

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

/**
 * Ask the LLM to find security vulnerabilities in the repo's source code.
 * Works for ANY language — the model understands the code itself.
 *
 * Returns findings shaped like scanner findings:
 *   { id, type: 'semantic', detectorId, label, severity, confidence,
 *     file, line, code, match, description, fix }
 * Each finding is validated against the actual file contents; invalid or
 * hallucinated ones are dropped.
 */
export async function analyzeWithLLM(files, llm = {}, { signal, log = () => {} } = {}) {
  const {
    apiKey,
    baseUrl: rawBaseUrl,
    model = 'qwen-plus',
    timeoutMs = 60000,
  } = llm;
  // Self-heal malformed LLM_BASE_URL (DashScope native /api/v1 path or
  // trailing cruft like " model=qwen3.6-flash" pasted after the URL).
  const baseUrl = normalizeBaseUrl(rawBaseUrl) || 'https://dashscope-us.aliyuncs.com/compatible-mode/v1';
  // Return shape: { findings, failed } — `failed: true` means the LLM call
  // itself errored/timed out (NOT "nothing found"), so callers can report
  // the difference honestly instead of conflating a failure with a clean scan.
  if (!apiKey) return { findings: [], failed: false };

  const sample = sampleSource(files);
  if (sample.length === 0) return { findings: [], failed: false };

  const codeBlock = sample
    .map((s) => `\n===== FILE: ${s.rel} =====\n${s.content}`)
    .join('\n');

  const system = [
    'You are a senior application security engineer performing a static security review of source code.',
    'Find REAL security vulnerabilities in ANY programming language. Categories to look for:',
    '- Injection: SQL, NoSQL, command, template (SSTI), LDAP, XXE',
    '- Hardcoded secrets/credentials (API keys, passwords, tokens, private keys, IVs)',
    '- Broken authentication / authorization, IDOR',
    '- Insecure crypto (weak algorithms, hardcoded keys/IVs, improper padding)',
    '- XSS (DOM, stored, reflected), unsafe innerHTML',
    '- SSRF, path traversal, insecure file upload, unsafe deserialization (pickle/yaml/Java), RCE via eval/exec',
    '- Insecure defaults (WebView JS enabled, CORS *, debug backdoors, disabled TLS)',
    'Respond with ONLY a JSON object (no markdown fences) shaped like:',
    '{"findings":[{"type":"sql_injection","severity":"high","file":"src/app.js","line":12,"code":"const q = `SELECT * FROM users WHERE id=${id}`","label":"SQL injection via string interpolation","description":"...","fix":"..."}]}',
    'Rules:',
    '- file MUST be one of the FILE: paths shown above. line MUST be the actual line number where the issue is.',
    '- code MUST be the exact source line (or the exact snippet) at that line.',
    '- Only report issues you are confident are real. No style nits, no hypotheticals.',
    '- severity: critical | high | medium | low.',
    '- Return at most 12 findings, most severe first.',
    '- If no real vulnerabilities exist, return {"findings":[]}.',
  ].join(' ');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const fetchSignal = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;

  try {
    log(`[AI-ANALYSIS] requesting ${baseUrl}/chat/completions model=${model} chars=${codeBlock.length}`);
    const res = await fetch(`${baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      signal: fetchSignal,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0.1,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: codeBlock },
        ],
      }),
    });

    if (!res.ok) {
      const bodyText = await res.text().catch(() => '');
      log(`[AI-ANALYSIS] HTTP ${res.status} from ${baseUrl} model=${model} — body: ${bodyText.slice(0, 300)}`);
      return { findings: [], failed: true };
    }

    const data = await res.json();
    const content = data?.choices?.[0]?.message?.content;
    const parsed = extractJson(content);
    if (!parsed || !Array.isArray(parsed.findings)) {
      log(`[AI-ANALYSIS] unparseable response model=${model} — raw: ${String(content).slice(0, 300)}`);
      return { findings: [], failed: true };
    }

    // Build a lookup of file -> actual lines so we can validate + dedupe.
    const fileLines = new Map(); // rel -> array of line strings
    for (const s of sample) {
      fileLines.set(s.rel, s.content.split('\n'));
    }

    const findings = [];
    const seen = new Set();
    for (const raw of parsed.findings.slice(0, MAX_FINDINGS)) {
      if (!raw || typeof raw !== 'object') continue;
      const rel = String(raw.file || '').replace(/^\.\//, '');
      const lines = fileLines.get(rel);
      if (!lines) continue; // hallucinated file — drop
      const line = Number(raw.line);
      if (!Number.isInteger(line) || line < 1 || line > lines.length) continue; // bad line — drop

      // Validate the reported code snippet actually appears near that line.
      const actual = lines[line - 1] || '';
      const reported = String(raw.code || '').trim();
      const nearby = (lines.slice(Math.max(0, line - 3), line + 2) || []).join('\n');
      if (reported && !nearby.includes(reported.slice(0, 60))) continue; // fabricated snippet — drop

      const key = `${rel}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const severity = SEVERITIES.has(raw.severity) ? raw.severity : 'medium';
      findings.push({
        id: `semantic-${findings.length + 1}`,
        type: 'semantic',
        detectorId: 'llm_semantic_analysis',
        label: String(raw.label || raw.type || 'AI-detected vulnerability'),
        severity,
        confidence: 'llm',
        file: rel,
        line,
        code: reported || actual.trim(),
        match: reported || actual.trim(),
        description: String(raw.description || 'AI semantic analysis found a potential vulnerability here.'),
        fix: String(raw.fix || 'Review and fix this issue.'),
      });
    }
    return { findings, failed: false };
  } catch (err) {
    const timedOut = err && err.name === 'AbortError' && !signal?.aborted;
    log(
      `[AI-ANALYSIS] request failed — baseUrl: ${baseUrl}, model: ${model}, timeoutMs: ${timeoutMs}, error: ${timedOut ? `timed out after ${timeoutMs / 1000}s` : String((err && err.message) || err)}`
    );
    return { findings: [], failed: true };
  } finally {
    clearTimeout(timer);
  }
}
