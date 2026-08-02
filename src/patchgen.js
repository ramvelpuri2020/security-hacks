/**
 * Patch generation. Two modes:
 *  - LLM mode (LLM_API_KEY set): OpenAI-compatible chat completion asks the
 *    model to produce a focused explanation + a unified diff fixing the finding.
 *  - Deterministic mode (no key): a best-effort fix template derived from the
 *    finding itself, so the pipeline still works end-to-end without keys.
 */

/** Strip ```json fences / markdown from a raw LLM response to get pure JSON. */
function extractJson(raw) {
  if (!raw) return null;
  let text = String(raw).trim();
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) text = fence[1].trim();
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
}

/** Deterministic fix used when no LLM key is configured (or LLM call fails). */
export function deterministicPatch(finding) {
  const line = finding.code || '';
  if (finding.type === 'secret') {
    const env = finding.envVar || 'SECRET_VALUE';
    const hasMatch = finding.match && line.includes(finding.match);
    const fixed = hasMatch
      ? line.split(finding.match).join(`process.env.${env}`)
      : `process.env.${env} // TODO: remove the hardcoded value`;
    return {
      explanation: `Hardcoded credential detected. Replace the literal with a value read from the environment at runtime.`,
      patch: [
        `--- a/${finding.file}`,
        `+++ b/${finding.file}`,
        `@@ -${finding.line} +${finding.line} @@`,
        `-${line}`,
        `+${fixed}`,
        ``,
        `+// TODO: set ${env} in your deployment environment (env var / secrets manager)`,
      ].join('\n'),
    };
  }
  if (finding.type === 'injection') {
    return {
      explanation: `${finding.label}. ${finding.description}`,
      patch: [
        `--- a/${finding.file}`,
        `+++ b/${finding.file}`,
        `@@ -${finding.line} +${finding.line} @@`,
        `-${line}`,
        `+// FIX: ${finding.fix}`,
        `+// ${line}`,
      ].join('\n'),
    };
  }
  return {
    explanation: finding.description || 'Review this finding and apply the suggested fix.',
    patch: `--- a/${finding.file}\n+++ b/${finding.file}\n@@ -${finding.line} +${finding.line} @@\n-${line}\n+// FIX: ${finding.fix || 'review and fix'}`,
  };
}

/**
 * Generate an explanation + unified-diff patch for one finding.
 * `llm` = { apiKey, baseUrl, model } — if apiKey is missing, uses deterministicPatch.
 */
export async function generatePatch(finding, llm = {}, signal) {
  const { apiKey, baseUrl = 'https://dashscope-us.aliyuncs.com/compatible-mode/v1', model = 'qwen-plus' } = llm;
  if (!apiKey) return deterministicPatch(finding);

  const system = [
    'You are a senior application security engineer. You receive a static-analysis finding',
    'about a codebase. Respond with ONLY a JSON object (no markdown fences) shaped like:',
    '{"explanation": "<2-4 sentence plain-language explanation of the vulnerability and impact>",',
    ' "patch": "<a unified diff (--- a/... / +++ b/... / @@ ... @@) that fixes the issue>"}',
    'The patch must reference the exact file and line given. Keep the diff minimal and correct.',
  ].join(' ');

  const user = JSON.stringify(
    {
      task: 'Generate a fix for this finding',
      finding: {
        label: finding.label,
        severity: finding.severity,
        file: finding.file,
        line: finding.line,
        code: finding.code,
        description: finding.description,
        suggestedFix: finding.fix,
        cveContext: finding.cveContext || null,
      },
    },
    null,
    2
  );

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  // Link the pipeline's abort signal (client disconnect) to this request.
  const fetchSignal = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      signal: fetchSignal,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0.2,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      }),
    });
    if (!res.ok) {
      return { ...deterministicPatch(finding), llmError: `HTTP ${res.status}` };
    }
    const data = await res.json();
    const content = data?.choices?.[0]?.message?.content;
    const parsed = extractJson(content);
    if (!parsed || !parsed.patch) {
      return { ...deterministicPatch(finding), llmError: 'unparseable response' };
    }
    return {
      explanation: parsed.explanation || deterministicPatch(finding).explanation,
      patch: parsed.patch,
    };
  } catch (err) {
    const timedOut = err && err.name === 'AbortError' && !signal?.aborted;
    return {
      ...deterministicPatch(finding),
      llmError: timedOut ? 'LLM request timed out' : String(err && err.message || err),
    };
  } finally {
    clearTimeout(timer);
  }
}
