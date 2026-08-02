const TAVILY_ENDPOINT = 'https://api.tavily.com/search';

export function extractCveIds(text) {
  return [...new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((s) => s.toUpperCase()))];
}

/**
 * Look up known CVEs for a dependency via Tavily web search, restricted to
 * authoritative vulnerability databases (NVD + cve.org).
 *
 * Key-optional: without TAVILY_API_KEY it returns status:'skipped' so the
 * pipeline degrades gracefully.
 */
export async function lookupDepCVE(dep, apiKey, { timeoutMs = 15000, signal } = {}) {
  if (!apiKey) {
    return { dep, status: 'skipped', reason: 'TAVILY_API_KEY not set' };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  // Link the pipeline's abort signal (client disconnect) to this request.
  const fetchSignal = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
  try {
    const res = await fetch(TAVILY_ENDPOINT, {
      method: 'POST',
      signal: fetchSignal,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        query: `${dep.name} ${dep.version} CVE vulnerability`,
        search_depth: 'basic',
        max_results: 4,
        include_domains: ['nvd.nist.gov', 'cve.org'],
        include_answer: false,
      }),
    });
    if (!res.ok) {
      return { dep, status: 'error', error: `Tavily HTTP ${res.status}` };
    }
    const data = await res.json();
    const results = (data.results || []).map((r) => ({
      title: r.title,
      url: r.url,
      content: (r.content || '').slice(0, 500),
    }));
    const cves = extractCveIds(
      results.map((r) => `${r.title} ${r.url} ${r.content}`).join(' ')
    );
    return { dep, status: 'ok', cves, results };
  } catch (err) {
    const timedOut = err && err.name === 'AbortError' && !signal?.aborted;
    return {
      dep,
      status: 'error',
      error: timedOut
        ? 'Tavily request timed out'
        : String(err && err.message || err),
    };
  } finally {
    clearTimeout(timer);
  }
}
