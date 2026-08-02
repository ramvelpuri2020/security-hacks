// Shared Finding type + mapper from backend finding objects.
// Used by the pipeline display (live scan), the results screen,
// and the dashboard's history drill-down (GET /api/history/:id).

export type Finding = {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  file: string
  line: number
  title: string
  description: string
  vulnerable: string
  patch: string
  cveId?: string
  cveUrl?: string
}

// Map a backend finding to the Finding type used by the results screen.
export function toFinding(raw: any): Finding {
  return {
    id: String(raw.id),
    severity: raw.severity,
    file: raw.file,
    line: raw.line,
    title: raw.label,
    description: raw.explanation || raw.description,
    vulnerable: raw.code,
    patch: raw.patch || '',
    cveId: raw.cveId,
    cveUrl: raw.cveUrl,
  }
}

// Dependency extracted from a repo manifest (package.json / requirements.txt).
export type Dependency = {
  name: string
  version: string
  ecosystem: string
  source?: string
  section?: string
  range?: string
}

// One dependency's live CVE research result (from the `cve` events / report).
export type CveResult = {
  dep: Dependency
  status: 'ok' | 'skipped' | 'none' | 'error' | string
  cves?: string[]
  error?: string
}
