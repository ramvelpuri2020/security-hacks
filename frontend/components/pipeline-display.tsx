'use client'

import { useEffect, useRef, useState } from 'react'
import { PipelineStepper, type PipelineStage } from './pipeline-stepper'
import type { Finding } from './results-screen'

interface PipelineDisplayProps {
  repoUrl: string
  onComplete: (findings: Finding[]) => void
}

// Backend base URL — override with NEXT_PUBLIC_API_BASE (e.g. your Render URL in prod).
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:4000'

// Map a backend finding to the Finding type used by the results screen.
function toFinding(raw: any): Finding {
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

export function PipelineDisplay({
  repoUrl,
  onComplete,
}: PipelineDisplayProps) {
  const [stages, setStages] = useState<PipelineStage[]>([
    { id: 'clone', label: 'Cloning repository...', status: 'pending' },
    { id: 'secrets', label: 'Scanning for secrets...', status: 'pending' },
    { id: 'injection', label: 'Checking for injection risks...', status: 'pending' },
    { id: 'deps', label: 'Parsing dependencies...', status: 'pending' },
    { id: 'cve', label: 'Cross-referencing CVE database...', status: 'pending' },
    { id: 'patches', label: 'Generating patches...', status: 'pending' },
  ])
  const [error, setError] = useState('')

  const findingsRef = useRef<any[]>([])
  const cveCountRef = useRef(0)
  const doneRef = useRef(false)

  const setStage = (
    id: string,
    patch: Partial<PipelineStage> | ((prev: PipelineStage) => Partial<PipelineStage>)
  ) => {
    setStages((prev) =>
      prev.map((s) =>
        s.id === id
          ? { ...s, ...(typeof patch === 'function' ? patch(s) : patch) }
          : s
      )
    )
  }

  useEffect(() => {
    findingsRef.current = []
    cveCountRef.current = 0
    doneRef.current = false
    setError('')

    const es = new EventSource(
      `${API_BASE}/api/scan?url=${encodeURIComponent(repoUrl)}`
    )

    es.addEventListener('step', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      if (data.step === 'clone') setStage('clone', { status: 'running' })
      else if (data.step === 'scan') {
        setStage('clone', { status: 'complete' })
        setStage('secrets', { status: 'running' })
      } else if (data.step === 'cve') setStage('cve', { status: 'running' })
      else if (data.step === 'patch') {
        // CVE stage is done once patch generation begins — but don't
        // clobber a result that was already shown (skipped / no deps / error).
        const cves = cveCountRef.current
        setStage('cve', (prev) =>
          prev.status === 'complete' || prev.result
            ? {}
            : {
                status: 'complete',
                result:
                  cves > 0
                    ? `matched ${cves} known CVE${cves === 1 ? '' : 's'}`
                    : 'no CVEs matched',
              }
        )
        setStage('patches', { status: 'running' })
      }
    })

    es.addEventListener('scan', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      setStage('secrets', {
        status: 'complete',
        result: `found ${data.secrets} secret${data.secrets === 1 ? '' : 's'}`,
      })
      setStage('injection', {
        status: 'complete',
        result: `detected ${data.injection} injection risk${data.injection === 1 ? '' : 's'}`,
      })
      setStage('deps', {
        status: 'complete',
        result: `parsed ${data.dependencies} dependencies`,
      })
    })

    es.addEventListener('finding', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      findingsRef.current.push(data)
    })

    es.addEventListener('cve', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      if (data.status === 'ok' && Array.isArray(data.cves)) {
        cveCountRef.current += data.cves.length
      } else if (data.status === 'skipped') {
        setStage('cve', { status: 'complete', result: 'CVE lookup skipped (no API key)' })
      } else if (data.status === 'none') {
        setStage('cve', { status: 'complete', result: 'no pinned dependencies' })
      } else if (data.status === 'error') {
        setStage('cve', {
          status: 'complete',
          result: `CVE lookup error: ${data.error || 'unknown'}`,
        })
      }
    })

    es.addEventListener('patch', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      setStage('patches', {
        status: 'running',
        result: `generating ${data.index + 1}/${data.total}...`,
      })
    })

    es.addEventListener('done', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      doneRef.current = true
      const count = findingsRef.current.length
      setStage('patches', {
        status: 'complete',
        result: `${count} patch${count === 1 ? '' : 'es'} generated`,
      })
      const results = data.results?.findings || findingsRef.current
      onComplete(results.map(toFinding))
      es.close()
    })

    es.addEventListener('error', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      doneRef.current = true
      setError(data.message || 'Scan failed')
      es.close()
    })

    es.onerror = () => {
      // Network-level failure (or stream closed before `done`).
      if (!doneRef.current) {
        setError('Could not reach the scan service. Is the backend running?')
      }
      es.close()
    }

    return () => es.close()
  }, [repoUrl, onComplete])

  return (
    <div className="min-h-screen bg-gradient-to-b from-black via-black to-neutral-900/50 flex items-center justify-center px-4 relative overflow-hidden">
      {/* Radial glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />

      {/* Main content */}
      <div className="relative w-full max-w-3xl z-10">
        <div className="space-y-8">
          {/* Header */}
          <div className="text-center space-y-2 mb-12">
            <h1 className="text-4xl font-bold tracking-tight text-foreground">Scanning Repository</h1>
            <p className="text-muted-foreground text-sm font-mono break-all">{repoUrl}</p>
          </div>

          {/* Pipeline stepper */}
          <PipelineStepper stages={stages} />

          {/* Status info */}
          <div className="text-center space-y-2 pt-4">
            {error ? (
              <p className="text-sm text-red-400 font-mono">{error}</p>
            ) : (
              <p className="text-xs text-muted-foreground">Running multi-stage security analysis...</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
