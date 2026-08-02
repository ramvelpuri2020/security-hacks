'use client'

import { useEffect, useRef, useState } from 'react'
import { PipelineStepper, type PipelineStage } from './pipeline-stepper'
import { API_BASE } from '@/lib/api'
import { toFinding, type CveResult, type Dependency, type Finding } from '@/lib/findings'

export interface ScanMeta {
  truncated?: boolean
  truncatedMessage?: string | null
  cves?: CveResult[]
  dependencies?: Dependency[]
}

interface PipelineDisplayProps {
  repoUrl: string
  onComplete: (findings: Finding[], meta?: ScanMeta) => void
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
  const [llmFallback, setLlmFallback] = useState('')
  const [stalled, setStalled] = useState(false)
  const [truncated, setTruncated] = useState(false)
  const [truncatedMessage, setTruncatedMessage] = useState('')

  const findingsRef = useRef<any[]>([])
  const cveCountRef = useRef(0)
  const doneRef = useRef(false)
  const lastEventRef = useRef(Date.now())
  const truncatedRef = useRef(false)
  const truncatedMessageRef = useRef('')

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
    lastEventRef.current = Date.now()
    truncatedRef.current = false
    truncatedMessageRef.current = ''
    setError('')
    setLlmFallback('')
    setStalled(false)
    setTruncated(false)
    setTruncatedMessage('')

    // If no SSE events arrive for a while (e.g. LLM endpoint hanging), show a
    // nudge so the user knows the scan is still running rather than frozen.
    // Threshold is above the AI semantic analysis budget (up to 120s) so a
    // legitimately long analysis isn't falsely flagged as stalled.
    const stallTimer = setInterval(() => {
      if (doneRef.current) return
      if (Date.now() - lastEventRef.current > 130000) {
        setStalled(true)
      }
    }, 5000)

    const es = new EventSource(
      `${API_BASE}/api/scan?url=${encodeURIComponent(repoUrl)}`
    )

    const markEvent = () => {
      lastEventRef.current = Date.now()
      setStalled(false)
    }

    es.addEventListener('step', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      markEvent()
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
      markEvent()
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
      // Partial-scan honesty: remember truncation so the results screen can
      // tell the user this wasn't a full-repo scan.
      if (data.truncated) {
        truncatedRef.current = true
        truncatedMessageRef.current =
          data.truncatedMessage ||
          'This repo exceeds scan limits — results reflect a partial scan, not the full repository.'
        setTruncated(true)
        setTruncatedMessage(truncatedMessageRef.current)
      }
    })

    es.addEventListener('finding', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      findingsRef.current.push(data)
    })

    es.addEventListener('cve', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      markEvent()
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
      markEvent()
      setStage('patches', {
        status: 'running',
        result: `generated ${data.done ?? data.index + 1}/${data.total}`,
      })
      if (data.llmError) {
        setLlmFallback(String(data.llmError))
      }
    })

    es.addEventListener('done', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      markEvent()
      doneRef.current = true
      setStalled(false)
      const count = findingsRef.current.length
      setStage('patches', {
        status: 'complete',
        result: `${count} patch${count === 1 ? '' : 'es'} generated`,
      })
      const results = data.results?.findings || findingsRef.current
      onComplete(results.map(toFinding), {
        truncated: truncatedRef.current,
        truncatedMessage: truncatedMessageRef.current || null,
        cves: Array.isArray(data.results?.cves) ? data.results.cves : undefined,
        dependencies: Array.isArray(data.results?.dependencies) ? data.results.dependencies : undefined,
      })
      es.close()
    })

    es.addEventListener('error', (event) => {
      const data = JSON.parse((event as MessageEvent).data)
      markEvent()
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

    return () => {
      clearInterval(stallTimer)
      es.close()
    }
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
            ) : stalled ? (
              <p className="text-sm text-yellow-400 font-mono">
                Still running — the scan service may be slow. Hang tight...
              </p>
            ) : llmFallback ? (
              <p className="text-xs text-yellow-400/80 font-mono">
                AI patch service unavailable ({llmFallback}) — showing suggested fixes
              </p>
            ) : truncated ? (
              <p className="text-xs text-amber-400/80 font-mono">⚠ {truncatedMessage}</p>
            ) : (
              <p className="text-xs text-muted-foreground">Running multi-stage security analysis...</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
