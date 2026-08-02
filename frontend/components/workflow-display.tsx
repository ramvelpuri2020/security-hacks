'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { API_BASE } from '@/lib/api'
import { toFinding, type Finding } from '@/lib/findings'
import { ArrowLeft, CheckCircle2, ExternalLink, Loader2, RefreshCw, Workflow, XCircle } from 'lucide-react'

interface WorkflowDisplayProps {
  repoUrl: string
  onComplete: (findings: Finding[]) => void
  onBack: () => void
}

type RunState =
  | { phase: 'starting' }
  | { phase: 'pending'; runId: string }
  | { phase: 'running'; runId: string }
  | { phase: 'error'; message: string }
  | { phase: 'done' }

const STATUS_TEXT: Record<string, string> = {
  pending: 'Queued — Render is provisioning a dedicated instance…',
  running: 'Scan running on Render’s managed infrastructure…',
}

/** Fetch with a hard timeout so the UI can never hang on a silent request. */
async function fetchWithTimeout(url: string, options: RequestInit = {}, ms = 15000) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), ms)
  try {
    const res = await fetch(url, { ...options, signal: controller.signal })
    return res
  } finally {
    clearTimeout(timer)
  }
}

export function WorkflowDisplay({ repoUrl, onComplete, onBack }: WorkflowDisplayProps) {
  const [state, setState] = useState<RunState>({ phase: 'starting' })
  const [elapsed, setElapsed] = useState(0)
  const onCompleteRef = useRef(onComplete)
  onCompleteRef.current = onComplete
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const startedRef = useRef(false)

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [])

  const poll = useCallback(
    async (runId: string) => {
      try {
        const res = await fetchWithTimeout(`${API_BASE}/api/scan/workflow/${runId}`, {}, 10000)
        const data = await res.json().catch(() => ({}))
        if (!res.ok) {
          stopPolling()
          setState({ phase: 'error', message: data.error || `Status check failed (HTTP ${res.status})` })
          return
        }
        if (data.status === 'completed') {
          stopPolling()
          const results = data.results
          const findings = Array.isArray(results?.findings) ? results.findings : []
          setState({ phase: 'done' })
          onCompleteRef.current(findings.map(toFinding))
          return
        }
        if (data.status === 'failed' || data.status === 'canceled') {
          stopPolling()
          setState({ phase: 'error', message: data.error || `Workflow run ${data.status}` })
          return
        }
        setState({ phase: data.status === 'pending' ? 'pending' : 'running', runId })
      } catch {
        stopPolling()
        setState({ phase: 'error', message: 'Lost connection while checking the workflow run.' })
      }
    },
    [stopPolling]
  )

  const startRun = useCallback(async () => {
    stopPolling()
    setState({ phase: 'starting' })
    setElapsed(0)
    try {
      const res = await fetchWithTimeout(
        `${API_BASE}/api/scan/workflow`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: repoUrl }),
        },
        20000
      )
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setState({ phase: 'error', message: data.error || `Could not start workflow (HTTP ${res.status})` })
        return
      }
      const runId = data.taskRunId
      if (!runId) {
        setState({ phase: 'error', message: 'Backend did not return a workflow run id.' })
        return
      }
      setState({ phase: 'pending', runId })
      poll(runId)
      pollRef.current = setInterval(() => poll(runId), 3000)
    } catch (err) {
      const timedOut = (err as { name?: string } | null)?.name === 'AbortError'
      setState({
        phase: 'error',
        message: timedOut
          ? `Timed out contacting the backend (${API_BASE}). Is the backend deployed and reachable?`
          : 'Could not reach the backend to start the workflow.',
      })
    }
  }, [repoUrl, poll, stopPolling])

  useEffect(() => {
    // Guard against React StrictMode double-mount in dev — otherwise two
    // workflow runs get kicked off.
    if (startedRef.current) return
    startedRef.current = true
    startRun()
    return stopPolling
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [startRun, stopPolling])

  useEffect(() => {
    if (state.phase !== 'pending' && state.phase !== 'running') return
    const t = setInterval(() => setElapsed((s) => s + 1), 1000)
    return () => clearInterval(t)
  }, [state.phase])

  const busy = state.phase === 'starting' || state.phase === 'pending' || state.phase === 'running'
  const runId = state.phase === 'pending' || state.phase === 'running' ? state.runId : null

  return (
    <div className="min-h-screen bg-gradient-to-b from-black via-black to-neutral-900/50 flex items-center justify-center px-4 relative overflow-hidden">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
      <div className="relative z-10 w-full max-w-xl">
        <div className="glass-panel p-8 md:p-10 space-y-6">
          {/* Header */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
                <Workflow className="w-6 h-6 text-primary" />
              </div>
            </div>
            <h1 className="text-2xl font-bold tracking-tight">Render Workflow Scan</h1>
            <p className="text-muted-foreground text-sm font-mono truncate">{repoUrl}</p>
          </div>

          {busy && (
            <div className="space-y-5">
              <div className="flex items-center gap-3">
                <Loader2 className="w-5 h-5 text-primary animate-spin" />
                <span className="text-sm text-muted-foreground">
                  {state.phase === 'starting' ? 'Contacting Render API…' : STATUS_TEXT[state.phase]}
                </span>
              </div>
              <div className="space-y-2">
                {['Clone repository', 'Scan for secrets & injection risks', 'Research live CVEs (Tavily)', 'Generate patches (Qwen)'].map((step, i) => (
                  <div key={step} className="flex items-center gap-3 text-sm">
                    <div
                      className={`w-2 h-2 rounded-full ${i <= 0 ? 'bg-primary animate-pulse' : 'bg-white/10'}`}
                    />
                    <span className={i <= 0 ? 'text-foreground' : 'text-muted-foreground/60'}>{step}</span>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-between text-xs text-muted-foreground/70 border-t border-white/8 pt-4">
                <span>Run ID: <span className="font-mono">{runId || '…'}</span></span>
                <span>{Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2, '0')} elapsed</span>
              </div>
              <a
                href="https://dashboard.render.com"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-primary/80 hover:text-primary transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Watch this run live in the Render dashboard (Workflows → securrity-hacks → scan_repo)
              </a>
            </div>
          )}

          {state.phase === 'done' && (
            <div className="flex flex-col items-center gap-3 text-center">
              <CheckCircle2 className="w-10 h-10 text-emerald-400" />
              <p className="text-sm text-muted-foreground">Workflow completed — loading results…</p>
            </div>
          )}

          {state.phase === 'error' && (
            <div className="space-y-4">
              <div className="flex items-start gap-3 px-4 py-3 rounded-lg bg-destructive/10 border border-destructive/30">
                <XCircle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
                <div className="text-sm text-destructive space-y-1">
                  <p className="font-medium">Workflow failed to start</p>
                  <p className="text-destructive/80">{state.message}</p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <button
                  onClick={startRun}
                  className="inline-flex items-center gap-2 text-sm text-primary hover:text-primary/80 transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                  Retry
                </button>
                <button
                  onClick={onBack}
                  className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                >
                  <ArrowLeft className="w-4 h-4" />
                  Back to input
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
