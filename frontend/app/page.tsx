'use client'

import { useState } from 'react'
import { DashboardHome } from '@/components/dashboard-home'
import { InputScreen } from '@/components/input-screen'
import { PipelineDisplay, type ScanMeta } from '@/components/pipeline-display'
import { ResultsScreen } from '@/components/results-screen'
import { WorkflowDisplay } from '@/components/workflow-display'
import { API_BASE } from '@/lib/api'
import { toFinding, type Finding } from '@/lib/findings'

type Screen = 'home' | 'input' | 'pipeline' | 'workflow' | 'results'

// Partial-scan warning surfaced when a repo exceeded scan limits.
const WARNING_FALLBACK =
  'This repo exceeds scan limits — results reflect a partial scan, not the full repository.'

function warningFromMeta(meta?: ScanMeta | null): string | null {
  if (!meta?.truncated) return null
  return meta.truncatedMessage || WARNING_FALLBACK
}

export default function Page() {
  const [currentScreen, setCurrentScreen] = useState<Screen>('home')
  const [repoUrl, setRepoUrl] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])
  const [viewingScan, setViewingScan] = useState(false)
  const [warning, setWarning] = useState<string | null>(null)

  const handleNewScan = () => {
    setCurrentScreen('input')
    setRepoUrl('')
    setFindings([])
    setViewingScan(false)
    setWarning(null)
  }

  const handleScan = (url: string, mode: 'inline' | 'workflow' = 'inline') => {
    setRepoUrl(url)
    setCurrentScreen(mode === 'workflow' ? 'workflow' : 'pipeline')
  }

  const handlePipelineComplete = (results: Finding[], meta?: ScanMeta) => {
    setFindings(results)
    setWarning(warningFromMeta(meta))
    setViewingScan(false) // a fresh scan is not an archived re-open
    setCurrentScreen('results')
  }

  const handleViewScan = async (id: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/history/${id}`)
      if (!res.ok) return
      const data = await res.json()
      const scan = data.scan
      if (!scan) return
      setFindings((scan.findings || []).map(toFinding))
      setRepoUrl(scan.meta?.repo || '')
      setWarning(warningFromMeta(scan.meta))
      setViewingScan(true)
      setCurrentScreen('results')
    } catch {
      // History fetch failed — ignore; stay on the dashboard.
    }
  }

  const handleBackToHome = () => {
    // Land back on the dashboard so the just-finished scan appears in Recent Scans.
    setCurrentScreen('home')
    setRepoUrl('')
    setFindings([])
    setViewingScan(false)
    setWarning(null)
  }

  return (
    <main className="bg-black min-h-screen">
      {currentScreen === 'home' && <DashboardHome onNewScan={handleNewScan} onViewScan={handleViewScan} />}
      {currentScreen === 'input' && <InputScreen onScan={handleScan} isLoading={false} />}
      {currentScreen === 'pipeline' && <PipelineDisplay repoUrl={repoUrl} onComplete={handlePipelineComplete} />}
      {currentScreen === 'workflow' && (
        <WorkflowDisplay repoUrl={repoUrl} onComplete={handlePipelineComplete} onBack={() => setCurrentScreen('input')} />
      )}
      {currentScreen === 'results' && (
        <ResultsScreen
          findings={findings}
          onBackToHome={handleBackToHome}
          archived={viewingScan}
          warning={warning}
        />
      )}
    </main>
  )
}
