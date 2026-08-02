'use client'

import { useState } from 'react'
import { DashboardHome } from '@/components/dashboard-home'
import { InputScreen } from '@/components/input-screen'
import { PipelineDisplay } from '@/components/pipeline-display'
import { ResultsScreen, type Finding } from '@/components/results-screen'

type Screen = 'home' | 'input' | 'pipeline' | 'results'

export default function Page() {
  const [currentScreen, setCurrentScreen] = useState<Screen>('home')
  const [repoUrl, setRepoUrl] = useState('')
  const [findings, setFindings] = useState<Finding[]>([])

  const handleNewScan = () => {
    setCurrentScreen('input')
    setRepoUrl('')
    setFindings([])
  }

  const handleScan = (url: string) => {
    setRepoUrl(url)
    setCurrentScreen('pipeline')
  }

  const handlePipelineComplete = (results: Finding[]) => {
    setFindings(results)
    setCurrentScreen('results')
  }

  const handleBackToHome = () => {
    // Land back on the dashboard so the just-finished scan appears in Recent Scans.
    setCurrentScreen('home')
    setRepoUrl('')
    setFindings([])
  }

  return (
    <main className="bg-black min-h-screen">
      {currentScreen === 'home' && <DashboardHome onNewScan={handleNewScan} />}
      {currentScreen === 'input' && <InputScreen onScan={handleScan} isLoading={false} />}
      {currentScreen === 'pipeline' && <PipelineDisplay repoUrl={repoUrl} onComplete={handlePipelineComplete} />}
      {currentScreen === 'results' && <ResultsScreen findings={findings} onBackToHome={handleBackToHome} />}
    </main>
  )
}
