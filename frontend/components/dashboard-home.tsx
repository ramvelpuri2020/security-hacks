'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { BarChart3, Shield, ArrowRight, GitBranch, Plus, Boxes, XCircle } from 'lucide-react'
import { API_BASE } from '@/lib/api'

interface ScanSummary {
  id: string
  repo: string
  date: string
  status: 'completed' | 'failed'
  error?: string
  summary?: {
    totalFindings: number
    bySeverity: Record<string, number>
    secrets: number
    injection: number
    dependencies: number
  }
}

interface HistoryResponse {
  scans: ScanSummary[]
}

function timeAgo(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`
  const days = Math.floor(hours / 24)
  return `${days} day${days === 1 ? '' : 's'} ago`
}

function shortRepo(url: string): string {
  return url.replace(/^https?:\/\/(www\.)?(github\.com|gitlab\.com|bitbucket\.org)\//, '').replace(/\/$/, '')
}

interface DashboardHomeProps {
  onNewScan: () => void
  onViewScan: (id: string) => void
}

export function DashboardHome({ onNewScan, onViewScan }: DashboardHomeProps) {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    fetch(`${API_BASE}/api/history`)
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return res.json() as Promise<HistoryResponse>
      })
      .then((data) => {
        if (!cancelled) setScans(data.scans || [])
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'failed to load scan history')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const completed = scans.filter((s) => s.status === 'completed')
  const totalScans = scans.length
  const totalFindings = completed.reduce((acc, s) => acc + (s.summary?.totalFindings ?? 0), 0)
  const criticalFindings = completed.reduce((acc, s) => acc + (s.summary?.bySeverity?.critical ?? 0), 0)
  const totalDependencies = completed.reduce((acc, s) => acc + (s.summary?.dependencies ?? 0), 0)

  const stats = [
    { label: 'Total Scans', value: totalScans, sub: 'repositories analyzed', tone: 'text-green-500' },
    { label: 'Total Findings', value: totalFindings, sub: 'issues detected', tone: 'text-orange-500' },
    { label: 'Critical Issues', value: criticalFindings, sub: 'require attention', tone: 'text-primary' },
    { label: 'Dependencies Scanned', value: totalDependencies, sub: 'across all repos', tone: 'text-green-500' },
  ]

  return (
    <div className="min-h-screen bg-gradient-to-b from-black via-black to-neutral-900/50">
      {/* Header */}
      <div className="border-b border-white/8 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                <Shield className="w-6 h-6 text-primary" />
              </div>
              <h1 className="text-3xl font-bold tracking-tight">Security Scanner</h1>
            </div>
            <Button onClick={onNewScan} size="lg" className="gap-2">
              <Plus className="w-4 h-4" />
              New Scan
            </Button>
          </div>
          <p className="text-muted-foreground mt-2">Real-time vulnerability detection for your repositories</p>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-12">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-12">
          {stats.map((stat) => (
            <Card key={stat.label} className="glass-card border-white/8 bg-white/3">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">{stat.label}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold">
                    {loading ? <span className="animate-pulse text-muted-foreground">—</span> : stat.value}
                  </span>
                  <span className={`text-xs ${stat.tone}`}>{stat.sub}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Recent Scans */}
        <Card className="glass-card border-white/8 bg-white/3 overflow-hidden">
          <CardHeader className="border-b border-white/8">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Recent Scans</CardTitle>
                <CardDescription>Your scanning activity — live from the backend</CardDescription>
              </div>
              <BarChart3 className="w-5 h-5 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="p-8 text-center text-sm text-muted-foreground animate-pulse">Loading scan history…</div>
            ) : error ? (
              <div className="p-8 text-center">
                <XCircle className="w-8 h-8 text-red-400 mx-auto mb-3" />
                <p className="text-sm text-red-400">Could not reach the scan service ({error})</p>
                <p className="text-xs text-muted-foreground mt-1">Make sure the backend is running and NEXT_PUBLIC_API_BASE points at it.</p>
              </div>
            ) : scans.length === 0 ? (
              <div className="p-12 text-center">
                <Boxes className="w-10 h-10 text-muted-foreground/40 mx-auto mb-4" />
                <p className="font-medium text-muted-foreground">No scans yet</p>
                <p className="text-sm text-muted-foreground/70 mt-1 mb-6">Run your first scan to see real results here.</p>
                <Button onClick={onNewScan} className="gap-2">
                  <Plus className="w-4 h-4" />
                  Run your first scan
                </Button>
              </div>
            ) : (
              <div className="divide-y divide-white/8">
                {scans.map((scan, idx) => (
                  <button
                    key={scan.id}
                    onClick={() => scan.status === 'completed' && onViewScan(scan.id)}
                    disabled={scan.status !== 'completed'}
                    className={`w-full p-4 text-left transition-colors group ${
                      scan.status === 'completed'
                        ? 'hover:bg-white/5 cursor-pointer'
                        : 'cursor-default'
                    }`}
                    style={{ animationDelay: `${idx * 50}ms` }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4 flex-1">
                        <GitBranch className="w-4 h-4 text-muted-foreground" />
                        <div>
                          <p className="font-medium text-sm">{shortRepo(scan.repo)}</p>
                          <p className="text-xs text-muted-foreground">{timeAgo(scan.date)}</p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        {scan.status === 'failed' ? (
                          <Badge variant="secondary" className="bg-red-500/10 text-red-400 border-red-500/20">
                            Failed
                          </Badge>
                        ) : (
                          <>
                            {(scan.summary?.bySeverity?.critical ?? 0) > 0 && (
                              <Badge variant="destructive" className="bg-red-500/10 text-red-400 border-red-500/20">
                                {scan.summary?.bySeverity?.critical} Critical
                              </Badge>
                            )}
                            {(scan.summary?.bySeverity?.high ?? 0) > 0 && (
                              <Badge variant="secondary" className="bg-orange-500/10 text-orange-400 border-orange-500/20">
                                {scan.summary?.bySeverity?.high} High
                              </Badge>
                            )}
                            <span className="text-xs text-muted-foreground">
                              {scan.summary?.bySeverity?.medium ?? 0} med
                            </span>
                          </>
                        )}
                        <span className="text-xs text-primary opacity-0 group-hover:opacity-100 transition-opacity font-medium">
                          {scan.status === 'completed' ? 'View results →' : ''}
                        </span>
                      </div>
                    </div>
                    {scan.status === 'failed' && scan.error && (
                      <p className="text-xs text-red-400/70 mt-2 font-mono">{scan.error}</p>
                    )}
                  </button>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
