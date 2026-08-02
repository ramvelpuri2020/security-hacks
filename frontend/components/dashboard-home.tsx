'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { BarChart3, Shield, AlertOctagon, TrendingUp, ArrowRight, GitBranch, Plus } from 'lucide-react'

interface ScanResult {
  id: string
  repo: string
  date: string
  findings: {
    critical: number
    high: number
    medium: number
    low: number
  }
  status: 'completed' | 'running' | 'failed'
}

const recentScans: ScanResult[] = [
  {
    id: '1',
    repo: 'vercel/next.js',
    date: '2 hours ago',
    findings: { critical: 1, high: 2, medium: 3, low: 2 },
    status: 'completed',
  },
  {
    id: '2',
    repo: 'facebook/react',
    date: '1 day ago',
    findings: { critical: 0, high: 1, medium: 4, low: 3 },
    status: 'completed',
  },
  {
    id: '3',
    repo: 'torvalds/linux',
    date: '3 days ago',
    findings: { critical: 2, high: 5, medium: 8, low: 12 },
    status: 'completed',
  },
]

export function DashboardHome({ onNewScan }: { onNewScan: () => void }) {
  const totalScans = recentScans.length
  const totalFindings = recentScans.reduce((acc, scan) => {
    return acc + scan.findings.critical + scan.findings.high + scan.findings.medium + scan.findings.low
  }, 0)

  const criticalFindings = recentScans.reduce((acc, scan) => acc + scan.findings.critical, 0)

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
          <Card className="glass-card border-white/8 bg-white/3">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Scans</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold">{totalScans}</span>
                <span className="text-xs text-green-500 flex items-center gap-1">
                  <TrendingUp className="w-3 h-3" />
                  +2 this week
                </span>
              </div>
            </CardContent>
          </Card>

          <Card className="glass-card border-white/8 bg-white/3">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold">{totalFindings}</span>
                <span className="text-xs text-orange-500">Issues detected</span>
              </div>
            </CardContent>
          </Card>

          <Card className="glass-card border-white/8 bg-white/3">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">Critical Issues</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold text-primary">{criticalFindings}</span>
                <span className="text-xs text-red-500">Require attention</span>
              </div>
            </CardContent>
          </Card>

          <Card className="glass-card border-white/8 bg-white/3">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">Avg Fix Time</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold">2.3h</span>
                <span className="text-xs text-green-500">per issue</span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Recent Scans */}
        <Card className="glass-card border-white/8 bg-white/3 overflow-hidden">
          <CardHeader className="border-b border-white/8">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Recent Scans</CardTitle>
                <CardDescription>Your last scanning activity</CardDescription>
              </div>
              <BarChart3 className="w-5 h-5 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-white/8">
              {recentScans.map((scan, idx) => (
                <div
                  key={scan.id}
                  className="p-4 hover:bg-white/5 transition-colors cursor-pointer group"
                  style={{ animationDelay: `${idx * 50}ms` }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 flex-1">
                      <GitBranch className="w-4 h-4 text-muted-foreground" />
                      <div>
                        <p className="font-medium text-sm">{scan.repo}</p>
                        <p className="text-xs text-muted-foreground">{scan.date}</p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      {scan.findings.critical > 0 && (
                        <Badge variant="destructive" className="bg-red-500/10 text-red-400 border-red-500/20">
                          {scan.findings.critical} Critical
                        </Badge>
                      )}
                      {scan.findings.high > 0 && (
                        <Badge variant="secondary" className="bg-orange-500/10 text-orange-400 border-orange-500/20">
                          {scan.findings.high} High
                        </Badge>
                      )}
                      <span className="text-xs text-muted-foreground">{scan.findings.medium} med</span>

                      <ArrowRight className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
