'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { ChevronDown, ChevronUp, AlertTriangle, AlertCircle, AlertOctagon, ExternalLink, ArrowLeft } from 'lucide-react'

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

interface ResultsScreenProps {
  findings: Finding[]
  onBackToInput: () => void
}

const severityConfig = {
  critical: {
    icon: AlertOctagon,
    label: 'Critical',
    textColor: 'text-red-400',
    borderColor: 'border-l-red-500',
    badgeVariant: 'destructive' as const,
  },
  high: {
    icon: AlertTriangle,
    label: 'High',
    textColor: 'text-orange-400',
    borderColor: 'border-l-orange-500',
    badgeVariant: 'secondary' as const,
  },
  medium: {
    icon: AlertTriangle,
    label: 'Medium',
    textColor: 'text-yellow-400',
    borderColor: 'border-l-yellow-500',
    badgeVariant: 'secondary' as const,
  },
  low: {
    icon: AlertCircle,
    label: 'Low',
    textColor: 'text-blue-400',
    borderColor: 'border-l-blue-500',
    badgeVariant: 'secondary' as const,
  },
}

function FindingCard({ finding }: { finding: Finding }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const config = severityConfig[finding.severity]
  const Icon = config.icon

  return (
    <Card className={`glass-card border-l-4 ${config.borderColor} overflow-hidden hover:bg-white/6 transition-all cursor-pointer`}>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-6 py-4 flex items-start gap-4 text-left"
      >
        <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${config.textColor}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <h3 className="font-semibold text-foreground text-base">{finding.title}</h3>
            <Badge variant={config.badgeVariant} className="text-xs">
              {config.label}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">{finding.description}</p>
          <p className="text-xs text-muted-foreground/70 mt-2 font-mono">{finding.file}:{finding.line}</p>
        </div>
        <div className="flex-shrink-0 pt-1">
          {isExpanded ? (
            <ChevronUp className="w-5 h-5 text-muted-foreground" />
          ) : (
            <ChevronDown className="w-5 h-5 text-muted-foreground" />
          )}
        </div>
      </button>

      {isExpanded && (
        <CardContent className="pt-0 border-t border-white/8 space-y-4">
          {/* Vulnerable Code */}
          <div className="space-y-2">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Vulnerable Code</p>
            <div className="bg-black/50 rounded-lg border border-white/10 p-4 font-mono text-xs overflow-x-auto">
              <div className="text-red-400 line-through opacity-70">{finding.vulnerable}</div>
            </div>
          </div>

          {/* Patch */}
          <div className="space-y-2">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Recommended Fix</p>
            <div className="bg-black/50 rounded-lg border border-white/10 p-4 font-mono text-xs overflow-x-auto">
              <div className="text-green-400">{finding.patch}</div>
            </div>
          </div>

          {/* CVE */}
          {finding.cveId && (
            <div className="flex items-center gap-2 pt-2 border-t border-white/8">
              <span className="text-xs text-muted-foreground font-medium">Reference:</span>
              <a
                href={finding.cveUrl || `https://nvd.nist.gov/vuln/detail/${finding.cveId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-primary hover:text-primary/80 transition-colors flex items-center gap-1"
              >
                {finding.cveId}
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          )}
        </CardContent>
      )}
    </Card>
  )
}

export function ResultsScreen({
  findings,
  onBackToInput,
}: ResultsScreenProps) {
  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount = findings.filter((f) => f.severity === 'low').length

  const sortedFindings = [...findings].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
    return severityOrder[a.severity] - severityOrder[b.severity]
  })

  return (
    <div className="min-h-screen bg-gradient-to-b from-black via-black to-neutral-900/50 px-4 md:px-8 py-8 md:py-12">
      <div className="max-w-5xl mx-auto space-y-8">
        {/* Header with back button */}
        <div className="space-y-4">
          <Button
            variant="ghost"
            onClick={onBackToInput}
            className="gap-2 text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </Button>

          <div className="space-y-2">
            <h1 className="text-4xl font-bold tracking-tight text-foreground">Security Analysis Complete</h1>
            <p className="text-muted-foreground text-lg">
              {findings.length} issue{findings.length !== 1 ? 's' : ''} detected in this repository
            </p>
          </div>

          {/* Summary stats grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2">
            {[
              { count: criticalCount, label: 'Critical', color: 'text-red-400', bg: 'bg-red-500/10' },
              { count: highCount, label: 'High', color: 'text-orange-400', bg: 'bg-orange-500/10' },
              { count: mediumCount, label: 'Medium', color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
              { count: lowCount, label: 'Low', color: 'text-blue-400', bg: 'bg-blue-500/10' },
            ].map((stat) => (
              <Card key={stat.label} className="glass-card border-white/8">
                <CardContent className="p-4">
                  <p className={`text-2xl font-bold ${stat.color}`}>{stat.count}</p>
                  <p className="text-xs text-muted-foreground mt-1">{stat.label}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Findings list */}
        <div className="space-y-3">
          {sortedFindings.length > 0 ? (
            sortedFindings.map((finding, index) => (
              <div
                key={finding.id}
                className="fade-in-up"
                style={{
                  animationDelay: `${index * 50}ms`,
                }}
              >
                <FindingCard finding={finding} />
              </div>
            ))
          ) : (
            <Card className="glass-card border-green-500/20 bg-green-500/5">
              <CardContent className="p-12 text-center">
                <p className="text-green-400 font-semibold text-lg">✓ No vulnerabilities found</p>
                <p className="text-muted-foreground text-sm mt-2">This repository passed all security checks</p>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Footer */}
        <div className="py-8 border-t border-white/8 text-center text-xs text-muted-foreground">
          <p>Run another scan to continue analyzing your repositories</p>
        </div>
      </div>
    </div>
  )
}
