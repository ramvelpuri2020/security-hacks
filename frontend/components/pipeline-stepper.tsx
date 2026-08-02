'use client'

import { Check } from 'lucide-react'

export type PipelineStage = {
  id: string
  label: string
  status: 'pending' | 'running' | 'complete'
  result?: string
}

interface PipelineStepperProps {
  stages: PipelineStage[]
}

export function PipelineStepper({ stages }: PipelineStepperProps) {
  return (
    <div className="w-full max-w-2xl mx-auto space-y-1">
      {stages.map((stage, index) => (
        <div
          key={stage.id}
          className="group animate-in fade-in slide-in-from-left-4"
          style={{
            animationDelay: `${index * 100}ms`,
            animationFillMode: 'both',
          }}
        >
          <div
            className={`px-6 py-4 rounded-lg transition-all duration-300 border ${
              stage.status === 'pending'
                ? 'bg-black border-white/5 text-muted-foreground'
                : stage.status === 'running'
                  ? 'bg-black border-white/10 text-foreground'
                  : 'bg-black border-white/5 text-foreground'
            }`}
          >
            <div className="flex items-center gap-4 relative">
              {/* Status indicator circle */}
              <div className="flex-shrink-0 relative">
                {stage.status === 'pending' ? (
                  <div className="w-6 h-6 rounded-full border-2 border-white/20" />
                ) : stage.status === 'running' ? (
                  <div className="relative w-6 h-6">
                    <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-primary border-r-primary animate-spin" />
                    <div
                      className="absolute inset-1 rounded-full bg-primary/20 animate-pulse"
                      style={{
                        boxShadow: '0 0 12px rgba(239, 68, 68, 0.4)',
                      }}
                    />
                  </div>
                ) : (
                  <div className="w-6 h-6 rounded-full bg-primary flex items-center justify-center animate-in zoom-in">
                    <Check className="w-4 h-4 text-white" />
                  </div>
                )}
              </div>

              {/* Stage label and result */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3">
                  <span
                    className={`text-sm font-medium transition-colors ${
                      stage.status === 'running' ? 'text-primary' : ''
                    }`}
                  >
                    {stage.label}
                  </span>
                  {stage.status === 'running' && (
                    <span className="inline-block text-xs px-2 py-1 rounded bg-primary/10 text-primary font-mono">
                      scanning...
                    </span>
                  )}
                </div>
                {stage.result && stage.status === 'complete' && (
                  <div className="mt-2 text-xs text-muted-foreground font-mono px-2 py-1 bg-white/5 rounded inline-block max-w-full">
                    {stage.result}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
