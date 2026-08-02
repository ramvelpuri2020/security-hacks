'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ArrowRight, GitBranch, Sparkles } from 'lucide-react'

interface InputScreenProps {
  onScan: (repoUrl: string) => void
  isLoading?: boolean
}

export function InputScreen({ onScan, isLoading = false }: InputScreenProps) {
  const [repoUrl, setRepoUrl] = useState('https://github.com/vercel/next.js')
  const [error, setError] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (!repoUrl.trim()) {
      setError('Please enter a repository URL')
      return
    }

    if (!repoUrl.includes('github.com') || !repoUrl.includes('/') || repoUrl.split('/').length < 5) {
      setError('Please enter a valid GitHub repository URL')
      return
    }

    onScan(repoUrl)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.nativeEvent.isComposing) {
      handleSubmit(e as any)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-black via-black to-neutral-900/50 flex items-center justify-center px-4 relative overflow-hidden">
      {/* Background grid effect */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGRlZnM+PHBhdHRlcm4gaWQ9ImdyaWQiIHdpZHRoPSI2MCIgaGVpZ2h0PSI2MCIgcGF0dGVyblVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHBhdGggZD0iTSA2MCAwIEwgMCAwIDAgNjAiIGZpbGw9Im5vbmUiIHN0cm9rZT0icmdiYSgyNTUsIDI1NSwyNTUsIDAuMDMpIiBzdHJva2Utd2lkdGg9IjEiLz48L3BhdHRlcm4+PC9kZWZzPjxyZWN0IHdpZHRoPSIxMDAlIiBoZWlnaHQ9IjEwMCUiIGZpbGw9InVybCgjZ3JpZCkiLz48L3N2Zz4=')] opacity-30" />

      {/* Radial glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />

      <div className="relative z-10 w-full max-w-2xl">
        <div className="glass-panel p-8 md:p-12 space-y-8">
          {/* Header */}
          <div className="text-center space-y-3">
            <div className="flex justify-center mb-4">
              <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
                <GitBranch className="w-6 h-6 text-primary" />
              </div>
            </div>
            <h1 className="text-4xl font-bold tracking-tight">Security Scanner</h1>
            <p className="text-muted-foreground text-lg">
              Scan your repository for vulnerabilities, secrets, and security risks in real-time
            </p>
          </div>

          {/* Input Section */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="repo-url" className="text-sm font-medium text-foreground block">
                GitHub Repository URL
              </label>
              <div className="flex gap-2">
                <Input
                  id="repo-url"
                  type="text"
                  placeholder="https://github.com/owner/repo"
                  value={repoUrl}
                  onChange={(e) => {
                    setRepoUrl(e.target.value)
                    setError('')
                  }}
                  onKeyDown={handleKeyDown}
                  disabled={isLoading}
                  className="flex-1 bg-white/5 border-white/10 text-foreground placeholder:text-muted-foreground/50 focus:border-primary/50 focus:ring-1 focus:ring-primary/30 h-11 text-base"
                />
                <Button
                  type="submit"
                  disabled={isLoading || !repoUrl.trim()}
                  size="lg"
                  className="gap-2 px-8 bg-primary hover:bg-primary/90 h-11"
                >
                  {isLoading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Scanning
                    </>
                  ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    Scan
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
                </Button>
              </div>
            </div>

            {error && (
              <div className="px-4 py-3 rounded-lg bg-destructive/10 border border-destructive/30 text-destructive text-sm">
                {error}
              </div>
            )}
          </form>

          {/* Example repo suggestion */}
          <div className="pt-4 border-t border-white/8">
            <p className="text-xs text-muted-foreground mb-3">Example repositories:</p>
            <div className="grid grid-cols-2 gap-2">
              {['https://github.com/vercel/next.js', 'https://github.com/facebook/react'].map((url) => (
                <button
                  key={url}
                  onClick={() => {
                    setRepoUrl(url)
                    setError('')
                  }}
                  className="text-left px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs text-muted-foreground hover:text-foreground transition-all truncate font-mono"
                >
                  {url.replace('https://github.com/', '')}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
