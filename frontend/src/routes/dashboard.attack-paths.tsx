import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Waypoints, Play, Loader2, Route as RouteIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { ErrorState, EmptyState } from '@/components/dashboard/states'
import { ParetoChart } from '@/components/attack/ParetoChart'
import { PathList, prettyObjective } from '@/components/attack/PathList'
import { NetworkBuilder } from '@/components/attack/NetworkBuilder'
import { WhatIfPanel } from '@/components/attack/WhatIfPanel'
import { attackPathApi, ApiError, type AttackPathResponse, type AttackPathNode, type AttackPathVuln } from '@/api/client'
import { formatTime, cn } from '@/lib/utils'

export const Route = createFileRoute('/dashboard/attack-paths')({
  component: AttackPathsPage,
})

type Tab = 'sample' | 'custom'

function AttackPathsPage() {
  const [tab, setTab] = useState<Tab>('sample')
  const [result, setResult] = useState<AttackPathResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [customSpec, setCustomSpec] = useState<{ nodes: AttackPathNode[]; vulnerabilities: AttackPathVuln[] } | null>(null)

  const onError = (e: unknown) => {
    setError(e instanceof ApiError ? e.message : 'Analysis failed.')
    setResult(null)
  }

  const sampleMutation = useMutation({
    mutationFn: () => attackPathApi.sample(),
    onSuccess: (res) => { setResult(res); setError(null) },
    onError,
  })

  const analyzeMutation = useMutation({
    mutationFn: (input: { nodes: AttackPathNode[]; vulnerabilities: AttackPathVuln[] }) =>
      attackPathApi.analyze({ ...input, max_depth: 8 }),
    onSuccess: (res) => { setResult(res); setError(null) },
    onError,
  })

  const paths = result?.paths.pareto_optimal ?? []

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold">Attack paths</h1>
        <p className="text-muted">
          Pareto-optimal paths balancing success probability, time-to-exploit and business impact.
        </p>
      </header>

      {/* Tabs */}
      <div className="flex w-fit gap-1 rounded-xl border border-line bg-surface/40 p-1">
        {(['sample', 'custom'] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={cn(
              'rounded-lg px-4 py-1.5 text-sm transition-colors',
              tab === t ? 'bg-cyber/15 text-cyber' : 'text-muted hover:text-fg',
            )}
          >
            {t === 'sample' ? 'Sample network' : 'Build your own'}
          </button>
        ))}
      </div>

      {tab === 'sample' ? (
        <Card className="flex flex-col items-start gap-4">
          <p className="text-sm text-muted">
            Run NAMOA* over a built-in sample enterprise network to see the Pareto front.
          </p>
          <Button onClick={() => sampleMutation.mutate()} disabled={sampleMutation.isPending}>
            {sampleMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Run sample analysis
          </Button>
        </Card>
      ) : (
        <Card>
          <NetworkBuilder
            isPending={analyzeMutation.isPending}
            onAnalyze={(nodes, vulnerabilities) => {
              setCustomSpec({ nodes, vulnerabilities })
              analyzeMutation.mutate({ nodes, vulnerabilities })
            }}
          />
        </Card>
      )}

      {error && <ErrorState error={error} />}

      {result && (
        <div className="flex flex-col gap-6">
          {/* Risk summary */}
          <div className="flex flex-wrap gap-3">
            {Object.entries(result.risk_summary).map(([k, v]) => (
              <div key={k} className="flex min-w-[9rem] flex-1 flex-col gap-1 rounded-2xl border border-line bg-surface/40 p-4">
                <span className="font-display text-2xl font-bold text-cyber">{String(v)}</span>
                <span className="text-xs text-muted">{prettyObjective(k)}</span>
              </div>
            ))}
          </div>

          {paths.length === 0 ? (
            <EmptyState
              Icon={RouteIcon}
              title="No non-dominated paths"
              description="The graph needs at least one entry point and one critical asset, connected by vulnerabilities."
            />
          ) : (
            <>
              <Card>
                <h2 className="mb-4 text-lg font-semibold">Pareto front</h2>
                <ParetoChart paths={paths} />
              </Card>
              <div className="flex flex-col gap-3">
                <div className="flex items-center gap-2">
                  <Waypoints className="h-5 w-5 text-cyber" />
                  <h2 className="text-lg font-semibold">{paths.length} optimal path{paths.length === 1 ? '' : 's'}</h2>
                </div>
                <PathList paths={paths} />
              </div>
            </>
          )}

          {tab === 'custom' && customSpec && paths.length > 0 && (
            <WhatIfPanel nodes={customSpec.nodes} vulnerabilities={customSpec.vulnerabilities} />
          )}

          <span className="text-xs text-faint">Computed in {formatTime(result.processing_time_ms)}</span>
        </div>
      )}
    </div>
  )
}
