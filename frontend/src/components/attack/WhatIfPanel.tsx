import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Loader2, ShieldCheck, Zap } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import {
  attackPathApi, ApiError,
  type AttackPathNode, type AttackPathVuln, type WhatIfSummary,
} from '@/api/client'
import { cn } from '@/lib/utils'

/**
 * What-if remediation simulator (Phase 6, surfaces the D4 exact-incremental engine).
 * Pick CVE(s) to patch; the backend returns the before/after Pareto front and reachability
 * reduction, and tells you when the front is *provably unchanged* without re-searching (D4 skip).
 */
export function WhatIfPanel({
  nodes, vulnerabilities,
}: {
  nodes: AttackPathNode[]
  vulnerabilities: AttackPathVuln[]
}) {
  const [patched, setPatched] = useState<Set<string>>(new Set())
  const [summary, setSummary] = useState<WhatIfSummary | null>(null)
  const [error, setError] = useState<string | null>(null)

  const toggle = (cve: string) =>
    setPatched((prev) => {
      const next = new Set(prev)
      next.has(cve) ? next.delete(cve) : next.add(cve)
      return next
    })

  const mutation = useMutation({
    mutationFn: () =>
      attackPathApi.whatif({ nodes, vulnerabilities, patch_cves: [...patched], max_depth: 8 }),
    onSuccess: (res) => { setSummary(res.whatif); setError(null) },
    onError: (e: unknown) =>
      setError(e instanceof ApiError ? e.message : 'What-if simulation failed.'),
  })

  const cves = [...new Set(vulnerabilities.map((v) => v.cve_id))]

  return (
    <Card className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-5 w-5 text-cyber" />
        <h2 className="text-lg font-semibold">What-if: simulate patching</h2>
      </div>
      <p className="text-sm text-muted">
        Select the CVE(s) you&apos;re considering patching. The engine recomputes the Pareto front
        exactly — and when a patched CVE is on no optimal path, it proves the front is unchanged
        without re-searching.
      </p>

      <div className="flex flex-wrap gap-2">
        {cves.map((cve) => (
          <button
            key={cve}
            type="button"
            onClick={() => toggle(cve)}
            aria-pressed={patched.has(cve)}
            className={cn(
              'rounded-lg border px-3 py-1.5 text-xs transition-colors',
              patched.has(cve)
                ? 'border-cyber bg-cyber/15 text-cyber'
                : 'border-line bg-surface/40 text-muted hover:text-fg',
            )}
          >
            {cve}
          </button>
        ))}
      </div>

      <Button
        onClick={() => mutation.mutate()}
        disabled={mutation.isPending || patched.size === 0}
        className="w-fit"
      >
        {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
        Simulate patch
      </Button>

      {error && <p className="text-sm text-red-400">{error}</p>}

      {summary && (
        <div className="flex flex-col gap-3 rounded-2xl border border-line bg-surface/40 p-4">
          <div className="flex flex-wrap gap-6">
            <Metric label="Reachability before" value={summary.before_reachability.toFixed(3)} />
            <Metric label="Reachability after" value={summary.after_reachability.toFixed(3)} />
            <Metric
              label="Reduction"
              value={summary.reachability_reduction.toFixed(3)}
              highlight={summary.reachability_reduction > 0}
            />
            <Metric
              label="Optimal paths"
              value={`${summary.before_num_paths} → ${summary.after_num_paths}`}
            />
          </div>
          {summary.skipped_recompute && (
            <p className="text-xs text-faint">
              {summary.skip_reason ??
                'Patched CVE(s) lie on no optimal path — the front is provably unchanged (no re-search needed).'}
            </p>
          )}
        </div>
      )}
    </Card>
  )
}

function Metric({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className="flex flex-col gap-1">
      <span className={cn('font-display text-2xl font-bold', highlight ? 'text-cyber' : 'text-fg')}>
        {value}
      </span>
      <span className="text-xs text-muted">{label}</span>
    </div>
  )
}
