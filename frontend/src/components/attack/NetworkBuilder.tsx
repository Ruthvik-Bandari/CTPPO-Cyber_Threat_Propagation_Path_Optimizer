import { useState } from 'react'
import { Plus, Trash2, Loader2, Play } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import type { AttackPathNode, AttackPathVuln } from '@/api/client'

const SEED_NODES: AttackPathNode[] = [
  { id: 'internet', is_entry_point: true, is_critical_asset: false },
  { id: 'web01', is_entry_point: false, is_critical_asset: false },
  { id: 'db01', is_entry_point: false, is_critical_asset: true },
]

const SEED_VULNS: AttackPathVuln[] = [
  { cve_id: 'CVE-2021-44228', source: 'internet', target: 'web01', cvss_score: 9.8, has_exploit: true },
  { cve_id: 'CVE-2019-0708', source: 'web01', target: 'db01', cvss_score: 9.0, has_exploit: false },
]

const selectCls =
  'h-9 rounded-lg border border-line bg-base-2/60 px-2 text-sm text-fg outline-none focus:border-cyber/60'

interface NetworkBuilderProps {
  onAnalyze: (nodes: AttackPathNode[], vulns: AttackPathVuln[]) => void
  isPending: boolean
}

export function NetworkBuilder({ onAnalyze, isPending }: NetworkBuilderProps) {
  const [nodes, setNodes] = useState<AttackPathNode[]>(SEED_NODES)
  const [vulns, setVulns] = useState<AttackPathVuln[]>(SEED_VULNS)

  const nodeIds = nodes.map((n) => n.id).filter(Boolean)

  const setNode = (i: number, patch: Partial<AttackPathNode>) =>
    setNodes((prev) => prev.map((n, idx) => (idx === i ? { ...n, ...patch } : n)))
  const setVuln = (i: number, patch: Partial<AttackPathVuln>) =>
    setVulns((prev) => prev.map((v, idx) => (idx === i ? { ...v, ...patch } : v)))

  return (
    <div className="flex flex-col gap-6">
      {/* Nodes */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold">Hosts</h3>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setNodes((p) => [...p, { id: '', is_entry_point: false, is_critical_asset: false }])}
          >
            <Plus className="h-3.5 w-3.5" /> Host
          </Button>
        </div>
        <div className="flex flex-col gap-2">
          {nodes.map((n, i) => (
            <div key={i} className="flex flex-wrap items-center gap-3 rounded-xl border border-line-soft bg-surface/30 p-3">
              <Input
                value={n.id}
                onChange={(e) => setNode(i, { id: e.target.value })}
                placeholder="host id"
                className="h-9 w-40"
              />
              <label className="flex items-center gap-2 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={n.is_entry_point}
                  onChange={(e) => setNode(i, { is_entry_point: e.target.checked })}
                  className="accent-marine"
                />
                Entry point
              </label>
              <label className="flex items-center gap-2 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={n.is_critical_asset}
                  onChange={(e) => setNode(i, { is_critical_asset: e.target.checked })}
                  className="accent-crit"
                />
                Critical asset
              </label>
              <button
                type="button"
                aria-label="Remove host"
                onClick={() => setNodes((p) => p.filter((_, idx) => idx !== i))}
                className="ml-auto text-faint transition-colors hover:text-danger"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Vulnerabilities (edges) */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold">Vulnerabilities</h3>
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              setVulns((p) => [
                ...p,
                { cve_id: '', source: nodeIds[0] ?? '', target: nodeIds[1] ?? '', cvss_score: 7.5, has_exploit: false },
              ])
            }
          >
            <Plus className="h-3.5 w-3.5" /> Vulnerability
          </Button>
        </div>
        <div className="flex flex-col gap-2">
          {vulns.map((v, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2 rounded-xl border border-line-soft bg-surface/30 p-3">
              <Input
                value={v.cve_id}
                onChange={(e) => setVuln(i, { cve_id: e.target.value })}
                placeholder="CVE id"
                className="h-9 w-44"
              />
              <select value={v.source} onChange={(e) => setVuln(i, { source: e.target.value })} className={cn(selectCls)} aria-label="Source host">
                {nodeIds.map((id) => (
                  <option key={id} value={id}>{id}</option>
                ))}
              </select>
              <span className="text-faint">→</span>
              <select value={v.target} onChange={(e) => setVuln(i, { target: e.target.value })} className={cn(selectCls)} aria-label="Target host">
                {nodeIds.map((id) => (
                  <option key={id} value={id}>{id}</option>
                ))}
              </select>
              <Input
                type="number"
                step="0.1"
                min="0"
                max="10"
                value={v.cvss_score}
                onChange={(e) => setVuln(i, { cvss_score: Number(e.target.value) })}
                aria-label="CVSS score"
                className="h-9 w-20"
              />
              <label className="flex items-center gap-2 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={v.has_exploit ?? false}
                  onChange={(e) => setVuln(i, { has_exploit: e.target.checked })}
                  className="accent-crit"
                />
                Known exploit
              </label>
              <button
                type="button"
                aria-label="Remove vulnerability"
                onClick={() => setVulns((p) => p.filter((_, idx) => idx !== i))}
                className="ml-auto text-faint transition-colors hover:text-danger"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      </div>

      <Button
        onClick={() => onAnalyze(nodes.filter((n) => n.id), vulns.filter((v) => v.source && v.target))}
        disabled={isPending}
        className="w-full sm:w-auto"
      >
        {isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
        Analyze paths
      </Button>
      <p className="text-xs text-faint">
        Needs at least one entry point and one critical asset. Lateral edges and data-grounded
        costs are derived server-side.
      </p>
    </div>
  )
}
