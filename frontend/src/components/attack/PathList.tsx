import { ChevronRight, Flag, Crosshair } from 'lucide-react'
import type { ParetoPath } from '@/api/client'

export function prettyObjective(key: string) {
  return key.replace(/_/g, ' ').toLowerCase()
}

export function PathList({ paths }: { paths: ParetoPath[] }) {
  return (
    <div className="flex flex-col gap-4">
      {paths.map((p, i) => (
        <div key={i} className="flex flex-col gap-4 rounded-2xl border border-line bg-surface/40 p-5">
          <div className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber/15 font-mono text-xs text-cyber">
              {i + 1}
            </span>
            <div className="flex flex-wrap items-center gap-1.5">
              {p.path.map((node, j) => (
                <span key={j} className="flex items-center gap-1.5">
                  <span className="flex items-center gap-1.5 rounded-lg border border-line bg-base-2/60 px-2.5 py-1 text-sm">
                    {j === 0 && <Flag className="h-3 w-3 text-marine-bright" />}
                    {j === p.path.length - 1 && <Crosshair className="h-3 w-3 text-crit" />}
                    {node}
                  </span>
                  {j < p.path.length - 1 && <ChevronRight className="h-4 w-4 text-faint" />}
                </span>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(p.cost).map(([k, v]) => (
              <span
                key={k}
                className="flex items-center gap-1.5 rounded-full border border-line-soft bg-base-2/60 px-3 py-1 text-xs text-muted"
              >
                {prettyObjective(k)}
                <span className="font-mono text-cyber-bright">{v}</span>
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
