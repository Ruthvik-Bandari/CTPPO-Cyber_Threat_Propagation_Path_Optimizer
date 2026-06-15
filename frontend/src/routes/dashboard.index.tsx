import { createFileRoute, Link } from '@tanstack/react-router'
import { Boxes, Radar, Waypoints, BrainCircuit } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'

export const Route = createFileRoute('/dashboard/')({
  component: Overview,
})

interface Shortcut {
  to: string
  title: string
  description: string
  Icon: LucideIcon
}

const SHORTCUTS: Shortcut[] = [
  {
    to: '/dashboard/instances',
    title: 'Instances',
    description: 'Create scan and analysis workspaces.',
    Icon: Boxes,
  },
  {
    to: '/dashboard/scan',
    title: 'Scan',
    description: 'Probe a host or URL for exposure issues.',
    Icon: Radar,
  },
  {
    to: '/dashboard/attack-paths',
    title: 'Attack paths',
    description: 'Compute Pareto-optimal attack paths with NAMOA*.',
    Icon: Waypoints,
  },
  {
    to: '/dashboard/classify',
    title: 'CVE severity',
    description: 'Predict severity from the description text alone.',
    Icon: BrainCircuit,
  },
]

function Overview() {
  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold">CTPPO workspace</h1>
        <p className="text-muted">Multi-objective attack-path analysis, grounded in real exploit data.</p>
      </header>

      <div className="flex flex-wrap gap-5">
        {SHORTCUTS.map((s) => (
          <Link key={s.to} to={s.to} className="min-w-[16rem] flex-1">
            <Card className="h-full transition-colors hover:border-cyber/40">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-cyber/15 text-cyber">
                    <s.Icon className="h-5 w-5" />
                  </span>
                  <CardTitle>{s.title}</CardTitle>
                </div>
                <CardDescription>{s.description}</CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
