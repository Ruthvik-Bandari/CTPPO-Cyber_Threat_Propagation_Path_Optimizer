import { ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, CartesianGrid } from 'recharts'
import type { ParetoPath } from '@/api/client'
import { prettyObjective } from './PathList'

interface PointDatum {
  x: number
  y: number
  z: number
  name: string
  idx: number
}

function ChartTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: PointDatum }> }) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className="glass max-w-xs rounded-xl px-3 py-2 text-xs">
      <div className="mb-1 font-medium text-cyber">Path {d.idx}</div>
      <div className="text-muted">{d.name}</div>
    </div>
  )
}

/*
 * Scatter of the Pareto front across two engine objectives (axes) with a third encoded as
 * point size. Objective keys are taken from the response as-is — no re-interpretation.
 */
export function ParetoChart({ paths }: { paths: ParetoPath[] }) {
  const keys = paths.length ? Object.keys(paths[0].cost) : []
  if (keys.length < 2) return null
  const [xk, yk, zk] = keys

  const data: PointDatum[] = paths.map((p, i) => ({
    x: p.cost[xk] ?? 0,
    y: p.cost[yk] ?? 0,
    z: zk ? (p.cost[zk] ?? 1) : 1,
    name: p.path.join(' → '),
    idx: i + 1,
  }))

  const axisStyle = { fontSize: 11, fill: '#93a4c4' }

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <ScatterChart margin={{ top: 16, right: 20, bottom: 28, left: 8 }}>
          <CartesianGrid stroke="#14203d" />
          <XAxis
            type="number"
            dataKey="x"
            name={prettyObjective(xk)}
            tick={axisStyle}
            stroke="#1c2c54"
            label={{ value: prettyObjective(xk), position: 'bottom', fill: '#5d6f93', fontSize: 11 }}
          />
          <YAxis
            type="number"
            dataKey="y"
            name={prettyObjective(yk)}
            tick={axisStyle}
            stroke="#1c2c54"
            label={{ value: prettyObjective(yk), angle: -90, position: 'left', fill: '#5d6f93', fontSize: 11 }}
          />
          <ZAxis type="number" dataKey="z" range={[60, 320]} name={zk ? prettyObjective(zk) : ''} />
          <Tooltip content={<ChartTooltip />} cursor={{ strokeDasharray: '3 3', stroke: '#2ff5a8' }} />
          <Scatter data={data} fill="#2ff5a8" fillOpacity={0.7} />
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  )
}
