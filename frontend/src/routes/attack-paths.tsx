import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Network,
  Shield,
  AlertTriangle,
  Loader2,
  ChevronRight,
  Target,
  Globe,
  Scan,
  Layers,
  Circle,
  GitBranch,
  ZoomIn,
  ZoomOut,
  RotateCcw,
} from 'lucide-react'
import { useAuthStore } from '@/stores/auth'

export const Route = createFileRoute('/attack-paths')({
  component: AttackPathsPage,
})

type LayoutType = 'hierarchical' | 'circular' | 'radial'

interface PathData {
  name: string
  vulnerabilities: any[]
  riskScore: number
  hopCount: number
  successProb: number
  timeToExploit: number
  businessImpact: number
  severity: string
}

// SVG Network Graph Component
function NetworkGraph({
  data,
  selectedPath,
  setSelectedPath,
  layout,
}: {
  data: any
  selectedPath: string | null
  setSelectedPath: (path: string | null) => void
  layout: LayoutType
}) {
  const [zoom, setZoom] = useState(1)
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null)

  if (!data?.network) return null

  const nodes = data.network.nodes || []
  const edges = data.network.edges || {}
  const entryPoints = data.network.entry_points || []
  const criticalAssets = data.network.critical_assets || []

  // Calculate positions based on layout
  const width = 700
  const height = 450
  const centerX = width / 2
  const centerY = height / 2

  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {}

    if (layout === 'hierarchical') {
      // Entry points on left, critical on right
      const entryNodes = nodes.filter((n: string) => entryPoints.includes(n))
      const criticalNodes = nodes.filter((n: string) => criticalAssets.includes(n))
      const middleNodes = nodes.filter(
        (n: string) => !entryPoints.includes(n) && !criticalAssets.includes(n)
      )

      entryNodes.forEach((n: string, i: number) => {
        positions[n] = { x: 100, y: centerY + (i - (entryNodes.length - 1) / 2) * 80 }
      })
      middleNodes.forEach((n: string, i: number) => {
        positions[n] = { x: centerX, y: centerY + (i - (middleNodes.length - 1) / 2) * 80 }
      })
      criticalNodes.forEach((n: string, i: number) => {
        positions[n] = { x: width - 100, y: centerY + (i - (criticalNodes.length - 1) / 2) * 80 }
      })
    } else if (layout === 'circular') {
      const radius = Math.min(width, height) / 2 - 80
      nodes.forEach((n: string, i: number) => {
        const angle = (i / nodes.length) * Math.PI * 2 - Math.PI / 2
        positions[n] = {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
        }
      })
    } else {
      // Radial - entry in center, others radiate out
      const entryNode = entryPoints[0]
      if (entryNode) {
        positions[entryNode] = { x: centerX, y: centerY }
      }
      const otherNodes = nodes.filter((n: string) => n !== entryNode)
      const radius = Math.min(width, height) / 2 - 80
      otherNodes.forEach((n: string, i: number) => {
        const angle = (i / otherNodes.length) * Math.PI * 2 - Math.PI / 2
        positions[n] = {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
        }
      })
    }

    return positions
  }, [nodes, layout, entryPoints, criticalAssets])

  // Flatten and dedupe edges
  const allEdges: Array<{
    source: string
    target: string
    severity: string
    cveId: string
    index: number
    total: number
  }> = []

  const edgeCounts: Record<string, number> = {}
  Object.entries(edges).forEach(([source, edgeList]) => {
    ;(edgeList as any[]).forEach((e) => {
      const key = `${source}->${e.target}`
      edgeCounts[key] = (edgeCounts[key] || 0) + 1
    })
  })

  const edgeIndices: Record<string, number> = {}
  Object.entries(edges).forEach(([source, edgeList]) => {
    ;(edgeList as any[]).forEach((e) => {
      const key = `${source}->${e.target}`
      const index = edgeIndices[key] || 0
      edgeIndices[key] = index + 1
      allEdges.push({
        source,
        target: e.target,
        severity: e.severity,
        cveId: e.cve_id,
        index,
        total: edgeCounts[key],
      })
    })
  })

  // Get selected path edges
  const selectedPathData = selectedPath && data.paths?.[selectedPath]?.[0]
  const selectedCveIds = new Set(
    selectedPathData?.vulnerabilities?.map((v: any) => v.cve_id) || []
  )

  const severityColors: Record<string, string> = {
    CRITICAL: '#dc2626',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#22c55e',
    INFO: '#6b7280',
  }

  // Calculate curved path for edge
  const getEdgePath = (
    x1: number,
    y1: number,
    x2: number,
    y2: number,
    index: number,
    total: number
  ) => {
    if (total === 1) {
      return `M ${x1} ${y1} L ${x2} ${y2}`
    }

    // Calculate curve offset
    const dx = x2 - x1
    const dy = y2 - y1
    const dist = Math.sqrt(dx * dx + dy * dy)

    // Perpendicular direction
    const px = -dy / dist
    const py = dx / dist

    // Spread edges
    const spread = 25
    const offset = (index - (total - 1) / 2) * spread

    // Control point
    const cx = (x1 + x2) / 2 + px * offset
    const cy = (y1 + y2) / 2 + py * offset

    return `M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`
  }

  const formatNodeLabel = (node: string) => {
    if (node.startsWith('host_')) {
      return node.replace('host_', '').replace(/_/g, '.').slice(0, 20)
    }
    return node
  }

  return (
    <div className="relative w-full h-full bg-gray-900/50 rounded-xl overflow-hidden">
      {/* Zoom controls */}
      <div className="absolute top-4 left-4 flex gap-2 z-10">
        <button
          onClick={() => setZoom((z) => Math.min(z + 0.2, 2))}
          className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(z - 0.2, 0.5))}
          className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom(1)}
          className="p-2 bg-gray-800 rounded-lg hover:bg-gray-700"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* Edge count indicator */}
      <div className="absolute top-4 right-4 bg-gray-800/80 rounded-lg px-3 py-2 text-sm">
        <span className="text-gray-400">Edges: </span>
        <span className="text-white font-bold">{allEdges.length}</span>
      </div>

      <svg
        width="100%"
        height="100%"
        viewBox={`0 0 ${width} ${height}`}
        style={{ transform: `scale(${zoom})`, transformOrigin: 'center' }}
      >
        <defs>
          {/* Arrow markers for each severity */}
          {Object.entries(severityColors).map(([sev, color]) => (
            <marker
              key={sev}
              id={`arrow-${sev}`}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill={color} />
            </marker>
          ))}
          <marker
            id="arrow-default"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#666" />
          </marker>
        </defs>

        {/* Grid */}
        <g opacity={0.1}>
          {Array.from({ length: 15 }).map((_, i) => (
            <line
              key={`h${i}`}
              x1={0}
              y1={i * 30}
              x2={width}
              y2={i * 30}
              stroke="white"
              strokeWidth={0.5}
            />
          ))}
          {Array.from({ length: 24 }).map((_, i) => (
            <line
              key={`v${i}`}
              x1={i * 30}
              y1={0}
              x2={i * 30}
              y2={height}
              stroke="white"
              strokeWidth={0.5}
            />
          ))}
        </g>

        {/* Edges */}
        {allEdges.map((edge, i) => {
          const start = nodePositions[edge.source]
          const end = nodePositions[edge.target]
          if (!start || !end) return null

          const isSelected = selectedCveIds.has(edge.cveId) || !selectedPath
          const isHovered = hoveredEdge === edge.cveId
          const color = severityColors[edge.severity] || '#666'

          return (
            <g key={`edge-${i}`}>
              <path
                d={getEdgePath(start.x, start.y, end.x, end.y, edge.index, edge.total)}
                stroke={isSelected || isHovered ? color : '#444'}
                strokeWidth={isHovered ? 4 : isSelected ? 2.5 : 1.5}
                fill="none"
                opacity={isSelected || isHovered ? 1 : 0.3}
                markerEnd={`url(#arrow-${isSelected || isHovered ? edge.severity : 'default'})`}
                style={{ cursor: 'pointer', transition: 'all 0.2s' }}
                onMouseEnter={() => setHoveredEdge(edge.cveId)}
                onMouseLeave={() => setHoveredEdge(null)}
              />
              {isHovered && (
                <text
                  x={(start.x + end.x) / 2}
                  y={(start.y + end.y) / 2 - 10}
                  fill="white"
                  fontSize={11}
                  textAnchor="middle"
                  className="pointer-events-none"
                >
                  {edge.cveId} ({edge.severity})
                </text>
              )}
            </g>
          )
        })}

        {/* Nodes */}
        {nodes.map((node: string) => {
          const pos = nodePositions[node]
          if (!pos) return null

          const isEntry = entryPoints.includes(node)
          const isCritical = criticalAssets.includes(node)
          const color = isEntry ? '#3b82f6' : isCritical ? '#ef4444' : '#6b7280'

          return (
            <g key={node}>
              {/* Glow effect */}
              <circle cx={pos.x} cy={pos.y} r={35} fill={color} opacity={0.2} />
              {/* Main circle */}
              <circle
                cx={pos.x}
                cy={pos.y}
                r={28}
                fill="#1f2937"
                stroke={color}
                strokeWidth={3}
              />
              {/* Icon */}
              {isEntry ? (
                <text x={pos.x} y={pos.y + 5} fill={color} fontSize={20} textAnchor="middle">
                  🌐
                </text>
              ) : isCritical ? (
                <text x={pos.x} y={pos.y + 5} fill={color} fontSize={20} textAnchor="middle">
                  🎯
                </text>
              ) : (
                <text x={pos.x} y={pos.y + 5} fill={color} fontSize={20} textAnchor="middle">
                  💻
                </text>
              )}
              {/* Label */}
              <text
                x={pos.x}
                y={pos.y + 50}
                fill="white"
                fontSize={12}
                textAnchor="middle"
                fontWeight="500"
              >
                {formatNodeLabel(node)}
              </text>
            </g>
          )
        })}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-gray-800/90 rounded-lg p-3">
        <div className="text-xs font-semibold mb-2 text-gray-300">Edge Severity</div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          {Object.entries(severityColors).map(([sev, color]) => (
            <div key={sev} className="flex items-center gap-2">
              <div className="w-4 h-1 rounded" style={{ backgroundColor: color }} />
              <span className="text-gray-300">{sev}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// Interactive Pareto Chart
function ParetoChart({
  paths,
  selectedPath,
  setSelectedPath,
}: {
  paths: PathData[]
  selectedPath: string | null
  setSelectedPath: (path: string | null) => void
}) {
  const [hoveredPath, setHoveredPath] = useState<PathData | null>(null)
  const [tooltip, setTooltip] = useState<{ x: number; y: number } | null>(null)

  const width = 320
  const height = 220
  const padding = { top: 20, right: 20, bottom: 40, left: 50 }
  const chartWidth = width - padding.left - padding.right
  const chartHeight = height - padding.top - padding.bottom

  const maxTime = Math.max(...paths.map((p) => p.timeToExploit), 50)
  const maxProb = 1

  const scaleX = (time: number) => padding.left + (time / maxTime) * chartWidth
  const scaleY = (prob: number) => padding.top + (1 - prob / maxProb) * chartHeight

  const getColor = (impact: number) => {
    if (impact >= 7.5) return '#dc2626'
    if (impact >= 5) return '#f97316'
    if (impact >= 2.5) return '#eab308'
    return '#22c55e'
  }

  return (
    <div className="p-4 rounded-xl bg-card border border-border relative">
      <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
        📊 Pareto Front Analysis
      </h3>
      <p className="text-xs text-gray-400 mb-3">
        Click points to select paths. Higher = easier to exploit.
      </p>

      <svg
        width={width}
        height={height}
        className="mx-auto"
        onMouseLeave={() => {
          setHoveredPath(null)
          setTooltip(null)
        }}
      >
        {/* Background */}
        <rect
          x={padding.left}
          y={padding.top}
          width={chartWidth}
          height={chartHeight}
          fill="#1a1a2e"
          rx={4}
        />

        {/* Grid */}
        {[0.2, 0.4, 0.6, 0.8].map((v) => (
          <g key={v}>
            <line
              x1={padding.left}
              y1={scaleY(v)}
              x2={width - padding.right}
              y2={scaleY(v)}
              stroke="#333"
              strokeDasharray="3,3"
            />
            <text x={padding.left - 5} y={scaleY(v) + 4} fill="#666" fontSize={9} textAnchor="end">
              {(v * 100).toFixed(0)}%
            </text>
          </g>
        ))}
        {[10, 20, 30, 40].map((v) => (
          <g key={v}>
            <line
              x1={scaleX(v)}
              y1={padding.top}
              x2={scaleX(v)}
              y2={height - padding.bottom}
              stroke="#333"
              strokeDasharray="3,3"
            />
            <text x={scaleX(v)} y={height - padding.bottom + 15} fill="#666" fontSize={9} textAnchor="middle">
              {v}h
            </text>
          </g>
        ))}

        {/* Axis labels */}
        <text
          x={width / 2}
          y={height - 5}
          fill="#888"
          fontSize={10}
          textAnchor="middle"
        >
          Time to Exploit
        </text>
        <text
          x={12}
          y={height / 2}
          fill="#888"
          fontSize={10}
          textAnchor="middle"
          transform={`rotate(-90, 12, ${height / 2})`}
        >
          Success Probability
        </text>

        {/* Data points */}
        {paths.map((p, i) => {
          const x = scaleX(p.timeToExploit)
          const y = scaleY(p.successProb)
          const isSelected = selectedPath === p.name
          const isHovered = hoveredPath?.name === p.name
          const r = isSelected ? 12 : isHovered ? 10 : 7

          return (
            <g
              key={i}
              style={{ cursor: 'pointer' }}
              onClick={() => setSelectedPath(isSelected ? null : p.name)}
              onMouseEnter={(e) => {
                setHoveredPath(p)
                setTooltip({ x: e.clientX, y: e.clientY })
              }}
              onMouseMove={(e) => setTooltip({ x: e.clientX, y: e.clientY })}
              onMouseLeave={() => {
                setHoveredPath(null)
                setTooltip(null)
              }}
            >
              {/* Pulse animation for selected */}
              {isSelected && (
                <circle cx={x} cy={y} r={r + 5} fill={getColor(p.businessImpact)} opacity={0.3}>
                  <animate
                    attributeName="r"
                    values={`${r + 5};${r + 15};${r + 5}`}
                    dur="1.5s"
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="opacity"
                    values="0.3;0;0.3"
                    dur="1.5s"
                    repeatCount="indefinite"
                  />
                </circle>
              )}
              <circle
                cx={x}
                cy={y}
                r={r}
                fill={getColor(p.businessImpact)}
                stroke={isSelected ? 'white' : isHovered ? '#fff' : 'none'}
                strokeWidth={isSelected ? 3 : 2}
                style={{ transition: 'all 0.2s' }}
              />
            </g>
          )
        })}

        {/* Legend */}
        <g transform={`translate(${width - 85}, ${padding.top + 5})`}>
          <rect x={-5} y={-5} width={75} height={70} fill="#1f2937" rx={4} />
          <text x={0} y={8} fill="#888" fontSize={8} fontWeight="bold">
            Impact
          </text>
          {[
            { color: '#dc2626', label: 'Critical' },
            { color: '#f97316', label: 'High' },
            { color: '#eab308', label: 'Medium' },
            { color: '#22c55e', label: 'Low' },
          ].map((item, i) => (
            <g key={i} transform={`translate(0, ${18 + i * 12})`}>
              <circle cx={6} cy={0} r={4} fill={item.color} />
              <text x={14} y={3} fill="#aaa" fontSize={8}>
                {item.label}
              </text>
            </g>
          ))}
        </g>
      </svg>

      {/* Tooltip */}
      <AnimatePresence>
        {hoveredPath && tooltip && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="fixed z-50 bg-gray-900 border border-gray-700 rounded-lg p-3 shadow-xl pointer-events-none"
            style={{
              left: tooltip.x + 10,
              top: tooltip.y - 80,
            }}
          >
            <div className="text-sm font-semibold text-white mb-1">
              {hoveredPath.name.slice(0, 35)}...
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              <div className="text-gray-400">Risk Score:</div>
              <div className="text-white font-medium">{hoveredPath.riskScore.toFixed(1)}</div>
              <div className="text-gray-400">Success:</div>
              <div className="text-white font-medium">{(hoveredPath.successProb * 100).toFixed(0)}%</div>
              <div className="text-gray-400">Time:</div>
              <div className="text-white font-medium">{hoveredPath.timeToExploit.toFixed(0)}h</div>
              <div className="text-gray-400">Severity:</div>
              <div
                className="font-medium"
                style={{ color: getColor(hoveredPath.businessImpact) }}
              >
                {hoveredPath.severity}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function AttackPathsPage() {
  const { accessToken } = useAuthStore()
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [scanMode, setScanMode] = useState<'demo' | 'real'>('demo')
  const [targetUrl, setTargetUrl] = useState('')
  const [scanResult, setScanResult] = useState<any>(null)
  const [layout, setLayout] = useState<LayoutType>('hierarchical')

  const sampleQuery = useQuery({
    queryKey: ['attack-paths-sample'],
    queryFn: async () => {
      const res = await fetch('/api/attack-paths/sample', {
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      if (!res.ok) throw new Error('Failed to fetch sample')
      return res.json()
    },
    enabled: scanMode === 'demo',
  })

  const scanMutation = useMutation({
    mutationFn: async (target: string) => {
      const res = await fetch(`/api/attack-paths/from-scan?target=${encodeURIComponent(target)}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      if (!res.ok) throw new Error('Scan failed')
      return res.json()
    },
    onSuccess: (data) => {
      setScanResult(data)
      setSelectedPath(null)
    },
  })

  const handleScan = () => {
    if (targetUrl.trim()) {
      scanMutation.mutate(targetUrl.trim())
    }
  }

  const data = scanMode === 'demo' ? sampleQuery.data : scanResult
  const isLoading = scanMode === 'demo' ? sampleQuery.isLoading : scanMutation.isPending
  const error = scanMode === 'demo' ? sampleQuery.error : scanMutation.error

  // Process paths for Pareto chart
  const pathsData: PathData[] = useMemo(() => {
    if (!data?.paths) return []

    return Object.entries(data.paths).map(([name, pathList]: [string, any]) => {
      const path = pathList[0]
      const vulns = path.vulnerabilities || []
      const avgCvss =
        vulns.length > 0
          ? vulns.reduce((sum: number, v: any) => sum + (v.cvss_score || 0), 0) / vulns.length
          : 0
      const maxCvss = vulns.length > 0 ? Math.max(...vulns.map((v: any) => v.cvss_score || 0)) : 0
      const hopCount = path.hop_count || 1
      const severity = vulns[0]?.severity || 'LOW'

      return {
        name,
        vulnerabilities: vulns,
        riskScore: path.risk_score || maxCvss,
        hopCount,
        successProb: Math.min(avgCvss / 10, 0.95),
        timeToExploit: hopCount * 8 + (10 - avgCvss) * 3,
        businessImpact: maxCvss,
        severity,
      }
    })
  }, [data])

  const layoutOptions: Array<{ value: LayoutType; label: string; icon: any }> = [
    { value: 'hierarchical', label: 'Hierarchical', icon: Layers },
    { value: 'circular', label: 'Circular', icon: Circle },
    { value: 'radial', label: 'Radial', icon: GitBranch },
  ]

  return (
    <div className="h-full flex flex-col gap-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Network className="w-6 h-6 text-primary" />
            Attack Path Analysis
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            NAMOA* multi-objective optimization for attack path discovery
          </p>
        </div>

        {/* Layout Selector */}
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Layout:</span>
          <div className="flex rounded-lg border border-border overflow-hidden">
            {layoutOptions.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setLayout(opt.value)}
                className={`px-3 py-2 flex items-center gap-1.5 text-sm transition-colors ${
                  layout === opt.value
                    ? 'bg-primary text-primary-foreground'
                    : 'hover:bg-secondary'
                }`}
              >
                <opt.icon className="w-4 h-4" />
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="rounded-xl bg-card border border-border p-4">
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => {
              setScanMode('demo')
              setScanResult(null)
            }}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              scanMode === 'demo'
                ? 'bg-primary text-primary-foreground'
                : 'bg-secondary hover:bg-secondary/80'
            }`}
          >
            Demo Network
          </button>
          <button
            onClick={() => setScanMode('real')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              scanMode === 'real'
                ? 'bg-primary text-primary-foreground'
                : 'bg-secondary hover:bg-secondary/80'
            }`}
          >
            Scan Real Target
          </button>
        </div>

        {scanMode === 'real' && (
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="Enter target URL (e.g., testphp.vulnweb.com)"
                className="w-full pl-10 pr-4 py-3 rounded-lg bg-background border border-border focus:outline-none focus:ring-2 focus:ring-primary/50"
                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              />
            </div>
            <button
              onClick={handleScan}
              disabled={scanMutation.isPending || !targetUrl.trim()}
              className="px-6 py-3 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50 flex items-center gap-2"
            >
              {scanMutation.isPending ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" /> Scanning...
                </>
              ) : (
                <>
                  <Scan className="w-5 h-5" /> Analyze
                </>
              )}
            </button>
          </div>
        )}

        {scanMode === 'real' && scanResult?.scan_summary && (
          <div className="mt-4 p-3 rounded-lg bg-green-500/10 border border-green-500/30">
            <p className="text-sm text-green-400">
              ✓ Scanned <strong>{scanResult.scan_summary.host}</strong>: Found{' '}
              {scanResult.scan_summary.open_ports} open ports,{' '}
              {scanResult.scan_summary.vulnerabilities_found} vulnerabilities
            </p>
          </div>
        )}

        {error && (
          <div className="mt-4 p-3 rounded-lg bg-destructive/20 text-destructive flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" />
            <span>{(error as Error).message}</span>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 grid grid-cols-3 gap-4 min-h-0">
        {/* Network Graph */}
        <div className="col-span-2 rounded-xl bg-card border border-border overflow-hidden">
          {isLoading ? (
            <div className="h-full flex items-center justify-center">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : data ? (
            <NetworkGraph
              data={data}
              selectedPath={selectedPath}
              setSelectedPath={setSelectedPath}
              layout={layout}
            />
          ) : (
            <div className="h-full flex items-center justify-center text-muted-foreground">
              {scanMode === 'real' ? 'Enter a target URL and click Analyze' : 'Loading...'}
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="flex flex-col gap-4 overflow-auto">
          {/* Risk Summary */}
          {data?.risk_summary && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className={`p-4 rounded-xl ${
                data.risk_summary.overall_risk === 'CRITICAL'
                  ? 'bg-red-600'
                  : data.risk_summary.overall_risk === 'HIGH'
                  ? 'bg-orange-600'
                  : data.risk_summary.overall_risk === 'MEDIUM'
                  ? 'bg-yellow-600'
                  : 'bg-green-600'
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white/80 text-sm">Overall Risk</p>
                  <p className="text-2xl font-bold text-white">
                    {data.risk_summary.overall_risk || 'LOW'}
                  </p>
                </div>
                <Shield className="w-10 h-10 text-white/30" />
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                <div className="bg-white/10 rounded p-2">
                  <p className="text-white/70">Paths</p>
                  <p className="text-white font-bold">{data.risk_summary.total_paths || 0}</p>
                </div>
                <div className="bg-white/10 rounded p-2">
                  <p className="text-white/70">Critical</p>
                  <p className="text-white font-bold">{data.risk_summary.critical_paths || 0}</p>
                </div>
              </div>
            </motion.div>
          )}

          {/* Pareto Chart */}
          {pathsData.length > 0 && (
            <ParetoChart
              paths={pathsData}
              selectedPath={selectedPath}
              setSelectedPath={setSelectedPath}
            />
          )}

          {/* Attack Paths List */}
          <div className="flex-1 p-4 rounded-xl bg-card border border-border overflow-auto">
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Target className="w-4 h-4" />
              Attack Paths ({pathsData.length})
            </h3>

            {pathsData.length > 0 ? (
              <div className="space-y-1">
                {pathsData.map((p) => {
                  const severityColors: Record<string, string> = {
                    CRITICAL: 'border-red-500 bg-red-500/10',
                    HIGH: 'border-orange-500 bg-orange-500/10',
                    MEDIUM: 'border-yellow-500 bg-yellow-500/10',
                    LOW: 'border-green-500 bg-green-500/10',
                  }

                  return (
                    <button
                      key={p.name}
                      onClick={() => setSelectedPath(selectedPath === p.name ? null : p.name)}
                      className={`w-full p-2 rounded-lg text-left transition-all border ${
                        selectedPath === p.name
                          ? 'bg-primary/20 border-primary ring-2 ring-primary/50'
                          : `${severityColors[p.severity] || 'border-border'} hover:bg-secondary/50`
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-xs truncate pr-2">{p.name}</span>
                        <ChevronRight
                          className={`w-3 h-3 transition-transform flex-shrink-0 ${
                            selectedPath === p.name ? 'rotate-90' : ''
                          }`}
                        />
                      </div>
                      <div className="mt-0.5 text-xs text-muted-foreground">
                        {p.hopCount} hops • Risk: {p.riskScore.toFixed(1)} •{' '}
                        {(p.successProb * 100).toFixed(0)}% success
                      </div>
                    </button>
                  )
                })}
              </div>
            ) : (
              <p className="text-muted-foreground text-sm">No attack paths found</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
