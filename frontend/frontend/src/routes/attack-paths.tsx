import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { attackPathApi, SampleNetworkResponse } from '@/api/client'
import { motion, AnimatePresence } from 'framer-motion'
import { Canvas } from '@react-three/fiber'
import { OrbitControls, Text, Line } from '@react-three/drei'
import * as THREE from 'three'
import {
  Network,
  Shield,
  AlertTriangle,
  Loader2,
  Play,
  Info,
  ChevronRight,
  Target,
  Server,
  Globe,
} from 'lucide-react'

export const Route = createFileRoute('/attack-paths')({
  component: AttackPathsPage,
})

// 3D Network Node Component
function NetworkNode3D({ 
  position, 
  label, 
  type,
  isSelected,
  onClick 
}: { 
  position: [number, number, number]
  label: string
  type: 'entry' | 'critical' | 'normal'
  isSelected: boolean
  onClick: () => void
}) {
  const colors = {
    entry: '#3b82f6',
    critical: '#ef4444',
    normal: '#6b7280',
  }

  return (
    <group position={position}>
      <mesh onClick={onClick}>
        <sphereGeometry args={[0.4, 32, 32]} />
        <meshStandardMaterial 
          color={colors[type]} 
          emissive={colors[type]}
          emissiveIntensity={isSelected ? 0.5 : 0.2}
        />
      </mesh>
      <Text
        position={[0, 0.7, 0]}
        fontSize={0.25}
        color="white"
        anchorX="center"
        anchorY="middle"
      >
        {label}
      </Text>
    </group>
  )
}

// 3D Network Edge Component
function NetworkEdge3D({
  start,
  end,
  color = '#ffffff',
  isHighlighted = false,
}: {
  start: [number, number, number]
  end: [number, number, number]
  color?: string
  isHighlighted?: boolean
}) {
  return (
    <Line
      points={[start, end]}
      color={isHighlighted ? '#ef4444' : color}
      lineWidth={isHighlighted ? 3 : 1}
      opacity={isHighlighted ? 1 : 0.3}
      transparent
    />
  )
}

// 3D Network Visualization
function NetworkVisualization3D({ 
  data,
  selectedPath 
}: { 
  data: SampleNetworkResponse
  selectedPath: string | null
}) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null)

  // Calculate node positions
  const nodePositions: Record<string, [number, number, number]> = {}
  const nodes = data.network.nodes
  
  nodes.forEach((node, index) => {
    const angle = (index / nodes.length) * Math.PI * 2
    const radius = 3
    const x = Math.cos(angle) * radius
    const z = Math.sin(angle) * radius
    const y = Math.random() * 0.5 - 0.25
    nodePositions[node] = [x, y, z]
  })

  // Get edges from network
  const edges: Array<{ source: string; target: string; cveId: string }> = []
  Object.entries(data.network.edges).forEach(([source, vulns]) => {
    (vulns as any[]).forEach((v) => {
      edges.push({ source, target: v.target, cveId: v.cve_id })
    })
  })

  // Get nodes in selected path
  const pathNodes = selectedPath 
    ? data.paths[selectedPath]?.[0]?.vulnerabilities.flatMap(v => [v.source, v.target]) || []
    : []

  return (
    <Canvas camera={{ position: [0, 5, 8], fov: 50 }}>
      <ambientLight intensity={0.4} />
      <pointLight position={[10, 10, 10]} intensity={1} />
      <pointLight position={[-10, -10, -10]} intensity={0.5} />

      {/* Render edges */}
      {edges.map((edge, i) => {
        const start = nodePositions[edge.source]
        const end = nodePositions[edge.target]
        if (!start || !end) return null
        
        const isInPath = pathNodes.includes(edge.source) && pathNodes.includes(edge.target)
        
        return (
          <NetworkEdge3D
            key={`${edge.source}-${edge.target}-${i}`}
            start={start}
            end={end}
            isHighlighted={isInPath}
          />
        )
      })}

      {/* Render nodes */}
      {nodes.map((node) => {
        const pos = nodePositions[node]
        const type = data.network.entry_points.includes(node) 
          ? 'entry' 
          : data.network.critical_assets.includes(node) 
            ? 'critical' 
            : 'normal'
        
        return (
          <NetworkNode3D
            key={node}
            position={pos}
            label={node.replace(/_/g, '\n')}
            type={type}
            isSelected={selectedNode === node || pathNodes.includes(node)}
            onClick={() => setSelectedNode(node === selectedNode ? null : node)}
          />
        )
      })}

      <OrbitControls 
        enablePan={true}
        enableZoom={true}
        enableRotate={true}
        autoRotate={!selectedPath}
        autoRotateSpeed={0.5}
      />
      
      {/* Grid */}
      <gridHelper args={[10, 10, '#333', '#222']} position={[0, -1, 0]} />
    </Canvas>
  )
}

// Severity Badge Component
function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: 'bg-red-600',
    HIGH: 'bg-orange-600',
    MEDIUM: 'bg-yellow-600',
    LOW: 'bg-green-600',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium text-white ${colors[severity] || 'bg-gray-600'}`}>
      {severity}
    </span>
  )
}

function AttackPathsPage() {
  const [selectedPath, setSelectedPath] = useState<string | null>(null)

  const sampleQuery = useQuery({
    queryKey: ['attack-paths-sample'],
    queryFn: attackPathApi.getSample,
    enabled: false,
  })

  const handleAnalyze = () => {
    sampleQuery.refetch()
  }

  const data = sampleQuery.data

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Network className="w-8 h-8 text-primary" />
          Attack Path Analysis
        </h1>
        <p className="text-muted-foreground mt-2">
          Visualize and analyze network attack paths using NAMOA* algorithm
        </p>
      </motion.div>

      {/* Action Button */}
      {!data && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="text-center py-12"
        >
          <div className="inline-flex p-6 rounded-full bg-primary/20 mb-6">
            <Network className="w-16 h-16 text-primary" />
          </div>
          <h2 className="text-2xl font-semibold mb-4">Ready to Analyze</h2>
          <p className="text-muted-foreground mb-6 max-w-md mx-auto">
            Click below to load a sample enterprise network and discover all possible attack paths
          </p>
          <button
            onClick={handleAnalyze}
            disabled={sampleQuery.isFetching}
            className="px-8 py-4 rounded-xl bg-primary text-primary-foreground font-medium
              hover:bg-primary/90 disabled:opacity-50 flex items-center gap-2 mx-auto"
          >
            {sampleQuery.isFetching ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Analyzing Network...
              </>
            ) : (
              <>
                <Play className="w-5 h-5" />
                Analyze Sample Network
              </>
            )}
          </button>
        </motion.div>
      )}

      {/* Results */}
      {data && (
        <div className="grid lg:grid-cols-3 gap-6">
          {/* 3D Visualization */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="lg:col-span-2 h-[500px] rounded-2xl overflow-hidden bg-card border border-border"
          >
            <div className="p-4 border-b border-border flex items-center justify-between">
              <h3 className="font-medium">Network Topology (3D)</h3>
              <div className="flex items-center gap-4 text-xs">
                <span className="flex items-center gap-1">
                  <Globe className="w-3 h-3 text-blue-500" /> Entry Point
                </span>
                <span className="flex items-center gap-1">
                  <Target className="w-3 h-3 text-red-500" /> Critical Asset
                </span>
                <span className="flex items-center gap-1">
                  <Server className="w-3 h-3 text-gray-500" /> System
                </span>
              </div>
            </div>
            <NetworkVisualization3D data={data} selectedPath={selectedPath} />
          </motion.div>

          {/* Risk Summary */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="space-y-4"
          >
            {/* Risk Level */}
            <div className={`p-6 rounded-xl ${
              data.risk_summary.risk_level === 'CRITICAL' ? 'bg-red-600' :
              data.risk_summary.risk_level === 'HIGH' ? 'bg-orange-600' :
              data.risk_summary.risk_level === 'MEDIUM' ? 'bg-yellow-600' : 'bg-green-600'
            }`}>
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle className="w-6 h-6 text-white" />
                <span className="text-white/80 text-sm">Overall Risk Level</span>
              </div>
              <p className="text-3xl font-bold text-white">{data.risk_summary.risk_level}</p>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-card border border-border text-center">
                <p className="text-2xl font-bold">{data.risk_summary.total_paths}</p>
                <p className="text-xs text-muted-foreground">Attack Paths</p>
              </div>
              <div className="p-4 rounded-xl bg-card border border-border text-center">
                <p className="text-2xl font-bold">{data.network.nodes.length}</p>
                <p className="text-xs text-muted-foreground">Systems</p>
              </div>
            </div>

            {/* Critical Vulnerabilities */}
            <div className="p-4 rounded-xl bg-card border border-border">
              <h4 className="font-medium mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Critical Vulnerabilities
              </h4>
              <div className="space-y-2">
                {data.risk_summary.critical_vulnerabilities.slice(0, 5).map((v) => (
                  <div key={v.cve_id} className="flex justify-between text-sm">
                    <span className="font-mono">{v.cve_id}</span>
                    <span className="text-muted-foreground">{v.path_count} paths</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendation */}
            {data.risk_summary.recommendation && (
              <div className="p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/30">
                <div className="flex items-start gap-2">
                  <Info className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <p className="text-sm">{data.risk_summary.recommendation}</p>
                </div>
              </div>
            )}
          </motion.div>
        </div>
      )}

      {/* Attack Paths List */}
      {data && Object.keys(data.paths).length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-4"
        >
          <h3 className="text-xl font-semibold">Discovered Attack Paths</h3>
          
          <div className="space-y-3">
            {Object.entries(data.paths).map(([route, paths]) => (
              <div key={route} className="rounded-xl bg-card border border-border overflow-hidden">
                <button
                  onClick={() => setSelectedPath(selectedPath === route ? null : route)}
                  className="w-full p-4 flex items-center justify-between hover:bg-secondary/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <ChevronRight className={`w-5 h-5 transition-transform ${
                      selectedPath === route ? 'rotate-90' : ''
                    }`} />
                    <span className="font-medium">{route}</span>
                    <span className="text-sm text-muted-foreground">
                      {paths.length} optimal path(s)
                    </span>
                  </div>
                  {paths[0] && (
                    <div className="flex items-center gap-2">
                      <span className="text-sm">Risk: {paths[0].risk_score.toFixed(1)}</span>
                      <SeverityBadge severity={paths[0].max_severity} />
                    </div>
                  )}
                </button>
                
                <AnimatePresence>
                  {selectedPath === route && (
                    <motion.div
                      initial={{ height: 0 }}
                      animate={{ height: 'auto' }}
                      exit={{ height: 0 }}
                      className="overflow-hidden"
                    >
                      <div className="p-4 bg-secondary/30 space-y-4">
                        {paths.slice(0, 3).map((path, idx) => (
                          <div key={idx} className="p-4 rounded-lg bg-card">
                            <div className="flex items-center justify-between mb-3">
                              <span className="font-medium">Path {idx + 1}</span>
                              <div className="flex items-center gap-4 text-sm">
                                <span>Hops: {path.path_length}</span>
                                <span>Risk: {path.risk_score.toFixed(2)}</span>
                              </div>
                            </div>
                            
                            <div className="space-y-2">
                              {path.vulnerabilities.map((v, vIdx) => (
                                <div key={vIdx} className="flex items-center gap-2 text-sm">
                                  <span className="text-muted-foreground">{v.source}</span>
                                  <ChevronRight className="w-4 h-4" />
                                  <span className="font-mono text-xs bg-secondary px-2 py-0.5 rounded">
                                    {v.cve_id}
                                  </span>
                                  <SeverityBadge severity={v.severity} />
                                  <ChevronRight className="w-4 h-4" />
                                  <span className="text-muted-foreground">{v.target}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  )
}
