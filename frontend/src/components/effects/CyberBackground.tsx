import { useMemo, useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'

/*
 * Animated WebGL background — a cyber + AI theme.
 * Layers (back to front):
 *   1. CSS marble wash (fallback if WebGL is unavailable).
 *   2. Neural / attack-graph network: nodes connected by edges, with bright "data pulses"
 *      flowing along the edges — CTPPO's own motif (attack paths + AI signal propagation).
 *   3. Drifting particle field (dust).
 *   4. Two nested rotating wireframe shells — the "AI core".
 * Palette = theme tokens: cyber-green #2ff5a8 / #5affc1, marine-blue #3b6fff / #6f97ff.
 * Fixed, full-bleed, pointer-events-none, -z-10.
 */

const GREEN = '#2ff5a8'
const GREEN_BRIGHT = '#5affc1'
const BLUE = '#3b6fff'
const BLUE_BRIGHT = '#6f97ff'

// ---- Neural / attack-graph network with flowing data pulses -------------------------------

const NODE_COUNT = 90
const NEIGHBORS = 3 // edges per node to its nearest neighbours
const PULSE_COUNT = 70

function NeuralNetwork() {
  const group = useRef<THREE.Group>(null)
  const pulseGeom = useRef<THREE.BufferGeometry>(null)

  const { nodePositions, edgePositions, edges } = useMemo(() => {
    const nodes: THREE.Vector3[] = []
    for (let i = 0; i < NODE_COUNT; i++) {
      nodes.push(new THREE.Vector3(
        (Math.random() - 0.5) * 22,
        (Math.random() - 0.5) * 13,
        (Math.random() - 0.5) * 10,
      ))
    }
    // connect each node to its NEIGHBORS nearest neighbours (dedup undirected pairs)
    const seen = new Set<string>()
    const edgeList: Array<[number, number]> = []
    for (let i = 0; i < NODE_COUNT; i++) {
      const dists = nodes
        .map((n, j) => ({ j, d: nodes[i].distanceToSquared(n) }))
        .filter((x) => x.j !== i)
        .sort((a, b) => a.d - b.d)
        .slice(0, NEIGHBORS)
      for (const { j } of dists) {
        const key = i < j ? `${i}-${j}` : `${j}-${i}`
        if (!seen.has(key)) { seen.add(key); edgeList.push([i, j]) }
      }
    }
    const nodePos = new Float32Array(NODE_COUNT * 3)
    nodes.forEach((n, i) => { nodePos[i * 3] = n.x; nodePos[i * 3 + 1] = n.y; nodePos[i * 3 + 2] = n.z })
    const edgePos = new Float32Array(edgeList.length * 6)
    edgeList.forEach(([a, b], k) => {
      edgePos.set([nodes[a].x, nodes[a].y, nodes[a].z, nodes[b].x, nodes[b].y, nodes[b].z], k * 6)
    })
    return { nodePositions: nodePos, edgePositions: edgePos, edges: edgeList, _nodes: nodes }
  }, [])

  // pulses travelling along random edges
  const pulses = useMemo(() =>
    Array.from({ length: PULSE_COUNT }, () => ({
      edge: Math.floor(Math.random() * edges.length),
      t: Math.random(),
      speed: 0.15 + Math.random() * 0.5,
    })), [edges.length])

  const pulsePositions = useMemo(() => new Float32Array(PULSE_COUNT * 3), [])

  useFrame((_, delta) => {
    if (group.current) {
      group.current.rotation.y += delta * 0.025
      group.current.rotation.x = Math.sin(Date.now() * 0.00005) * 0.12
    }
    // advance each pulse along its edge; respawn on a new edge when it arrives
    for (let p = 0; p < PULSE_COUNT; p++) {
      const pulse = pulses[p]
      pulse.t += delta * pulse.speed
      if (pulse.t >= 1) { pulse.t = 0; pulse.edge = Math.floor(Math.random() * edges.length) }
      const e = pulse.edge * 6
      pulsePositions[p * 3] = edgePositions[e] + (edgePositions[e + 3] - edgePositions[e]) * pulse.t
      pulsePositions[p * 3 + 1] = edgePositions[e + 1] + (edgePositions[e + 4] - edgePositions[e + 1]) * pulse.t
      pulsePositions[p * 3 + 2] = edgePositions[e + 2] + (edgePositions[e + 5] - edgePositions[e + 2]) * pulse.t
    }
    if (pulseGeom.current) {
      const attr = pulseGeom.current.getAttribute('position') as THREE.BufferAttribute
      attr.needsUpdate = true
    }
  })

  return (
    <group ref={group}>
      {/* edges */}
      <lineSegments>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[edgePositions, 3]} />
        </bufferGeometry>
        <lineBasicMaterial color={BLUE} transparent opacity={0.18} depthWrite={false} />
      </lineSegments>
      {/* nodes */}
      <points>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[nodePositions, 3]} />
        </bufferGeometry>
        <pointsMaterial color={GREEN} size={0.12} transparent opacity={0.85} sizeAttenuation depthWrite={false} />
      </points>
      {/* data pulses flowing along edges */}
      <points>
        <bufferGeometry ref={pulseGeom}>
          <bufferAttribute attach="attributes-position" args={[pulsePositions, 3]} />
        </bufferGeometry>
        <pointsMaterial color={GREEN_BRIGHT} size={0.2} transparent opacity={0.95} sizeAttenuation depthWrite={false} />
      </points>
    </group>
  )
}

// ---- Drifting particle dust ----------------------------------------------------------------

function ParticleField() {
  const ref = useRef<THREE.Points>(null)
  const positions = useMemo(() => {
    const count = 1400
    const arr = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      arr[i * 3] = (Math.random() - 0.5) * 26
      arr[i * 3 + 1] = (Math.random() - 0.5) * 16
      arr[i * 3 + 2] = (Math.random() - 0.5) * 14
    }
    return arr
  }, [])
  useFrame((_, delta) => {
    if (!ref.current) return
    ref.current.rotation.y -= delta * 0.012
  })
  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.03} color={BLUE_BRIGHT} transparent opacity={0.4} sizeAttenuation depthWrite={false} />
    </points>
  )
}

// ---- Nested rotating wireframe "AI core" ---------------------------------------------------

function AICore() {
  const outer = useRef<THREE.Mesh>(null)
  const inner = useRef<THREE.Mesh>(null)
  useFrame((_, delta) => {
    if (outer.current) { outer.current.rotation.y += delta * 0.08; outer.current.rotation.z += delta * 0.03 }
    if (inner.current) { inner.current.rotation.y -= delta * 0.14; inner.current.rotation.x += delta * 0.05 }
  })
  return (
    <group position={[3.2, 0.3, -1]}>
      <mesh ref={outer}>
        <icosahedronGeometry args={[2.6, 1]} />
        <meshBasicMaterial color={BLUE} wireframe transparent opacity={0.14} />
      </mesh>
      <mesh ref={inner}>
        <icosahedronGeometry args={[1.5, 1]} />
        <meshBasicMaterial color={GREEN} wireframe transparent opacity={0.2} />
      </mesh>
    </group>
  )
}

export function CyberBackground() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10">
      <div className="absolute inset-0 marble" />
      <Canvas
        className="absolute inset-0"
        camera={{ position: [0, 0, 11], fov: 62 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
      >
        <NeuralNetwork />
        <ParticleField />
        <AICore />
      </Canvas>
      {/* fade content edges into the base color */}
      <div className="absolute inset-x-0 top-0 h-40 bg-gradient-to-b from-base to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-56 bg-gradient-to-t from-base to-transparent" />
    </div>
  )
}
