import { useMemo, useRef } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'

/*
 * Animated WebGL background — a drifting particle field around a wireframe "threat surface".
 * Deliberately not a grid (per design direction): organic point cloud + icosahedron.
 * Fixed, full-bleed, pointer-events-none; a CSS marble wash sits behind it as a fallback.
 */

function ParticleField() {
  const ref = useRef<THREE.Points>(null)

  const positions = useMemo(() => {
    const count = 1800
    const arr = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      arr[i * 3] = (Math.random() - 0.5) * 20
      arr[i * 3 + 1] = (Math.random() - 0.5) * 13
      arr[i * 3 + 2] = (Math.random() - 0.5) * 13
    }
    return arr
  }, [])

  useFrame((_, delta) => {
    if (!ref.current) return
    ref.current.rotation.y += delta * 0.02
    ref.current.rotation.x += delta * 0.006
  })

  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={0.035}
        color="#2ff5a8"
        transparent
        opacity={0.55}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  )
}

function ThreatCore() {
  const ref = useRef<THREE.Mesh>(null)
  useFrame((_, delta) => {
    if (!ref.current) return
    ref.current.rotation.y += delta * 0.1
    ref.current.rotation.z += delta * 0.04
  })
  return (
    <mesh ref={ref} position={[2.4, 0.2, 0]}>
      <icosahedronGeometry args={[2.4, 2]} />
      <meshBasicMaterial color="#3b6fff" wireframe transparent opacity={0.16} />
    </mesh>
  )
}

export function CyberBackground() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10">
      <div className="absolute inset-0 marble" />
      <Canvas
        className="absolute inset-0"
        camera={{ position: [0, 0, 9], fov: 60 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
      >
        <ParticleField />
        <ThreatCore />
      </Canvas>
      {/* fade content edges into the base color */}
      <div className="absolute inset-x-0 top-0 h-40 bg-gradient-to-b from-base to-transparent" />
      <div className="absolute inset-x-0 bottom-0 h-56 bg-gradient-to-t from-base to-transparent" />
    </div>
  )
}
