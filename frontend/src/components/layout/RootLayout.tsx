import { lazy, Suspense } from 'react'
import { Outlet } from '@tanstack/react-router'

/*
 * Root shell. The animated cyber/AI WebGL background is mounted here so it sits behind EVERY
 * route (landing + dashboard + tools) at -z-10. It is lazy-loaded so the three.js bundle never
 * blocks first paint, and a CSS marble wash inside it is the no-WebGL fallback.
 * Per-area chrome (nav, footer, dashboard sidebar) is composed inside the individual routes.
 */
const CyberBackground = lazy(() =>
  import('@/components/effects/CyberBackground').then((m) => ({ default: m.CyberBackground })),
)

export default function RootLayout() {
  return (
    <div className="min-h-screen text-fg antialiased">
      <Suspense fallback={null}>
        <CyberBackground />
      </Suspense>
      <Outlet />
    </div>
  )
}
