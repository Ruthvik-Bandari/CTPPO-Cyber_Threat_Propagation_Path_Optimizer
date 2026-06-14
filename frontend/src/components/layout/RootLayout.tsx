import { Outlet } from '@tanstack/react-router'
import { useEffect } from 'react'
import { useAuthStore } from '@/stores/auth'

/*
 * Root shell. Rehydrates the session on mount; per-area chrome (nav, footer, dashboard
 * sidebar) is composed inside the individual routes so public and authed surfaces can differ.
 */
export default function RootLayout() {
  const bootstrap = useAuthStore((s) => s.bootstrap)

  useEffect(() => {
    void bootstrap()
  }, [bootstrap])

  return (
    <div className="min-h-screen bg-base text-fg antialiased">
      <Outlet />
    </div>
  )
}
