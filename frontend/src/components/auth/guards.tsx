import { Navigate } from '@tanstack/react-router'
import { Loader2 } from 'lucide-react'
import type { ReactNode } from 'react'
import { useAuthStore } from '@/stores/auth'

export function FullScreenLoader() {
  return (
    <div className="marble flex min-h-screen items-center justify-center">
      <Loader2 className="h-7 w-7 animate-spin text-cyber" />
    </div>
  )
}

/** Gate a route on an authenticated session; otherwise send to login. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const status = useAuthStore((s) => s.status)
  if (status === 'loading') return <FullScreenLoader />
  if (status === 'unauthenticated') return <Navigate to="/login" />
  return <>{children}</>
}

/** Keep already-signed-in users off the auth pages. */
export function RedirectIfAuthed({ children }: { children: ReactNode }) {
  const status = useAuthStore((s) => s.status)
  if (status === 'loading') return <FullScreenLoader />
  // Target switches to /dashboard in B6.3 once that route exists.
  if (status === 'authenticated') return <Navigate to="/" />
  return <>{children}</>
}
