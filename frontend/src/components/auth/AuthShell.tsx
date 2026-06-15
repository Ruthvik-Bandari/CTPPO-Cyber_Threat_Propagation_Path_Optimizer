import { Link } from '@tanstack/react-router'
import { ShieldHalf } from 'lucide-react'
import type { ReactNode } from 'react'

interface AuthShellProps {
  title: string
  subtitle?: string
  children: ReactNode
  footer?: ReactNode
}

export function AuthShell({ title, subtitle, children, footer }: AuthShellProps) {
  return (
    <div className="marble relative flex min-h-screen items-center justify-center px-6 py-16">
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-24 h-72 w-72 -translate-x-1/2 rounded-full bg-cyber/10 blur-[120px]"
      />
      <div className="relative flex w-full max-w-md flex-col gap-6">
        <Link to="/" className="flex items-center justify-center gap-2.5">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyber/15 text-cyber">
            <ShieldHalf className="h-5 w-5" />
          </span>
          <span className="font-display text-xl font-semibold">CTPPO</span>
        </Link>
        <div className="glass flex flex-col gap-6 rounded-3xl p-8">
          <div className="flex flex-col gap-1.5 text-center">
            <h1 className="text-2xl font-bold">{title}</h1>
            {subtitle && <p className="text-sm text-muted">{subtitle}</p>}
          </div>
          {children}
        </div>
        {footer && <p className="text-center text-sm text-muted">{footer}</p>}
      </div>
    </div>
  )
}
