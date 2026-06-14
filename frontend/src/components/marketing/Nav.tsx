import { useState } from 'react'
import { Link } from '@tanstack/react-router'
import { motion, AnimatePresence } from 'motion/react'
import { ShieldHalf, Menu, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useAuthStore } from '@/stores/auth'

const SECTIONS = [
  { href: '/#capabilities', label: 'Capabilities' },
  { href: '/#how', label: 'How it works' },
  { href: '/#metrics', label: 'Results' },
]

export function Nav() {
  const status = useAuthStore((s) => s.status)
  const [open, setOpen] = useState(false)
  const authed = status === 'authenticated'

  return (
    <header className="fixed inset-x-0 top-0 z-40">
      <div className="glass mx-auto mt-3 flex max-w-6xl items-center justify-between rounded-2xl px-4 py-3 sm:px-6">
        <Link to="/" className="flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyber/15 text-cyber">
            <ShieldHalf className="h-5 w-5" />
          </span>
          <span className="font-display text-lg font-semibold tracking-tight">CTPPO</span>
        </Link>

        <nav className="hidden items-center gap-1 md:flex">
          {SECTIONS.map((s) => (
            <a
              key={s.href}
              href={s.href}
              className="rounded-lg px-3 py-2 text-sm text-muted transition-colors hover:text-fg"
            >
              {s.label}
            </a>
          ))}
          <Link
            to="/about"
            className="rounded-lg px-3 py-2 text-sm text-muted transition-colors hover:text-fg [&.active]:text-cyber"
          >
            About
          </Link>
        </nav>

        <div className="hidden items-center gap-2 md:flex">
          {authed ? (
            <Button asChild size="sm">
              <a href="/dashboard">Dashboard</a>
            </Button>
          ) : (
            <>
              <Button asChild variant="ghost" size="sm">
                <a href="/login">Sign in</a>
              </Button>
              <Button asChild size="sm">
                <a href="/register">Get started</a>
              </Button>
            </>
          )}
        </div>

        <button
          onClick={() => setOpen((v) => !v)}
          aria-label="Toggle menu"
          aria-expanded={open}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-line text-muted md:hidden"
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            className="glass mx-auto mt-2 flex max-w-6xl flex-col gap-1 rounded-2xl p-3 md:hidden"
          >
            {SECTIONS.map((s) => (
              <a
                key={s.href}
                href={s.href}
                onClick={() => setOpen(false)}
                className="rounded-lg px-3 py-2.5 text-sm text-muted hover:bg-surface/60 hover:text-fg"
              >
                {s.label}
              </a>
            ))}
            <Link
              to="/about"
              onClick={() => setOpen(false)}
              className="rounded-lg px-3 py-2.5 text-sm text-muted hover:bg-surface/60 hover:text-fg"
            >
              About
            </Link>
            <div className="my-1 hairline" />
            {authed ? (
              <a href="/dashboard" className="rounded-lg px-3 py-2.5 text-sm font-medium text-cyber">
                Dashboard
              </a>
            ) : (
              <div className="flex gap-2 px-1 pt-1">
                <Button asChild variant="outline" size="sm" className="flex-1">
                  <a href="/login">Sign in</a>
                </Button>
                <Button asChild size="sm" className="flex-1">
                  <a href="/register">Get started</a>
                </Button>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  )
}
