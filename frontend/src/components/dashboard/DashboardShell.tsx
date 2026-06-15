import { useState } from 'react'
import { Link, Outlet, useNavigate } from '@tanstack/react-router'
import { LayoutDashboard, Boxes, Waypoints, BrainCircuit, Building2, LogOut, Menu, ShieldHalf } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
}

// Grows as feature routes are added in B6.7.
const NAV: NavItem[] = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard },
  { to: '/dashboard/instances', label: 'Instances', icon: Boxes },
  { to: '/dashboard/attack-paths', label: 'Attack paths', icon: Waypoints },
  { to: '/dashboard/classify', label: 'CVE severity', icon: BrainCircuit },
  { to: '/dashboard/enterprise', label: 'Enterprise', icon: Building2 },
]

function initials(name?: string) {
  if (!name) return 'U'
  return name
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? '')
    .join('')
}

export function DashboardShell() {
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)

  const handleLogout = async () => {
    await logout()
    navigate({ to: '/' })
  }

  const SidebarContent = (
    <div className="flex h-full flex-col">
      <Link to="/dashboard" className="flex items-center gap-2.5 px-6 py-6" onClick={() => setOpen(false)}>
        <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyber/15 text-cyber">
          <ShieldHalf className="h-5 w-5" />
        </span>
        <span className="font-display text-lg font-semibold">CTPPO</span>
      </Link>

      <nav className="flex flex-1 flex-col gap-1 px-3">
        {NAV.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            activeOptions={{ exact: item.to === '/dashboard' }}
            onClick={() => setOpen(false)}
            className="flex items-center gap-3 rounded-xl px-4 py-2.5 text-sm text-muted transition-colors hover:bg-surface/70 hover:text-fg"
            activeProps={{ className: 'bg-cyber/10 text-cyber' }}
          >
            <item.icon className="h-[18px] w-[18px]" />
            <span>{item.label}</span>
          </Link>
        ))}
      </nav>

      <div className="flex flex-col gap-2 border-t border-line-soft p-3">
        <div className="flex items-center gap-3 rounded-xl bg-surface/50 px-3 py-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-full bg-cyber/15 text-sm font-semibold text-cyber">
            {initials(user?.name)}
          </span>
          <div className="flex min-w-0 flex-col">
            <span className="truncate text-sm font-medium">{user?.name}</span>
            <span className="truncate text-xs text-faint">{user?.email}</span>
          </div>
        </div>
        <button
          type="button"
          onClick={handleLogout}
          className="flex items-center gap-3 rounded-xl px-4 py-2.5 text-sm text-muted transition-colors hover:bg-danger/15 hover:text-danger"
        >
          <LogOut className="h-[18px] w-[18px]" />
          <span>Sign out</span>
        </button>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-base">
      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-line-soft bg-base-2/60 backdrop-blur lg:block">
        {SidebarContent}
      </aside>

      {/* Mobile drawer */}
      {open && (
        <>
          <div className="fixed inset-0 z-40 bg-base/70 backdrop-blur-sm lg:hidden" onClick={() => setOpen(false)} />
          <aside className="fixed inset-y-0 left-0 z-50 w-64 border-r border-line-soft bg-base-2 lg:hidden">
            {SidebarContent}
          </aside>
        </>
      )}

      <div className="lg:pl-64">
        {/* Mobile top bar */}
        <div className="flex items-center justify-between border-b border-line-soft px-4 py-3 lg:hidden">
          <Link to="/dashboard" className="flex items-center gap-2">
            <ShieldHalf className="h-5 w-5 text-cyber" />
            <span className="font-display font-semibold">CTPPO</span>
          </Link>
          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-label="Open menu"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-line text-muted"
          >
            <Menu className="h-5 w-5" />
          </button>
        </div>

        <main className="mx-auto max-w-6xl px-5 py-8 sm:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
