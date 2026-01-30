import { Outlet, Link, useNavigate } from '@tanstack/react-router'
import { useAuthStore } from '@/stores/auth'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield,
  LayoutDashboard,
  Target,
  Network,
  Settings,
  LogOut,
  Menu,
  X,
  User,
  Radar,
} from 'lucide-react'
import { useState } from 'react'

export default function RootLayout() {
  const { isAuthenticated, user, logout } = useAuthStore()
  const navigate = useNavigate()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const handleLogout = () => {
    logout()
    navigate({ to: '/login' })
  }

  const navItems = [
    { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/scan', icon: Radar, label: 'Scan Target' },
    { to: '/classify', icon: Target, label: 'Classify CVE' },
    { to: '/attack-paths', icon: Network, label: 'Attack Paths' },
    { to: '/settings', icon: Settings, label: 'Settings' },
  ]

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-background bg-grid">
        <Outlet />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Mobile menu button */}
      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-secondary"
      >
        {sidebarOpen ? <X size={24} /> : <Menu size={24} />}
      </button>

      {/* Sidebar */}
      <AnimatePresence>
        {(sidebarOpen || true) && (
          <motion.aside
            initial={{ x: -280 }}
            animate={{ x: 0 }}
            exit={{ x: -280 }}
            className={`fixed inset-y-0 left-0 z-40 w-64 bg-card border-r border-border transform 
              ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0 transition-transform`}
          >
            {/* Logo */}
            <div className="flex items-center gap-3 px-6 py-6 border-b border-border">
              <div className="p-2 rounded-xl bg-primary/20">
                <Shield className="w-8 h-8 text-primary" />
              </div>
              <div>
                <h1 className="text-xl font-bold">CTPPO</h1>
                <p className="text-xs text-muted-foreground">v3.0.0</p>
              </div>
            </div>

            {/* Navigation */}
            <nav className="p-4 space-y-2">
              {navItems.map((item) => (
                <Link
                  key={item.to}
                  to={item.to}
                  onClick={() => setSidebarOpen(false)}
                  className="flex items-center gap-3 px-4 py-3 rounded-lg text-muted-foreground 
                    hover:bg-secondary hover:text-foreground transition-colors
                    [&.active]:bg-primary/20 [&.active]:text-primary"
                >
                  <item.icon size={20} />
                  <span>{item.label}</span>
                </Link>
              ))}
            </nav>

            {/* User section */}
            <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-border">
              <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-secondary/50">
                <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
                  <User size={20} className="text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{user?.name}</p>
                  <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center gap-3 px-4 py-3 mt-2 w-full rounded-lg 
                  text-muted-foreground hover:bg-destructive/20 hover:text-destructive transition-colors"
              >
                <LogOut size={20} />
                <span>Logout</span>
              </button>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Main content */}
      <main className="lg:ml-64 min-h-screen">
        <div className="p-6 lg:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
