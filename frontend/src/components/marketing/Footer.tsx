import { Link } from '@tanstack/react-router'
import { ShieldHalf } from 'lucide-react'

export function Footer() {
  return (
    <footer className="relative mt-24 border-t border-line-soft">
      <div className="mx-auto flex max-w-6xl flex-col gap-8 px-6 py-12 md:flex-row md:items-start md:justify-between">
        <div className="flex max-w-sm flex-col gap-3">
          <div className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyber/15 text-cyber">
              <ShieldHalf className="h-5 w-5" />
            </span>
            <span className="font-display text-lg font-semibold">CTPPO</span>
          </div>
          <p className="text-sm text-muted">
            Cyber Threat Propagation Path Optimizer — multi-objective attack-path analysis grounded
            in real exploit data.
          </p>
        </div>

        <div className="flex flex-wrap gap-12">
          <div className="flex flex-col gap-2.5">
            <span className="text-xs font-medium uppercase tracking-widest text-faint">Product</span>
            <a href="/#capabilities" className="text-sm text-muted hover:text-fg">Capabilities</a>
            <a href="/#how" className="text-sm text-muted hover:text-fg">How it works</a>
            <a href="/#metrics" className="text-sm text-muted hover:text-fg">Results</a>
          </div>
          <div className="flex flex-col gap-2.5">
            <span className="text-xs font-medium uppercase tracking-widest text-faint">Platform</span>
            <Link to="/about" className="text-sm text-muted hover:text-fg">About</Link>
            <a href="/login" className="text-sm text-muted hover:text-fg">Sign in</a>
            <a href="/register" className="text-sm text-muted hover:text-fg">Get started</a>
          </div>
        </div>
      </div>

      <div className="mx-auto flex max-w-6xl flex-col gap-2 border-t border-line-soft px-6 py-6 text-xs text-faint md:flex-row md:items-center md:justify-between">
        <span>© {new Date().getFullYear()} CTPPO. Proprietary software — license required.</span>
        <span>Built on a data-grounded engine. No fabricated metrics.</span>
      </div>
    </footer>
  )
}
