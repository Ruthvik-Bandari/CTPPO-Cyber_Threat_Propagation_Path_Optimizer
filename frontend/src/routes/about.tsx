import { createFileRoute } from '@tanstack/react-router'
import {
  Target,
  Database,
  BrainCircuit,
  Layers,
  Building2,
  KeyRound,
  Terminal,
  CircleAlert,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { ScrollReveal } from '@/components/effects/ScrollReveal'
import { Nav } from '@/components/marketing/Nav'
import { Footer } from '@/components/marketing/Footer'

export const Route = createFileRoute('/about')({
  component: About,
})

interface Capability {
  Icon: LucideIcon
  title: string
  body: string
}

const ENGINE: Capability[] = [
  {
    Icon: Target,
    title: 'Multi-objective attack-path optimization',
    body: 'NAMOA*, a multi-objective A* search, returns the Pareto front of attack paths through the graph — every route where no objective can improve without another getting worse. It optimizes success probability, time-to-exploit (attacker effort) and business impact simultaneously, rather than collapsing risk to a single CVSS or EPSS rank.',
  },
  {
    Icon: Database,
    title: 'Data-grounded cost model',
    body: 'Each edge cost is derived from real data — EPSS exploit-prediction scores, the CISA Known-Exploited-Vulnerabilities catalog, and CVSS impact/exploitability sub-scores. A live snapshot of 341,309 EPSS scores and 1,619 KEV CVEs is cached locally, and every cost component records its provenance so data-grounded values are never confused with heuristic fallbacks.',
  },
  {
    Icon: BrainCircuit,
    title: 'ML-assisted triage',
    body: 'A fine-tuned text-only DistilBERT classifier predicts CVE severity from the description alone (0.73 held-out macro-F1 vs a 0.10 majority baseline). A graph neural network refines per-edge exploitability from topology — externally validated at 0.956 ROC-AUC on a real Active-Directory dataset. On our own synthetic graphs the GNN improves calibration but only matches EPSS ranking, and we report that honestly.',
  },
  {
    Icon: Layers,
    title: 'Multi-host network modeling',
    body: 'A spec-driven builder turns hosts, vulnerabilities and segmentation zones into a canonical attack graph with lateral-movement edges. Per-host exploit edges are data-grounded; cross-host lateral edges use a segmentation-aware prior, explicitly flagged as a heuristic calibration target.',
  },
]

const PLATFORM: Capability[] = [
  {
    Icon: KeyRound,
    title: 'Accounts & subscriptions',
    body: 'Server-side session authentication with an HttpOnly cookie (revocable logout), salted password hashing, and password reset. The dashboard unlocks only when a product key is activated and the subscription is active.',
  },
  {
    Icon: Layers,
    title: 'Instances (workspaces)',
    body: 'Each scan or analysis lives in an owner-scoped instance with full CRUD — a prompt, a target spec and file metadata. You only ever see your own.',
  },
  {
    Icon: Building2,
    title: 'Enterprise tier',
    body: 'Organizations with a seat allotment and role-based access control: the creator is the first admin, admins manage membership and roles, the last admin is protected, and members can view the roster.',
  },
  {
    Icon: Terminal,
    title: 'API keys & CI/CD client',
    body: 'Issue subscription-tied API keys (shown once, stored only as a hash) and drive the platform from a distributable pip client — walk a repository, run the model-assisted reviewer, and submit results as an instance. Built for pipelines.',
  },
]

const STUBS = [
  'In-memory stores (subscriptions, instances, orgs, API keys) are not yet backed by Postgres/Redis.',
  'Password-reset email delivery is stubbed in development — the reset token is returned in the response rather than emailed.',
  'The CLI scans local paths only; SSH login and remote Git clone/verification are not implemented yet.',
  'The LLM code reviewer needs the anthropic package and an API key to produce findings; otherwise it degrades to metadata only.',
]

function Section({ items }: { items: Capability[] }) {
  return (
    <div className="flex flex-col gap-5 md:flex-row md:flex-wrap">
      {items.map((c, i) => (
        <ScrollReveal key={c.title} delay={i * 0.06} className="min-w-[18rem] flex-1">
          <div className="flex h-full flex-col gap-3 rounded-3xl border border-line bg-surface/40 p-7 backdrop-blur">
            <div className="flex w-fit rounded-2xl bg-cyber/10 p-3 text-cyber">
              <c.Icon className="h-6 w-6" />
            </div>
            <h3 className="text-xl font-semibold">{c.title}</h3>
            <p className="text-sm text-muted">{c.body}</p>
          </div>
        </ScrollReveal>
      ))}
      {/* keep a balanced flex row when the count is odd */}
      {items.length % 2 === 1 && <div className="hidden min-w-[18rem] flex-1 md:block" aria-hidden />}
    </div>
  )
}

function About() {
  return (
    <div className="relative overflow-x-hidden">
      <Nav />

      <main className="mx-auto max-w-6xl px-6 pt-36">
        <ScrollReveal className="flex max-w-3xl flex-col gap-4">
          <Badge variant="cyber" className="w-fit">About CTPPO</Badge>
          <h1 className="text-balance text-5xl font-bold leading-[1.05] sm:text-6xl">
            What CTPPO actually does
          </h1>
          <p className="text-lg text-muted">
            CTPPO — the Cyber Threat Propagation Path Optimizer — answers a question vulnerability
            scanners don't: <span className="text-fg">given everything wrong with my network, which
            attack path matters most, and what should I fix first?</span> It models the network as an
            attack graph, grounds every edge in real exploit data, and searches for the
            Pareto-optimal paths an attacker would take.
          </p>
        </ScrollReveal>

        <section className="mt-20 flex flex-col gap-8">
          <ScrollReveal>
            <h2 className="text-3xl font-bold sm:text-4xl">The engine</h2>
          </ScrollReveal>
          <Section items={ENGINE} />
        </section>

        <section className="mt-20 flex flex-col gap-8">
          <ScrollReveal>
            <h2 className="text-3xl font-bold sm:text-4xl">The platform</h2>
          </ScrollReveal>
          <Section items={PLATFORM} />
        </section>

        <section className="mt-20">
          <ScrollReveal>
            <div className="flex flex-col gap-5 rounded-3xl border border-warn/25 bg-warn/5 p-8">
              <div className="flex items-center gap-3">
                <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-warn/15 text-warn">
                  <CircleAlert className="h-5 w-5" />
                </span>
                <h2 className="text-2xl font-bold">What's honestly still a stub</h2>
              </div>
              <p className="text-sm text-muted">
                Honesty-first is a core principle here — these are real gaps, labeled as such, not
                bugs and not hidden behind marketing copy.
              </p>
              <ul className="flex flex-col gap-2.5">
                {STUBS.map((s) => (
                  <li key={s} className="flex gap-3 text-sm text-muted">
                    <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-warn" />
                    <span>{s}</span>
                  </li>
                ))}
              </ul>
            </div>
          </ScrollReveal>
        </section>

        <section className="mt-20">
          <ScrollReveal>
            <div className="flex flex-col gap-3 rounded-3xl border border-line bg-surface/40 p-8 backdrop-blur">
              <h2 className="text-2xl font-bold">Built with</h2>
              <p className="text-sm text-muted">
                A Python engine (NumPy, NetworkX-style graph search, PyTorch + Transformers for the
                ML) behind a FastAPI service, and this React 19 + TypeScript + Tailwind v4 frontend
                with TanStack Router, Motion and react-three-fiber.
              </p>
            </div>
          </ScrollReveal>
        </section>
      </main>

      <Footer />
    </div>
  )
}
