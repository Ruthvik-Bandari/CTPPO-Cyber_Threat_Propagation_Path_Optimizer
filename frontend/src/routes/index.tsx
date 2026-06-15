import { lazy, Suspense } from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { motion, useScroll, useTransform } from 'motion/react'
import {
  Waypoints,
  Database,
  BrainCircuit,
  Workflow,
  Server,
  Terminal,
  ArrowRight,
  Sparkles,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollReveal } from '@/components/effects/ScrollReveal'
import { AppleCarousel, type CarouselCard } from '@/components/effects/AppleCarousel'
import { Nav } from '@/components/marketing/Nav'
import { Footer } from '@/components/marketing/Footer'

// three.js is heavy — keep it out of the landing's critical path; the CSS marble wash shows first.
const CyberBackground = lazy(() =>
  import('@/components/effects/CyberBackground').then((m) => ({ default: m.CyberBackground })),
)

export const Route = createFileRoute('/')({
  component: Landing,
})

const CAPABILITIES: CarouselCard[] = [
  {
    category: 'Core Engine',
    title: 'Multi-objective path optimization',
    description: 'NAMOA* returns the Pareto front of attack paths — not one arbitrary ranking.',
    stat: '3 competing objectives',
    Icon: Waypoints,
    details: (
      <div className="flex flex-col gap-3">
        <p>
          The engine searches the attack graph with NAMOA*, a multi-objective A* variant, and
          returns every <em>Pareto-optimal</em> path: routes where you cannot improve one
          objective without sacrificing another.
        </p>
        <p>It optimizes three competing objectives per path:</p>
        <ul className="flex flex-col gap-1.5 text-sm">
          <li>· <span className="text-fg">Success probability</span> — chance the chain actually works</li>
          <li>· <span className="text-fg">Time-to-exploit</span> — relative attacker effort</li>
          <li>· <span className="text-fg">Business impact</span> — value of what gets reached</li>
        </ul>
      </div>
    ),
  },
  {
    category: 'Threat Data',
    title: 'Data-grounded cost model',
    description: 'Edge costs come from real exploit data, with provenance tracked on every value.',
    stat: '341,309 EPSS · 1,619 KEV',
    Icon: Database,
    details: (
      <div className="flex flex-col gap-3">
        <p>
          Every edge cost is derived from real vulnerability data — EPSS exploit-prediction
          scores, the CISA Known-Exploited-Vulnerabilities catalog, and CVSS sub-scores — not
          hand-tuned severity formulas.
        </p>
        <p>
          A live snapshot of <span className="font-mono text-cyber-bright">341,309</span> EPSS
          scores and <span className="font-mono text-cyber-bright">1,619</span> KEV CVEs is cached
          locally. Each cost component records its provenance, so data-grounded values are
          distinguishable from heuristic fallbacks.
        </p>
      </div>
    ),
  },
  {
    category: 'Machine Learning',
    title: 'ML-assisted CVE triage',
    description: 'A text-only classifier predicts severity from the description alone.',
    stat: '0.73 macro-F1 (held-out)',
    Icon: BrainCircuit,
    details: (
      <div className="flex flex-col gap-3">
        <p>
          A fine-tuned DistilBERT classifier predicts CVE severity from the description text —
          <span className="text-fg"> description in, severity out</span>. It deliberately does not
          take the CVSS score as input (severity is a threshold on that score, which would be
          circular).
        </p>
        <p>
          Held-out macro-F1 is <span className="font-mono text-cyber-bright">0.73</span> versus a
          0.10 majority-class baseline. An honest, measured number — not a marketing figure.
        </p>
      </div>
    ),
  },
  {
    category: 'Graph AI',
    title: 'GNN exploitability refinement',
    description: 'A graph neural network refines per-edge success probability from topology.',
    stat: '0.956 ROC-AUC (external)',
    Icon: Workflow,
    details: (
      <div className="flex flex-col gap-3">
        <p>
          A graph neural network runs over the attack-graph topology and blends a learned
          exploitability signal into each edge's success probability before the search.
        </p>
        <p>
          On a real external Active-Directory attack-graph dataset, message passing reached
          <span className="font-mono text-cyber-bright"> 0.956</span> ROC-AUC for attack-path
          structure versus 0.883 without it. Reported as external validation — on CTPPO's own
          synthetic graphs the GNN improves calibration but only matches EPSS ranking, and we say
          so.
        </p>
      </div>
    ),
  },
  {
    category: 'Modeling',
    title: 'Multi-host network modeling',
    description: 'Build attack graphs with lateral movement across segmented zones.',
    stat: 'zones + lateral movement',
    Icon: Server,
    details: (
      <div className="flex flex-col gap-3">
        <p>
          A spec-driven builder turns a network description (hosts, vulnerabilities, segmentation
          zones) into a canonical attack graph with lateral-movement edges — compromising one host
          unlocks pivots to the hosts it can reach.
        </p>
        <p>
          Per-host exploit edges are data-grounded; cross-host lateral edges use a
          segmentation-aware prior, explicitly flagged as a heuristic calibration target.
        </p>
      </div>
    ),
  },
  {
    category: 'Automation',
    title: 'Terminal & CI/CD client',
    description: 'Scan a repository from the command line with a subscription-tied API key.',
    stat: 'ctppo-cli',
    Icon: Terminal,
    details: (
      <div className="flex flex-col gap-3">
        <p>
          A distributable pip client authenticates with an API key issued from your subscription,
          walks a repository, runs the model-assisted reviewer when available, and submits the
          results as a workspace — designed to drop into CI/CD pipelines.
        </p>
        <p className="font-mono text-sm text-cyber-bright">$ ctppo-cli scan ./repo</p>
      </div>
    ),
  },
]

const METRICS = [
  { value: '0.73', unit: 'macro-F1', label: 'CVE severity (held-out, text-only)' },
  { value: '341,309', unit: 'scores', label: 'EPSS exploit predictions (live)' },
  { value: '1,619', unit: 'CVEs', label: 'CISA KEV tracked' },
  { value: '0.956', unit: 'ROC-AUC', label: 'Attack-path structure (external validation)' },
]

const STEPS = [
  {
    n: '01',
    title: 'Model the network',
    body: 'Describe hosts, vulnerabilities and segmentation zones — or import a scan. The builder constructs a canonical attack graph with lateral movement.',
  },
  {
    n: '02',
    title: 'Ground the costs',
    body: 'EPSS, CISA KEV and CVSS map each edge to three objectives: success probability, time-to-exploit and business impact — with provenance tracked.',
  },
  {
    n: '03',
    title: 'Optimize the paths',
    body: 'NAMOA* returns the Pareto-optimal attack paths, so you remediate what actually shifts the front — not whatever EPSS happened to rank first.',
  },
]

function Landing() {
  const { scrollY } = useScroll()
  const heroY = useTransform(scrollY, [0, 500], [0, 120])
  const heroOpacity = useTransform(scrollY, [0, 420], [1, 0])

  return (
    <div className="relative overflow-x-hidden">
      {/* CSS marble fallback shows until the WebGL chunk loads */}
      <div aria-hidden className="marble pointer-events-none fixed inset-0 -z-10" />
      <Suspense fallback={null}>
        <CyberBackground />
      </Suspense>
      <Nav />

      {/* Hero */}
      <section className="relative flex min-h-screen items-center justify-center px-6 pt-28">
        <motion.div
          style={{ y: heroY, opacity: heroOpacity }}
          className="flex max-w-3xl flex-col items-center text-center"
        >
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          >
            <Badge variant="cyber" className="mb-6">
              <Sparkles className="h-3.5 w-3.5" />
              AI-powered cybersecurity platform
            </Badge>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 22 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.05, ease: [0.16, 1, 0.3, 1] }}
            className="text-balance text-5xl font-bold leading-[1.05] sm:text-6xl md:text-7xl"
          >
            <span className="text-gradient">See the path</span>
            <br />
            attackers actually take.
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 22 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.12, ease: [0.16, 1, 0.3, 1] }}
            className="mt-6 max-w-xl text-lg text-muted"
          >
            CTPPO finds the Pareto-optimal attack paths through your network — balancing success
            probability, attacker effort and business impact — grounded in real exploit data.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 22 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.18, ease: [0.16, 1, 0.3, 1] }}
            className="mt-9 flex flex-wrap items-center justify-center gap-3"
          >
            <Button asChild size="lg">
              <a href="/register">
                Get started <ArrowRight className="h-4 w-4" />
              </a>
            </Button>
            <Button asChild variant="outline" size="lg">
              <a href="#capabilities">Explore capabilities</a>
            </Button>
          </motion.div>
        </motion.div>
      </section>

      {/* Capabilities */}
      <section id="capabilities" className="relative mx-auto max-w-6xl px-6 py-24">
        <ScrollReveal className="mb-10 flex max-w-2xl flex-col gap-3">
          <Badge variant="marine" className="w-fit">What it does</Badge>
          <h2 className="text-4xl font-bold sm:text-5xl">A real engine, not a dashboard skin</h2>
          <p className="text-muted">
            Six capabilities power CTPPO end to end. Tap a card for the details — including the
            honest caveats.
          </p>
        </ScrollReveal>
        <ScrollReveal delay={0.1}>
          <AppleCarousel cards={CAPABILITIES} />
        </ScrollReveal>
      </section>

      {/* How it works */}
      <section id="how" className="relative mx-auto max-w-6xl px-6 py-24">
        <ScrollReveal className="mb-12 flex max-w-2xl flex-col gap-3">
          <Badge variant="cyber" className="w-fit">How it works</Badge>
          <h2 className="text-4xl font-bold sm:text-5xl">Three steps to the path that matters</h2>
        </ScrollReveal>
        <div className="flex flex-col gap-5 md:flex-row">
          {STEPS.map((step, i) => (
            <ScrollReveal key={step.n} delay={i * 0.1} className="flex-1">
              <div className="flex h-full flex-col gap-4 rounded-3xl border border-line bg-surface/40 p-7 backdrop-blur transition-colors hover:border-cyber/40">
                <span className="font-mono text-3xl font-semibold text-cyber/70">{step.n}</span>
                <h3 className="text-xl font-semibold">{step.title}</h3>
                <p className="text-sm text-muted">{step.body}</p>
              </div>
            </ScrollReveal>
          ))}
        </div>
      </section>

      {/* Metrics */}
      <section id="metrics" className="relative mx-auto max-w-6xl px-6 py-24">
        <ScrollReveal className="mb-12 flex max-w-2xl flex-col gap-3">
          <Badge variant="marine" className="w-fit">Measured, not marketed</Badge>
          <h2 className="text-4xl font-bold sm:text-5xl">Numbers we can stand behind</h2>
          <p className="text-muted">
            Every figure below is a documented measurement with its evaluation context. No
            invented accuracy claims.
          </p>
        </ScrollReveal>
        <div className="flex flex-wrap gap-5">
          {METRICS.map((m, i) => (
            <ScrollReveal key={m.label} delay={i * 0.08} className="min-w-[15rem] flex-1">
              <div className="flex h-full flex-col gap-2 rounded-3xl border border-line bg-surface/40 p-7 backdrop-blur">
                <div className="flex items-baseline gap-2">
                  <span className="font-display text-4xl font-bold text-cyber">{m.value}</span>
                  <span className="text-sm text-muted">{m.unit}</span>
                </div>
                <span className="text-sm text-muted">{m.label}</span>
              </div>
            </ScrollReveal>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="relative mx-auto max-w-6xl px-6 py-24">
        <ScrollReveal>
          <div className="glow-cyber flex flex-col items-center gap-6 rounded-[2rem] border border-cyber/20 bg-surface/50 px-8 py-16 text-center backdrop-blur">
            <h2 className="max-w-2xl text-4xl font-bold sm:text-5xl">
              Activate your license and start mapping risk
            </h2>
            <p className="max-w-xl text-muted">
              Create an account, activate a product key, and unlock the full platform — instances,
              attack-path analysis, the enterprise tier and the CI/CD client.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <Button asChild size="lg">
                <a href="/register">
                  Create account <ArrowRight className="h-4 w-4" />
                </a>
              </Button>
              <Button asChild variant="outline" size="lg">
                <a href="/login">Sign in</a>
              </Button>
            </div>
          </div>
        </ScrollReveal>
      </section>

      <Footer />
    </div>
  )
}
