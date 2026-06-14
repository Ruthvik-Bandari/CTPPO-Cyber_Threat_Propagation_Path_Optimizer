import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/')({
  component: Landing,
})

// Placeholder — the full landing (3D background, scroll animations, Apple carousel) lands in B6.1.
function Landing() {
  return (
    <main className="marble flex min-h-screen flex-col items-center justify-center gap-4 px-6 text-center">
      <span className="rounded-full border border-cyber/30 px-3 py-1 text-xs uppercase tracking-widest text-cyber">
        AI-Powered Cybersecurity
      </span>
      <h1 className="text-gradient text-5xl font-bold sm:text-6xl">CTPPO</h1>
      <p className="max-w-xl text-muted">
        Cyber Threat Propagation Path Optimizer — frontend rebuild in progress.
      </p>
    </main>
  )
}
