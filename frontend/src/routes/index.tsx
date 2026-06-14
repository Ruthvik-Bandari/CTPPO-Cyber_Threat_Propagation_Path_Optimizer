import { useState } from 'react'
import { Link, createFileRoute } from '@tanstack/react-router'
import { motion } from 'framer-motion'
import {
  Shield,
  Zap,
  Network,
  FileText,
  Brain,
  Target,
  CheckCircle,
  ArrowRight,
  Mail,
  Key,
  Loader2,
  AlertCircle,
  Github,
  Linkedin,
  // ExternalLink,
} from 'lucide-react'

export const Route = createFileRoute('/')({
  component: LandingPage,
})

function LandingPage() {
  const [activeTab, setActiveTab] = useState<'features' | 'about' | 'subscribe'>('features')
  const [email, setEmail] = useState('')
  const [productKey, setProductKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const handleActivate = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setMessage(null)

    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/subscription/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ product_key: productKey, email }),
      })

      const data = await response.json()

      if (response.ok) {
        setMessage({ type: 'success', text: data.message || 'Product key activated successfully!' })
        setEmail('')
        setProductKey('')
      } else {
        setMessage({ type: 'error', text: data.detail || 'Activation failed' })
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Network error. Please try again.' })
    } finally {
      setLoading(false)
    }
  }

  const features = [
    {
      icon: Brain,
      title: 'AI-Powered CVE Classification',
      description: 'DistilBERT classifier predicting CVE severity from descriptions (0.71 macro-F1, held-out)',
      stat: '0.71 macro-F1',
    },
    {
      icon: Network,
      title: 'NAMOA* Path Optimization',
      description: 'Multi-objective attack path analysis using Pareto-optimal algorithms',
      stat: 'Multi-Objective',
    },
    {
      icon: Target,
      title: 'Real-time Scanning',
      description: 'Fast vulnerability scanning with cloud provider detection',
      stat: '<30s',
    },
    {
      icon: Shield,
      title: 'Security Headers Check',
      description: 'Comprehensive HTTP security headers and SSL/TLS analysis',
      stat: '10+ Checks',
    },
    {
      icon: Zap,
      title: 'Graph Neural Networks',
      description: 'Advanced GNN models for attack propagation prediction',
      stat: 'GNN + RL',
    },
    {
      icon: FileText,
      title: 'Professional Reports',
      description: 'Generate detailed PDF reports for compliance and audits',
      stat: 'PDF Export',
    },
  ]

  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-lg border-b border-border">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-primary/20">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <span className="text-xl font-bold">CTPPO</span>
            <span className="text-xs text-muted-foreground">v3.0.0</span>
          </div>

          <div className="flex items-center gap-2">
            {(['features', 'about', 'subscribe'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === tab
                    ? 'bg-primary text-primary-foreground'
                    : 'hover:bg-secondary'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
            <Link
              to="/login"
              className="ml-4 px-4 py-2 rounded-lg bg-secondary hover:bg-secondary/80 text-sm font-medium"
            >
              Login
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-16 px-4">
        <div className="max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm mb-6">
              <Zap size={16} />
              0.71 macro-F1 on CVE severity classification
            </div>

            <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-primary via-blue-400 to-cyan-400 bg-clip-text text-transparent">
              Cyber Threat Propagation Path Optimizer
            </h1>

            <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
              Enterprise-grade AI-powered cybersecurity platform combining ML, Graph Neural Networks, 
              and multi-objective optimization for attack path analysis.
            </p>

            <div className="flex items-center justify-center gap-4 mb-12">
              <Link
                to="/login"
                className="px-6 py-3 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 flex items-center gap-2"
              >
                Get Started
                <ArrowRight size={18} />
              </Link>
              <button
                onClick={() => setActiveTab('features')}
                className="px-6 py-3 rounded-lg border border-border hover:bg-secondary font-medium"
              >
                Learn More
              </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-2xl mx-auto">
              {[
                { value: '0.71', label: 'Macro-F1 (held-out)' },
                { value: '3.2K', label: 'CVEs trained' },
                { value: '341K', label: 'EPSS scores' },
                { value: '1.6K', label: 'CISA KEV tracked' },
              ].map((stat, i) => (
                <motion.div
                  key={stat.label}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 + i * 0.1 }}
                  className="p-4 rounded-xl bg-card border border-border"
                >
                  <div className="text-2xl font-bold text-primary">{stat.value}</div>
                  <div className="text-sm text-muted-foreground">{stat.label}</div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* Tab Content */}
      <section className="py-16 px-4">
        <div className="max-w-6xl mx-auto">
          {/* Features Tab */}
          {activeTab === 'features' && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.3 }}
            >
              <h2 className="text-3xl font-bold text-center mb-12">Core Features</h2>
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {features.map((feature, i) => (
                  <motion.div
                    key={feature.title}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="p-6 rounded-xl bg-card border border-border hover:border-primary/50 transition-colors"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="p-3 rounded-lg bg-primary/20">
                        <feature.icon className="w-6 h-6 text-primary" />
                      </div>
                      <span className="px-3 py-1 rounded-full bg-green-500/20 text-green-500 text-xs font-medium">
                        {feature.stat}
                      </span>
                    </div>
                    <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
                    <p className="text-muted-foreground text-sm">{feature.description}</p>
                  </motion.div>
                ))}
              </div>

              {/* Technology Stack */}
              <div className="mt-16">
                <h3 className="text-2xl font-bold text-center mb-8">Technology Stack</h3>
                <div className="grid md:grid-cols-3 gap-6">
                  <div className="p-6 rounded-xl bg-card border border-border">
                    <h4 className="font-semibold mb-3 text-primary">Frontend</h4>
                    <ul className="space-y-2 text-sm text-muted-foreground">
                      <li>• React 18 + TypeScript</li>
                      <li>• TailwindCSS</li>
                      <li>• TanStack Router & Query</li>
                      <li>• Framer Motion</li>
                    </ul>
                  </div>
                  <div className="p-6 rounded-xl bg-card border border-border">
                    <h4 className="font-semibold mb-3 text-primary">Backend</h4>
                    <ul className="space-y-2 text-sm text-muted-foreground">
                      <li>• Python 3.10+</li>
                      <li>• FastAPI</li>
                      <li>• JWT + 2FA Auth</li>
                      <li>• Pydantic v2</li>
                    </ul>
                  </div>
                  <div className="p-6 rounded-xl bg-card border border-border">
                    <h4 className="font-semibold mb-3 text-primary">ML/AI</h4>
                    <ul className="space-y-2 text-sm text-muted-foreground">
                      <li>• PyTorch</li>
                      <li>• HuggingFace Transformers</li>
                      <li>• DistilBERT</li>
                      <li>• NetworkX + GNN</li>
                    </ul>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* About Tab */}
          {activeTab === 'about' && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.3 }}
              className="max-w-3xl mx-auto"
            >
              <h2 className="text-3xl font-bold text-center mb-12">About the Developer</h2>
              
              <div className="p-8 rounded-2xl bg-card border border-border">
                <div className="flex flex-col md:flex-row items-center gap-8">
                  <div className="w-32 h-32 rounded-full bg-gradient-to-br from-primary to-cyan-500 flex items-center justify-center text-4xl font-bold text-white">
                    RB
                  </div>
                  <div className="flex-1 text-center md:text-left">
                    <h3 className="text-2xl font-bold mb-2">Ruthvik Bandari</h3>
                    <p className="text-primary mb-4">MS Applied AI @ Northeastern University</p>
                    <p className="text-muted-foreground mb-4">
                      Graduate student specializing in Machine Learning, Deep Learning, and Cybersecurity.
                      Building AI-powered solutions to solve real-world security challenges.
                    </p>
                    <div className="flex items-center justify-center md:justify-start gap-3">
                      <a
                        href="mailto:bandari.ru@northeastern.edu"
                        className="p-2 rounded-lg bg-secondary hover:bg-secondary/80"
                        title="Email"
                      >
                        <Mail size={20} />
                      </a>
                      <a
                        href="https://linkedin.com/in/ruthvikbandari"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2 rounded-lg bg-secondary hover:bg-secondary/80"
                        title="LinkedIn"
                      >
                        <Linkedin size={20} />
                      </a>
                      <a
                        href="https://github.com/Ruthvik-Bandari"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2 rounded-lg bg-secondary hover:bg-secondary/80"
                        title="GitHub"
                      >
                        <Github size={20} />
                      </a>
                    </div>
                  </div>
                </div>

                <div className="mt-8 pt-8 border-t border-border">
                  <h4 className="font-semibold mb-4">Key Achievements</h4>
                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
                      <span className="text-sm text-muted-foreground">4.0 GPA at Northeastern University</span>
                    </div>
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
                      <span className="text-sm text-muted-foreground">CVE severity classifier (0.71 macro-F1, held-out)</span>
                    </div>
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
                      <span className="text-sm text-muted-foreground">200K+ CVEs processed</span>
                    </div>
                    <div className="flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
                      <span className="text-sm text-muted-foreground">Novel NAMOA* implementation</span>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* Subscribe Tab */}
          {activeTab === 'subscribe' && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.3 }}
              className="max-w-2xl mx-auto"
            >
              <h2 className="text-3xl font-bold text-center mb-4">Activate Your License</h2>
              <p className="text-center text-muted-foreground mb-12">
                Enter your product key to activate CTPPO on your account
              </p>

              {/* Pricing Cards */}
              <div className="grid md:grid-cols-2 gap-6 mb-12">
                <div className="p-6 rounded-xl bg-card border border-border">
                  <h3 className="text-lg font-semibold mb-2">Individual License</h3>
                  <p className="text-3xl font-bold mb-4">Contact</p>
                  <ul className="space-y-2 text-sm text-muted-foreground mb-6">
                    <li className="flex items-center gap-2">
                      <CheckCircle size={16} className="text-green-500" />
                      Full platform access
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle size={16} className="text-green-500" />
                      CVE classification
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle size={16} className="text-green-500" />
                      Attack path analysis
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle size={16} className="text-green-500" />
                      PDF reports
                    </li>
                  </ul>
                </div>
                <div className="p-6 rounded-xl bg-primary/10 border border-primary">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-lg font-semibold">Enterprise License</h3>
                    <span className="px-2 py-1 rounded bg-primary text-primary-foreground text-xs">Popular</span>
                  </div>
                  <p className="text-3xl font-bold mb-4">Contact</p>
                  <ul className="space-y-2 text-sm text-muted-foreground mb-6">
                    <li className="flex items-center gap-2">
                      <CheckCircle size={16} className="text-green-500" />
                      Everything in Individual
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle size={16} className="text-green-500" />
                      Multi-user access
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle size={16} className="text-green-500" />
                      API integration
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle size={16} className="text-green-500" />
                      Priority support
                    </li>
                  </ul>
                </div>
              </div>

              {/* Activation Form */}
              <div className="p-8 rounded-2xl bg-card border border-border">
                <h3 className="text-lg font-semibold mb-6">Activate Product Key</h3>

                {message && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`flex items-center gap-2 p-3 mb-6 rounded-lg ${
                      message.type === 'success'
                        ? 'bg-green-500/20 text-green-500'
                        : 'bg-destructive/20 text-destructive'
                    }`}
                  >
                    {message.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
                    <span className="text-sm">{message.text}</span>
                  </motion.div>
                )}

                <form onSubmit={handleActivate} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-2">Email Address</label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                      <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="you@example.com"
                        required
                        className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border focus:outline-none focus:ring-2 focus:ring-primary/50"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Product Key</label>
                    <div className="relative">
                      <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                      <input
                        type="text"
                        value={productKey}
                        onChange={(e) => setProductKey(e.target.value.toUpperCase())}
                        placeholder="CTPPO-XXXX-XXXX-XXXX-XXXX"
                        required
                        className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-3 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50 flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-5 h-5 animate-spin" />
                        Activating...
                      </>
                    ) : (
                      'Activate Product Key'
                    )}
                  </button>
                </form>

                <p className="mt-6 text-center text-sm text-muted-foreground">
                  Don't have a product key?{' '}
                  <a href="mailto:bandari.ru@northeastern.edu" className="text-primary hover:underline">
                    Contact us
                  </a>
                </p>
              </div>
            </motion.div>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-4 border-t border-border">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            <span className="font-semibold">CTPPO</span>
            <span className="text-muted-foreground text-sm">© 2026 Ruthvik Bandari. All rights reserved.</span>
          </div>
          <div className="text-sm text-muted-foreground">
            Proprietary Software - License Required
          </div>
        </div>
      </footer>
    </div>
  )
}
