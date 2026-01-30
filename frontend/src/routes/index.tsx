import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { createFileRoute } from '@tanstack/react-router'
import { motion } from 'framer-motion'
import {
  Shield,
  Network,
  Brain,
  Target,
  Lock,
  Zap,
  BarChart3,
  FileText,
  ChevronRight,
  Mail,
  Linkedin,
  Github,
  CheckCircle,
  Star,
  Award,
  GraduationCap,
  ArrowRight,
  Key,
} from 'lucide-react'

export const Route = createFileRoute('/')({
  component: LandingPage,
})

function LandingPage() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<'features' | 'about' | 'subscribe'>('features')

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 bg-slate-950/80 backdrop-blur-lg border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">CTPPO</h1>
              <p className="text-xs text-slate-400">v3.0.0</p>
            </div>
          </div>
          
          <div className="flex items-center gap-6">
            <button
              onClick={() => setActiveTab('features')}
              className={`text-sm font-medium transition-colors ${
                activeTab === 'features' ? 'text-cyan-400' : 'text-slate-400 hover:text-white'
              }`}
            >
              Features
            </button>
            <button
              onClick={() => setActiveTab('about')}
              className={`text-sm font-medium transition-colors ${
                activeTab === 'about' ? 'text-cyan-400' : 'text-slate-400 hover:text-white'
              }`}
            >
              About
            </button>
            <button
              onClick={() => setActiveTab('subscribe')}
              className={`text-sm font-medium transition-colors ${
                activeTab === 'subscribe' ? 'text-cyan-400' : 'text-slate-400 hover:text-white'
              }`}
            >
              Subscribe
            </button>
            <button
              onClick={() => navigate({ to: '/login' })}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors"
            >
              Login
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-6">
        <div className="max-w-7xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-cyan-500/10 border border-cyan-500/30 mb-6">
              <Star className="w-4 h-4 text-cyan-400" />
              <span className="text-cyan-400 text-sm font-medium">97.5% F1 Score on CVE Classification</span>
            </div>
            
            <h1 className="text-5xl md:text-7xl font-bold text-white mb-6">
              Cyber Threat
              <span className="block text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
                Propagation Path Optimizer
              </span>
            </h1>
            
            <p className="text-xl text-slate-400 max-w-3xl mx-auto mb-10">
              Enterprise-grade AI-powered cybersecurity platform leveraging Graph Neural Networks 
              and NAMOA* multi-objective optimization for advanced attack path analysis.
            </p>
            
            <div className="flex items-center justify-center gap-4">
              <button
                onClick={() => setActiveTab('subscribe')}
                className="px-8 py-4 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-semibold text-lg hover:opacity-90 transition-opacity flex items-center gap-2"
              >
                Get Started <ArrowRight className="w-5 h-5" />
              </button>
              <button
                onClick={() => setActiveTab('features')}
                className="px-8 py-4 rounded-xl bg-slate-800 text-white font-semibold text-lg hover:bg-slate-700 transition-colors"
              >
                Learn More
              </button>
            </div>
          </motion.div>

          {/* Stats */}
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-20"
          >
            {[
              { value: '97.5%', label: 'F1 Score', icon: Target },
              { value: '200K+', label: 'CVEs Analyzed', icon: Shield },
              { value: '<30s', label: 'Scan Speed', icon: Zap },
              { value: '94.2%', label: 'Detection Rate', icon: CheckCircle },
            ].map((stat, i) => (
              <div key={i} className="p-6 rounded-2xl bg-slate-800/50 border border-slate-700">
                <stat.icon className="w-8 h-8 text-cyan-400 mb-3 mx-auto" />
                <p className="text-3xl font-bold text-white">{stat.value}</p>
                <p className="text-slate-400">{stat.label}</p>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Main Content Based on Tab */}
      <section className="py-20 px-6 border-t border-slate-800">
        <div className="max-w-7xl mx-auto">
          {activeTab === 'features' && <FeaturesSection />}
          {activeTab === 'about' && <AboutSection />}
          {activeTab === 'subscribe' && <SubscribeSection navigate={navigate} />}
        </div>
      </section>

      {/* Comparison Section */}
      <section className="py-20 px-6 bg-slate-900/50">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-3xl font-bold text-white text-center mb-12">
            Why Choose CTPPO?
          </h2>
          
          <div className="grid md:grid-cols-2 gap-8">
            {/* Others */}
            <div className="p-8 rounded-2xl bg-slate-800/30 border border-slate-700">
              <h3 className="text-xl font-semibold text-slate-400 mb-6">Traditional Tools</h3>
              <ul className="space-y-4">
                {[
                  'Manual vulnerability scanning',
                  'Single-objective analysis',
                  'No ML-powered predictions',
                  'Basic reporting',
                  'Limited visualization',
                  'Rule-based detection only',
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-3 text-slate-500">
                    <div className="w-5 h-5 rounded-full bg-slate-700 flex items-center justify-center">
                      <span className="text-xs">✕</span>
                    </div>
                    {item}
                  </li>
                ))}
              </ul>
            </div>

            {/* CTPPO */}
            <div className="p-8 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/30">
              <h3 className="text-xl font-semibold text-cyan-400 mb-6">CTPPO Platform</h3>
              <ul className="space-y-4">
                {[
                  'AI-powered automated analysis',
                  'NAMOA* multi-objective optimization',
                  '97.5% F1 Score ML classifier',
                  'Professional PDF reports',
                  'Interactive Pareto visualization',
                  'GNN + RL hybrid detection',
                ].map((item, i) => (
                  <li key={i} className="flex items-center gap-3 text-white">
                    <div className="w-5 h-5 rounded-full bg-cyan-500 flex items-center justify-center">
                      <CheckCircle className="w-3 h-3 text-white" />
                    </div>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-6 border-t border-slate-800">
        <div className="max-w-7xl mx-auto text-center">
          <p className="text-slate-500 text-sm">
            © 2024-2026 Ruthvik Bandari. All Rights Reserved.
          </p>
          <p className="text-slate-600 text-xs mt-2">
            CTPPO is proprietary software. Unauthorized use is prohibited.
          </p>
        </div>
      </footer>
    </div>
  )
}

function FeaturesSection() {
  const features = [
    {
      icon: Brain,
      title: 'AI-Powered CVE Classification',
      description: 'Fine-tuned transformer models achieve 97.5% F1 score on CVE severity prediction, outperforming traditional rule-based systems.',
      color: 'from-purple-500 to-pink-500',
    },
    {
      icon: Network,
      title: 'NAMOA* Multi-Objective Optimization',
      description: 'Advanced Pareto-optimal attack path discovery considering exploitability, impact, and path length simultaneously.',
      color: 'from-cyan-500 to-blue-500',
    },
    {
      icon: Target,
      title: 'Graph Neural Networks',
      description: 'Message-passing neural networks predict attack propagation through network topology with high accuracy.',
      color: 'from-orange-500 to-red-500',
    },
    {
      icon: Shield,
      title: 'Real-time Vulnerability Scanning',
      description: 'Detect missing security headers, SSL issues, version disclosure, and open ports in under 30 seconds.',
      color: 'from-green-500 to-emerald-500',
    },
    {
      icon: BarChart3,
      title: 'Interactive Visualization',
      description: 'Multiple graph layouts (hierarchical, circular, radial) with Pareto front analysis and attack path highlighting.',
      color: 'from-yellow-500 to-orange-500',
    },
    {
      icon: FileText,
      title: 'Professional Reports',
      description: 'Generate comprehensive PDF security assessment reports with risk scores, recommendations, and remediation steps.',
      color: 'from-blue-500 to-indigo-500',
    },
  ]

  return (
    <div>
      <h2 className="text-3xl font-bold text-white text-center mb-4">
        Powerful Features
      </h2>
      <p className="text-slate-400 text-center max-w-2xl mx-auto mb-12">
        Enterprise-grade cybersecurity capabilities powered by cutting-edge AI and machine learning
      </p>
      
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        {features.map((feature, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: i * 0.1 }}
            className="p-6 rounded-2xl bg-slate-800/50 border border-slate-700 hover:border-slate-600 transition-colors"
          >
            <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${feature.color} flex items-center justify-center mb-4`}>
              <feature.icon className="w-6 h-6 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">{feature.title}</h3>
            <p className="text-slate-400 text-sm">{feature.description}</p>
          </motion.div>
        ))}
      </div>
    </div>
  )
}

function AboutSection() {
  return (
    <div className="max-w-4xl mx-auto">
      <h2 className="text-3xl font-bold text-white text-center mb-12">
        About the Developer
      </h2>
      
      <div className="p-8 rounded-2xl bg-slate-800/50 border border-slate-700">
        <div className="flex flex-col md:flex-row gap-8 items-center">
          <div className="w-40 h-40 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-6xl font-bold text-white">
            RB
          </div>
          
          <div className="flex-1 text-center md:text-left">
            <h3 className="text-2xl font-bold text-white mb-2">Ruthvik Bandari</h3>
            <p className="text-cyan-400 font-medium mb-4">AI/ML Engineer & Cybersecurity Researcher</p>
            
            <div className="flex flex-wrap gap-3 justify-center md:justify-start mb-6">
              <span className="px-3 py-1 rounded-full bg-cyan-500/20 text-cyan-400 text-sm">
                <GraduationCap className="w-4 h-4 inline mr-1" />
                MS Applied AI
              </span>
              <span className="px-3 py-1 rounded-full bg-green-500/20 text-green-400 text-sm">
                <Award className="w-4 h-4 inline mr-1" />
                4.0 GPA
              </span>
              <span className="px-3 py-1 rounded-full bg-purple-500/20 text-purple-400 text-sm">
                Northeastern University
              </span>
            </div>
            
            <p className="text-slate-400 mb-6">
              Graduate student specializing in Machine Learning, Graph Neural Networks, and Cybersecurity. 
              Developed CTPPO as a comprehensive solution for AI-powered attack path analysis, achieving 
              state-of-the-art results in CVE classification with 97.5% F1 score.
            </p>
            
            <div className="flex gap-4 justify-center md:justify-start">
              <a
                href="mailto:bandari.ru@northeastern.edu"
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white transition-colors"
              >
                <Mail className="w-4 h-4" />
                Email
              </a>
              <a
                href="https://linkedin.com/in/ruthvik-bandari"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
              >
                <Linkedin className="w-4 h-4" />
                LinkedIn
              </a>
              <a
                href="https://github.com/Ruthvik-Bandari"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white transition-colors"
              >
                <Github className="w-4 h-4" />
                GitHub
              </a>
            </div>
          </div>
        </div>
        
        {/* Expertise */}
        <div className="mt-8 pt-8 border-t border-slate-700">
          <h4 className="text-lg font-semibold text-white mb-4">Areas of Expertise</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              'Machine Learning',
              'Graph Neural Networks',
              'Cybersecurity',
              'Full-Stack Development',
              'Deep Learning',
              'NLP & Transformers',
              'Python/FastAPI',
              'React/TypeScript',
            ].map((skill, i) => (
              <div key={i} className="px-4 py-2 rounded-lg bg-slate-700/50 text-slate-300 text-sm text-center">
                {skill}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function SubscribeSection({ navigate }: { navigate: any }) {
  const [productKey, setProductKey] = useState('')
  const [email, setEmail] = useState('')
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle')
  const [message, setMessage] = useState('')

  const handleActivate = async () => {
    if (!productKey || !email) {
      setStatus('error')
      setMessage('Please enter both product key and email')
      return
    }

    setStatus('loading')
    
    try {
      const res = await fetch('/api/subscription/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ product_key: productKey, email }),
      })
      
      const data = await res.json()
      
      if (res.ok) {
        setStatus('success')
        setMessage('Product key activated successfully! You can now login.')
        setTimeout(() => navigate({ to: '/login' }), 2000)
      } else {
        setStatus('error')
        setMessage(data.detail || 'Activation failed')
      }
    } catch (err) {
      setStatus('error')
      setMessage('Network error. Please try again.')
    }
  }

  return (
    <div className="max-w-4xl mx-auto">
      <h2 className="text-3xl font-bold text-white text-center mb-4">
        Subscribe to CTPPO
      </h2>
      <p className="text-slate-400 text-center max-w-2xl mx-auto mb-12">
        Get access to the full platform with a valid product key
      </p>

      {/* Pricing Cards */}
      <div className="grid md:grid-cols-2 gap-6 mb-12">
        <div className="p-6 rounded-2xl bg-slate-800/50 border border-slate-700">
          <h3 className="text-xl font-semibold text-white mb-2">Individual License</h3>
          <p className="text-3xl font-bold text-white mb-4">
            Contact for Pricing
          </p>
          <ul className="space-y-3 mb-6">
            {[
              'Full platform access',
              'CVE classification',
              'Attack path analysis',
              'PDF reports',
              'Email support',
            ].map((item, i) => (
              <li key={i} className="flex items-center gap-2 text-slate-300">
                <CheckCircle className="w-4 h-4 text-green-400" />
                {item}
              </li>
            ))}
          </ul>
          <a
            href="mailto:bandari.ru@northeastern.edu?subject=CTPPO Individual License Inquiry"
            className="block w-full py-3 rounded-lg bg-slate-700 text-white font-medium text-center hover:bg-slate-600 transition-colors"
          >
            Contact for License
          </a>
        </div>

        <div className="p-6 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xl font-semibold text-white">Enterprise License</h3>
            <span className="px-2 py-1 rounded text-xs bg-cyan-500 text-white">RECOMMENDED</span>
          </div>
          <p className="text-3xl font-bold text-white mb-4">
            Custom Pricing
          </p>
          <ul className="space-y-3 mb-6">
            {[
              'Everything in Individual',
              'Multi-user access',
              'API integration',
              'Custom model training',
              'Priority support',
              'On-premise deployment',
            ].map((item, i) => (
              <li key={i} className="flex items-center gap-2 text-white">
                <CheckCircle className="w-4 h-4 text-cyan-400" />
                {item}
              </li>
            ))}
          </ul>
          <a
            href="mailto:bandari.ru@northeastern.edu?subject=CTPPO Enterprise License Inquiry"
            className="block w-full py-3 rounded-lg bg-cyan-600 text-white font-medium text-center hover:bg-cyan-500 transition-colors"
          >
            Request Enterprise Quote
          </a>
        </div>
      </div>

      {/* Activation Form */}
      <div className="p-8 rounded-2xl bg-slate-800/50 border border-slate-700">
        <h3 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
          <Key className="w-5 h-5 text-cyan-400" />
          Activate Your Product Key
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-slate-400 mb-2">Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com"
              className="w-full px-4 py-3 rounded-lg bg-slate-900 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
          
          <div>
            <label className="block text-sm text-slate-400 mb-2">Product Key</label>
            <input
              type="text"
              value={productKey}
              onChange={(e) => setProductKey(e.target.value.toUpperCase())}
              placeholder="CTPPO-XXXX-XXXX-XXXX-XXXX"
              className="w-full px-4 py-3 rounded-lg bg-slate-900 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono"
            />
          </div>

          {message && (
            <div className={`p-3 rounded-lg ${
              status === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
            }`}>
              {message}
            </div>
          )}
          
          <button
            onClick={handleActivate}
            disabled={status === 'loading'}
            className="w-full py-3 rounded-lg bg-cyan-600 text-white font-medium hover:bg-cyan-500 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {status === 'loading' ? (
              'Activating...'
            ) : (
              <>
                Activate Product Key
                <ChevronRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
        
        <p className="text-slate-500 text-sm mt-4 text-center">
          Don't have a product key?{' '}
          <a href="mailto:bandari.ru@northeastern.edu" className="text-cyan-400 hover:underline">
            Contact us
          </a>{' '}
          to purchase a license.
        </p>
      </div>
    </div>
  )
}
