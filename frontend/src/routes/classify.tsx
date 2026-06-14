import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { cveApi, CVEClassifyRequest, CVEClassifyResponse } from '@/api/client'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Target,
  Loader2,
  AlertCircle,
  CheckCircle2,
  Shield,
  Clock,
  ChevronDown,
  Zap,
} from 'lucide-react'

export const Route = createFileRoute('/classify')({
  component: ClassifyPage,
})

const SEVERITY_COLORS = {
  CRITICAL: { bg: 'bg-red-600', glow: 'glow-critical', text: 'text-red-500' },
  HIGH: { bg: 'bg-orange-600', glow: 'glow-high', text: 'text-orange-500' },
  MEDIUM: { bg: 'bg-yellow-600', glow: 'glow-medium', text: 'text-yellow-500' },
  LOW: { bg: 'bg-green-600', glow: 'glow-low', text: 'text-green-500' },
}

const CVSS_OPTIONS = {
  attackVector: ['NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL'],
  attackComplexity: ['LOW', 'HIGH'],
  privilegesRequired: ['NONE', 'LOW', 'HIGH'],
  userInteraction: ['NONE', 'REQUIRED'],
  scope: ['UNCHANGED', 'CHANGED'],
  confidentialityImpact: ['NONE', 'LOW', 'HIGH'],
  integrityImpact: ['NONE', 'LOW', 'HIGH'],
  availabilityImpact: ['NONE', 'LOW', 'HIGH'],
}

const SAMPLE_CVES = [
  {
    name: 'Log4Shell (CVE-2021-44228)',
    description: 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers.',
    cvss_score: 10.0,
  },
  {
    name: 'Heartbleed (CVE-2014-0160)',
    description: 'The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets.',
    cvss_score: 7.5,
  },
  {
    name: 'EternalBlue (CVE-2017-0144)',
    description: 'The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets, aka Windows SMB Remote Code Execution Vulnerability.',
    cvss_score: 8.1,
  },
]

function ClassifyPage() {
  const [description, setDescription] = useState('')
  const [cveId, setCveId] = useState('')
  const [cvssScore, setCvssScore] = useState(7.0)
  const [hasExploit, setHasExploit] = useState(false)
  const [hasPatch, setHasPatch] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [cvssVector, setCvssVector] = useState({
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    scope: 'UNCHANGED',
    confidentialityImpact: 'HIGH',
    integrityImpact: 'HIGH',
    availabilityImpact: 'HIGH',
  })
  
  const [result, setResult] = useState<CVEClassifyResponse | null>(null)
  const [error, setError] = useState('')

  const classifyMutation = useMutation({
    mutationFn: (request: CVEClassifyRequest) => cveApi.classify(request),
    onSuccess: (data) => {
      setResult(data)
      setError('')
    },
    onError: (err: Error) => {
      setError(err.message)
      setResult(null)
    },
  })

  const handleClassify = () => {
    if (!description.trim()) {
      setError('Please enter a CVE description')
      return
    }

    classifyMutation.mutate({
      description,
      cve_id: cveId || undefined,
      cvss_vector: cvssVector,
      cvss_score: cvssScore,
      has_exploit: hasExploit,
      has_patch: hasPatch,
    })
  }

  const loadSample = (sample: typeof SAMPLE_CVES[0]) => {
    setDescription(sample.description)
    setCvssScore(sample.cvss_score)
    setResult(null)
    setError('')
  }

  const severityStyle = result ? SEVERITY_COLORS[result.predicted_severity as keyof typeof SEVERITY_COLORS] : null

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Target className="w-8 h-8 text-primary" />
          CVE Severity Classification
        </h1>
        <p className="text-muted-foreground mt-2">
          Predict CVE severity from a description with a DistilBERT model (0.73 macro-F1 on held-out NVD CVEs)
        </p>
      </motion.div>

      <div className="grid lg:grid-cols-2 gap-8">
        {/* Input Section */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
          className="space-y-6"
        >
          {/* Sample CVEs */}
          <div className="p-4 rounded-xl bg-card border border-border">
            <h3 className="text-sm font-medium mb-3">Quick Load Sample CVEs</h3>
            <div className="flex flex-wrap gap-2">
              {SAMPLE_CVES.map((sample) => (
                <button
                  key={sample.name}
                  onClick={() => loadSample(sample)}
                  className="px-3 py-1.5 rounded-lg bg-secondary text-sm hover:bg-primary/20 transition-colors"
                >
                  {sample.name.split(' ')[0]}
                </button>
              ))}
            </div>
          </div>

          {/* CVE Description */}
          <div>
            <label className="block text-sm font-medium mb-2">CVE Description *</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Enter the CVE vulnerability description..."
              rows={6}
              className="w-full p-4 rounded-xl bg-secondary border border-border resize-none
                focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
          </div>

          {/* CVE ID & CVSS Score */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">CVE ID (Optional)</label>
              <input
                type="text"
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                placeholder="CVE-2024-XXXXX"
                className="w-full p-3 rounded-lg bg-secondary border border-border
                  focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">CVSS Score: {cvssScore.toFixed(1)}</label>
              <input
                type="range"
                min="0"
                max="10"
                step="0.1"
                value={cvssScore}
                onChange={(e) => setCvssScore(parseFloat(e.target.value))}
                className="w-full h-3 rounded-lg appearance-none cursor-pointer bg-secondary"
              />
            </div>
          </div>

          {/* Checkboxes */}
          <div className="flex gap-6">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={hasExploit}
                onChange={(e) => setHasExploit(e.target.checked)}
                className="w-4 h-4 rounded border-border"
              />
              <span className="text-sm">Known Exploit</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={hasPatch}
                onChange={(e) => setHasPatch(e.target.checked)}
                className="w-4 h-4 rounded border-border"
              />
              <span className="text-sm">Patch Available</span>
            </label>
          </div>

          {/* Advanced CVSS Options */}
          <div className="rounded-xl border border-border overflow-hidden">
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="w-full p-4 flex items-center justify-between bg-card hover:bg-secondary/50 transition-colors"
            >
              <span className="font-medium">Advanced CVSS Vector</span>
              <ChevronDown className={`w-5 h-5 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
            </button>
            
            <AnimatePresence>
              {showAdvanced && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 'auto' }}
                  exit={{ height: 0 }}
                  className="overflow-hidden"
                >
                  <div className="p-4 grid grid-cols-2 gap-4 bg-secondary/30">
                    {Object.entries(CVSS_OPTIONS).map(([key, options]) => (
                      <div key={key}>
                        <label className="block text-xs font-medium mb-1 capitalize">
                          {key.replace(/([A-Z])/g, ' $1').trim()}
                        </label>
                        <select
                          value={cvssVector[key as keyof typeof cvssVector]}
                          onChange={(e) => setCvssVector({ ...cvssVector, [key]: e.target.value })}
                          className="w-full p-2 rounded-lg bg-secondary border border-border text-sm"
                        >
                          {options.map((opt) => (
                            <option key={opt} value={opt}>{opt}</option>
                          ))}
                        </select>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Error */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-center gap-2 p-3 rounded-lg bg-destructive/20 text-destructive"
            >
              <AlertCircle size={18} />
              <span className="text-sm">{error}</span>
            </motion.div>
          )}

          {/* Classify Button */}
          <button
            onClick={handleClassify}
            disabled={classifyMutation.isPending || !description.trim()}
            className="w-full py-4 rounded-xl bg-primary text-primary-foreground font-medium
              hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed
              flex items-center justify-center gap-2 text-lg"
          >
            {classifyMutation.isPending ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Zap className="w-5 h-5" />
                Classify Severity
              </>
            )}
          </button>
        </motion.div>

        {/* Result Section */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
        >
          <AnimatePresence mode="wait">
            {result ? (
              <motion.div
                key="result"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="space-y-6"
              >
                {/* Severity Badge */}
                <div className={`p-8 rounded-2xl text-center ${severityStyle?.bg} ${severityStyle?.glow}`}>
                  <Shield className="w-16 h-16 mx-auto mb-4 text-white" />
                  <h2 className="text-4xl font-bold text-white mb-2">
                    {result.predicted_severity}
                  </h2>
                  <p className="text-white/80">Predicted Severity</p>
                </div>

                {/* Metrics */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-card border border-border text-center">
                    <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-green-500" />
                    <p className="text-2xl font-bold">{(result.confidence * 100).toFixed(1)}%</p>
                    <p className="text-sm text-muted-foreground">Confidence</p>
                  </div>
                  <div className="p-4 rounded-xl bg-card border border-border text-center">
                    <Clock className="w-8 h-8 mx-auto mb-2 text-blue-500" />
                    <p className="text-2xl font-bold">{result.processing_time_ms.toFixed(0)}ms</p>
                    <p className="text-sm text-muted-foreground">Processing Time</p>
                  </div>
                </div>

                {/* Probability Distribution */}
                <div className="p-6 rounded-xl bg-card border border-border">
                  <h3 className="font-medium mb-4">Probability Distribution</h3>
                  <div className="space-y-3">
                    {Object.entries(result.probabilities)
                      .sort((a, b) => b[1] - a[1])
                      .map(([severity, prob]) => {
                        const style = SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS]
                        return (
                          <div key={severity}>
                            <div className="flex justify-between text-sm mb-1">
                              <span className={style.text}>{severity}</span>
                              <span>{(prob * 100).toFixed(1)}%</span>
                            </div>
                            <div className="h-2 rounded-full bg-secondary overflow-hidden">
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${prob * 100}%` }}
                                transition={{ duration: 0.5, delay: 0.1 }}
                                className={`h-full ${style.bg}`}
                              />
                            </div>
                          </div>
                        )
                      })}
                  </div>
                </div>

                {/* CVE ID if provided */}
                {result.cve_id && (
                  <div className="p-4 rounded-xl bg-secondary/50 text-center">
                    <p className="text-sm text-muted-foreground">CVE ID</p>
                    <p className="font-mono font-medium">{result.cve_id}</p>
                  </div>
                )}
              </motion.div>
            ) : (
              <motion.div
                key="placeholder"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="h-full flex items-center justify-center p-12 rounded-2xl border-2 border-dashed border-border"
              >
                <div className="text-center">
                  <Target className="w-16 h-16 mx-auto mb-4 text-muted-foreground/50" />
                  <h3 className="text-lg font-medium mb-2">Ready to Classify</h3>
                  <p className="text-muted-foreground">
                    Enter a CVE description and click "Classify Severity" to see results
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </div>
    </div>
  )
}
