import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Radar,
  Shield,
  AlertTriangle,
  Loader2,
  Play,
  Globe,
  Server,
  Info,
  Wifi,
  Bug,
  ChevronRight,
  CheckCircle,
  XCircle,
} from 'lucide-react'
import { useAuthStore } from '@/stores/auth'

export const Route = createFileRoute('/scan')({
  component: ScanPage,
})

interface Vulnerability {
  id: string
  name: string
  severity: string
  description: string
  url?: string
  solution?: string
}

interface ScanResult {
  target: string
  scan_type: string
  hosts: Array<{
    host: string
    ports: Array<{ port: number; state: string; service: string; version: string }>
  }>
  web_vulnerabilities: Vulnerability[]
  risk_summary: {
    risk_level: string
    total_hosts: number
    total_open_ports: number
    vulnerabilities: { high: number; medium: number; low: number; total: number }
    recommendation: string
  }
  processing_time_ms: number
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: 'bg-red-600', HIGH: 'bg-orange-600', MEDIUM: 'bg-yellow-600', LOW: 'bg-green-600',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium text-white ${colors[severity.toUpperCase()] || 'bg-gray-600'}`}>
      {severity}
    </span>
  )
}

function ScanPage() {
  const { accessToken } = useAuthStore()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<'quick' | 'full' | 'web'>('quick')
  const [includeWebScan, setIncludeWebScan] = useState(true)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null)

  // Check capabilities
  const capsQuery = useQuery({
    queryKey: ['scan-caps'],
    queryFn: async () => {
      const res = await fetch('/api/scan/capabilities', {
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      return res.json()
    },
  })

  // Scan mutation
  const scanMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/scan/target', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ target, scan_type: scanType, include_web_scan: includeWebScan }),
      })
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || 'Scan failed')
      }
      return res.json() as Promise<ScanResult>
    },
    onSuccess: setResult,
  })

  const caps = capsQuery.data

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Radar className="w-8 h-8 text-primary" />
          Real-Time Security Scanner
        </h1>
        <p className="text-muted-foreground mt-2">
          Scan any URL or IP for vulnerabilities, open ports, and security issues
        </p>
      </motion.div>

      {/* Scanner Status */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
        className="grid grid-cols-3 gap-4">
        {[
          { key: 'scanner_available', label: 'Scanner', color: caps?.scanner_available },
          { key: 'nmap_available', label: 'Nmap', color: caps?.nmap_available },
          { key: 'zap_available', label: 'OWASP ZAP', color: caps?.zap_available },
        ].map((item) => (
          <div key={item.key} className={`p-4 rounded-xl border ${item.color ? 'bg-green-500/10 border-green-500/30' : 'bg-yellow-500/10 border-yellow-500/30'}`}>
            <div className="flex items-center gap-2">
              {item.color ? <CheckCircle className="w-5 h-5 text-green-500" /> : <XCircle className="w-5 h-5 text-yellow-500" />}
              <span className="font-medium">{item.label}</span>
            </div>
            <p className="text-sm text-muted-foreground mt-1">{item.color ? 'Available' : 'Not Available'}</p>
          </div>
        ))}
      </motion.div>

      {/* Scan Form */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
        className="p-6 rounded-xl bg-card border border-border">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Globe className="w-5 h-5" /> Target Configuration
        </h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Target URL or IP Address</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com or 192.168.1.1"
              className="w-full px-4 py-3 rounded-lg bg-secondary border border-border focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Scan Type</label>
            <div className="grid grid-cols-3 gap-3">
              {[
                { value: 'quick', label: 'Quick Scan', desc: 'Fast port scan', icon: Wifi },
                { value: 'full', label: 'Full Scan', desc: 'Comprehensive', icon: Radar },
                { value: 'web', label: 'Web Only', desc: 'Web vulnerabilities', icon: Bug },
              ].map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setScanType(opt.value as any)}
                  className={`p-4 rounded-lg border text-left ${scanType === opt.value ? 'border-primary bg-primary/10' : 'border-border hover:border-primary/50'}`}
                >
                  <opt.icon className={`w-5 h-5 mb-2 ${scanType === opt.value ? 'text-primary' : 'text-muted-foreground'}`} />
                  <p className="font-medium">{opt.label}</p>
                  <p className="text-xs text-muted-foreground">{opt.desc}</p>
                </button>
              ))}
            </div>
          </div>

          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={includeWebScan} onChange={(e) => setIncludeWebScan(e.target.checked)} className="w-4 h-4" />
            <span className="text-sm">Include Web Security Headers Check</span>
          </label>

          {scanMutation.isError && (
            <div className="p-3 rounded-lg bg-destructive/20 text-destructive flex items-center gap-2">
              <AlertTriangle className="w-5 h-5" />
              <span>{scanMutation.error?.message}</span>
            </div>
          )}

          <button
            onClick={() => scanMutation.mutate()}
            disabled={scanMutation.isPending || !target.trim()}
            className="w-full py-4 rounded-xl bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50 flex items-center justify-center gap-2 text-lg"
          >
            {scanMutation.isPending ? (
              <><Loader2 className="w-5 h-5 animate-spin" /> Scanning...</>
            ) : (
              <><Play className="w-5 h-5" /> Start Security Scan</>
            )}
          </button>
        </div>
      </motion.div>

      {/* Results */}
      <AnimatePresence>
        {result && (
          <motion.div key="results" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
            {/* Risk Level */}
            <div className={`p-6 rounded-xl ${
              result.risk_summary.risk_level === 'HIGH' ? 'bg-orange-600' :
              result.risk_summary.risk_level === 'CRITICAL' ? 'bg-red-600' :
              result.risk_summary.risk_level === 'MEDIUM' ? 'bg-yellow-600' : 'bg-green-600'
            }`}>
              <p className="text-white/80 text-sm">Overall Risk Level</p>
              <p className="text-3xl font-bold text-white">{result.risk_summary.risk_level}</p>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-4 gap-4">
              {[
                { icon: Server, value: result.risk_summary.total_hosts, label: 'Hosts', color: 'text-blue-500' },
                { icon: Wifi, value: result.risk_summary.total_open_ports, label: 'Open Ports', color: 'text-purple-500' },
                { icon: Bug, value: result.risk_summary.vulnerabilities.total, label: 'Vulnerabilities', color: 'text-red-500' },
                { icon: AlertTriangle, value: result.risk_summary.vulnerabilities.high, label: 'High Severity', color: 'text-orange-500' },
              ].map((stat, i) => (
                <div key={i} className="p-4 rounded-xl bg-card border border-border text-center">
                  <stat.icon className={`w-6 h-6 mx-auto mb-2 ${stat.color}`} />
                  <p className="text-2xl font-bold">{stat.value}</p>
                  <p className="text-xs text-muted-foreground">{stat.label}</p>
                </div>
              ))}
            </div>

            {/* Recommendation */}
            {result.risk_summary.recommendation && (
              <div className="p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/30 flex items-start gap-3">
                <Info className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <p className="text-sm">{result.risk_summary.recommendation}</p>
              </div>
            )}

            {/* Services */}
            {result.hosts?.length > 0 && (
              <div className="p-6 rounded-xl bg-card border border-border">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2"><Server className="w-5 h-5" /> Discovered Services</h3>
                {result.hosts.map((host, i) => (
                  <div key={i} className="p-4 rounded-lg bg-secondary/50 mb-2">
                    <p className="font-medium mb-2">{host.host}</p>
                    <div className="grid grid-cols-4 gap-2">
                      {host.ports.map((port, j) => (
                        <div key={j} className={`p-2 rounded text-sm ${port.state === 'open' ? 'bg-green-500/20' : 'bg-gray-500/20'}`}>
                          <p className="font-mono">{port.port}/{port.service}</p>
                          {port.version && <p className="text-xs text-muted-foreground truncate">{port.version}</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Vulnerabilities */}
            {result.web_vulnerabilities?.length > 0 && (
              <div className="p-6 rounded-xl bg-card border border-border">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Bug className="w-5 h-5" /> Vulnerabilities ({result.web_vulnerabilities.length})
                </h3>
                <div className="space-y-2">
                  {result.web_vulnerabilities.map((vuln, i) => (
                    <div key={i} className="rounded-lg border border-border overflow-hidden">
                      <button
                        onClick={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
                        className="w-full p-4 flex items-center justify-between hover:bg-secondary/50"
                      >
                        <div className="flex items-center gap-3">
                          <ChevronRight className={`w-4 h-4 transition-transform ${expandedVuln === vuln.id ? 'rotate-90' : ''}`} />
                          <SeverityBadge severity={vuln.severity} />
                          <span className="font-medium">{vuln.name}</span>
                        </div>
                      </button>
                      {expandedVuln === vuln.id && (
                        <div className="p-4 bg-secondary/30 text-sm space-y-2">
                          <p>{vuln.description}</p>
                          {vuln.solution && <p><strong>Solution:</strong> {vuln.solution}</p>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <p className="text-center text-sm text-muted-foreground">
              Scan completed in {(result.processing_time_ms / 1000).toFixed(2)}s
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
