import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Radar, Loader2, Play, ServerCog, Cloud, ShieldAlert, CircleCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge, severityVariant } from '@/components/ui/badge'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Field, FormError } from '@/components/ui/field'
import { scanApi, ApiError, type ScanResult, type ScanVuln } from '@/api/client'
import { formatTime, cn } from '@/lib/utils'

export const Route = createFileRoute('/dashboard/scan')({
  component: ScanPage,
})

const selectCls = 'h-11 rounded-xl border border-line bg-base-2/60 px-3 text-sm text-fg outline-none focus:border-cyber/60'

function vulnTitle(v: ScanVuln) {
  return v.name || v.alert || v.description?.slice(0, 60) || 'Finding'
}

function ScanPage() {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<'quick' | 'full' | 'vuln'>('quick')
  const [includeWeb, setIncludeWeb] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)

  const caps = useQuery({ queryKey: ['scan-capabilities'], queryFn: () => scanApi.capabilities(), retry: false })

  const mutation = useMutation({
    mutationFn: () => scanApi.scan({ target: target.trim(), scan_type: scanType, include_web_scan: includeWeb }),
    onSuccess: (res) => { setResult(res); setError(null) },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'Scan failed.'),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return setError('A target is required.')
    mutation.mutate()
  }

  const counts = result?.risk_summary?.vulnerabilities
  const webVulns = result?.web_vulnerabilities ?? []

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold">Scan</h1>
        <p className="text-muted">
          Probe a host or URL for security-header, TLS and exposure issues.
        </p>
      </header>

      {/* Capabilities — honest about what's installed */}
      {caps.data && (
        <div className="flex flex-wrap gap-2">
          <Badge variant={caps.data.simple_scanner ? 'cyber' : 'muted'}>
            <CircleCheck className="h-3 w-3" /> Built-in scanner
          </Badge>
          <Badge variant={caps.data.nmap_available ? 'cyber' : 'muted'}>
            nmap {caps.data.nmap_available ? 'available' : 'not installed'}
          </Badge>
          <Badge variant={caps.data.zap_available ? 'cyber' : 'muted'}>
            ZAP {caps.data.zap_available ? 'available' : 'not running'}
          </Badge>
        </div>
      )}

      <Card>
        <form onSubmit={submit} className="flex flex-col gap-4">
          {error && <FormError message={error} />}
          <div className="flex flex-col gap-4 md:flex-row md:items-end">
            <div className="flex-1">
              <Field label="Target" htmlFor="scan-target" hint="Host or URL, e.g. example.com or https://example.com">
                <Input id="scan-target" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" />
              </Field>
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="scan-type" className="text-sm font-medium text-fg">Scan type</label>
              <select id="scan-type" value={scanType} onChange={(e) => setScanType(e.target.value as typeof scanType)} className={selectCls}>
                <option value="quick">Quick</option>
                <option value="full">Full</option>
                <option value="vuln">Vulnerability</option>
              </select>
            </div>
          </div>
          <label className="flex w-fit items-center gap-2 text-sm text-muted">
            <input type="checkbox" checked={includeWeb} onChange={(e) => setIncludeWeb(e.target.checked)} className="accent-cyber" />
            Include web checks (security headers, TLS)
          </label>
          <Button type="submit" disabled={mutation.isPending} className="w-full sm:w-auto">
            {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Run scan
          </Button>
          <p className="text-xs text-faint">
            Only scan systems you are authorized to test. Results depend on the installed scanners.
          </p>
        </form>
      </Card>

      {result && (
        <div className="flex flex-col gap-6">
          {/* Risk summary */}
          <Card className={cn(result.risk_summary?.risk_level === 'LOW' ? 'border-cyber/25' : 'border-warn/30')}>
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-warn/15 text-warn">
                  <ShieldAlert className="h-6 w-6" />
                </span>
                <div className="flex flex-col">
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-semibold">Risk</h2>
                    <Badge variant={severityVariant(result.risk_summary?.risk_level ?? 'LOW')}>
                      {result.risk_summary?.risk_level ?? '—'}
                    </Badge>
                  </div>
                  <span className="text-sm text-muted">{result.risk_summary?.recommendation}</span>
                </div>
              </div>
              <span className="text-xs text-faint">
                {result.scanner_used} scanner · {formatTime(result.processing_time_ms ?? 0)}
              </span>
            </div>
            {counts && (
              <div className="mt-5 flex flex-wrap gap-2">
                <Badge variant="crit">{counts.critical} critical</Badge>
                <Badge variant="high">{counts.high} high</Badge>
                <Badge variant="med">{counts.medium} medium</Badge>
                <Badge variant="low">{counts.low} low</Badge>
              </div>
            )}
          </Card>

          {result.cloud_provider?.detected && (
            <div className="flex items-start gap-2 rounded-2xl border border-marine/30 bg-marine/5 px-4 py-3 text-sm text-muted">
              <Cloud className="mt-0.5 h-4 w-4 shrink-0 text-marine-bright" />
              <span>
                Cloud provider detected{result.cloud_provider.name ? ` (${result.cloud_provider.name})` : ''}.{' '}
                {result.cloud_provider.note || result.cloud_provider.warning}
              </span>
            </div>
          )}

          {/* Hosts / ports */}
          {(result.hosts ?? []).map((h, i) => (
            <Card key={i}>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <ServerCog className="h-5 w-5 text-muted" />
                  <CardTitle>{h.hostname || h.ip || result.target}</CardTitle>
                </div>
                {h.os_guess && <CardDescription>OS guess: {h.os_guess}</CardDescription>}
              </CardHeader>
              {h.ports && h.ports.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {h.ports.map((p, j) => (
                    <span key={j} className="rounded-lg border border-line-soft bg-base-2/60 px-2.5 py-1 font-mono text-xs text-muted">
                      {p.number ?? p.port}/{p.service || 'tcp'} {p.state ? `· ${p.state}` : ''}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-faint">No open ports reported.</p>
              )}
            </Card>
          ))}

          {/* Web vulnerabilities */}
          <div className="flex flex-col gap-3">
            <h2 className="text-lg font-semibold">
              {webVulns.length} web finding{webVulns.length === 1 ? '' : 's'}
            </h2>
            {webVulns.length === 0 ? (
              <p className="text-sm text-muted">No web findings reported.</p>
            ) : (
              webVulns.map((v, i) => (
                <div key={i} className="flex flex-col gap-2 rounded-2xl border border-line bg-surface/40 p-5">
                  <div className="flex items-start justify-between gap-3">
                    <h3 className="font-medium text-fg">{vulnTitle(v)}</h3>
                    {v.severity && <Badge variant={severityVariant(v.severity)}>{v.severity}</Badge>}
                  </div>
                  {v.description && <p className="text-sm text-muted">{v.description}</p>}
                  {(v.recommendation || v.solution) && (
                    <p className="text-sm text-cyber-bright/90">Fix: {v.recommendation || v.solution}</p>
                  )}
                  {v.url && <span className="break-all font-mono text-xs text-faint">{v.url}</span>}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {!result && !mutation.isPending && (
        <div className="flex flex-col items-center gap-2 py-8 text-center text-sm text-muted">
          <Radar className="h-7 w-7 text-faint" />
          <span>Enter a target above to run a scan.</span>
        </div>
      )}
    </div>
  )
}
