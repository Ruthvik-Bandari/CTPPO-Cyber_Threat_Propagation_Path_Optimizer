import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Loader2, BrainCircuit, Sparkles } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge, severityVariant } from '@/components/ui/badge'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Textarea, Input } from '@/components/ui/input'
import { Field, FormError } from '@/components/ui/field'
import { classifyApi, ApiError, type ClassifyResponse } from '@/api/client'
import { formatTime } from '@/lib/utils'

export const Route = createFileRoute('/dashboard/classify')({
  component: ClassifyPage,
})

function ClassifyPage() {
  const [description, setDescription] = useState('')
  const [cveId, setCveId] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ClassifyResponse | null>(null)

  // Honest model context — real held-out macro-F1, no fabricated accuracy.
  const modelInfo = useQuery({
    queryKey: ['model-info'],
    queryFn: () => classifyApi.modelInfo(),
    retry: false,
  })

  const mutation = useMutation({
    mutationFn: () => classifyApi.classify(description.trim(), cveId.trim() || undefined),
    onSuccess: (res) => {
      setResult(res)
      setError(null)
    },
    onError: (e) =>
      setError(
        e instanceof ApiError
          ? e.status === 503
            ? 'The severity model is not trained on this server yet.'
            : e.message
          : 'Classification failed.',
      ),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!description.trim()) {
      setError('A description is required.')
      return
    }
    mutation.mutate()
  }

  const sortedProbs = result
    ? Object.entries(result.probabilities).sort((a, b) => b[1] - a[1])
    : []

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold">CVE severity</h1>
        <p className="text-muted">
          Predict severity from the description text alone — no CVSS score required.
        </p>
      </header>

      <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
        <Card className="flex-1">
          <form onSubmit={submit} className="flex flex-col gap-4">
            {error && <FormError message={error} />}
            <Field label="CVE description" htmlFor="desc" hint="Paste the vulnerability description">
              <Textarea
                id="desc"
                rows={6}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="A remote attacker can execute arbitrary code via a crafted request to the…"
              />
            </Field>
            <Field label="CVE ID" htmlFor="cve" hint="Optional — for your reference only">
              <Input id="cve" value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2021-44228" />
            </Field>
            <Button type="submit" disabled={mutation.isPending} className="w-full">
              {mutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Classifying…
                </>
              ) : (
                <>
                  <Sparkles className="h-4 w-4" /> Classify severity
                </>
              )}
            </Button>
          </form>
        </Card>

        <div className="flex w-full flex-col gap-6 lg:w-96">
          {/* Result */}
          <Card>
            <CardHeader>
              <CardTitle>Prediction</CardTitle>
              <CardDescription>Model output for the description.</CardDescription>
            </CardHeader>
            {result ? (
              <div className="flex flex-col gap-5">
                <div className="flex items-center justify-between">
                  <Badge variant={severityVariant(result.predicted_severity)}>
                    {result.predicted_severity}
                  </Badge>
                  <span className="text-sm text-muted">
                    {(result.confidence * 100).toFixed(1)}% confidence
                  </span>
                </div>
                <div className="flex flex-col gap-3">
                  {sortedProbs.map(([cls, p]) => (
                    <div key={cls} className="flex flex-col gap-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted">{cls}</span>
                        <span className="font-mono text-faint">{(p * 100).toFixed(1)}%</span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
                        <div
                          className="h-full rounded-full bg-cyber"
                          style={{ width: `${Math.max(2, p * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
                <span className="text-xs text-faint">Processed in {formatTime(result.processing_time_ms)}</span>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2 py-8 text-center text-sm text-muted">
                <BrainCircuit className="h-7 w-7 text-faint" />
                <span>Submit a description to see the predicted severity.</span>
              </div>
            )}
          </Card>

          {/* Honest model info */}
          <Card>
            <CardHeader>
              <CardTitle>Model</CardTitle>
            </CardHeader>
            {modelInfo.isLoading ? (
              <span className="text-sm text-muted">Checking model…</span>
            ) : modelInfo.data ? (
              <div className="flex flex-col gap-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-muted">Status</span>
                  <Badge variant={modelInfo.data.loaded ? 'cyber' : 'muted'}>
                    {modelInfo.data.loaded ? 'Loaded' : 'Not trained'}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted">Held-out macro-F1</span>
                  <span className="font-mono text-fg">
                    {modelInfo.data.test_f1 != null ? modelInfo.data.test_f1.toFixed(2) : '—'}
                  </span>
                </div>
                <p className="pt-1 text-xs text-faint">
                  Text-only DistilBERT (description → severity). No CVSS inputs — feeding the score
                  would be circular.
                </p>
              </div>
            ) : (
              <span className="text-sm text-muted">Model info unavailable.</span>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}
