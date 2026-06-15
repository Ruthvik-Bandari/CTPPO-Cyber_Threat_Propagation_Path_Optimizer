import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Plus, Trash2, Loader2, Copy, Check, Terminal, TriangleAlert } from 'lucide-react'
import { RequireSubscription } from '@/components/auth/guards'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Modal } from '@/components/ui/dialog'
import { Field, FormError } from '@/components/ui/field'
import { LoadingState, ErrorState, EmptyState } from '@/components/dashboard/states'
import { keyApi, ApiError, type ApiKeyMeta, type IssuedKey } from '@/api/client'
import { formatDate } from '@/lib/utils'

export const Route = createFileRoute('/dashboard/keys')({
  component: () => (
    <RequireSubscription>
      <KeysPage />
    </RequireSubscription>
  ),
})

function KeysPage() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [issued, setIssued] = useState<IssuedKey | null>(null)
  const [toRevoke, setToRevoke] = useState<ApiKeyMeta | null>(null)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['keys'],
    queryFn: () => keyApi.list(),
  })

  const issueMutation = useMutation({
    mutationFn: () => keyApi.issue(name.trim() || 'default'),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['keys'] })
      setIssued(res)
      setName('')
      setFormError(null)
    },
    onError: (e) => setFormError(e instanceof ApiError ? e.message : 'Could not issue key.'),
  })

  const revokeMutation = useMutation({
    mutationFn: (id: string) => keyApi.revoke(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['keys'] })
      setToRevoke(null)
    },
  })

  const keys = data?.keys ?? []

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold">API keys</h1>
        <p className="text-muted">Authenticate the CLI and CI/CD with subscription-tied keys.</p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Issue a key</CardTitle>
          <CardDescription>The raw key is shown once — store it immediately.</CardDescription>
        </CardHeader>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            issueMutation.mutate()
          }}
          className="flex flex-wrap items-end gap-3"
        >
          {formError && (
            <div className="w-full">
              <FormError message={formError} />
            </div>
          )}
          <div className="min-w-[14rem] flex-1">
            <Field label="Key name" htmlFor="key-name" hint="A label to recognise it later">
              <Input id="key-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-pipeline" />
            </Field>
          </div>
          <Button type="submit" disabled={issueMutation.isPending}>
            {issueMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
            Issue key
          </Button>
        </form>
      </Card>

      {isLoading ? (
        <LoadingState label="Loading keys…" />
      ) : isError ? (
        <ErrorState error={error} />
      ) : keys.length === 0 ? (
        <EmptyState
          Icon={KeyRound}
          title="No API keys"
          description="Issue a key above to use the ctppo-cli client or call the API from CI/CD."
        />
      ) : (
        <Card>
          <div className="flex flex-col">
            {keys.map((k) => (
              <div key={k.id} className="flex flex-wrap items-center justify-between gap-3 border-b border-line-soft py-3 last:border-0">
                <div className="flex items-center gap-3">
                  <span className="flex h-9 w-9 items-center justify-center rounded-full bg-cyber/10 text-cyber">
                    <KeyRound className="h-4 w-4" />
                  </span>
                  <div className="flex flex-col">
                    <span className="text-sm font-medium text-fg">{k.name}</span>
                    <span className="font-mono text-xs text-faint">{k.prefix}…</span>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="hidden flex-col text-right text-xs text-faint sm:flex">
                    <span>Created {formatDate(k.created_at)}</span>
                    <span>{k.last_used_at ? `Last used ${formatDate(k.last_used_at)}` : 'Never used'}</span>
                  </div>
                  <Button variant="danger" size="sm" onClick={() => setToRevoke(k)}>
                    <Trash2 className="h-3.5 w-3.5" /> Revoke
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <RevealKeyModal issued={issued} onClose={() => setIssued(null)} />

      <Modal
        open={toRevoke !== null}
        onOpenChange={(o) => !o && setToRevoke(null)}
        title="Revoke API key"
        description={toRevoke ? `"${toRevoke.name}" will stop working immediately.` : ''}
      >
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setToRevoke(null)}>
            Cancel
          </Button>
          <Button variant="danger" disabled={revokeMutation.isPending} onClick={() => toRevoke && revokeMutation.mutate(toRevoke.id)}>
            {revokeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            Revoke
          </Button>
        </div>
      </Modal>
    </div>
  )
}

function RevealKeyModal({ issued, onClose }: { issued: IssuedKey | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    if (!issued) return
    try {
      await navigator.clipboard.writeText(issued.api_key)
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <Modal
      open={issued !== null}
      onOpenChange={(o) => !o && onClose()}
      title="Your new API key"
      description="Copy it now — it can't be retrieved again."
    >
      {issued && (
        <div className="flex flex-col gap-4">
          <div className="flex items-center gap-2 rounded-xl border border-warn/30 bg-warn/5 px-3.5 py-2.5 text-sm text-warn">
            <TriangleAlert className="h-4 w-4 shrink-0" />
            <span>Store this secret securely. We only keep its hash.</span>
          </div>
          <div className="flex items-center gap-2 rounded-xl border border-line bg-base-2/70 p-3">
            <code className="flex-1 break-all font-mono text-sm text-cyber-bright">{issued.api_key}</code>
            <Button variant="outline" size="sm" onClick={copy}>
              {copied ? <Check className="h-4 w-4 text-cyber" /> : <Copy className="h-4 w-4" />}
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
          <div className="flex flex-col gap-2 rounded-xl border border-line-soft bg-surface/40 p-3">
            <div className="flex items-center gap-2 text-xs font-medium text-muted">
              <Terminal className="h-3.5 w-3.5" /> Use it with the CLI
            </div>
            <code className="break-all font-mono text-xs text-faint">
              ctppo-cli configure --api-key {issued.prefix}…
            </code>
          </div>
          <Button onClick={onClose} className="w-full">
            Done
          </Button>
        </div>
      )}
    </Modal>
  )
}
