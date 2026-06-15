import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Trash2, Loader2, FileText } from 'lucide-react'
import { RequireSubscription } from '@/components/auth/guards'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Modal } from '@/components/ui/dialog'
import { InstanceForm, type InstanceFormValues } from '@/components/dashboard/InstanceForm'
import { LoadingState, ErrorState } from '@/components/dashboard/states'
import { instanceApi, ApiError } from '@/api/client'
import { formatDate } from '@/lib/utils'

export const Route = createFileRoute('/dashboard/instances/$instanceId')({
  component: () => (
    <RequireSubscription>
      <InstanceDetailPage />
    </RequireSubscription>
  ),
})

function InstanceDetailPage() {
  const { instanceId } = Route.useParams()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const { data: instance, isLoading, isError, error } = useQuery({
    queryKey: ['instance', instanceId],
    queryFn: () => instanceApi.get(instanceId),
  })

  const updateMutation = useMutation({
    mutationFn: (v: InstanceFormValues) => {
      const nextSpec: Record<string, unknown> = { ...(instance?.target_spec ?? {}) }
      if (v.target) nextSpec.target = v.target
      else delete nextSpec.target
      return instanceApi.update(instanceId, {
        name: v.name,
        prompt: v.prompt,
        target_spec: nextSpec,
        files: v.files,
      })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['instance', instanceId] })
      qc.invalidateQueries({ queryKey: ['instances'] })
      setFormError(null)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    },
    onError: (e) => setFormError(e instanceof ApiError ? e.message : 'Could not save changes.'),
  })

  const deleteMutation = useMutation({
    mutationFn: () => instanceApi.remove(instanceId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['instances'] })
      navigate({ to: '/dashboard/instances' })
    },
  })

  return (
    <div className="flex flex-col gap-6">
      <Link to="/dashboard/instances" className="flex w-fit items-center gap-2 text-sm text-muted hover:text-cyber">
        <ArrowLeft className="h-4 w-4" /> Back to instances
      </Link>

      {isLoading ? (
        <LoadingState label="Loading instance…" />
      ) : isError || !instance ? (
        <ErrorState error={error ?? new Error('Instance not found')} />
      ) : (
        <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
          {/* Edit */}
          <div className="flex flex-1 flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <h1 className="text-2xl font-bold">{instance.name}</h1>
                <Badge variant="muted">{instance.status}</Badge>
              </div>
              <Button variant="danger" size="sm" onClick={() => setConfirmOpen(true)}>
                <Trash2 className="h-3.5 w-3.5" /> Delete
              </Button>
            </div>
            {saved && (
              <div className="rounded-xl border border-cyber/30 bg-cyber/10 px-3.5 py-2.5 text-sm text-cyber">
                Changes saved.
              </div>
            )}
            <Card>
              <InstanceForm
                initial={{
                  name: instance.name,
                  prompt: instance.prompt,
                  target: typeof instance.target_spec?.target === 'string' ? (instance.target_spec.target as string) : '',
                  files: instance.files,
                }}
                submitLabel="Save changes"
                submitting={updateMutation.isPending}
                error={formError}
                onSubmit={(v) => updateMutation.mutate(v)}
              />
            </Card>
          </div>

          {/* Meta */}
          <Card className="w-full lg:w-80">
            <CardHeader>
              <CardTitle>Details</CardTitle>
              <CardDescription>Workspace metadata.</CardDescription>
            </CardHeader>
            <div className="flex flex-col gap-3 text-sm">
              <Meta label="Created" value={formatDate(instance.created_at)} />
              <Meta label="Updated" value={formatDate(instance.updated_at)} />
              <Meta label="Files" value={String(instance.files.length)} />
              {instance.files.length > 0 && (
                <div className="flex flex-col gap-1.5 border-t border-line-soft pt-3">
                  {instance.files.map((f, i) => (
                    <div key={`${f.name}-${i}`} className="flex items-center gap-2 text-xs text-muted">
                      <FileText className="h-3.5 w-3.5 shrink-0 text-faint" />
                      <span className="truncate">{f.name}</span>
                      {f.ext && <span className="ml-auto font-mono text-faint">.{f.ext}</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>
        </div>
      )}

      <Modal
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Delete instance"
        description={instance ? `"${instance.name}" will be permanently removed.` : ''}
      >
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setConfirmOpen(false)}>
            Cancel
          </Button>
          <Button variant="danger" disabled={deleteMutation.isPending} onClick={() => deleteMutation.mutate()}>
            {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            Delete
          </Button>
        </div>
      </Modal>
    </div>
  )
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted">{label}</span>
      <span className="font-medium text-fg">{value}</span>
    </div>
  )
}
