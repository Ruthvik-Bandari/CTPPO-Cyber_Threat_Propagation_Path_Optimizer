import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Boxes, Plus, FileText, Trash2, ArrowUpRight, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge, severityVariant } from '@/components/ui/badge'
import { Modal } from '@/components/ui/dialog'
import { InstanceForm, type InstanceFormValues } from '@/components/dashboard/InstanceForm'
import { LoadingState, ErrorState, EmptyState } from '@/components/dashboard/states'
import { instanceApi, ApiError, type Instance } from '@/api/client'
import { formatDate } from '@/lib/utils'

export const Route = createFileRoute('/dashboard/instances')({
  component: InstancesPage,
})

function buildPayload(v: InstanceFormValues) {
  return {
    name: v.name,
    prompt: v.prompt,
    target_spec: v.target ? { target: v.target } : {},
    files: v.files,
  }
}

function InstancesPage() {
  const qc = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [toDelete, setToDelete] = useState<Instance | null>(null)
  const [formError, setFormError] = useState<string | null>(null)

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['instances'],
    queryFn: () => instanceApi.list(),
  })

  const createMutation = useMutation({
    mutationFn: (v: InstanceFormValues) => instanceApi.create(buildPayload(v)),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['instances'] })
      setCreateOpen(false)
      setFormError(null)
    },
    onError: (e) => setFormError(e instanceof ApiError ? e.message : 'Could not create instance.'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => instanceApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['instances'] })
      setToDelete(null)
    },
  })

  const instances = data?.instances ?? []

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-3xl font-bold">Instances</h1>
          <p className="text-muted">Scan and analysis workspaces.</p>
        </div>
        <Button onClick={() => { setFormError(null); setCreateOpen(true) }}>
          <Plus className="h-4 w-4" /> New instance
        </Button>
      </header>

      {isLoading ? (
        <LoadingState label="Loading instances…" />
      ) : isError ? (
        <ErrorState error={error} />
      ) : instances.length === 0 ? (
        <EmptyState
          Icon={Boxes}
          title="No instances yet"
          description="Create a workspace to capture a prompt, a target and file metadata for analysis."
          action={
            <Button onClick={() => { setFormError(null); setCreateOpen(true) }}>
              <Plus className="h-4 w-4" /> New instance
            </Button>
          }
        />
      ) : (
        <div className="flex flex-wrap gap-5">
          {instances.map((inst) => (
            <div
              key={inst.id}
              className="flex min-w-[18rem] flex-1 flex-col gap-4 rounded-3xl border border-line bg-surface/40 p-6 backdrop-blur transition-colors hover:border-cyber/40"
            >
              <div className="flex items-start justify-between gap-3">
                <h3 className="text-lg font-semibold">{inst.name}</h3>
                <Badge variant={inst.status === 'draft' ? 'muted' : severityVariant('low')}>{inst.status}</Badge>
              </div>
              <p className="line-clamp-2 min-h-[2.5rem] text-sm text-muted">
                {inst.prompt || 'No prompt set.'}
              </p>
              <div className="flex items-center gap-4 text-xs text-faint">
                <span className="flex items-center gap-1.5">
                  <FileText className="h-3.5 w-3.5" />
                  {inst.files.length} file{inst.files.length === 1 ? '' : 's'}
                </span>
                <span>Updated {formatDate(inst.updated_at)}</span>
              </div>
              <div className="mt-auto flex items-center justify-between gap-2 border-t border-line-soft pt-4">
                <Button asChild variant="ghost" size="sm">
                  <Link to="/dashboard/instances/$instanceId" params={{ instanceId: inst.id }}>
                    Open <ArrowUpRight className="h-3.5 w-3.5" />
                  </Link>
                </Button>
                <Button variant="danger" size="sm" onClick={() => setToDelete(inst)}>
                  <Trash2 className="h-3.5 w-3.5" /> Delete
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create */}
      <Modal
        open={createOpen}
        onOpenChange={setCreateOpen}
        title="New instance"
        description="A workspace for one scan or analysis."
      >
        <InstanceForm
          submitLabel="Create instance"
          submitting={createMutation.isPending}
          error={formError}
          onSubmit={(v) => createMutation.mutate(v)}
        />
      </Modal>

      {/* Delete confirm */}
      <Modal
        open={toDelete !== null}
        onOpenChange={(o) => !o && setToDelete(null)}
        title="Delete instance"
        description={toDelete ? `"${toDelete.name}" will be permanently removed.` : ''}
      >
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setToDelete(null)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={deleteMutation.isPending}
            onClick={() => toDelete && deleteMutation.mutate(toDelete.id)}
          >
            {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            Delete
          </Button>
        </div>
      </Modal>
    </div>
  )
}
