import { useState } from 'react'
import { Loader2, Paperclip, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input, Textarea } from '@/components/ui/input'
import { Field, FormError } from '@/components/ui/field'
import type { FileMeta } from '@/api/client'

export interface InstanceFormValues {
  name: string
  prompt: string
  target: string
  files: FileMeta[]
}

interface InstanceFormProps {
  initial?: Partial<InstanceFormValues>
  submitLabel: string
  submitting?: boolean
  error?: string | null
  onSubmit: (values: InstanceFormValues) => void
}

function humanSize(bytes: number) {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)))
  return `${(bytes / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`
}

export function InstanceForm({ initial, submitLabel, submitting, error, onSubmit }: InstanceFormProps) {
  const [name, setName] = useState(initial?.name ?? '')
  const [prompt, setPrompt] = useState(initial?.prompt ?? '')
  const [target, setTarget] = useState(initial?.target ?? '')
  const [files, setFiles] = useState<FileMeta[]>(initial?.files ?? [])
  const [nameError, setNameError] = useState<string | null>(null)

  // Only file metadata is sent (the backend records a "metadata scan", never the bytes).
  const onPick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const picked = Array.from(e.target.files ?? []).map<FileMeta>((f) => ({
      name: f.name,
      size: f.size,
      content_type: f.type,
    }))
    setFiles((prev) => [...prev, ...picked])
    e.target.value = ''
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) {
      setNameError('Name is required')
      return
    }
    setNameError(null)
    onSubmit({ name: name.trim(), prompt: prompt.trim(), target: target.trim(), files })
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      {error && <FormError message={error} />}
      <Field label="Name" htmlFor="inst-name" error={nameError ?? undefined}>
        <Input id="inst-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Production network scan" />
      </Field>
      <Field label="Prompt" htmlFor="inst-prompt" hint="What should this workspace analyze?">
        <Textarea
          id="inst-prompt"
          rows={3}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          placeholder="Map the highest-impact attack paths to the database tier…"
        />
      </Field>
      <Field label="Target" htmlFor="inst-target" hint="Optional — host, URL or repository">
        <Input id="inst-target" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="app01.internal / github.com/org/repo" />
      </Field>

      <div className="flex flex-col gap-2">
        <span className="text-sm font-medium text-fg">Files</span>
        <label className="flex cursor-pointer items-center justify-center gap-2 rounded-xl border border-dashed border-line px-4 py-3 text-sm text-muted transition-colors hover:border-cyber/50 hover:text-fg">
          <Paperclip className="h-4 w-4" />
          <span>Add files (metadata only — contents aren't uploaded)</span>
          <input type="file" multiple className="hidden" onChange={onPick} />
        </label>
        {files.length > 0 && (
          <ul className="flex flex-col gap-1.5">
            {files.map((f, i) => (
              <li key={`${f.name}-${i}`} className="flex items-center justify-between rounded-lg bg-surface/60 px-3 py-2 text-sm">
                <span className="truncate text-fg">{f.name}</span>
                <span className="flex items-center gap-3 text-xs text-faint">
                  {humanSize(f.size)}
                  <button
                    type="button"
                    aria-label={`Remove ${f.name}`}
                    onClick={() => setFiles((prev) => prev.filter((_, idx) => idx !== i))}
                    className="text-faint transition-colors hover:text-danger"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <Button type="submit" disabled={submitting} className="mt-1 w-full">
        {submitting ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" /> Saving…
          </>
        ) : (
          submitLabel
        )}
      </Button>
    </form>
  )
}
