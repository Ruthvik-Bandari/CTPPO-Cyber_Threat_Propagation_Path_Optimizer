import { Loader2, CircleAlert } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { ApiError } from '@/api/client'

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-muted">
      <Loader2 className="h-5 w-5 animate-spin text-cyber" />
      <span className="text-sm">{label}</span>
    </div>
  )
}

export function ErrorState({ error }: { error: unknown }) {
  const message =
    error instanceof ApiError ? error.message : error instanceof Error ? error.message : 'Something went wrong.'
  return (
    <div className="flex items-center gap-2 rounded-2xl border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
      <CircleAlert className="h-4 w-4 shrink-0" />
      <span>{message}</span>
    </div>
  )
}

export function EmptyState({
  Icon,
  title,
  description,
  action,
}: {
  Icon: LucideIcon
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-3xl border border-dashed border-line bg-surface/30 px-6 py-16 text-center">
      <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber/10 text-cyber">
        <Icon className="h-6 w-6" />
      </span>
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="max-w-sm text-sm text-muted">{description}</p>
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
