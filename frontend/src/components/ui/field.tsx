import type { ReactNode } from 'react'
import { CircleAlert, CircleCheck } from 'lucide-react'

interface FieldProps {
  label: string
  htmlFor?: string
  error?: string
  hint?: string
  children: ReactNode
}

export function Field({ label, htmlFor, error, hint, children }: FieldProps) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-sm font-medium text-fg">
        {label}
      </label>
      {children}
      {hint && !error && <span className="text-xs text-faint">{hint}</span>}
      {error && <span className="text-xs text-danger">{error}</span>}
    </div>
  )
}

export function FormError({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-danger/30 bg-danger/10 px-3.5 py-2.5 text-sm text-danger">
      <CircleAlert className="h-4 w-4 shrink-0" />
      <span>{message}</span>
    </div>
  )
}

export function FormSuccess({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-cyber/30 bg-cyber/10 px-3.5 py-2.5 text-sm text-cyber">
      <CircleCheck className="h-4 w-4 shrink-0" />
      <span>{message}</span>
    </div>
  )
}
