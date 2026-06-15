import * as React from 'react'
import { cn } from '@/lib/utils'

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        'h-11 w-full rounded-xl border border-line bg-base-2/60 px-4 text-sm text-fg outline-none transition-colors placeholder:text-faint focus:border-cyber/60 focus:ring-2 focus:ring-cyber/20 disabled:opacity-50',
        className,
      )}
      {...props}
    />
  ),
)
Input.displayName = 'Input'

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        'w-full rounded-xl border border-line bg-base-2/60 px-4 py-3 text-sm text-fg outline-none transition-colors placeholder:text-faint focus:border-cyber/60 focus:ring-2 focus:ring-cyber/20 disabled:opacity-50',
        className,
      )}
      {...props}
    />
  ),
)
Textarea.displayName = 'Textarea'
