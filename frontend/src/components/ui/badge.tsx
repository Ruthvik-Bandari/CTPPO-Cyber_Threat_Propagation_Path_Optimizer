import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium tracking-wide',
  {
    variants: {
      variant: {
        cyber: 'border-cyber/30 bg-cyber/10 text-cyber',
        marine: 'border-marine/30 bg-marine/10 text-marine-bright',
        muted: 'border-line bg-surface/60 text-muted',
        crit: 'border-crit/30 bg-crit/10 text-crit',
        high: 'border-sev-high/30 bg-sev-high/10 text-sev-high',
        med: 'border-sev-med/30 bg-sev-med/10 text-sev-med',
        low: 'border-sev-low/30 bg-sev-low/10 text-sev-low',
      },
    },
    defaultVariants: { variant: 'cyber' },
  },
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}

/** Map an engine severity string to a Badge variant. */
export function severityVariant(severity: string): NonNullable<BadgeProps['variant']> {
  const s = severity.toUpperCase()
  if (s === 'CRITICAL') return 'crit'
  if (s === 'HIGH') return 'high'
  if (s === 'MEDIUM') return 'med'
  return 'low'
}
