import { createFileRoute } from '@tanstack/react-router'
import { ShieldCheck, ShieldAlert, CircleUser } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ActivateLicense } from '@/components/dashboard/ActivateLicense'
import { useAuthStore } from '@/stores/auth'
import { formatDate } from '@/lib/utils'

export const Route = createFileRoute('/dashboard/')({
  component: Overview,
})

function Overview() {
  const user = useAuthStore((s) => s.user)
  const subscription = useAuthStore((s) => s.subscription)
  const active = subscription?.has_subscription ?? false

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold">
          Welcome back{user?.name ? `, ${user.name.split(' ')[0]}` : ''}
        </h1>
        <p className="text-muted">Your CTPPO workspace overview.</p>
      </header>

      {/* Subscription */}
      <Card className={active ? 'border-cyber/25' : 'border-warn/30'}>
        <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
          <div className="flex items-start gap-4">
            <span
              className={`flex h-11 w-11 items-center justify-center rounded-2xl ${
                active ? 'bg-cyber/15 text-cyber' : 'bg-warn/15 text-warn'
              }`}
            >
              {active ? <ShieldCheck className="h-6 w-6" /> : <ShieldAlert className="h-6 w-6" />}
            </span>
            <div className="flex flex-col gap-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-lg font-semibold">Subscription</h2>
                {subscription === null ? (
                  <Badge variant="muted">Checking…</Badge>
                ) : subscription.is_owner ? (
                  <Badge variant="cyber">Owner</Badge>
                ) : active ? (
                  <Badge variant="cyber">Active</Badge>
                ) : subscription.status === 'expired' ? (
                  <Badge variant="high">Expired</Badge>
                ) : (
                  <Badge variant="muted">No subscription</Badge>
                )}
              </div>
              <p className="text-sm text-muted">
                {subscription?.is_owner
                  ? 'Owner account — full access, no product key required.'
                  : active
                    ? `${subscription?.subscription_type ?? 'Plan'} active${
                        subscription?.days_remaining != null ? ` · ${subscription.days_remaining} days remaining` : ''
                      }${subscription?.expires_at ? ` · renews ${formatDate(subscription.expires_at)}` : ''}`
                    : 'Activate a product key to unlock instances, attack-path analysis and the enterprise tier.'}
              </p>
            </div>
          </div>
        </div>

        {subscription !== null && !active && !subscription.is_owner && (
          <div className="mt-6 border-t border-line-soft pt-6">
            <ActivateLicense />
          </div>
        )}
      </Card>

      {/* Account */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <CircleUser className="h-5 w-5 text-muted" />
            <CardTitle>Account</CardTitle>
          </div>
          <CardDescription>Your profile details.</CardDescription>
        </CardHeader>
        <div className="flex flex-col gap-3">
          <Detail label="Name" value={user?.name} />
          <Detail label="Email" value={user?.email} />
          <Detail label="Role" value={user?.role ?? 'user'} />
          {user?.created_at && <Detail label="Member since" value={formatDate(user.created_at)} />}
        </div>
      </Card>
    </div>
  )
}

function Detail({ label, value }: { label: string; value?: string }) {
  return (
    <div className="flex items-center justify-between border-b border-line-soft pb-3 last:border-0 last:pb-0">
      <span className="text-sm text-muted">{label}</span>
      <span className="text-sm font-medium text-fg">{value ?? '—'}</span>
    </div>
  )
}
