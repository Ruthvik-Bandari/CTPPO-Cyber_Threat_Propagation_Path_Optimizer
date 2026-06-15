import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2, UserPlus, Trash2, Loader2, Crown, User as UserIcon } from 'lucide-react'
import { RequireSubscription } from '@/components/auth/guards'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Field, FormError } from '@/components/ui/field'
import { LoadingState, ErrorState, EmptyState } from '@/components/dashboard/states'
import { orgApi, ApiError, type Org } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { cn } from '@/lib/utils'

export const Route = createFileRoute('/dashboard/enterprise')({
  component: () => (
    <RequireSubscription>
      <EnterprisePage />
    </RequireSubscription>
  ),
})

const selectCls = 'h-9 rounded-lg border border-line bg-base-2/60 px-2 text-sm text-fg outline-none focus:border-cyber/60'

function EnterprisePage() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['org'],
    queryFn: () => orgApi.me(),
  })

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-1">
        <h1 className="text-3xl font-bold">Enterprise</h1>
        <p className="text-muted">Organizations, seats and role-based access.</p>
      </header>

      {isLoading ? (
        <LoadingState label="Loading organization…" />
      ) : isError ? (
        <ErrorState error={error} />
      ) : data?.org ? (
        <OrgView org={data.org} role={data.role ?? 'member'} />
      ) : (
        <CreateOrg />
      )}
    </div>
  )
}

function CreateOrg() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [seats, setSeats] = useState(5)
  const [formError, setFormError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () => orgApi.create(name.trim(), seats),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['org'] }),
    onError: (e) => setFormError(e instanceof ApiError ? e.message : 'Could not create organization.'),
  })

  return (
    <EmptyState
      Icon={Building2}
      title="No organization yet"
      description="Create an organization to invite teammates with seat-based, role-controlled access."
      action={
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (!name.trim()) return setFormError('Name is required')
            setFormError(null)
            mutation.mutate()
          }}
          className="flex w-full max-w-sm flex-col gap-3 text-left"
        >
          {formError && <FormError message={formError} />}
          <Field label="Organization name" htmlFor="org-name">
            <Input id="org-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Security" />
          </Field>
          <Field label="Seats" htmlFor="org-seats">
            <Input
              id="org-seats"
              type="number"
              min={1}
              value={seats}
              onChange={(e) => setSeats(Math.max(1, Number(e.target.value)))}
            />
          </Field>
          <Button type="submit" disabled={mutation.isPending} className="w-full">
            {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Building2 className="h-4 w-4" />}
            Create organization
          </Button>
        </form>
      }
    />
  )
}

function OrgView({ org, role }: { org: Org; role: string }) {
  const qc = useQueryClient()
  const currentEmail = useAuthStore((s) => s.user?.email?.toLowerCase())
  const isAdmin = role === 'admin'
  const [opError, setOpError] = useState<string | null>(null)
  const [newEmail, setNewEmail] = useState('')
  const [newRole, setNewRole] = useState('member')

  const members = Object.entries(org.members).map(([email, r]) => ({ email, role: r }))
  const seatsUsed = members.length

  const onError = (e: unknown) => setOpError(e instanceof ApiError ? e.message : 'Operation failed.')
  const onMutated = () => {
    qc.invalidateQueries({ queryKey: ['org'] })
    setOpError(null)
  }

  const addMutation = useMutation({
    mutationFn: () => orgApi.addMember(org.id, newEmail.trim(), newRole),
    onSuccess: () => { onMutated(); setNewEmail('') },
    onError,
  })
  const roleMutation = useMutation({
    mutationFn: (v: { email: string; role: string }) => orgApi.setRole(org.id, v.email, v.role),
    onSuccess: onMutated,
    onError,
  })
  const removeMutation = useMutation({
    mutationFn: (email: string) => orgApi.removeMember(org.id, email),
    onSuccess: onMutated,
    onError,
  })

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-marine/15 text-marine-bright">
              <Building2 className="h-6 w-6" />
            </span>
            <div className="flex flex-col gap-1">
              <h2 className="text-xl font-semibold">{org.name}</h2>
              <p className="text-sm text-muted">
                {seatsUsed} / {org.seats} seats used
              </p>
            </div>
          </div>
          <Badge variant={isAdmin ? 'cyber' : 'muted'}>{isAdmin ? 'Admin' : 'Member'}</Badge>
        </div>
      </Card>

      {opError && <ErrorState error={opError} />}

      {isAdmin && (
        <Card>
          <CardHeader>
            <CardTitle>Invite a member</CardTitle>
            <CardDescription>Add a teammate within your seat allotment.</CardDescription>
          </CardHeader>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (!newEmail.trim()) return setOpError('Email is required')
              addMutation.mutate()
            }}
            className="flex flex-wrap items-end gap-3"
          >
            <div className="min-w-[14rem] flex-1">
              <Field label="Email" htmlFor="member-email">
                <Input id="member-email" type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} placeholder="teammate@acme.com" />
              </Field>
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="member-role" className="text-sm font-medium text-fg">Role</label>
              <select id="member-role" value={newRole} onChange={(e) => setNewRole(e.target.value)} className={cn(selectCls, 'h-11')}>
                <option value="member">Member</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <Button type="submit" disabled={addMutation.isPending || seatsUsed >= org.seats}>
              {addMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="h-4 w-4" />}
              Add
            </Button>
          </form>
          {seatsUsed >= org.seats && <p className="mt-2 text-xs text-warn">Seat allotment exhausted.</p>}
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Members</CardTitle>
          <CardDescription>{isAdmin ? 'Manage roles and membership.' : 'Your organization roster.'}</CardDescription>
        </CardHeader>
        <div className="flex flex-col">
          {members.map((m) => {
            const isSelf = m.email === currentEmail
            return (
              <div key={m.email} className="flex flex-wrap items-center justify-between gap-3 border-b border-line-soft py-3 last:border-0">
                <div className="flex items-center gap-3">
                  <span className="flex h-9 w-9 items-center justify-center rounded-full bg-surface text-muted">
                    {m.role === 'admin' ? <Crown className="h-4 w-4 text-cyber" /> : <UserIcon className="h-4 w-4" />}
                  </span>
                  <div className="flex flex-col">
                    <span className="text-sm font-medium text-fg">
                      {m.email} {isSelf && <span className="text-xs text-faint">(you)</span>}
                    </span>
                    <span className="text-xs text-faint capitalize">{m.role}</span>
                  </div>
                </div>
                {isAdmin ? (
                  <div className="flex items-center gap-2">
                    <select
                      value={m.role}
                      onChange={(e) => roleMutation.mutate({ email: m.email, role: e.target.value })}
                      className={cn(selectCls)}
                      aria-label={`Role for ${m.email}`}
                    >
                      <option value="member">Member</option>
                      <option value="admin">Admin</option>
                    </select>
                    <button
                      type="button"
                      aria-label={`Remove ${m.email}`}
                      onClick={() => removeMutation.mutate(m.email)}
                      className="flex h-9 w-9 items-center justify-center rounded-lg border border-line text-faint transition-colors hover:border-danger/50 hover:text-danger"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ) : (
                  <Badge variant="muted">{m.role}</Badge>
                )}
              </div>
            )
          })}
        </div>
      </Card>
    </div>
  )
}
