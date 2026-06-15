import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import { AuthShell } from '@/components/auth/AuthShell'
import { RedirectIfAuthed } from '@/components/auth/guards'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Field, FormError, FormSuccess } from '@/components/ui/field'
import { authApi, ApiError } from '@/api/client'

export const Route = createFileRoute('/reset-password')({
  validateSearch: (search: Record<string, unknown>) => ({
    token: typeof search.token === 'string' ? search.token : '',
  }),
  component: () => (
    <RedirectIfAuthed>
      <ResetPasswordPage />
    </RedirectIfAuthed>
  ),
})

const schema = z
  .object({
    password: z.string().min(8, 'At least 8 characters'),
    confirm: z.string(),
  })
  .refine((d) => d.password === d.confirm, {
    message: 'Passwords do not match',
    path: ['confirm'],
  })
type Values = z.infer<typeof schema>

function ResetPasswordPage() {
  const { token } = Route.useSearch()
  const navigate = useNavigate()
  const [formError, setFormError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<Values>({ resolver: zodResolver(schema) })

  const onSubmit = handleSubmit(async ({ password }) => {
    setFormError(null)
    try {
      await authApi.resetPassword(token, password)
      setDone(true)
      setTimeout(() => navigate({ to: '/login' }), 1500)
    } catch (e) {
      setFormError(e instanceof ApiError ? e.message : 'Something went wrong. Please try again.')
    }
  })

  if (!token) {
    return (
      <AuthShell
        title="Invalid reset link"
        subtitle="This link is missing its reset token"
        footer={
          <Link to="/forgot-password" className="text-cyber hover:underline">
            Request a new link
          </Link>
        }
      >
        <FormError message="No reset token found. Please request a new password reset." />
      </AuthShell>
    )
  }

  return (
    <AuthShell
      title="Choose a new password"
      subtitle="Set a new password for your account"
      footer={
        <Link to="/login" className="text-cyber hover:underline">
          Back to sign in
        </Link>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        {formError && <FormError message={formError} />}
        {done && <FormSuccess message="Password updated. Redirecting to sign in…" />}
        <Field label="New password" htmlFor="password" error={errors.password?.message} hint="At least 8 characters">
          <Input id="password" type="password" autoComplete="new-password" placeholder="••••••••" {...register('password')} />
        </Field>
        <Field label="Confirm password" htmlFor="confirm" error={errors.confirm?.message}>
          <Input id="confirm" type="password" autoComplete="new-password" placeholder="••••••••" {...register('confirm')} />
        </Field>
        <Button type="submit" disabled={isSubmitting || done} className="mt-1 w-full">
          {isSubmitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Updating…
            </>
          ) : (
            'Update password'
          )}
        </Button>
      </form>
    </AuthShell>
  )
}
