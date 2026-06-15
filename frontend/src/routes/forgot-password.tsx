import { createFileRoute, Link } from '@tanstack/react-router'
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

export const Route = createFileRoute('/forgot-password')({
  component: () => (
    <RedirectIfAuthed>
      <ForgotPasswordPage />
    </RedirectIfAuthed>
  ),
})

const schema = z.object({ email: z.email('Enter a valid email') })
type Values = z.infer<typeof schema>

function ForgotPasswordPage() {
  const [formError, setFormError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [devToken, setDevToken] = useState<string | null>(null)
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<Values>({ resolver: zodResolver(schema) })

  const onSubmit = handleSubmit(async ({ email }) => {
    setFormError(null)
    try {
      const res = await authApi.forgotPassword(email)
      setMessage(res.message)
      setDevToken(res.dev_reset_token ?? null)
    } catch (e) {
      setFormError(e instanceof ApiError ? e.message : 'Something went wrong. Please try again.')
    }
  })

  return (
    <AuthShell
      title="Reset your password"
      subtitle="We'll send a reset link if an account exists"
      footer={
        <Link to="/login" className="text-cyber hover:underline">
          Back to sign in
        </Link>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        {formError && <FormError message={formError} />}
        {message && <FormSuccess message={message} />}
        {devToken && (
          <div className="flex flex-col gap-2 rounded-xl border border-warn/30 bg-warn/5 p-3.5 text-xs text-muted">
            <span className="font-medium text-warn">Dev only — email delivery is stubbed</span>
            <span>Use this single-use token to continue:</span>
            <Link
              to="/reset-password"
              search={{ token: devToken }}
              className="break-all font-mono text-cyber hover:underline"
            >
              {devToken}
            </Link>
          </div>
        )}
        <Field label="Email" htmlFor="email" error={errors.email?.message}>
          <Input id="email" type="email" autoComplete="email" placeholder="you@example.com" {...register('email')} />
        </Field>
        <Button type="submit" disabled={isSubmitting} className="mt-1 w-full">
          {isSubmitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Sending…
            </>
          ) : (
            'Send reset link'
          )}
        </Button>
      </form>
    </AuthShell>
  )
}
