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
import { Field, FormError } from '@/components/ui/field'
import { authApi, ApiError } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

export const Route = createFileRoute('/login')({
  component: () => (
    <RedirectIfAuthed>
      <LoginPage />
    </RedirectIfAuthed>
  ),
})

const schema = z.object({
  email: z.email('Enter a valid email'),
  password: z.string().min(1, 'Password is required'),
})
type Values = z.infer<typeof schema>

function LoginPage() {
  const navigate = useNavigate()
  const setUser = useAuthStore((s) => s.setUser)
  const refreshSubscription = useAuthStore((s) => s.refreshSubscription)
  const [formError, setFormError] = useState<string | null>(null)
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<Values>({ resolver: zodResolver(schema) })

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null)
    try {
      const { user } = await authApi.login(values.email, values.password)
      setUser(user)
      await refreshSubscription()
      navigate({ to: '/' })
    } catch (e) {
      setFormError(e instanceof ApiError ? e.message : 'Something went wrong. Please try again.')
    }
  })

  return (
    <AuthShell
      title="Welcome back"
      subtitle="Sign in to your CTPPO account"
      footer={
        <>
          New here?{' '}
          <Link to="/register" className="text-cyber hover:underline">
            Create an account
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        {formError && <FormError message={formError} />}
        <Field label="Email" htmlFor="email" error={errors.email?.message}>
          <Input id="email" type="email" autoComplete="email" placeholder="you@example.com" {...register('email')} />
        </Field>
        <Field label="Password" htmlFor="password" error={errors.password?.message}>
          <Input id="password" type="password" autoComplete="current-password" placeholder="••••••••" {...register('password')} />
        </Field>
        <div className="-mt-1 flex justify-end">
          <Link to="/forgot-password" className="text-xs text-muted hover:text-cyber">
            Forgot password?
          </Link>
        </div>
        <Button type="submit" disabled={isSubmitting} className="mt-1 w-full">
          {isSubmitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Signing in…
            </>
          ) : (
            'Sign in'
          )}
        </Button>
      </form>
    </AuthShell>
  )
}
