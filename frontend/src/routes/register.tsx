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

export const Route = createFileRoute('/register')({
  component: () => (
    <RedirectIfAuthed>
      <RegisterPage />
    </RedirectIfAuthed>
  ),
})

const schema = z
  .object({
    name: z.string().min(1, 'Name is required'),
    email: z.email('Enter a valid email'),
    password: z.string().min(8, 'At least 8 characters'),
    confirm: z.string(),
  })
  .refine((d) => d.password === d.confirm, {
    message: 'Passwords do not match',
    path: ['confirm'],
  })
type Values = z.infer<typeof schema>

function RegisterPage() {
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
      const { user } = await authApi.signup(values.email, values.password, values.name)
      setUser(user)
      await refreshSubscription()
      navigate({ to: '/' })
    } catch (e) {
      setFormError(e instanceof ApiError ? e.message : 'Something went wrong. Please try again.')
    }
  })

  return (
    <AuthShell
      title="Create your account"
      subtitle="Start mapping attack paths in minutes"
      footer={
        <>
          Already have an account?{' '}
          <Link to="/login" className="text-cyber hover:underline">
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4" noValidate>
        {formError && <FormError message={formError} />}
        <Field label="Name" htmlFor="name" error={errors.name?.message}>
          <Input id="name" autoComplete="name" placeholder="Ada Lovelace" {...register('name')} />
        </Field>
        <Field label="Email" htmlFor="email" error={errors.email?.message}>
          <Input id="email" type="email" autoComplete="email" placeholder="you@example.com" {...register('email')} />
        </Field>
        <Field label="Password" htmlFor="password" error={errors.password?.message} hint="At least 8 characters">
          <Input id="password" type="password" autoComplete="new-password" placeholder="••••••••" {...register('password')} />
        </Field>
        <Field label="Confirm password" htmlFor="confirm" error={errors.confirm?.message}>
          <Input id="confirm" type="password" autoComplete="new-password" placeholder="••••••••" {...register('confirm')} />
        </Field>
        <Button type="submit" disabled={isSubmitting} className="mt-1 w-full">
          {isSubmitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Creating account…
            </>
          ) : (
            'Create account'
          )}
        </Button>
      </form>
    </AuthShell>
  )
}
