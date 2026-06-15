import { useState } from 'react'
import { KeyRound, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { FormError, FormSuccess } from '@/components/ui/field'
import { subscriptionApi, ApiError } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

/* Product-key activation. On success it refreshes the subscription so gated routes unlock. */
export function ActivateLicense() {
  const refreshSubscription = useAuthStore((s) => s.refreshSubscription)
  const [key, setKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const res = await subscriptionApi.activate(key.trim())
      setSuccess(res.message ?? `Activated${res.subscription_type ? ` — ${res.subscription_type}` : ''}.`)
      setKey('')
      await refreshSubscription()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Activation failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      {error && <FormError message={error} />}
      {success && <FormSuccess message={success} />}
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="relative flex-1">
          <KeyRound className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <Input
            value={key}
            onChange={(e) => setKey(e.target.value.toUpperCase())}
            placeholder="CTPPO-XXXX-XXXX-XXXX-XXXX"
            aria-label="Product key"
            className="pl-10 font-mono"
          />
        </div>
        <Button type="submit" disabled={loading || key.trim().length === 0} className="sm:w-auto">
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Activating…
            </>
          ) : (
            'Activate'
          )}
        </Button>
      </div>
      <p className="text-xs text-faint">
        Don't have a product key?{' '}
        <a href="mailto:bandari.ru@northeastern.edu" className="text-cyber hover:underline">
          Contact us
        </a>
        .
      </p>
    </form>
  )
}
