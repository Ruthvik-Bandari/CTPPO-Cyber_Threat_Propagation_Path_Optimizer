import { useState } from 'react'
import { Link, useNavigate, createFileRoute } from '@tanstack/react-router'
import { useMutation } from '@tanstack/react-query'
import { useAuthStore } from '@/stores/auth'
import { authApi } from '@/api/client'
import { motion } from 'framer-motion'
import { Shield, Mail, Lock, Loader2, KeyRound, AlertCircle } from 'lucide-react'

export const Route = createFileRoute('/login')({
  component: LoginPage,
})

function LoginPage() {
  const navigate = useNavigate()
  const { setTokens, setUser, setRequires2FA, requires2FA, tempToken } = useAuthStore()
  
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [error, setError] = useState('')

  const loginMutation = useMutation({
    mutationFn: () => authApi.login(email, password),
    onSuccess: async (data) => {
      if (data.requires_2fa && data.temp_token) {
        setRequires2FA(true, data.temp_token)
      } else if (data.access_token && data.refresh_token) {
        setTokens(data.access_token, data.refresh_token)
        if (data.user) {
          setUser(data.user)
        }
        navigate({ to: '/dashboard' })
      }
    },
    onError: (err: Error) => {
      setError(err.message || 'Login failed')
    },
  })

  const verify2FAMutation = useMutation({
    mutationFn: () => authApi.verify2FA(email, tempToken!, totpCode),
    onSuccess: async (data) => {
      if (data.access_token && data.refresh_token) {
        setTokens(data.access_token, data.refresh_token)
        if (data.user) {
          setUser(data.user)
        }
        navigate({ to: '/dashboard' })
      }
    },
    onError: (err: Error) => {
      setError(err.message || 'Verification failed')
    },
  })

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    loginMutation.mutate()
  }

  const handleVerify2FA = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    verify2FAMutation.mutate()
  }

  const isLoading = loginMutation.isPending || verify2FAMutation.isPending

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-grid">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex p-4 rounded-2xl bg-primary/20 mb-4">
            <Shield className="w-12 h-12 text-primary" />
          </div>
          <h1 className="text-3xl font-bold">CTPPO</h1>
          <p className="text-muted-foreground mt-2">
            Cyber Threat Prioritization & Path Optimization
          </p>
        </div>

        {/* Card */}
        <div className="glass rounded-2xl p-8">
          <h2 className="text-xl font-semibold mb-6">
            {requires2FA ? 'Two-Factor Authentication' : 'Sign in to your account'}
          </h2>

          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-center gap-2 p-3 mb-4 rounded-lg bg-destructive/20 text-destructive"
            >
              <AlertCircle size={18} />
              <span className="text-sm">{error}</span>
            </motion.div>
          )}

          {!requires2FA ? (
            // Login form
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Email</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    required
                    className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border 
                      focus:outline-none focus:ring-2 focus:ring-primary/50"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Password</label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    required
                    className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border 
                      focus:outline-none focus:ring-2 focus:ring-primary/50"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-3 rounded-lg bg-primary text-primary-foreground font-medium
                  hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed
                  flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Signing in...
                  </>
                ) : (
                  'Sign in'
                )}
              </button>
            </form>
          ) : (
            // 2FA form
            <form onSubmit={handleVerify2FA} className="space-y-4">
              <p className="text-sm text-muted-foreground mb-4">
                Enter the 6-digit code from your authenticator app.
              </p>

              <div>
                <label className="block text-sm font-medium mb-2">Verification Code</label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="000000"
                    required
                    maxLength={6}
                    className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border 
                      focus:outline-none focus:ring-2 focus:ring-primary/50 text-center text-2xl tracking-widest"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading || totpCode.length !== 6}
                className="w-full py-3 rounded-lg bg-primary text-primary-foreground font-medium
                  hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed
                  flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Verifying...
                  </>
                ) : (
                  'Verify'
                )}
              </button>

              <button
                type="button"
                onClick={() => setRequires2FA(false)}
                className="w-full py-2 text-sm text-muted-foreground hover:text-foreground"
              >
                ← Back to login
              </button>
            </form>
          )}

          {!requires2FA && (
            <div className="mt-6 text-center text-sm text-muted-foreground">
              Don't have an account?{' '}
              <Link to="/register" className="text-primary hover:underline">
                Sign up
              </Link>
            </div>
          )}

          {/* Demo credentials */}
          <div className="mt-6 p-3 rounded-lg bg-secondary/50 text-sm">
            <p className="font-medium mb-1">Demo Account:</p>
            <p className="text-muted-foreground">Email: demo@ctppo.ai</p>
            <p className="text-muted-foreground">Password: demo123</p>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
