import { useState } from 'react'
import { Link, useNavigate, createFileRoute } from '@tanstack/react-router'
import { useMutation } from '@tanstack/react-query'
import { authApi } from '@/api/client'
import { motion } from 'framer-motion'
import { Shield, Mail, Lock, User, Loader2, AlertCircle, CheckCircle } from 'lucide-react'

export const Route = createFileRoute('/register')({
  component: RegisterPage,
})

function RegisterPage() {
  const navigate = useNavigate()
  
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)

  const registerMutation = useMutation({
    mutationFn: () => authApi.register(email, password, fullName),
    onSuccess: () => {
      setSuccess(true)
      setTimeout(() => navigate({ to: '/login' }), 2000)
    },
    onError: (err: Error) => {
      setError(err.message)
    },
  })

  const handleRegister = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    registerMutation.mutate()
  }

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
          <p className="text-muted-foreground mt-2">Create your account</p>
        </div>

        {/* Card */}
        <div className="glass rounded-2xl p-8">
          {success ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center py-8"
            >
              <div className="inline-flex p-4 rounded-full bg-green-500/20 mb-4">
                <CheckCircle className="w-12 h-12 text-green-500" />
              </div>
              <h2 className="text-xl font-semibold mb-2">Account Created!</h2>
              <p className="text-muted-foreground">Redirecting to login...</p>
            </motion.div>
          ) : (
            <>
              <h2 className="text-xl font-semibold mb-6">Sign up for CTPPO</h2>

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

              <form onSubmit={handleRegister} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Full Name</label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                    <input
                      type="text"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      placeholder="John Doe"
                      required
                      className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border 
                        focus:outline-none focus:ring-2 focus:ring-primary/50"
                    />
                  </div>
                </div>

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
                      minLength={8}
                      className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border 
                        focus:outline-none focus:ring-2 focus:ring-primary/50"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Confirm Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="••••••••"
                      required
                      className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border 
                        focus:outline-none focus:ring-2 focus:ring-primary/50"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={registerMutation.isPending}
                  className="w-full py-3 rounded-lg bg-primary text-primary-foreground font-medium
                    hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed
                    flex items-center justify-center gap-2"
                >
                  {registerMutation.isPending ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Creating account...
                    </>
                  ) : (
                    'Create Account'
                  )}
                </button>
              </form>

              <div className="mt-6 text-center text-sm text-muted-foreground">
                Already have an account?{' '}
                <Link to="/login" className="text-primary hover:underline">
                  Sign in
                </Link>
              </div>
            </>
          )}
        </div>
      </motion.div>
    </div>
  )
}
