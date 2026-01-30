import { useState, useEffect } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { authApi, Setup2FAResponse, subscriptionApi, SubscriptionStatus } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Settings,
  Shield,
  Smartphone,
  KeyRound,
  CheckCircle,
  XCircle,
  Loader2,
  AlertCircle,
  Copy,
  Check,
} from 'lucide-react'

export const Route = createFileRoute('/settings')({
  component: SettingsPage,
})

function SettingsPage() {
  const { user, setUser } = useAuthStore()
  const queryClient = useQueryClient()
  
  const [setup2FAData, setSetup2FAData] = useState<Setup2FAResponse | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [disableCode, setDisableCode] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [copied, setCopied] = useState(false)
  const [subscription, setSubscription] = useState<SubscriptionStatus | null>(null)

  // Fetch subscription status on mount
  useEffect(() => {
    if (user?.email) {
      subscriptionApi.check(user.email).then(setSubscription).catch(console.error)
    }
  }, [user?.email])

  const setup2FAMutation = useMutation({
    mutationFn: authApi.setup2FA,
    onSuccess: (data) => {
      setSetup2FAData(data)
      setError('')
    },
    onError: (err: Error) => {
      setError(err.message)
    },
  })

  const confirm2FAMutation = useMutation({
    mutationFn: (code: string) => authApi.confirm2FA(code),
    onSuccess: async () => {
      setSuccess('2FA has been enabled successfully!')
      setSetup2FAData(null)
      setTotpCode('')
      // Refresh user data
      const updatedUser = await authApi.getMe()
      setUser(updatedUser)
    },
    onError: (err: Error) => {
      setError(err.message)
    },
  })

  const disable2FAMutation = useMutation({
    mutationFn: (code: string) => authApi.disable2FA(code),
    onSuccess: async () => {
      setSuccess('2FA has been disabled.')
      setDisableCode('')
      // Refresh user data
      const updatedUser = await authApi.getMe()
      setUser(updatedUser)
    },
    onError: (err: Error) => {
      setError(err.message)
    },
  })

  const handleSetup2FA = () => {
    setError('')
    setSuccess('')
    setup2FAMutation.mutate()
  }

  const handleConfirm2FA = () => {
    if (totpCode.length !== 6) {
      setError('Please enter a 6-digit code')
      return
    }
    setError('')
    confirm2FAMutation.mutate(totpCode)
  }

  const handleDisable2FA = () => {
    if (disableCode.length !== 6) {
      setError('Please enter a 6-digit code')
      return
    }
    setError('')
    disable2FAMutation.mutate(disableCode)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const isLoading = setup2FAMutation.isPending || confirm2FAMutation.isPending || disable2FAMutation.isPending

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Settings className="w-8 h-8 text-primary" />
          Settings
        </h1>
        <p className="text-muted-foreground mt-2">
          Manage your account security and preferences
        </p>
      </motion.div>

      {/* Account Info */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="p-6 rounded-xl bg-card border border-border"
      >
        <h2 className="text-lg font-semibold mb-4">Account Information</h2>
        <div className="space-y-4">
          <div className="flex justify-between items-center py-3 border-b border-border">
            <span className="text-muted-foreground">Name</span>
            <span className="font-medium">{user?.name}</span>
          </div>
          <div className="flex justify-between items-center py-3 border-b border-border">
            <span className="text-muted-foreground">Email</span>
            <span className="font-medium">{user?.email}</span>
          </div>
          <div className="flex justify-between items-center py-3 border-b border-border">
            <span className="text-muted-foreground">Account Status</span>
            <span className={`flex items-center gap-2 ${subscription?.has_subscription ? 'text-green-500' : 'text-red-500'}`}>
              {subscription?.has_subscription ? <CheckCircle size={16} /> : <XCircle size={16} />}
              {subscription?.is_owner ? 'Active (Owner)' : subscription?.has_subscription ? 'Active' : 'Inactive'}
            </span>
          </div>
          <div className="flex justify-between items-center py-3">
            <span className="text-muted-foreground">Member Since</span>
            <span className="font-medium">
              {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
            </span>
          </div>
        </div>
      </motion.div>

      {/* 2FA Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="p-6 rounded-xl bg-card border border-border"
      >
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/20">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">Two-Factor Authentication</h2>
              <p className="text-sm text-muted-foreground">
                Add an extra layer of security to your account
              </p>
            </div>
          </div>
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
            user?.is_2fa_enabled 
              ? 'bg-green-500/20 text-green-500' 
              : 'bg-yellow-500/20 text-yellow-500'
          }`}>
            {user?.is_2fa_enabled ? (
              <>
                <CheckCircle size={14} />
                Enabled
              </>
            ) : (
              <>
                <AlertCircle size={14} />
                Disabled
              </>
            )}
          </div>
        </div>

        {/* Success/Error Messages */}
        <AnimatePresence>
          {success && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="flex items-center gap-2 p-3 mb-4 rounded-lg bg-green-500/20 text-green-500"
            >
              <CheckCircle size={18} />
              <span className="text-sm">{success}</span>
            </motion.div>
          )}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="flex items-center gap-2 p-3 mb-4 rounded-lg bg-destructive/20 text-destructive"
            >
              <AlertCircle size={18} />
              <span className="text-sm">{error}</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* 2FA Setup Flow */}
        {!user?.is_2fa_enabled && !setup2FAData && (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Protect your account by requiring a verification code from your authenticator app in addition to your password.
            </p>
            <button
              onClick={handleSetup2FA}
              disabled={isLoading}
              className="px-6 py-3 rounded-lg bg-primary text-primary-foreground font-medium
                hover:bg-primary/90 disabled:opacity-50 flex items-center gap-2"
            >
              {setup2FAMutation.isPending ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <Smartphone className="w-5 h-5" />
              )}
              Enable 2FA
            </button>
          </div>
        )}

        {/* QR Code Setup */}
        {setup2FAData && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            <div className="flex items-start gap-4">
              <div className="flex-shrink-0 p-4 bg-white rounded-xl">
                <img 
                  src={setup2FAData.qr_code} 
                  alt="2FA QR Code" 
                  className="w-40 h-40"
                />
              </div>
              <div className="space-y-3">
                <h3 className="font-medium">Scan QR Code</h3>
                <p className="text-sm text-muted-foreground">
                  Use an authenticator app like Google Authenticator, Authy, or 1Password to scan this QR code.
                </p>
                <div className="p-3 rounded-lg bg-secondary">
                  <p className="text-xs text-muted-foreground mb-1">Manual Entry Key</p>
                  <div className="flex items-center gap-2">
                    <code className="text-sm font-mono">{setup2FAData.manual_entry_key}</code>
                    <button
                      onClick={() => copyToClipboard(setup2FAData.manual_entry_key)}
                      className="p-1.5 rounded hover:bg-primary/20"
                    >
                      {copied ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <label className="block text-sm font-medium">
                Enter verification code to confirm
              </label>
              <div className="flex gap-3">
                <div className="relative flex-1">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="000000"
                    maxLength={6}
                    className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border
                      focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono text-lg tracking-widest"
                  />
                </div>
                <button
                  onClick={handleConfirm2FA}
                  disabled={isLoading || totpCode.length !== 6}
                  className="px-6 py-3 rounded-lg bg-primary text-primary-foreground font-medium
                    hover:bg-primary/90 disabled:opacity-50 flex items-center gap-2"
                >
                  {confirm2FAMutation.isPending ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : (
                    'Verify'
                  )}
                </button>
              </div>
            </div>

            <button
              onClick={() => setSetup2FAData(null)}
              className="text-sm text-muted-foreground hover:text-foreground"
            >
              Cancel setup
            </button>
          </motion.div>
        )}

        {/* Disable 2FA */}
        {user?.is_2fa_enabled && (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              To disable 2FA, enter a verification code from your authenticator app.
            </p>
            <div className="flex gap-3">
              <div className="relative flex-1">
                <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <input
                  type="text"
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="Enter code to disable"
                  maxLength={6}
                  className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border
                    focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono"
                />
              </div>
              <button
                onClick={handleDisable2FA}
                disabled={isLoading || disableCode.length !== 6}
                className="px-6 py-3 rounded-lg bg-destructive text-destructive-foreground font-medium
                  hover:bg-destructive/90 disabled:opacity-50 flex items-center gap-2"
              >
                {disable2FAMutation.isPending ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  'Disable 2FA'
                )}
              </button>
            </div>
          </div>
        )}
      </motion.div>

      {/* Security Tips */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="p-6 rounded-xl bg-primary/5 border border-primary/20"
      >
        <h3 className="font-medium mb-3 flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          Security Tips
        </h3>
        <ul className="space-y-2 text-sm text-muted-foreground">
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            Use a strong, unique password for your account
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            Enable two-factor authentication for maximum security
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            Store your 2FA backup codes in a secure location
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            Never share your verification codes with anyone
          </li>
        </ul>
      </motion.div>
    </div>
  )
}
