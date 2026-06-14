import { useState, useEffect } from 'react'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { motion } from 'framer-motion'
import {
  Shield,
  Key,
  Users,
  Trash2,
  Copy,
  Check,
  Loader2,
  AlertCircle,
  CheckCircle,
  Plus,
  RefreshCw,
  Lock,
} from 'lucide-react'

export const Route = createFileRoute('/admin')({
  component: AdminPage,
})

const API_BASE = import.meta.env.VITE_API_URL 
  ? `${import.meta.env.VITE_API_URL}/api` 
  : '/api'

interface ProductKey {
  key: string
  subscription_type: string
  validity_days: number
  created_at: string
  used: boolean
  used_by?: string
}

interface ActivatedKey {
  email: string
  subscription_type: string
  activated_at: string
  expires_at: string
}

function AdminPage() {
  const navigate = useNavigate()
  const [adminSecret, setAdminSecret] = useState('')
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [copied, setCopied] = useState<string | null>(null)

  // Key generation form
  const [subscriptionType, setSubscriptionType] = useState('individual')
  const [validityDays, setValidityDays] = useState(365)
  const [generatedKey, setGeneratedKey] = useState('')

  // Data
  const [productKeys, setProductKeys] = useState<ProductKey[]>([])
  const [activatedKeys, setActivatedKeys] = useState<ActivatedKey[]>([])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const response = await fetch(`${API_BASE}/admin/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ admin_secret: adminSecret }),
      })

      if (response.ok) {
        setIsAuthenticated(true)
        localStorage.setItem('admin_secret', adminSecret)
        fetchData()
      } else {
        setError('Invalid admin secret')
      }
    } catch (err) {
      setError('Connection error')
    } finally {
      setLoading(false)
    }
  }

  const fetchData = async () => {
    const secret = localStorage.getItem('admin_secret')
    if (!secret) return

    try {
      const [keysRes, activationsRes] = await Promise.all([
        fetch(`${API_BASE}/admin/keys?admin_secret=${encodeURIComponent(secret)}`),
        fetch(`${API_BASE}/admin/activations?admin_secret=${encodeURIComponent(secret)}`),
      ])

      if (keysRes.ok) {
        const keysData = await keysRes.json()
        setProductKeys(keysData.keys || [])
      }

      if (activationsRes.ok) {
        const activationsData = await activationsRes.json()
        setActivatedKeys(activationsData.activations || [])
      }
    } catch (err) {
      console.error('Error fetching data:', err)
    }
  }

  const generateKey = async () => {
    setLoading(true)
    setError('')
    setSuccess('')

    try {
      const response = await fetch(`${API_BASE}/admin/generate-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          admin_secret: localStorage.getItem('admin_secret'),
          subscription_type: subscriptionType,
          validity_days: validityDays,
        }),
      })

      const data = await response.json()

      if (response.ok) {
        setGeneratedKey(data.key)
        setSuccess('Product key generated successfully!')
        fetchData()
      } else {
        setError(data.detail || 'Failed to generate key')
      }
    } catch (err) {
      setError('Connection error')
    } finally {
      setLoading(false)
    }
  }

  const revokeKey = async (key: string) => {
    if (!confirm('Are you sure you want to revoke this key?')) return

    try {
      const response = await fetch(`${API_BASE}/admin/revoke-key`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          admin_secret: localStorage.getItem('admin_secret'),
          product_key: key,
        }),
      })

      if (response.ok) {
        setSuccess('Key revoked successfully')
        fetchData()
      } else {
        setError('Failed to revoke key')
      }
    } catch (err) {
      setError('Connection error')
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(text)
    setTimeout(() => setCopied(null), 2000)
  }

  useEffect(() => {
    const savedSecret = localStorage.getItem('admin_secret')
    if (savedSecret) {
      setAdminSecret(savedSecret)
      setIsAuthenticated(true)
      fetchData()
    }
  }, [])

  // Login Screen
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="w-full max-w-md p-8 rounded-2xl bg-card border border-border"
        >
          <div className="text-center mb-8">
            <div className="inline-flex p-4 rounded-2xl bg-primary/20 mb-4">
              <Lock className="w-8 h-8 text-primary" />
            </div>
            <h1 className="text-2xl font-bold">Admin Access</h1>
            <p className="text-muted-foreground mt-2">Enter admin secret to continue</p>
          </div>

          {error && (
            <div className="flex items-center gap-2 p-3 mb-4 rounded-lg bg-destructive/20 text-destructive">
              <AlertCircle size={18} />
              <span className="text-sm">{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">Admin Secret</label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <input
                  type="password"
                  value={adminSecret}
                  onChange={(e) => setAdminSecret(e.target.value)}
                  placeholder="Enter admin secret"
                  required
                  className="w-full pl-10 pr-4 py-3 rounded-lg bg-secondary border border-border focus:outline-none focus:ring-2 focus:ring-primary/50"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : 'Access Admin Panel'}
            </button>
          </form>
        </motion.div>
      </div>
    )
  }

  // Admin Dashboard
  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Shield className="w-8 h-8 text-primary" />
              Admin Panel
            </h1>
            <p className="text-muted-foreground mt-1">Manage product keys and subscriptions</p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={fetchData}
              className="px-4 py-2 rounded-lg bg-secondary hover:bg-secondary/80 flex items-center gap-2"
            >
              <RefreshCw size={18} />
              Refresh
            </button>
            <button
              onClick={() => {
                localStorage.removeItem('admin_secret')
                setIsAuthenticated(false)
              }}
              className="px-4 py-2 rounded-lg bg-destructive/20 text-destructive hover:bg-destructive/30"
            >
              Logout
            </button>
          </div>
        </div>

        {/* Messages */}
        {success && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-2 p-4 rounded-lg bg-green-500/20 text-green-500"
          >
            <CheckCircle size={18} />
            <span>{success}</span>
          </motion.div>
        )}

        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-2 p-4 rounded-lg bg-destructive/20 text-destructive"
          >
            <AlertCircle size={18} />
            <span>{error}</span>
          </motion.div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl bg-card border border-border">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-lg bg-primary/20">
                <Key className="w-6 h-6 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">{productKeys.length}</p>
                <p className="text-sm text-muted-foreground">Total Keys</p>
              </div>
            </div>
          </div>
          <div className="p-6 rounded-xl bg-card border border-border">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-lg bg-green-500/20">
                <Users className="w-6 h-6 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{activatedKeys.length}</p>
                <p className="text-sm text-muted-foreground">Active Subscriptions</p>
              </div>
            </div>
          </div>
          <div className="p-6 rounded-xl bg-card border border-border">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-lg bg-yellow-500/20">
                <Key className="w-6 h-6 text-yellow-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{productKeys.filter(k => !k.used).length}</p>
                <p className="text-sm text-muted-foreground">Available Keys</p>
              </div>
            </div>
          </div>
        </div>

        {/* Generate Key */}
        <div className="p-6 rounded-xl bg-card border border-border">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Plus size={20} />
            Generate New Product Key
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Subscription Type</label>
              <select
                value={subscriptionType}
                onChange={(e) => setSubscriptionType(e.target.value)}
                className="w-full px-4 py-3 rounded-lg bg-secondary border border-border focus:outline-none focus:ring-2 focus:ring-primary/50"
              >
                <option value="individual">Individual</option>
                <option value="enterprise">Enterprise</option>
                <option value="academic">Academic</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">Validity (Days)</label>
              <input
                type="number"
                value={validityDays}
                onChange={(e) => setValidityDays(parseInt(e.target.value))}
                min={1}
                max={3650}
                className="w-full px-4 py-3 rounded-lg bg-secondary border border-border focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>

            <div className="flex items-end">
              <button
                onClick={generateKey}
                disabled={loading}
                className="w-full py-3 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Key size={18} />}
                Generate Key
              </button>
            </div>
          </div>

          {generatedKey && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-4 p-4 rounded-lg bg-green-500/20 border border-green-500/30"
            >
              <p className="text-sm text-green-500 mb-2">Generated Key:</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-lg font-mono text-green-400">{generatedKey}</code>
                <button
                  onClick={() => copyToClipboard(generatedKey)}
                  className="p-2 rounded hover:bg-green-500/20"
                >
                  {copied === generatedKey ? <Check size={18} className="text-green-500" /> : <Copy size={18} />}
                </button>
              </div>
            </motion.div>
          )}
        </div>

        {/* Product Keys Table */}
        <div className="p-6 rounded-xl bg-card border border-border">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Key size={20} />
            Product Keys
          </h2>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Key</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Type</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Validity</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Status</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {productKeys.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-muted-foreground">
                      No product keys found. Generate one above!
                    </td>
                  </tr>
                ) : (
                  productKeys.map((key) => (
                    <tr key={key.key} className="border-b border-border/50 hover:bg-secondary/50">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <code className="text-sm font-mono">{key.key}</code>
                          <button
                            onClick={() => copyToClipboard(key.key)}
                            className="p-1 rounded hover:bg-primary/20"
                          >
                            {copied === key.key ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
                          </button>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-1 rounded-full text-xs bg-primary/20 text-primary">
                          {key.subscription_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm">{key.validity_days} days</td>
                      <td className="py-3 px-4">
                        {key.used ? (
                          <span className="px-2 py-1 rounded-full text-xs bg-yellow-500/20 text-yellow-500">
                            Used by {key.used_by}
                          </span>
                        ) : (
                          <span className="px-2 py-1 rounded-full text-xs bg-green-500/20 text-green-500">
                            Available
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <button
                          onClick={() => revokeKey(key.key)}
                          className="p-2 rounded hover:bg-destructive/20 text-destructive"
                          title="Revoke Key"
                        >
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Active Subscriptions */}
        <div className="p-6 rounded-xl bg-card border border-border">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Users size={20} />
            Active Subscriptions
          </h2>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Email</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Type</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Activated</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-muted-foreground">Expires</th>
                </tr>
              </thead>
              <tbody>
                {activatedKeys.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-muted-foreground">
                      No active subscriptions yet.
                    </td>
                  </tr>
                ) : (
                  activatedKeys.map((activation) => (
                    <tr key={activation.email} className="border-b border-border/50 hover:bg-secondary/50">
                      <td className="py-3 px-4 font-medium">{activation.email}</td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-1 rounded-full text-xs bg-primary/20 text-primary">
                          {activation.subscription_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm">
                        {new Date(activation.activated_at).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-4 text-sm">
                        {new Date(activation.expires_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
