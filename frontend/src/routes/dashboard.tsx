import { useQuery } from '@tanstack/react-query'
import { Link, createFileRoute } from '@tanstack/react-router'
import { healthApi, cveApi } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { motion } from 'framer-motion'
import {
  Shield,
  Target,
  Network,
  Activity,
  CheckCircle,
  XCircle,
  ArrowRight,
  Cpu,
  Zap,
  Lock,
} from 'lucide-react'

export const Route = createFileRoute('/dashboard')({
  component: DashboardPage,
})

function DashboardPage() {
  const { user } = useAuthStore()

  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: healthApi.check,
    refetchInterval: 30000,
  })

  const modelQuery = useQuery({
    queryKey: ['model-info'],
    queryFn: cveApi.getModelInfo,
  })

  const cards = [
    {
      title: 'Classify CVE',
      description: 'Analyze CVE severity using AI',
      icon: Target,
      to: '/classify',
      color: 'from-blue-600 to-blue-400',
    },
    {
      title: 'Attack Paths',
      description: 'Visualize network vulnerabilities',
      icon: Network,
      to: '/attack-paths',
      color: 'from-purple-600 to-purple-400',
    },
    {
      title: 'Settings',
      description: 'Manage your account & 2FA',
      icon: Lock,
      to: '/settings',
      color: 'from-green-600 to-green-400',
    },
  ]

  const stats = [
    {
      label: 'Severity Model',
      value: '0.73',
      subtext: 'Macro-F1 (held-out)',
      icon: Zap,
    },
    {
      label: 'CVE Classes',
      value: '4',
      subtext: 'CRITICAL, HIGH, MEDIUM, LOW',
      icon: Target,
    },
    {
      label: 'Inference Speed',
      value: '<50ms',
      subtext: 'Per prediction',
      icon: Cpu,
    },
  ]

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-bold">
          Welcome back, {user?.name?.split(' ')[0]}! 👋
        </h1>
        <p className="text-muted-foreground mt-2">
          Here's an overview of your CTPPO security dashboard
        </p>
      </motion.div>

      {/* Status Banner */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className={`flex items-center gap-4 p-4 rounded-xl ${
          healthQuery.data?.status === 'healthy'
            ? 'bg-green-500/10 border border-green-500/30'
            : 'bg-yellow-500/10 border border-yellow-500/30'
        }`}
      >
        {healthQuery.data?.status === 'healthy' ? (
          <>
            <CheckCircle className="w-6 h-6 text-green-500" />
            <div>
              <p className="font-medium">All Systems Operational</p>
              <p className="text-sm text-muted-foreground">
                Model loaded on {healthQuery.data?.device} • API responding normally
              </p>
            </div>
          </>
        ) : (
          <>
            <XCircle className="w-6 h-6 text-yellow-500" />
            <div>
              <p className="font-medium">System Status Unknown</p>
              <p className="text-sm text-muted-foreground">
                Checking connection to backend...
              </p>
            </div>
          </>
        )}
      </motion.div>

      {/* Quick Actions */}
      <div className="grid md:grid-cols-3 gap-6">
        {cards.map((card, index) => (
          <motion.div
            key={card.to}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 + index * 0.1 }}
          >
            <Link
              to={card.to}
              className="block p-6 rounded-xl bg-card border border-border hover:border-primary/50 
                transition-all hover:shadow-lg hover:shadow-primary/10 group"
            >
              <div className={`inline-flex p-3 rounded-lg bg-gradient-to-br ${card.color} mb-4`}>
                <card.icon className="w-6 h-6 text-white" />
              </div>
              <h3 className="text-lg font-semibold mb-2 flex items-center gap-2">
                {card.title}
                <ArrowRight className="w-4 h-4 opacity-0 -translate-x-2 group-hover:opacity-100 
                  group-hover:translate-x-0 transition-all" />
              </h3>
              <p className="text-muted-foreground">{card.description}</p>
            </Link>
          </motion.div>
        ))}
      </div>

      {/* Stats */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="grid md:grid-cols-3 gap-6"
      >
        {stats.map((stat, index) => (
          <div
            key={stat.label}
            className="p-6 rounded-xl bg-card border border-border"
          >
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-lg bg-primary/20">
                <stat.icon className="w-5 h-5 text-primary" />
              </div>
              <span className="text-sm text-muted-foreground">{stat.label}</span>
            </div>
            <p className="text-3xl font-bold">{stat.value}</p>
            <p className="text-sm text-muted-foreground mt-1">{stat.subtext}</p>
          </div>
        ))}
      </motion.div>

      {/* Model Info */}
      {modelQuery.data && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="p-6 rounded-xl bg-card border border-border"
        >
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5" />
            Model Information
          </h2>
          <div className="grid md:grid-cols-4 gap-4">
            <div>
              <p className="text-sm text-muted-foreground">Status</p>
              <p className="font-medium flex items-center gap-2">
                {modelQuery.data.loaded ? (
                  <>
                    <span className="w-2 h-2 rounded-full bg-green-500" />
                    Loaded
                  </>
                ) : (
                  <>
                    <span className="w-2 h-2 rounded-full bg-red-500" />
                    Not Loaded
                  </>
                )}
              </p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Device</p>
              <p className="font-medium uppercase">{modelQuery.data.device}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Test F1 Score</p>
              <p className="font-medium text-green-500">{modelQuery.data.test_f1}</p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Security Badge */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="flex items-center justify-center gap-4 p-6 rounded-xl bg-gradient-to-r 
          from-primary/10 via-primary/5 to-transparent border border-primary/20"
      >
        <Shield className="w-10 h-10 text-primary" />
        <div>
          <p className="font-semibold">Your account is {user?.is_2fa_enabled ? 'fully' : 'partially'} secured</p>
          <p className="text-sm text-muted-foreground">
            {user?.is_2fa_enabled 
              ? '2FA is enabled. Your account has maximum protection.'
              : 'Enable 2FA in settings for enhanced security.'}
          </p>
        </div>
        {!user?.is_2fa_enabled && (
          <Link
            to="/settings"
            className="ml-auto px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium"
          >
            Enable 2FA
          </Link>
        )}
      </motion.div>
    </div>
  )
}
