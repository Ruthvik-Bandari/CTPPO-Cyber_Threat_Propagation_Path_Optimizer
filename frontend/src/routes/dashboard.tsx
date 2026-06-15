import { createFileRoute } from '@tanstack/react-router'
import { DashboardShell } from '@/components/dashboard/DashboardShell'

export const Route = createFileRoute('/dashboard')({
  component: DashboardShell,
})
