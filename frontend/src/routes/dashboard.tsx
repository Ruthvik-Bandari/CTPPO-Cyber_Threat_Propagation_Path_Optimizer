import { createFileRoute } from '@tanstack/react-router'
import { RequireAuth } from '@/components/auth/guards'
import { DashboardShell } from '@/components/dashboard/DashboardShell'

export const Route = createFileRoute('/dashboard')({
  component: () => (
    <RequireAuth>
      <DashboardShell />
    </RequireAuth>
  ),
})
