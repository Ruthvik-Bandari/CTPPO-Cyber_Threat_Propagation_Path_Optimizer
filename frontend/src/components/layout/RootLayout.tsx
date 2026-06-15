import { Outlet } from '@tanstack/react-router'

/*
 * Root shell. Per-area chrome (nav, footer, dashboard sidebar) is composed inside the
 * individual routes.
 */
export default function RootLayout() {
  return (
    <div className="min-h-screen bg-base text-fg antialiased">
      <Outlet />
    </div>
  )
}
