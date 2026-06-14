import { create } from 'zustand'
import { authApi, subscriptionApi, type User, type SubscriptionStatus } from '@/api/client'

/*
 * Session auth store.
 *
 * Holds the current user + subscription in memory only — nothing sensitive is persisted to
 * localStorage (the credential is an HttpOnly cookie the JS never sees). On app load we call
 * bootstrap() to rehydrate identity from the server.
 */

type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated'

interface AuthState {
  user: User | null
  subscription: SubscriptionStatus | null
  status: AuthStatus
  bootstrap: () => Promise<void>
  refreshSubscription: () => Promise<void>
  setUser: (user: User) => void
  logout: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  subscription: null,
  status: 'loading',

  bootstrap: async () => {
    try {
      const { user } = await authApi.me()
      set({ user, status: 'authenticated' })
      await get().refreshSubscription()
    } catch {
      set({ user: null, subscription: null, status: 'unauthenticated' })
    }
  },

  refreshSubscription: async () => {
    try {
      set({ subscription: await subscriptionApi.status() })
    } catch {
      set({ subscription: null })
    }
  },

  setUser: (user) => set({ user, status: 'authenticated' }),

  logout: async () => {
    try {
      await authApi.logout()
    } catch {
      /* even if the network call fails, drop local state */
    }
    set({ user: null, subscription: null, status: 'unauthenticated' })
  },
}))
