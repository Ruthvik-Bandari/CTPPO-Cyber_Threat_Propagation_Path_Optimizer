import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface User {
  id?: number
  email: string
  name: string
  role?: string
  is_2fa_enabled: boolean
  created_at?: string
}

interface AuthState {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  isLoading: boolean
  requires2FA: boolean
  tempToken: string | null
  
  // Actions
  setUser: (user: User) => void
  setTokens: (accessToken: string, refreshToken: string) => void
  setRequires2FA: (requires: boolean, tempToken?: string) => void
  logout: () => void
  setLoading: (loading: boolean) => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: true,
      requires2FA: false,
      tempToken: null,

      setUser: (user) => set({ user, isAuthenticated: true, isLoading: false }),
      
      setTokens: (accessToken, refreshToken) => set({ 
        accessToken, 
        refreshToken, 
        isAuthenticated: true,
        requires2FA: false,
        tempToken: null,
        isLoading: false 
      }),
      
      setRequires2FA: (requires, tempToken) => set({ 
        requires2FA: requires, 
        tempToken: tempToken || null,
        isLoading: false 
      }),
      
      logout: () => set({ 
        user: null, 
        accessToken: null, 
        refreshToken: null, 
        isAuthenticated: false,
        requires2FA: false,
        tempToken: null,
        isLoading: false 
      }),
      
      setLoading: (isLoading) => set({ isLoading }),
    }),
    {
      name: 'ctppo-auth',
      partialize: (state) => ({ 
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
      }),
    }
  )
)
