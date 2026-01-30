import { useAuthStore } from '@/stores/auth'

const API_BASE = '/api'

interface FetchOptions extends RequestInit {
  requiresAuth?: boolean
}

class ApiClient {
  private getHeaders(requiresAuth: boolean = true): HeadersInit {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    }
    
    if (requiresAuth) {
      const token = useAuthStore.getState().accessToken
      if (token) {
        headers['Authorization'] = `Bearer ${token}`
      }
    }
    
    return headers
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    if (response.status === 401) {
      // Try to refresh token
      const refreshed = await this.refreshToken()
      if (!refreshed) {
        useAuthStore.getState().logout()
        throw new Error('Session expired. Please login again.')
      }
    }
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
      // Handle different error formats
      const message = typeof error === 'string' 
        ? error 
        : error.detail || error.message || JSON.stringify(error)
      throw new Error(message)
    }
    
    return response.json()
  }

  private async refreshToken(): Promise<boolean> {
    const { refreshToken, setTokens, logout } = useAuthStore.getState()
    
    if (!refreshToken) return false
    
    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      })
      
      if (!response.ok) {
        logout()
        return false
      }
      
      const data = await response.json()
      setTokens(data.access_token, data.refresh_token)
      return true
    } catch {
      logout()
      return false
    }
  }

  async get<T>(endpoint: string, options: FetchOptions = {}): Promise<T> {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'GET',
      headers: this.getHeaders(options.requiresAuth !== false),
      ...options,
    })
    return this.handleResponse<T>(response)
  }

  async post<T>(endpoint: string, data?: unknown, options: FetchOptions = {}): Promise<T> {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: this.getHeaders(options.requiresAuth !== false),
      body: data ? JSON.stringify(data) : undefined,
      ...options,
    })
    return this.handleResponse<T>(response)
  }

  // Form data for OAuth login
  async postForm<T>(endpoint: string, data: URLSearchParams): Promise<T> {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: data,
    })
    return this.handleResponse<T>(response)
  }
}

export const apiClient = new ApiClient()

// ============================================================================
// AUTH API
// ============================================================================

export interface LoginResponse {
  access_token?: string
  refresh_token?: string
  token_type?: string
  requires_2fa?: boolean
  temp_token?: string
  message?: string
  user?: User
}

export interface User {
  id?: number
  email: string
  name: string
  role?: string
  is_2fa_enabled: boolean
  created_at?: string
}

export interface Setup2FAResponse {
  secret: string
  qr_code: string
  manual_entry_key: string
}

export const authApi = {
  login: async (email: string, password: string): Promise<LoginResponse> => {
    return apiClient.post('/auth/login', { 
      email, 
      password 
    }, { requiresAuth: false })
  },
  
  verify2FA: async (email: string, tempToken: string, code: string): Promise<LoginResponse> => {
    return apiClient.post('/auth/verify-2fa', { 
      email, 
      temp_token: tempToken, 
      totp_code: code 
    }, { requiresAuth: false })
  },
  
  register: async (email: string, password: string, fullName: string): Promise<User> => {
    return apiClient.post('/auth/register', { 
      email, 
      password, 
      name: fullName 
    }, { requiresAuth: false })
  },
  
  getMe: async (): Promise<User> => {
    return apiClient.get('/auth/me')
  },
  
  setup2FA: async (): Promise<Setup2FAResponse> => {
    return apiClient.post('/auth/setup-2fa')
  },
  
  confirm2FA: async (code: string): Promise<{ message: string }> => {
    return apiClient.post('/auth/enable-2fa', { code })
  },
  
  disable2FA: async (code: string): Promise<{ message: string }> => {
    return apiClient.post('/auth/disable-2fa', { code })
  },
}

// ============================================================================
// SCAN API (Real Vulnerability Scanning)
// ============================================================================

export interface ScanCapabilities {
  scanner_available: boolean
  nmap_available: boolean
  zap_available: boolean
  simple_scanner: boolean
}

export interface ScanRequest {
  target: string
  scan_type: 'quick' | 'full' | 'vuln'
  include_web_scan: boolean
}

export interface DiscoveredPort {
  number: number
  protocol: string
  state: string
  service: string
  version: string
  product: string
}

export interface DiscoveredHost {
  ip: string
  hostname: string
  mac: string
  os_guess: string
  ports: DiscoveredPort[]
  status: string
}

export interface WebVulnerability {
  alert: string
  risk: string
  confidence: string
  url: string
  description: string
  solution: string
  cwe_id?: number
}

export interface ScanResult {
  target: string
  scan_type: string
  started_at: string
  completed_at: string
  hosts: DiscoveredHost[]
  web_vulnerabilities: WebVulnerability[]
  cve_matches: any[]
  risk_summary: {
    risk_level: string
    total_hosts: number
    total_open_ports: number
    vulnerabilities: {
      high: number
      medium: number
      low: number
      total: number
    }
    recommendation: string
  }
  processing_time_ms: number
  scanner_used: string
}

export const scanApi = {
  getCapabilities: async (): Promise<ScanCapabilities> => {
    return apiClient.get('/scan/capabilities')
  },
  
  scanTarget: async (request: ScanRequest): Promise<ScanResult> => {
    return apiClient.post('/scan/target', request)
  },
  
  quickScan: async (target: string): Promise<ScanResult> => {
    return apiClient.post('/scan/quick', null, {
      headers: { 'Content-Type': 'application/json' }
    })
  },
}

// ============================================================================
// CVE API
// ============================================================================

export interface CVSSVector {
  attackVector: string
  attackComplexity: string
  privilegesRequired: string
  userInteraction: string
  scope: string
  confidentialityImpact: string
  integrityImpact: string
  availabilityImpact: string
}

export interface CVEClassifyRequest {
  description: string
  cve_id?: string
  cvss_vector?: CVSSVector
  cvss_score?: number
  exploitability_score?: number
  impact_score?: number
  cwe_id?: string
  has_exploit?: boolean
  has_patch?: boolean
}

export interface CVEClassifyResponse {
  cve_id: string | null
  predicted_severity: string
  confidence: number
  probabilities: Record<string, number>
  processing_time_ms: number
}

export interface BatchClassifyResponse {
  results: CVEClassifyResponse[]
  total_time_ms: number
}

export const cveApi = {
  classify: async (request: CVEClassifyRequest): Promise<CVEClassifyResponse> => {
    return apiClient.post('/classify', request)
  },
  
  classifyBatch: async (cves: CVEClassifyRequest[]): Promise<BatchClassifyResponse> => {
    return apiClient.post('/classify/batch', { cves })
  },
  
  getModelInfo: async () => {
    return apiClient.get('/model/info')
  },
}

// ============================================================================
// ATTACK PATH API
// ============================================================================

export interface NetworkNode {
  id: string
  is_entry_point: boolean
  is_critical_asset: boolean
}

export interface NetworkVuln {
  cve_id: string
  source: string
  target: string
  severity: string
  cvss_score: number
  exploitability_score: number
  impact_score: number
  has_exploit: boolean
}

export interface AttackPathRequest {
  nodes: NetworkNode[]
  vulnerabilities: NetworkVuln[]
  max_depth?: number
}

export interface AttackPath {
  source: string
  target: string
  path_length: number
  total_cvss: number
  max_severity: string
  risk_score: number
  vulnerabilities: NetworkVuln[]
}

export interface RiskSummary {
  total_paths: number
  highest_risk_path: AttackPath | null
  critical_vulnerabilities: { cve_id: string; path_count: number }[]
  risk_level: string
  recommendation?: string
}

export interface AttackPathResponse {
  paths: Record<string, AttackPath[]>
  risk_summary: RiskSummary
  processing_time_ms: number
}

export interface SampleNetworkResponse extends AttackPathResponse {
  network: {
    nodes: string[]
    entry_points: string[]
    critical_assets: string[]
    edges: Record<string, unknown[]>
  }
}

export const attackPathApi = {
  analyze: async (request: AttackPathRequest): Promise<AttackPathResponse> => {
    return apiClient.post('/attack-paths/analyze', request)
  },
  
  getSample: async (): Promise<SampleNetworkResponse> => {
    return apiClient.get('/attack-paths/sample')
  },
}

// ============================================================================
// HEALTH API
// ============================================================================

export const healthApi = {
  check: async () => {
    return apiClient.get('/health', { requiresAuth: false })
  },
}

// ============================================================================
// SUBSCRIPTION API
// ============================================================================

export interface SubscriptionStatus {
  has_subscription: boolean
  is_owner: boolean
  status: string
  subscription_type?: string
  expires_at?: string
}

export const subscriptionApi = {
  check: async (email: string): Promise<SubscriptionStatus> => {
    return apiClient.post(`/subscription/check?email=${encodeURIComponent(email)}`, null, { requiresAuth: false })
  },
  
  activate: async (productKey: string, email: string): Promise<{ success: boolean; message: string }> => {
    return apiClient.post('/subscription/activate', { product_key: productKey, email }, { requiresAuth: false })
  },
}
