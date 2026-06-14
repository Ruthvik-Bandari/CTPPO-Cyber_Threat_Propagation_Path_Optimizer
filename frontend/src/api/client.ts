/*
 * CTPPO API client (Phase B / B6).
 *
 * Session-cookie based: the backend issues an HttpOnly `ctppo_session` cookie (B1), so the
 * browser sends it automatically with `credentials: 'include'`. We never read or store a
 * token in JS — that keeps the credential out of reach of any XSS. Identity is rehydrated
 * via /api/auth/me on load. No Authorization header, no refresh dance.
 */

const API_BASE = import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api` : '/api'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

async function request<T>(method: string, endpoint: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method,
    credentials: 'include',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (!res.ok) {
    let detail = `Request failed (${res.status})`
    try {
      const data = await res.json()
      detail = typeof data === 'string' ? data : (data?.detail ?? data?.message ?? detail)
    } catch {
      /* response had no JSON body */
    }
    throw new ApiError(res.status, String(detail))
  }

  if (res.status === 204) return undefined as T
  const text = await res.text()
  return (text ? JSON.parse(text) : undefined) as T
}

const get = <T>(endpoint: string) => request<T>('GET', endpoint)
const post = <T>(endpoint: string, body?: unknown) => request<T>('POST', endpoint, body)
const put = <T>(endpoint: string, body?: unknown) => request<T>('PUT', endpoint, body)
const del = <T>(endpoint: string) => request<T>('DELETE', endpoint)

// ============================================================================
// Shared types (mirror the backend store shapes)
// ============================================================================

export interface User {
  id?: string
  email: string
  name: string
  role?: string
  is_2fa_enabled?: boolean
  created_at?: string
}

export interface SubscriptionStatus {
  has_subscription: boolean
  is_owner: boolean
  status: string
  subscription_type?: string
  expires_at?: string | null
  days_remaining?: number
}

export interface ActivateResponse {
  success: boolean
  subscription_type?: string
  expires_at?: string | null
  days_remaining?: number
  is_owner?: boolean
  message?: string
}

export interface FileMeta {
  name: string
  size: number
  content_type?: string
  ext?: string
  scanned_at?: string
}

export interface Instance {
  id: string
  owner: string
  name: string
  prompt: string
  target_spec: Record<string, unknown>
  files: FileMeta[]
  status: string
  created_at: string
  updated_at: string
}

export interface OrgMember {
  email: string
  role: string
}

export interface Org {
  id: string
  name: string
  seats: number
  members: Record<string, string>
  created_at: string
}

export interface ApiKeyMeta {
  id: string
  name: string
  prefix: string
  created_at: string
  last_used_at: string | null
}

export interface IssuedKey {
  api_key: string
  id: string
  name: string
  prefix: string
  note: string
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export interface ClassifyResponse {
  cve_id: string | null
  predicted_severity: string
  confidence: number
  probabilities: Record<string, number>
  processing_time_ms: number
}

export interface ModelInfo {
  loaded: boolean
  device: string
  classes: string[]
  test_f1: number | null
}

export interface AttackPathNode {
  id: string
  is_entry_point: boolean
  is_critical_asset: boolean
}

export interface AttackPathVuln {
  cve_id: string
  source: string
  target: string
  severity?: string
  cvss_score?: number
  exploitability_score?: number
  impact_score?: number
  has_exploit?: boolean
}

export interface AttackPathRequest {
  nodes: AttackPathNode[]
  vulnerabilities: AttackPathVuln[]
  max_depth?: number
}

export interface ParetoPath {
  path: string[]
  cost: Record<string, number>
}

export interface AttackPathResponse {
  paths: { pareto_optimal: ParetoPath[] }
  risk_summary: Record<string, number | string>
  processing_time_ms: number
}

export interface SampleAttackPathResponse extends AttackPathResponse {
  network: { nodes: number; edges: number }
}

// ============================================================================
// API groups
// ============================================================================

export const authApi = {
  signup: (email: string, password: string, name: string) =>
    post<{ user: User }>('/auth/signup', { email, password, name }),
  login: (email: string, password: string) =>
    post<{ user: User }>('/auth/login', { email, password }),
  logout: () => post<{ ok: boolean; revoked: boolean }>('/auth/logout'),
  me: () => get<{ user: User }>('/auth/me'),
  whoami: () => get<{ user: User }>('/auth/whoami'),
  forgotPassword: (email: string) =>
    post<{ message: string; dev_reset_token?: string }>('/auth/forgot-password', { email }),
  resetPassword: (token: string, newPassword: string) =>
    post<{ ok: boolean }>('/auth/reset-password', { token, new_password: newPassword }),
}

export const subscriptionApi = {
  status: () => get<SubscriptionStatus>('/subscription/status'),
  activate: (productKey: string) =>
    post<ActivateResponse>('/subscription/activate', { product_key: productKey }),
}

export const instanceApi = {
  list: () => get<{ instances: Instance[] }>('/instances'),
  get: (id: string) => get<Instance>(`/instances/${id}`),
  create: (body: { name: string; prompt?: string; target_spec?: Record<string, unknown>; files?: FileMeta[] }) =>
    post<Instance>('/instances', body),
  update: (id: string, body: Partial<{ name: string; prompt: string; target_spec: Record<string, unknown>; files: FileMeta[]; status: string }>) =>
    put<Instance>(`/instances/${id}`, body),
  remove: (id: string) => del<{ ok: boolean }>(`/instances/${id}`),
}

export const orgApi = {
  me: () => get<{ org: Org | null; role: string | null }>('/orgs/me'),
  create: (name: string, seats: number) => post<Org>('/orgs', { name, seats }),
  listMembers: (orgId: string) => get<{ members: OrgMember[] }>(`/orgs/${orgId}/members`),
  addMember: (orgId: string, email: string, role: string) =>
    post<Org>(`/orgs/${orgId}/members`, { email, role }),
  setRole: (orgId: string, email: string, role: string) =>
    put<Org>(`/orgs/${orgId}/members/${encodeURIComponent(email)}`, { role }),
  removeMember: (orgId: string, email: string) =>
    del<{ ok: boolean }>(`/orgs/${orgId}/members/${encodeURIComponent(email)}`),
}

export const keyApi = {
  list: () => get<{ keys: ApiKeyMeta[] }>('/keys'),
  issue: (name: string) => post<IssuedKey>('/keys', { name }),
  revoke: (id: string) => del<{ ok: boolean }>(`/keys/${id}`),
}

export const classifyApi = {
  classify: (description: string, cveId?: string) =>
    post<ClassifyResponse>('/classify', { description, cve_id: cveId }),
  modelInfo: () => get<ModelInfo>('/model/info'),
}

export const attackPathApi = {
  analyze: (req: AttackPathRequest) => post<AttackPathResponse>('/attack-paths/analyze', req),
  sample: () => get<SampleAttackPathResponse>('/attack-paths/sample'),
}

export const healthApi = {
  check: () => get<{ status?: string }>('/health'),
}
