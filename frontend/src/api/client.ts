/*
 * CTPPO API client (open-source, local-first, no-auth).
 *
 * Calls the backend directly with no auth headers and no credentialed cookies. The base URL is
 * configurable via VITE_API_BASE (defaults to the same-origin `/api`, which the dev server
 * proxies to http://localhost:8000).
 */

const API_BASE = import.meta.env.VITE_API_BASE ?? '/api'

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
    credentials: 'omit',
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

export interface FileMeta {
  name: string
  size: number
  content_type?: string
  ext?: string
  scanned_at?: string
}

export interface Instance {
  id: string
  owner?: string
  name: string
  prompt: string
  target_spec: Record<string, unknown>
  files: FileMeta[]
  status: string
  created_at: string
  updated_at: string
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

export const instanceApi = {
  list: () => get<{ instances: Instance[] }>('/instances'),
  get: (id: string) => get<Instance>(`/instances/${id}`),
  create: (body: { name: string; prompt?: string; target_spec?: Record<string, unknown>; files?: FileMeta[] }) =>
    post<Instance>('/instances', body),
  update: (id: string, body: Partial<{ name: string; prompt: string; target_spec: Record<string, unknown>; files: FileMeta[]; status: string }>) =>
    put<Instance>(`/instances/${id}`, body),
  remove: (id: string) => del<{ ok: boolean }>(`/instances/${id}`),
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

// ---- Scanning (SimpleScanner always available; nmap/zap optional, degrade gracefully) ----

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

export interface ScanVuln {
  severity?: string
  name?: string
  alert?: string
  description?: string
  recommendation?: string
  solution?: string
  url?: string
  [k: string]: unknown
}

export interface ScanPort {
  number?: number
  port?: number
  service?: string
  state?: string
  product?: string
  version?: string
  [k: string]: unknown
}

export interface ScanHost {
  ip?: string
  hostname?: string
  os_guess?: string
  ports?: ScanPort[]
  is_cloud_hosted?: boolean
  [k: string]: unknown
}

export interface ScanResult {
  target: string
  scan_type: string
  started_at?: string
  completed_at?: string
  hosts?: ScanHost[]
  web_vulnerabilities?: ScanVuln[]
  risk_summary: {
    risk_level?: string
    total_hosts?: number
    total_open_ports?: number
    vulnerabilities?: { critical: number; high: number; medium: number; low: number; info?: number; total: number }
    recommendation?: string
    [k: string]: unknown
  }
  processing_time_ms?: number
  scanner_used?: string
  cloud_provider?: { detected?: boolean; name?: string; note?: string; warning?: string }
}

export const scanApi = {
  capabilities: () => get<ScanCapabilities>('/scan/capabilities'),
  scan: (req: ScanRequest) => post<ScanResult>('/scan/target', req),
}

export const healthApi = {
  check: () => get<{ status?: string }>('/health'),
}
