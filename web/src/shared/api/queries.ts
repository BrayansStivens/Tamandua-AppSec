// Consultas compartidas (TanStack Query): una clave y una forma de pedir cada recurso, para que dos vistas que
// muestran lo mismo compartan caché y una mutación sepa qué invalidar.
import { queryOptions } from '@tanstack/react-query'
import { api, query } from '@/shared/api/http'
import { apiGet } from '@/shared/api/client'
import type { Dashboard, RunRow } from '@/shared/lib/types'

export const keys = {
  runs: ['runs'] as const,
  run: (id: string) => ['runs', id] as const,
  dashboard: (days: number, tz?: string) => ['dashboard', days, tz] as const,
  sla: ['sla'] as const,
  cra: ['cra'] as const,
  craOverview: ['cra', 'overview'] as const,
  craAssets: ['cra', 'assets'] as const,
  secretRules: ['secret-rules'] as const,
  secretBuiltinRules: ['secret-rules', 'builtin'] as const,
  assetSecretsAll: ['secret-rules', 'asset'] as const,
  assetSecrets: (key: string) => ['secret-rules', 'asset', key] as const,
  exclusions: (key: string) => ['exclusions', key] as const,
}

const active = (status?: string) => status === 'queued' || status === 'running'

export const runsQuery = () => queryOptions({
  queryKey: keys.runs,
  queryFn: ({ signal }) => api.get<RunRow[]>('/api/runs', { signal }),
  // Mientras algo esté en cola o corriendo, se sondea; si no, no (antes: un setInterval fijo por vista).
  refetchInterval: query => (query.state.data ?? []).some(row => active(row.status)) ? 3000 : false,
})

export const runQuery = <T extends { status: string }>(id: string) => queryOptions({
  queryKey: keys.run(id),
  queryFn: ({ signal }) => api.get<T>(`/api/runs/${encodeURIComponent(id)}`, { signal }),
  refetchInterval: query => active(query.state.data?.status) ? 2000 : false,
})

export const slaQuery = () => queryOptions({ queryKey: keys.sla, queryFn: ({ signal }) => apiGet('/api/sla', undefined, { signal }) })
export const craQuery = () => queryOptions({ queryKey: keys.craOverview, queryFn: ({ signal }) => apiGet('/api/cra', undefined, { signal }) })
// Assets that can still be marked as CRA products, searched by name (the picker shows the first matches).
export const craAssetsQuery = (q: string) => queryOptions({
  queryKey: [...keys.craAssets, q], staleTime: 30_000,
  queryFn: ({ signal }) => apiGet('/api/cra/assets', { q: q || undefined, limit: 20 }, { signal }),
})
export const secretRulesQuery = () => queryOptions({ queryKey: keys.secretRules, queryFn: ({ signal }) => apiGet('/api/secrets/config', undefined, { signal }) })
// The built-in rule list only changes with the pinned Gitleaks image.
// A repository's excluded paths (table route: typed here by hand).
export type Exclusions = { patterns: string[]; reason: string | null; by: string | null; at: string | null }
export const exclusionsQuery = (key: string) => queryOptions({
  queryKey: keys.exclusions(key), queryFn: ({ signal }) => api.get<Exclusions>(`/api/assets/exclusions?${query({ key })}`, { signal }),
})
// A repository's own secret detection entries, added to the defaults in its scans.
export const assetSecretsQuery = (key: string) => queryOptions({
  queryKey: keys.assetSecrets(key), queryFn: ({ signal }) => apiGet('/api/assets/secrets', { key }, { signal }),
})
export const secretBuiltinRulesQuery = () => queryOptions({
  queryKey: keys.secretBuiltinRules, staleTime: Infinity,
  queryFn: ({ signal }) => apiGet('/api/secrets/builtin-rules', undefined, { signal }),
})
export const dashboardQuery = (days: number, tz?: string) => queryOptions({
  queryKey: keys.dashboard(days, tz),
  queryFn: ({ signal }) => api.get<Dashboard>(`/api/dashboard?${query({ days, tz })}`, { signal }),
})
