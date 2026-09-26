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
export const craQuery = () => queryOptions({ queryKey: keys.cra, queryFn: ({ signal }) => apiGet('/api/cra', undefined, { signal }) })
export const dashboardQuery = (days: number, tz?: string) => queryOptions({
  queryKey: keys.dashboard(days, tz),
  queryFn: ({ signal }) => api.get<Dashboard>(`/api/dashboard?${query({ days, tz })}`, { signal }),
})
