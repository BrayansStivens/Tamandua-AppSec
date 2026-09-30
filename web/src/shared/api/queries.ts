// Consultas compartidas (TanStack Query): una clave y una forma de pedir cada recurso, para que dos vistas que
// muestran lo mismo compartan caché y una mutación sepa qué invalidar.
import { infiniteQueryOptions, queryOptions } from '@tanstack/react-query'
import { api, query } from '@/shared/api/http'
import { apiGet, type Response } from '@/shared/api/client'
import type { Dashboard, Page, RunRow } from '@/shared/lib/types'

export const keys = {
  runs: ['runs'] as const,
  run: (id: string) => ['runs', id] as const,
  dashboard: (days: number, tz?: string) => ['dashboard', days, tz] as const,
  sla: ['sla'] as const,
  cra: ['cra'] as const,
  craOverview: ['cra', 'overview'] as const,
  craAssets: ['cra', 'assets'] as const,
  craPolicy: ['cra-policy'] as const,
  evidence: ['evidence'] as const,
  evidenceAssets: ['evidence', 'assets'] as const,
  secretRules: ['secret-rules'] as const,
  secretBuiltinRules: ['secret-rules', 'builtin'] as const,
  assetSecretsAll: ['secret-rules', 'asset'] as const,
  assetSecrets: (key: string) => ['secret-rules', 'asset', key] as const,
  exclusions: (key: string) => ['exclusions', key] as const,
  asset: (key: string) => ['assets', 'one', key] as const,
  jira: ['jira'] as const,
  jiraRouting: ['jira', 'routing'] as const,
  jiraBackfill: ['jira', 'backfill'] as const,
  jiraVariables: ['jira', 'variables'] as const,
  jiraProjects: (q: string) => ['jira', 'projects', q] as const,
  jiraIssueTypes: (project: string) => ['jira', 'issue-types', project] as const,
  jiraFields: (project: string, issueType: string) => ['jira', 'fields', project, issueType] as const,
  jiraFieldValues: (project: string, issueType: string, field: string, q: string) => ['jira', 'fields', project, issueType, field, q] as const,
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
// Whether the workspace sells products in the EU: without it, no CRA UI anywhere.
export const craPolicyQuery = () => queryOptions({ queryKey: keys.craPolicy, queryFn: ({ signal }) => apiGet('/api/policies/cra', undefined, { signal }), staleTime: 60_000 })
export const evidenceQuery = () => queryOptions({ queryKey: keys.evidence, queryFn: ({ signal }) => apiGet('/api/evidence', undefined, { signal }) })
// Analyzed assets for the evidence hub's picker, searched by name on the server.
export const evidenceAssetsQuery = (q: string) => queryOptions({
  queryKey: [...keys.evidenceAssets, q], staleTime: 30_000,
  queryFn: ({ signal }) => apiGet('/api/evidence/assets', { q: q || undefined, limit: 20 }, { signal }),
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

// One asset by key (its name for pickers and summaries that only store keys).
export type AssetSummary = { key: string; name: string; removed_at: string | null }
export const assetQuery = (key: string) => queryOptions({
  queryKey: keys.asset(key), staleTime: 5 * 60_000,
  queryFn: async ({ signal }) => (await api.get<Page<AssetSummary>>(`/api/assets?${query({ key, limit: 1 })}`, { signal })).items[0] ?? null,
})

// Jira: the credential's status is anyone's; routing and discovery are for administrators.
export type JiraStatus = Response<'/api/integrations/jira'>
export type JiraRouting = Response<'/api/integrations/jira/routing'>
export type JiraFields = Response<'/api/integrations/jira/projects/{project}/issue-types/{issue_type}/fields'>
export type JiraIssueTypes = Response<'/api/integrations/jira/projects/{project}/issue-types'>
export type JiraFieldValues = Response<'/api/integrations/jira/projects/{project}/issue-types/{issue_type}/fields/{field}/values'>
export const jiraStatusQuery = () => queryOptions({ queryKey: keys.jira, queryFn: ({ signal }) => apiGet('/api/integrations/jira', undefined, { signal }) })
export const jiraRoutingQuery = () => queryOptions({ queryKey: keys.jiraRouting, queryFn: ({ signal }) => apiGet('/api/integrations/jira/routing', undefined, { signal }) })
export const jiraVariablesQuery = () => queryOptions({
  queryKey: keys.jiraVariables, staleTime: Infinity, queryFn: ({ signal }) => apiGet('/api/integrations/jira/variables', undefined, { signal }),
})
// Backfills are polled only while one still has issues in the queue.
export const jiraBackfillQuery = () => queryOptions({
  queryKey: keys.jiraBackfill, queryFn: ({ signal }) => apiGet('/api/integrations/jira/backfill', undefined, { signal }),
  refetchInterval: query => (query.state.data?.items ?? []).some(item => item.pending > 0) ? 5000 : false,
})
// Projects by name or key, a page at a time (a Jira site may have thousands).
export const jiraProjectsQuery = (q: string) => infiniteQueryOptions({
  queryKey: keys.jiraProjects(q), staleTime: 60_000, initialPageParam: 0,
  queryFn: ({ signal, pageParam }) => apiGet('/api/integrations/jira/projects', { q: q || undefined, start: pageParam, limit: 50 }, { signal }),
  getNextPageParam: last => last.last || !last.items.length ? undefined : last.start + last.items.length,
})
export const jiraIssueTypesQuery = (project: string) => queryOptions({
  queryKey: keys.jiraIssueTypes(project), staleTime: 60_000,
  queryFn: ({ signal }) => api.get<JiraIssueTypes>(`/api/integrations/jira/projects/${encodeURIComponent(project)}/issue-types`, { signal }),
})
export const jiraFieldsQuery = (project: string, issueType: string) => queryOptions({
  queryKey: keys.jiraFields(project, issueType), staleTime: 60_000,
  queryFn: ({ signal }) => api.get<JiraFields>(`/api/integrations/jira/projects/${encodeURIComponent(project)}/issue-types/${encodeURIComponent(issueType)}/fields`, { signal }),
})
// One field's allowed values by name, for fields with more of them than /fields carries.
export const jiraFieldValuesQuery = (project: string, issueType: string, field: string, q: string) => queryOptions({
  queryKey: keys.jiraFieldValues(project, issueType, field, q), staleTime: 60_000,
  queryFn: ({ signal }) => api.get<JiraFieldValues>(`/api/integrations/jira/projects/${encodeURIComponent(project)}/issue-types/${encodeURIComponent(issueType)}/fields/${encodeURIComponent(field)}/values?${query({ q, limit: 50 })}`, { signal }),
})
