import { useEffect, useRef } from 'react'
import { useQuery, type QueryClient } from '@tanstack/react-query'
import { api } from '@/shared/api/http'
import type { PostBody } from '@/shared/api/client'
import { jiraBatchesQuery, keys, type JiraBatches, type JiraQueued } from '@/shared/api/queries'

export type JiraQueueBody = PostBody<'/api/integrations/jira/issues/queue'>
export type JiraSelectionBody = JiraQueueBody['selections'][number]

// Batches queued from this tab and not announced yet: the shell says they started whenever it first sees them, whether
// or not it had read my batches before (so the toast never depends on which request came first).
export const toAnnounce = new Set<string>()

// Queues a selection (with `force`, new issues even for findings that already have one) and adds the batch to the
// background work, which starts following it at once.
export async function queueJira(client: QueryClient, selections: JiraSelectionBody[], force = false): Promise<JiraQueued> {
  const body: JiraQueueBody = force ? { selections, force: true } : { selections }
  const queued = await api.post<JiraQueued>('/api/integrations/jira/issues/queue', 'export-jira', body)
  toAnnounce.add(queued.batch)
  client.setQueryData<JiraBatches>(keys.jiraBatches, previous => ({ ...previous, items: [queued, ...(previous?.items ?? []).filter(item => item.batch !== queued.batch)] }))
  return queued
}

// Findings already linked, grouped by asset: the selections of a "create anyway".
export function byAsset(items: { fingerprint: string; asset?: string | null }[]): JiraSelectionBody[] {
  const groups = new Map<string, string[]>()
  for (const item of items) if (item.asset) groups.set(item.asset, [...(groups.get(item.asset) ?? []), item.fingerprint])
  return [...groups.entries()].map(([asset, fingerprints]) => ({ asset, fingerprints }))
}

// Calls `onSettled` each time one of my queued batches finishes (not for those already finished when it mounts).
export function useJiraSettled(onSettled: (batch: JiraQueued) => void) {
  const items = useQuery(jiraBatchesQuery()).data?.items
  const pending = useRef<Set<string> | null>(null)
  const callback = useRef(onSettled)
  useEffect(() => { callback.current = onSettled })
  useEffect(() => {
    if (!items) return
    const before = pending.current
    pending.current = new Set(items.filter(item => item.pending > 0).map(item => item.batch))
    if (before) for (const item of items) if (before.has(item.batch) && item.pending === 0) callback.current(item)
  }, [items])
}
