import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { api, query } from '@/shared/api/http'
import type { Page } from '@/shared/lib/types'

// Key prefix of every page of `path`: invalidating it refreshes whichever page is on screen.
export const pagedKey = (path: string) => ['paged', path] as const

// Server-side paging against an endpoint that answers { items, total, limit, offset }, cached with TanStack Query.
// The previous page stays on screen while the next one loads; new filters go back to the first page.
export function usePaged<T>(path: string, filters: Record<string, string | undefined>, size = 25, refreshKey = 0, enabled = true) {
  const key = JSON.stringify(filters)
  const [position, setPosition] = useState({ key, size, offset: 0 })
  const offset = position.key === key && position.size === size ? position.offset : 0
  const result = useQuery({
    queryKey: [...pagedKey(path), filters, size, offset, refreshKey],
    queryFn: ({ signal }) => api.get<Page<T>>(`${path}?${query({ ...filters, limit: size, offset })}`, { signal }),
    placeholderData: keepPreviousData,
    enabled,
  })
  const page = result.data ?? { items: [] as T[], total: 0, limit: size, offset }
  const pageCount = Math.max(1, Math.ceil(page.total / size))
  const last = (pageCount - 1) * size
  // A change elsewhere can leave this page past the end (the last item of the last page was removed): step back.
  if (!result.isPlaceholderData && result.data !== undefined && offset > 0 && offset >= result.data.total) setPosition({ key, size, offset: last })
  const move = (next: number) => setPosition({ key, size, offset: Math.max(0, Math.min(next, last)) })
  return { ...page, loading: result.isFetching, error: result.error ? (result.error instanceof Error ? result.error.message : String(result.error)) : null,
    reload: () => result.refetch(), pageIndex: Math.floor(offset / size), pageCount, next: () => move(offset + size), prev: () => move(offset - size) }
}
