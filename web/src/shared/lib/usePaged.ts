import { useCallback, useEffect, useState } from 'react'
import { api, query } from '@/shared/api/http'
import type { Page } from '@/shared/lib/types'

// Paginación reutilizable contra un endpoint que devuelve { items, total, limit, offset }.
export function usePaged<T>(path: string, filters: Record<string, string | undefined>, size = 25, refreshKey = 0) {
  const [offset, setOffset] = useState(0)
  const [page, setPage] = useState<Page<T>>({ items: [], total: 0, limit: size, offset: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const key = JSON.stringify(filters)
  useEffect(() => { setOffset(0) }, [key, size])
  const load = useCallback(async () => {
    setLoading(true)
    try { setPage(await api.get<Page<T>>(`${path}?${query({ ...filters, limit: size, offset })}`)); setError(null) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setLoading(false) }
  }, [path, key, size, offset]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { void load() }, [load, refreshKey])
  return { ...page, loading, error, reload: load, pageIndex: Math.floor(offset / size), pageCount: Math.max(1, Math.ceil(page.total / size)),
    next: () => setOffset(current => Math.min(current + size, Math.max(0, (Math.ceil(page.total / size) - 1) * size))), prev: () => setOffset(current => Math.max(0, current - size)) }
}
