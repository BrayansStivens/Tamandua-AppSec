import { useCallback, useEffect, useRef, useState } from 'react'
import { api, query as toQuery } from '@/shared/api/http'

export type Source = { id: string; name: string; provider: 'local' | 'github' | 'gitlab'; private: boolean; branch: string | null; uid?: string; account?: string; installation_id?: number }
export type Providers = Record<'github' | 'gitlab', { configured: boolean; origin: 'session' | 'environment' | 'github_app' | null; error?: string }>
// Una página de repositorios: el servidor solo pide a GitHub la página visible (o su búsqueda).
export type SourcePage = { sources: Source[]; providers: Providers; total: number; page: number; per_page: number; partial?: boolean; accounts?: string[] }
export type SourceFilters = { query?: string; account?: string; provider?: 'github' | 'gitlab' | 'local'; page?: number; perPage?: number }

// Carga la página pedida; la búsqueda espera a que se deje de escribir para no gastar el límite de GitHub.
// `reload(true)` descarta lo cacheado en el servidor («Actualizar lista»).
export function useSourcePage({ query = '', account, provider, page = 1, perPage = 25 }: SourceFilters, enabled = true) {
  const [data, setData] = useState<SourcePage | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [nonce, setNonce] = useState(0)
  const refresh = useRef(false)
  const reload = useCallback((fresh = false) => { refresh.current = fresh; setNonce(value => value + 1) }, [])
  useEffect(() => {
    if (!enabled) return
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      const fresh = refresh.current
      refresh.current = false
      setLoading(true); setError('')
      api.get<SourcePage>(`/api/sources?${toQuery({ q: query.trim() || undefined, account, provider, page, per_page: perPage, refresh: fresh ? 1 : undefined })}`, { signal: controller.signal })
        .then(setData)
        .catch(caught => { if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : String(caught)) })
        .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    }, query ? 300 : 0)
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [enabled, query, account, provider, page, perPage, nonce])
  // Búsqueda parcial (cuenta con repositorios seleccionados que aún se está leyendo): se repite sola.
  useEffect(() => { if (!data?.partial) return; const timer = window.setTimeout(() => reload(), 2000); return () => window.clearTimeout(timer) }, [data, reload])
  return { data, error, loading, reload }
}

// Un repositorio concreto por id (enlace directo o selección guardada), sin pedir el catálogo.
export const fetchSource = (id: string) => api.get<{ sources: Source[] }>(`/api/sources?${toQuery({ id })}`).then(result => result.sources[0] ?? null)
