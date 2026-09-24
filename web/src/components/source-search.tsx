import { useEffect, useState, type ReactNode } from 'react'
import { LoaderCircle, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SkeletonList } from '@/components/loading'
import { useSourcePage, type Source, type SourceFilters, type SourcePage } from '@/lib/sources'

export function Pager({ page, perPage, total, onPage, loading = false }: { page: number; perPage: number; total: number; onPage: (page: number) => void; loading?: boolean }) {
  const pages = Math.max(1, Math.ceil(total / perPage))
  if (total <= perPage) return null
  return <div className="flex items-center justify-between gap-3 text-xs text-app-muted">
    <span className="flex items-center gap-2">{loading && <LoaderCircle className="size-3.5 animate-spin" />}{(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} de {total}</span>
    <div className="flex gap-2"><Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={page <= 1 || loading} onClick={() => onPage(page - 1)}>Anterior</Button>
      <Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={page >= pages || loading} onClick={() => onPage(page + 1)}>Siguiente</Button></div>
  </div>
}

// Buscador de repositorios con resultados paginados en el servidor, para diálogos y selectores.
export function SourceSearch({ provider, perPage = 10, render, empty = 'No hay repositorios que coincidan.', label = 'Buscar repositorio', autoFocus = false, onLoaded }: {
  provider?: SourceFilters['provider']; perPage?: number; render: (source: Source) => ReactNode; empty?: string; label?: string; autoFocus?: boolean; onLoaded?: (data: SourcePage) => void
}) {
  const [text, setText] = useState('')
  const [page, setPage] = useState(1)
  const { data, error, loading } = useSourcePage({ query: text, provider, page, perPage })
  useEffect(() => { if (data) onLoaded?.(data) }, [data, onLoaded])
  return <div className="space-y-2">
    <div className="relative"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input autoFocus={autoFocus} aria-label={label} placeholder="Buscar por nombre…" value={text} onChange={event => { setText(event.target.value); setPage(1) }} className="border-app-line bg-app-soft pl-9" /></div>
    {data?.partial && <p role="status" className="text-xs text-app-muted">Resultados parciales: la lista de esta cuenta se está leyendo de GitHub.</p>}
    {error && <p role="alert" className="text-xs text-danger">{error}</p>}
    <div className="space-y-1">
      {!data && <SkeletonList rows={Math.min(perPage, 6)} dense label="Cargando repositorios" />}
      {data?.sources.map(source => <div key={source.id}>{render(source)}</div>)}
      {data && !data.sources.length && !loading && <p className="py-6 text-center text-sm text-app-muted">{empty}</p>}
    </div>
    {data && <Pager page={page} perPage={perPage} total={data.total} onPage={setPage} loading={loading} />}
  </div>
}
