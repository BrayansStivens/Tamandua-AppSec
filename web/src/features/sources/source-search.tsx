import { useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { LoaderCircle, Search } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { SkeletonList } from '@/shared/ui/loading'
import { formatNumber } from '@/shared/i18n/format'
import { useSourcePage, type Source, type SourceFilters, type SourcePage } from '@/features/sources/sources'

export function Pager({ page, perPage, total, onPage, loading = false }: { page: number; perPage: number; total: number; onPage: (page: number) => void; loading?: boolean }) {
  const { t } = useTranslation('sources')
  const pages = Math.max(1, Math.ceil(total / perPage))
  if (total <= perPage) return null
  return <div className="flex items-center justify-between gap-3 text-xs text-app-muted">
    <span className="flex items-center gap-2">{loading && <LoaderCircle className="size-3.5 animate-spin" />}{t('pager.range', { from: formatNumber((page - 1) * perPage + 1), to: formatNumber(Math.min(page * perPage, total)), total: formatNumber(total) })}</span>
    <div className="flex gap-2"><Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={page <= 1 || loading} onClick={() => onPage(page - 1)}>{t('pager.previous')}</Button>
      <Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={page >= pages || loading} onClick={() => onPage(page + 1)}>{t('common:actions.next')}</Button></div>
  </div>
}

// Buscador de repositorios con resultados paginados en el servidor, para diálogos y selectores.
export function SourceSearch({ provider, perPage = 10, render, empty, label, autoFocus = false, onLoaded }: {
  provider?: SourceFilters['provider']; perPage?: number; render: (source: Source) => ReactNode; empty?: string; label?: string; autoFocus?: boolean; onLoaded?: (data: SourcePage) => void
}) {
  const { t } = useTranslation('sources')
  const [text, setText] = useState('')
  const [page, setPage] = useState(1)
  const { data, error, loading } = useSourcePage({ query: text, provider, page, perPage })
  useEffect(() => { if (data) onLoaded?.(data) }, [data, onLoaded])
  return <div className="space-y-2">
    <div className="relative"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input autoFocus={autoFocus} aria-label={label ?? t('search.label')} placeholder={t('search.placeholder')} value={text} onChange={event => { setText(event.target.value); setPage(1) }} className="border-app-line bg-app-soft pl-9" /></div>
    {data?.partial && <p role="status" className="text-xs text-app-muted">{t('search.partial')}</p>}
    {error && <p role="alert" className="text-xs text-danger">{error}</p>}
    <div className="space-y-1">
      {!data && <SkeletonList rows={Math.min(perPage, 6)} dense label={t('repositories.loading')} />}
      {data?.sources.map(source => <div key={source.id}>{render(source)}</div>)}
      {data && !data.sources.length && !loading && <p className="py-6 text-center text-sm text-app-muted">{empty ?? t('repositories.no_match')}</p>}
    </div>
    {data && <Pager page={page} perPage={perPage} total={data.total} onPage={setPage} loading={loading} />}
  </div>
}
