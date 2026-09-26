import { useQuery, useQueryClient } from '@tanstack/react-query'
import { craAssetsQuery, craQuery, keys } from '@/shared/api/queries'
import { useCallback, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { Check, Clock3, Copy, ExternalLink, Flame, LoaderCircle, Plus, X } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { Pagination } from '@/shared/ui/pagination'
import { SkeletonCard, SkeletonList } from '@/shared/ui/loading'
import { api } from '@/shared/api/http'
import type { Response } from '@/shared/api/client'
import { pagedKey, usePaged } from '@/shared/lib/usePaged'
import { formatDate } from '@/shared/i18n/format'

type Stage = { id: string; label: string; due: string | null; state: 'overdue' | 'pending' | 'waiting' | 'sent'; sent: { at: string; by: string } | null }
type CraEvent = { id: string; asset: string; product: string; cve: string; title: string | null; packages: string[]; status: 'open' | 'fixed'
  kev: { date_added: string | null; ransomware: boolean; name: string | null }; aware_at: string | null; stages: Stage[]; done: boolean; draft: string }
type Product = { key: string; name: string; asset: string; support_until: string | null; last_complete: string | null }
type Overview = Response<'/api/cra'>
type Counts = Overview['counts']
const EVENTS_PAGE = 10
const PRODUCTS_PAGE = 10
const LISTS = ['/api/cra/events', '/api/cra/products'] as const

const left = (iso: string, t: TFunction<'compliance'>) => {
  const hours = (new Date(iso).getTime() - Date.now()) / 3_600_000
  const whole = Math.max(1, Math.round(Math.abs(hours)))
  if (whole >= 48) return hours < 0 ? t('due.overdue_days', { count: Math.round(whole / 24) }) : t('due.left_days', { count: Math.round(whole / 24) })
  return hours < 0 ? t('due.overdue_hours', { count: whole }) : t('due.left_hours', { count: whole })
}
const STAGE_STYLE: Record<Stage['state'], string> = {
  overdue: 'border-danger-line bg-danger-soft text-danger', pending: 'border-warning-line bg-warning-soft text-warning',
  waiting: 'border-app-line bg-app-soft text-app-muted', sent: 'border-app-line bg-app-soft text-brand',
}

// Kit CRA (art. 14 del Reglamento UE 2024/2847): qué productos están bajo el CRA y los tres plazos de cada
// vulnerabilidad explotada activamente. Tamandua no notifica: prepara el borrador y guarda quién lo envió.
export function Compliance({ user, onNew }: { user: SessionUser; onNew: () => void }) {
  const { t } = useTranslation('compliance')
  const [error, setError] = useState('')
  const admin = user.role === 'admin'
  const queryClient = useQueryClient()
  const result = useQuery(craQuery())
  const overview = result.data ?? null
  // Events and products are paged on the server: a large organization never loads them all.
  const events = usePaged<CraEvent>('/api/cra/events', {}, EVENTS_PAGE)
  const loadError = result.error ? (result.error instanceof Error ? result.error.message : String(result.error)) : ''
  // Devuelve si se guardó: el formulario solo se cierra entonces (un error no borra lo escrito).
  const change = async (body: object) => {
    setError('')
    try {
      queryClient.setQueryData(keys.craOverview, await api.post<Overview>('/api/cra', 'cra', body))
      await Promise.all([keys.craAssets, ...LISTS.map(pagedKey)].map(queryKey => queryClient.invalidateQueries({ queryKey })))
      return true
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)); return false }
  }

  if (!overview) return error || loadError ? <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error || loadError}</div>
    : <div className="space-y-5"><SkeletonCard lines={4} label={t('loading')} /><SkeletonList rows={3} label={t('loading_events')} /></div>
  const { counts } = overview
  return <div className="space-y-5">
    {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
    <Card className="border-app-line bg-panel"><CardHeader><CardTitle className="text-base">{t('cra.title')}</CardTitle>
      <CardDescription className="leading-6">{t('cra.description')}</CardDescription></CardHeader>
      <CardContent className="space-y-3">
        <Products counts={counts} admin={admin} onChange={change} onNew={onNew} />
        <a href={overview.reporting_page} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-app-muted hover:text-app-fg">{t('cra.how_to_report')} <ExternalLink className="size-3" /></a>
      </CardContent></Card>

    <section aria-labelledby="cra-events" className="space-y-3">
      <h2 id="cra-events" className="text-base font-semibold">{counts.pending ? t('events.pending', { count: counts.pending }) : t('events.none_pending')}</h2>
      {!counts.events && <p className="rounded-xl border border-app-line bg-panel px-4 py-6 text-center text-sm text-app-muted">{!counts.products
        ? t('events.no_products')
        : counts.unscanned === counts.products ? t('events.not_scanned')
        : `${t('events.none_in_kev')}${counts.unscanned ? ` ${t('events.unscanned', { count: counts.unscanned })}` : ''}`}</p>}
      {events.error && <p role="alert" className="text-sm text-danger">{events.error}</p>}
      {counts.events > 0 && !events.items.length && events.loading ? <SkeletonList rows={3} label={t('loading_events')} />
        : <div className={`space-y-3 transition-opacity ${events.loading ? 'opacity-60' : ''}`}>{events.items.map(event => <EventCard key={event.id} event={event} admin={admin} onMark={(stage, sent) => change({ op: 'mark', event: event.id, stage, sent })} />)}</div>}
      {events.total > events.limit && <div className="rounded-xl border border-app-line bg-panel"><Pagination total={events.total} limit={events.limit} offset={events.offset} onPrev={events.prev} onNext={events.next} noun={t('events.noun')} /></div>}
    </section>
  </div>
}

function Products({ counts, admin, onChange, onNew }: { counts: Counts; admin: boolean; onChange: (body: object) => Promise<boolean>; onNew: () => void }) {
  const { t } = useTranslation('compliance')
  const queryClient = useQueryClient()
  const products = usePaged<Product>('/api/cra/products', {}, PRODUCTS_PAGE)
  const [adding, setAdding] = useState(false)
  const [picked, setPicked] = useState<ComboOption | null>(null)
  const [name, setName] = useState('')
  const [until, setUntil] = useState('')
  const [busy, setBusy] = useState(false)
  // Only assets that are not products yet, searched on the server as you type.
  const search = useCallback((q: string) => queryClient.fetchQuery(craAssetsQuery(q))
    .then(page => ({ options: page.items.map(asset => ({ id: asset.key, label: asset.name })), total: page.total })), [queryClient])
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!picked) return
    setBusy(true)
    const saved = await onChange({ op: 'product', key: picked.id, name: name.trim(), support_until: until || null })
    setBusy(false)
    if (saved) { setAdding(false); setPicked(null); setName(''); setUntil('') }
  }
  return <div className="space-y-2">
    <p className="text-sm font-medium">{counts.products ? t('products.title') : t('products.title_none')}</p>
    {products.error && <p role="alert" className="text-xs text-danger">{products.error}</p>}
    {counts.products > 0 && (!products.items.length && products.loading ? <SkeletonList rows={2} dense label={t('products.loading')} />
      : <div className="overflow-hidden rounded-xl border border-app-line"><ul className={`divide-y divide-app-line transition-opacity ${products.loading ? 'opacity-60' : ''}`}>{products.items.map(product => <li key={product.key} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm">
      <span className="min-w-0"><span className="font-medium">{product.name}</span><span className="block truncate text-xs text-app-subtle">{product.support_until ? t('products.supported_until', { asset: product.asset, date: product.support_until }) : product.asset}</span>
        {!product.last_complete && <span className="block text-xs text-warning">{t('products.not_scanned')}</span>}</span>
      {admin && <Button size="xs" variant="ghost" aria-label={t('products.remove', { name: product.name })} onClick={() => void onChange({ op: 'unproduct', key: product.key })}><X />{t('common:actions.remove')}</Button>}
    </li>)}</ul>
      {products.total > products.limit && <div className="border-t border-app-line"><Pagination total={products.total} limit={products.limit} offset={products.offset} onPrev={products.prev} onNext={products.next} noun={t('products.noun')} /></div>}</div>)}
    {admin && !counts.assets && <p className="text-xs text-app-muted">{t('products.scan_first')} <button type="button" onClick={onNew} className="min-h-6 text-brand underline-offset-2 hover:underline">{t('products.new_scan')}</button></p>}
    {admin && !adding && counts.candidates > 0 && <Button size="sm" variant="outline" onClick={() => setAdding(true)} className="border-app-line bg-app-soft"><Plus />{t('products.mark')}</Button>}
    {!admin && <p className="text-xs text-app-subtle">{t('products.admin_only')}</p>}
    {adding && <form onSubmit={submit} className="grid gap-2 rounded-xl border border-app-line bg-inset p-3 sm:grid-cols-[1fr_1fr_10rem_auto] sm:items-end">
      <div className="text-xs text-app-muted"><span>{t('products.asset')}</span>
        <Combobox className="mt-1" label={t('products.asset')} placeholder={t('products.choose')} emptyText={t('products.no_candidates')} value={picked} search={search}
          onSelect={option => { setPicked(option); if (!name) setName(option.label) }} /></div>
      <label className="text-xs text-app-muted">{t('products.name')}<Input required maxLength={120} value={name} onChange={event => setName(event.target.value)} className="mt-1 h-9 border-app-line bg-app" /></label>
      <label className="text-xs text-app-muted">{t('products.support_until')}<Input type="date" value={until} onChange={event => setUntil(event.target.value)} className="mt-1 h-9 border-app-line bg-app" /></label>
      <div className="flex gap-2"><Button type="submit" size="sm" disabled={!picked || !name.trim() || busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => setAdding(false)}>{t('common:actions.cancel')}</Button></div>
    </form>}
  </div>
}

function EventCard({ event, admin, onMark }: { event: CraEvent; admin: boolean; onMark: (stage: string, sent: boolean) => Promise<boolean> }) {
  const { t } = useTranslation('compliance')
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const copy = async () => { try { await navigator.clipboard.writeText(event.draft); setCopied(true); window.setTimeout(() => setCopied(false), 2000) } catch { setOpen(true) } }
  return <Card className="border-app-line bg-panel"><CardContent className="space-y-3 p-4">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div className="min-w-0"><p className="flex flex-wrap items-center gap-2 font-medium"><Flame aria-hidden className="size-4 text-danger" /><span className="font-mono text-sm">{event.cve}</span>{event.kev.ransomware && <span className="rounded border border-danger-line px-1.5 text-[11px] text-danger">{t('event.ransomware')}</span>}{event.status === 'fixed' && <span className="rounded border border-app-line px-1.5 text-[11px] text-brand">{t('event.fixed')}</span>}</p>
        <p className="mt-0.5 text-sm text-app-muted">{event.product} · {event.packages.join(', ') || event.title}</p>
        <p className="text-xs text-app-subtle">{[event.kev.name, t('event.in_kev', { date: event.kev.date_added ?? '—' }), event.aware_at ? t('event.clock', { date: formatDate(event.aware_at) }) : ''].filter(Boolean).join(' · ')}</p>
        <p className="mt-1 text-xs text-app-muted">{t('event.candidate')}</p></div>
      <div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => void copy()} className="border-app-line bg-app-soft">{copied ? <Check /> : <Copy />}{copied ? t('common:actions.copied') : t('event.copy_draft')}</Button><span role="status" className="sr-only">{copied ? t('event.draft_copied') : ''}</span>
        <Button size="sm" variant="ghost" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? t('event.hide_draft') : t('event.view_draft')}</Button></div>
    </div>
    <ol className="grid gap-2 sm:grid-cols-3">{event.stages.map(stage => <li key={stage.id} className={`rounded-lg border px-3 py-2 text-xs ${STAGE_STYLE[stage.state]}`}>
      <p className="flex items-center justify-between gap-2 font-medium"><span>{stage.label}</span>{stage.state === 'sent' ? <Check aria-hidden className="size-3.5" /> : <Clock3 aria-hidden className="size-3.5" />}</p>
      <p className="mt-0.5">{stage.state === 'sent' && stage.sent ? t('stage.sent_by', { by: stage.sent.by, date: formatDate(stage.sent.at) }) : stage.due ? `${formatDate(stage.due)} · ${left(stage.due, t)}` : t('stage.waiting')}</p>
      {admin && stage.state !== 'waiting' && <button type="button" aria-label={stage.state === 'sent' ? t('stage.unmark_label', { stage: stage.label, cve: event.cve }) : t('stage.mark_label', { stage: stage.label, cve: event.cve })} onClick={() => void onMark(stage.id, stage.state !== 'sent')} className="mt-1 min-h-6 underline-offset-2 hover:underline">{stage.state === 'sent' ? t('stage.unmark') : t('stage.mark')}</button>}
    </li>)}</ol>
    {open && <pre tabIndex={0} aria-label={t('event.draft_label', { cve: event.cve })} className="max-h-72 overflow-auto rounded-lg bg-inset p-3 text-xs leading-5 whitespace-pre-wrap">{event.draft}</pre>}
  </CardContent></Card>
}
