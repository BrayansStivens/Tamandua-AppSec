import { useQuery, useQueryClient } from '@tanstack/react-query'
import { keys } from '@/shared/api/queries'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { Check, Clock3, Copy, ExternalLink, Flame, LoaderCircle, Plus, X } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { SkeletonCard, SkeletonList } from '@/shared/ui/loading'
import { api } from '@/shared/api/http'
import { formatDate } from '@/shared/i18n/format'

type Stage = { id: string; label: string; due: string | null; state: 'overdue' | 'pending' | 'waiting' | 'sent'; sent: { at: string; by: string } | null }
type CraEvent = { id: string; asset: string; product: string; cve: string; title: string | null; packages: string[]; status: 'open' | 'fixed'
  kev: { date_added: string | null; ransomware: boolean; name: string | null }; aware_at: string | null; stages: Stage[]; done: boolean; draft: string }
type Product = { key: string; name: string; asset: string; support_until: string | null; last_complete: string | null }
type State = { products: Product[]; events: CraEvent[]; assets: { key: string; name: string }[]; reporting_page: string }

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
  const result = useQuery({ queryKey: keys.cra, queryFn: ({ signal }) => api.get<State>('/api/cra', { signal }) })
  const state = result.data ?? null
  const loadError = result.error ? (result.error instanceof Error ? result.error.message : String(result.error)) : ''
  // Devuelve si se guardó: el formulario solo se cierra entonces (un error no borra lo escrito).
  const change = async (body: object) => {
    setError('')
    try { queryClient.setQueryData(keys.cra, await api.post<State>('/api/cra', 'cra', body)); return true } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)); return false }
  }

  if (!state) return error || loadError ? <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error || loadError}</div>
    : <div className="space-y-5"><SkeletonCard lines={4} label={t('loading')} /><SkeletonList rows={3} label={t('loading_events')} /></div>
  const running = state.events.filter(event => !event.done)
  const unscanned = state.products.filter(product => !product.last_complete)
  return <div className="space-y-5">
    {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
    <Card className="border-app-line bg-panel"><CardHeader><CardTitle className="text-base">{t('cra.title')}</CardTitle>
      <CardDescription className="leading-6">{t('cra.description')}</CardDescription></CardHeader>
      <CardContent className="space-y-3">
        <Products state={state} admin={admin} onChange={change} onNew={onNew} />
        <a href={state.reporting_page} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-app-muted hover:text-app-fg">{t('cra.how_to_report')} <ExternalLink className="size-3" /></a>
      </CardContent></Card>

    <section aria-labelledby="cra-events" className="space-y-3">
      <h2 id="cra-events" className="text-base font-semibold">{running.length ? t('events.pending', { count: running.length }) : t('events.none_pending')}</h2>
      {!state.events.length && <p className="rounded-xl border border-app-line bg-panel px-4 py-6 text-center text-sm text-app-muted">{!state.products.length
        ? t('events.no_products')
        : unscanned.length === state.products.length ? t('events.not_scanned')
        : `${t('events.none_in_kev')}${unscanned.length ? ` ${t('events.unscanned', { count: unscanned.length })}` : ''}`}</p>}
      {state.events.map(event => <EventCard key={event.id} event={event} admin={admin} onMark={(stage, sent) => change({ op: 'mark', event: event.id, stage, sent })} />)}
    </section>
  </div>
}

function Products({ state, admin, onChange, onNew }: { state: State; admin: boolean; onChange: (body: object) => Promise<boolean>; onNew: () => void }) {
  const { t } = useTranslation('compliance')
  const [adding, setAdding] = useState(false)
  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [until, setUntil] = useState('')
  const [busy, setBusy] = useState(false)
  const candidates = state.assets.filter(asset => !state.products.some(product => product.key === asset.key))
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true)
    const saved = await onChange({ op: 'product', key, name: name.trim(), support_until: until || null })
    setBusy(false)
    if (saved) { setAdding(false); setKey(''); setName(''); setUntil('') }
  }
  return <div className="space-y-2">
    <p className="text-sm font-medium">{state.products.length ? t('products.title') : t('products.title_none')}</p>
    {state.products.length > 0 && <ul className="divide-y divide-app-line rounded-xl border border-app-line">{state.products.map(product => <li key={product.key} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm">
      <span className="min-w-0"><span className="font-medium">{product.name}</span><span className="block truncate text-xs text-app-subtle">{product.support_until ? t('products.supported_until', { asset: product.asset, date: product.support_until }) : product.asset}</span>
        {!product.last_complete && <span className="block text-xs text-warning">{t('products.not_scanned')}</span>}</span>
      {admin && <Button size="xs" variant="ghost" aria-label={t('products.remove', { name: product.name })} onClick={() => void onChange({ op: 'unproduct', key: product.key })}><X />{t('common:actions.remove')}</Button>}
    </li>)}</ul>}
    {admin && !state.assets.length && <p className="text-xs text-app-muted">{t('products.scan_first')} <button type="button" onClick={onNew} className="min-h-6 text-brand underline-offset-2 hover:underline">{t('products.new_scan')}</button></p>}
    {admin && !adding && candidates.length > 0 && <Button size="sm" variant="outline" onClick={() => setAdding(true)} className="border-app-line bg-app-soft"><Plus />{t('products.mark')}</Button>}
    {!admin && <p className="text-xs text-app-subtle">{t('products.admin_only')}</p>}
    {adding && <form onSubmit={submit} className="grid gap-2 rounded-xl border border-app-line bg-inset p-3 sm:grid-cols-[1fr_1fr_10rem_auto] sm:items-end">
      <label className="text-xs text-app-muted">{t('products.asset')}
        <Select value={key} onValueChange={value => { setKey(value ?? ''); if (!name) setName(candidates.find(item => item.key === value)?.name ?? '') }}>
          <SelectTrigger aria-label={t('products.asset')} className="mt-1 w-full border-app-line bg-app">{candidates.find(item => item.key === key)?.name ?? t('products.choose')}</SelectTrigger>
          <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{candidates.map(item => <SelectItem key={item.key} value={item.key}>{item.name}</SelectItem>)}</SelectContent></Select></label>
      <label className="text-xs text-app-muted">{t('products.name')}<Input required maxLength={120} value={name} onChange={event => setName(event.target.value)} className="mt-1 h-9 border-app-line bg-app" /></label>
      <label className="text-xs text-app-muted">{t('products.support_until')}<Input type="date" value={until} onChange={event => setUntil(event.target.value)} className="mt-1 h-9 border-app-line bg-app" /></label>
      <div className="flex gap-2"><Button type="submit" size="sm" disabled={!key || !name.trim() || busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
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
