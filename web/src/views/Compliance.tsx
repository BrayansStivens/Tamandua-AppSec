import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Check, Clock3, Copy, ExternalLink, Flame, LoaderCircle, Plus, X } from 'lucide-react'
import type { SessionUser } from '@/components/auth/session'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/components/ui/select'
import { Skeleton } from '@/components/loading'
import { api } from '@/lib/api'

type Stage = { id: string; label: string; due: string | null; state: 'overdue' | 'pending' | 'waiting' | 'sent'; sent: { at: string; by: string } | null }
type CraEvent = { id: string; asset: string; product: string; cve: string; title: string | null; packages: string[]; status: 'open' | 'fixed'
  kev: { date_added: string | null; ransomware: boolean; name: string | null }; aware_at: string | null; stages: Stage[]; done: boolean; draft: string }
type Product = { key: string; name: string; asset: string; support_until: string | null }
type State = { products: Product[]; events: CraEvent[]; assets: { key: string; name: string }[]; reporting_page: string }

const when = (iso: string) => new Date(iso).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })
const left = (iso: string) => {
  const hours = Math.round((new Date(iso).getTime() - Date.now()) / 3_600_000)
  const span = Math.abs(hours) >= 48 ? `${Math.round(Math.abs(hours) / 24)} días` : `${Math.abs(hours)} h`
  return hours < 0 ? `vencida hace ${span}` : `quedan ${span}`
}
const STAGE_STYLE: Record<Stage['state'], string> = {
  overdue: 'border-danger-line bg-danger-soft text-danger', pending: 'border-warning-line bg-warning-soft text-warning',
  waiting: 'border-app-line bg-app-soft text-app-muted', sent: 'border-app-line bg-app-soft text-brand',
}

// Kit CRA (art. 14 del Reglamento UE 2024/2847): qué productos están bajo el CRA y los tres plazos de cada
// vulnerabilidad explotada activamente. Tamandua no notifica: prepara el borrador y guarda quién lo envió.
export function Compliance({ user }: { user: SessionUser }) {
  const [state, setState] = useState<State | null>(null)
  const [error, setError] = useState('')
  const admin = user.role === 'admin'
  const load = useCallback(() => api.get<State>('/api/cra').then(setState).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))), [])
  useEffect(() => { void load() }, [load])
  const change = async (body: object) => {
    setError('')
    try { setState(await api.post<State>('/api/cra', 'cra', body)) } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }

  if (!state) return error ? <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div> : <Skeleton rows={5} />
  const running = state.events.filter(event => !event.done)
  return <div className="space-y-5">
    {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
    <Card className="border-app-line bg-panel"><CardHeader><CardTitle className="text-base">Reglamento de Ciberresiliencia (CRA) · notificación de vulnerabilidades</CardTitle>
      <CardDescription className="leading-6">Desde el 11-09-2026, si vendes en la UE un producto con software, cada vulnerabilidad suya que se explote activamente se notifica a ENISA: alerta temprana en 24 h, notificación en 72 h e informe final 14 días después de tener la corrección. Aquí ves esos plazos para tus productos; la explotación activa sale del catálogo CISA KEV.</CardDescription></CardHeader>
      <CardContent className="space-y-3">
        <Products state={state} admin={admin} onChange={change} />
        <a href={state.reporting_page} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-app-muted hover:text-app-fg">Cómo se notifica (Comisión Europea) <ExternalLink className="size-3" /></a>
      </CardContent></Card>

    <section aria-labelledby="cra-events" className="space-y-3">
      <h2 id="cra-events" className="text-base font-semibold">{running.length ? `${running.length} ${running.length === 1 ? 'vulnerabilidad por notificar' : 'vulnerabilidades por notificar'}` : 'Nada por notificar'}</h2>
      {!state.events.length && <p className="rounded-xl border border-app-line bg-panel px-4 py-6 text-center text-sm text-app-muted">{state.products.length
        ? 'Ninguna vulnerabilidad de tus productos está en el catálogo CISA KEV. Se revisa en cada análisis.'
        : 'Marca primero qué repositorios o imágenes son productos bajo el CRA.'}</p>}
      {state.events.map(event => <EventCard key={event.id} event={event} admin={admin} onMark={(stage, sent) => change({ op: 'mark', event: event.id, stage, sent })} />)}
    </section>
  </div>
}

function Products({ state, admin, onChange }: { state: State; admin: boolean; onChange: (body: object) => Promise<void> }) {
  const [adding, setAdding] = useState(false)
  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [until, setUntil] = useState('')
  const [busy, setBusy] = useState(false)
  const candidates = state.assets.filter(asset => !state.products.some(product => product.key === asset.key))
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true)
    await onChange({ op: 'product', key, name: name.trim(), support_until: until || null })
    setBusy(false); setAdding(false); setKey(''); setName(''); setUntil('')
  }
  return <div className="space-y-2">
    <p className="text-sm font-medium">Productos bajo el CRA{state.products.length ? '' : ': ninguno'}</p>
    {state.products.length > 0 && <ul className="divide-y divide-app-line rounded-xl border border-app-line">{state.products.map(product => <li key={product.key} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm">
      <span className="min-w-0"><span className="font-medium">{product.name}</span><span className="block truncate text-xs text-app-subtle">{product.asset}{product.support_until ? ` · soporte hasta ${product.support_until}` : ''}</span></span>
      {admin && <Button size="xs" variant="ghost" aria-label={`Quitar ${product.name} de los productos CRA`} onClick={() => void onChange({ op: 'unproduct', key: product.key })}><X />Quitar</Button>}
    </li>)}</ul>}
    {admin && !adding && candidates.length > 0 && <Button size="sm" variant="outline" onClick={() => setAdding(true)} className="border-app-line bg-app-soft"><Plus />Marcar un producto</Button>}
    {!admin && <p className="text-xs text-app-subtle">Solo un administrador marca productos y registra las notificaciones.</p>}
    {adding && <form onSubmit={submit} className="grid gap-2 rounded-xl border border-app-line bg-inset p-3 sm:grid-cols-[1fr_1fr_10rem_auto] sm:items-end">
      <label className="text-xs text-app-muted">Repositorio o imagen
        <Select value={key} onValueChange={value => { setKey(value ?? ''); if (!name) setName(candidates.find(item => item.key === value)?.name ?? '') }}>
          <SelectTrigger aria-label="Repositorio o imagen" className="mt-1 w-full border-app-line bg-app">{candidates.find(item => item.key === key)?.name ?? 'Elige…'}</SelectTrigger>
          <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{candidates.map(item => <SelectItem key={item.key} value={item.key}>{item.name}</SelectItem>)}</SelectContent></Select></label>
      <label className="text-xs text-app-muted">Nombre comercial del producto<Input required maxLength={120} value={name} onChange={event => setName(event.target.value)} className="mt-1 h-9 border-app-line bg-app" /></label>
      <label className="text-xs text-app-muted">Soporte hasta<Input type="date" value={until} onChange={event => setUntil(event.target.value)} className="mt-1 h-9 border-app-line bg-app" /></label>
      <div className="flex gap-2"><Button type="submit" size="sm" disabled={!key || !name.trim() || busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}Guardar</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => setAdding(false)}>Cancelar</Button></div>
    </form>}
  </div>
}

function EventCard({ event, admin, onMark }: { event: CraEvent; admin: boolean; onMark: (stage: string, sent: boolean) => Promise<void> }) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const copy = async () => { try { await navigator.clipboard.writeText(event.draft); setCopied(true); window.setTimeout(() => setCopied(false), 2000) } catch { setOpen(true) } }
  return <Card className="border-app-line bg-panel"><CardContent className="space-y-3 p-4">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div className="min-w-0"><p className="flex flex-wrap items-center gap-2 font-medium"><Flame aria-hidden className="size-4 text-danger" /><span className="font-mono text-sm">{event.cve}</span>{event.kev.ransomware && <span className="rounded border border-danger-line px-1.5 text-[11px] text-danger">ransomware</span>}{event.status === 'fixed' && <span className="rounded border border-app-line px-1.5 text-[11px] text-brand">corregida</span>}</p>
        <p className="mt-0.5 text-sm text-app-muted">{event.product} · {event.packages.join(', ') || event.title}</p>
        <p className="text-xs text-app-subtle">{event.kev.name ? `${event.kev.name} · ` : ''}en KEV desde {event.kev.date_added ?? '—'}{event.aware_at ? ` · lo sabes desde ${when(event.aware_at)}` : ''}</p></div>
      <div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => void copy()} className="border-app-line bg-app-soft">{copied ? <Check /> : <Copy />}{copied ? 'Copiado' : 'Copiar borrador'}</Button>
        <Button size="sm" variant="ghost" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? 'Ocultar' : 'Ver borrador'}</Button></div>
    </div>
    <ol className="grid gap-2 sm:grid-cols-3">{event.stages.map(stage => <li key={stage.id} className={`rounded-lg border px-3 py-2 text-xs ${STAGE_STYLE[stage.state]}`}>
      <p className="flex items-center justify-between gap-2 font-medium"><span>{stage.label}</span>{stage.state === 'sent' ? <Check aria-hidden className="size-3.5" /> : <Clock3 aria-hidden className="size-3.5" />}</p>
      <p className="mt-0.5">{stage.state === 'sent' && stage.sent ? `Enviada por ${stage.sent.by}, ${when(stage.sent.at)}` : stage.due ? `${when(stage.due)} · ${left(stage.due)}` : 'Empieza cuando haya corrección'}</p>
      {admin && stage.state !== 'waiting' && <button type="button" onClick={() => void onMark(stage.id, stage.state !== 'sent')} className="mt-1 min-h-6 underline-offset-2 hover:underline">{stage.state === 'sent' ? 'Desmarcar' : 'Marcar como enviada'}</button>}
    </li>)}</ol>
    {open && <pre className="max-h-72 overflow-auto rounded-lg bg-inset p-3 text-xs leading-5 whitespace-pre-wrap">{event.draft}</pre>}
  </CardContent></Card>
}
