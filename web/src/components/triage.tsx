import { useState, type FormEvent } from 'react'
import { CheckCheck, ChevronDown, CircleDot, Clock3, LoaderCircle, RotateCcw, ShieldX, ThumbsUp, Wrench } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/components/ui/menu'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/types'

export type TriageStatus = 'open' | 'in_progress' | 'false_positive' | 'accepted' | 'fixed'
export type TriageEvent = { status: TriageStatus; reason?: string; note?: string; by: string; at: string; expires_at?: string | null; run_id?: string }
export type TriageState = { status: TriageStatus; reason?: string | null; note?: string | null; by?: string | null; at?: string | null; expires_at?: string | null; expired?: boolean; history?: TriageEvent[] }

export const triageLabel: Record<TriageStatus, string> = { open: 'Abierto', in_progress: 'En curso', false_positive: 'Falso positivo', accepted: 'Riesgo aceptado', fixed: 'Remediado' }
export const SUPPRESSED: TriageStatus[] = ['false_positive', 'accepted', 'fixed']
export const triageClass: Record<TriageStatus, string> = {
  open: 'border-app-line text-app-muted', in_progress: 'border-info-line text-info',
  false_positive: 'border-app-line bg-app-soft text-app-subtle line-through decoration-app-faint', accepted: 'border-brand/30 text-brand',
  fixed: 'border-brand/30 text-brand',
}
const icon: Record<TriageStatus, typeof CircleDot> = { open: RotateCcw, in_progress: Wrench, false_positive: ShieldX, accepted: ThumbsUp, fixed: CheckCheck }
const verb: Record<TriageStatus, string> = { open: 'Reabrir', in_progress: 'En curso', false_positive: 'Falso positivo', accepted: 'Aceptar riesgo', fixed: 'Marcar remediado' }
const needsReason = (status: TriageStatus) => SUPPRESSED.includes(status)
const inDays = (days: number) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10)

export function TriageBadge({ state }: { state?: TriageState }) {
  const status = state?.status ?? 'open'
  if (status === 'open' && !state?.expired) return null
  return <Badge variant="outline" className={`w-fit text-[11px] ${triageClass[status]}`}>{state?.expired ? 'Aceptación caducada' : triageLabel[status]}</Badge>
}

// Decisión de triage. Ley de Hick: una acción principal (la más habitual) y el resto en un menú,
// en lugar de cuatro o cinco botones iguales por hallazgo. "Aceptar riesgo" solo lo ve un
// administrador: es una decisión de negocio.
export function TriageActions({ current, canAccept, onPick, size = 'sm' }: { current?: TriageStatus; canAccept: boolean; onPick: (status: TriageStatus) => void; size?: 'sm' | 'xs' }) {
  const options = (['fixed', 'in_progress', 'false_positive', ...(canAccept ? ['accepted' as const] : []), 'open'] as TriageStatus[])
    .filter(status => status !== current && !(status === 'open' && !current))
  const [primary, ...rest] = options
  if (!primary) return null
  const Primary = icon[primary]
  return <div className="flex flex-wrap gap-1.5">
    <Button type="button" size={size} variant="outline" onClick={() => onPick(primary)} className="border-app-line bg-app-soft"><Primary />{verb[primary]}</Button>
    {rest.length > 0 && <Menu><MenuTrigger render={<Button type="button" size={size} variant="outline" className="border-app-line bg-app-soft" />}>Más estados<ChevronDown className="size-3.5" /></MenuTrigger>
      <MenuContent align="start">{rest.map(status => { const Icon = icon[status]; return <MenuItem key={status} onClick={() => onPick(status)}><Icon />{verb[status]}</MenuItem> })}</MenuContent></Menu>}
  </div>
}

// Diálogo común a la decisión individual y a la masiva: pide motivo cuando el hallazgo deja de contar.
export function TriageDialog({ runId, status, fingerprints, onClose, onDone }: { runId: string; status: TriageStatus | null; fingerprints: string[]; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState('')
  const [note, setNote] = useState('')
  const [expires, setExpires] = useState(inDays(90))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  if (!status) return null
  const count = fingerprints.length
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    try {
      await api.post('/api/findings/triage', 'triage', { run_id: runId, fingerprints, status, reason: reason.trim() || undefined, note: note.trim() || undefined, expires_at: status === 'accepted' ? expires : undefined })
      onDone()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const description = {
    open: 'Vuelve a contar como pendiente en el panel, los tickets y el SARIF.',
    in_progress: 'Indica que alguien lo está corrigiendo. Sigue contando como pendiente.',
    false_positive: 'Deja de contar como pendiente en este y en los próximos escaneos del repositorio. Queda en el historial con tu usuario y el motivo.',
    accepted: 'El riesgo se asume de forma temporal: deja de contar como pendiente hasta la fecha de caducidad y luego vuelve a abrirse solo.',
    fixed: 'Se da por corregido sin esperar al siguiente escaneo. Explica cómo se remedió (PR, parche, despliegue): queda en el historial. Si el próximo escaneo lo vuelve a encontrar, se reabre solo.',
  }[status]
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>{verb[status]} · {count} {count === 1 ? 'hallazgo' : 'hallazgos'}</DialogTitle><DialogDescription>{description}</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><label htmlFor="triage-reason" className="text-xs text-app-muted">Motivo{needsReason(status) ? '' : ' (opcional)'}</label>
        <textarea id="triage-reason" required={needsReason(status)} minLength={needsReason(status) ? 10 : undefined} maxLength={500} rows={3} value={reason} onChange={event => setReason(event.target.value)}
          placeholder={status === 'false_positive' ? 'p. ej. El HTML viene de una plantilla estática y se sanea con DOMPurify' : status === 'accepted' ? 'p. ej. No expuesto a internet; se corrige en la migración del Q4' : status === 'fixed' ? 'p. ej. Token revocado en Auth0 y eliminado del README en el PR #5' : ''}
          className="w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-brand/40" /></div>
      {status === 'accepted' && <div className="space-y-1.5"><label htmlFor="triage-expires" className="text-xs text-app-muted">Caduca el</label><Input id="triage-expires" type="date" required min={inDays(1)} max={inDays(365)} value={expires} onChange={event => setExpires(event.target.value)} className="w-48 border-app-line bg-app-soft" /></div>}
      <div className="space-y-1.5"><label htmlFor="triage-note" className="text-xs text-app-muted">Nota (opcional: ticket, PR, responsable)</label><Input id="triage-note" maxLength={1000} value={note} onChange={event => setNote(event.target.value)} className="border-app-line bg-app-soft" /></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>Cancelar</Button><Button type="submit" disabled={busy || (needsReason(status) && reason.trim().length < 10)} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}Guardar</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

export function TriageHistory({ state }: { state?: TriageState }) {
  const history = state?.history ?? []
  if (!history.length) return null
  return <details className="mt-3"><summary className="cursor-pointer text-xs text-app-muted">Historial de triage · {history.length}</summary>
    <ol className="mt-2 space-y-1.5 border-l border-app-line pl-3 text-xs">{[...history].reverse().map((event, index) => <li key={index} className="text-app-muted">
      <span className="flex items-center gap-1.5"><Clock3 className="size-3 text-app-subtle" /><span className="font-medium text-app-secondary">{triageLabel[event.status]}</span> · {event.by} · {formatDate(event.at)}{event.expires_at ? ` · caduca ${event.expires_at}` : ''}</span>
      {event.reason && <span className="block pl-4.5">{event.reason}</span>}{event.note && <span className="block pl-4.5 text-app-subtle">{event.note}</span>}
    </li>)}</ol></details>
}
