import { useQuery } from '@tanstack/react-query'
import { useCallback, useEffect, useState } from 'react'
import { Layers3, LoaderCircle } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { api, query } from '@/shared/api/http'

export type BatchSummary = { id: string; label: string; status: 'running' | 'done' | 'cancelled'; created_at: string; by: string; total: number
  pending: number; running: number; done: number; failed: number; critical: number; high: number; eta_seconds: number
  failed_items: { name: string; error: string }[] }

const duration = (seconds: number) => seconds < 90 ? 'menos de 2 min' : seconds < 5400 ? `~${Math.round(seconds / 60)} min` : `~${Math.round(seconds / 3600)} h`

// Estado del lote activo, sondeado mientras avanza. Devuelve también una función para refrescarlo al crear uno.
export function useBatches() {
  // Sondea cada 5 s solo mientras haya un lote activo (antes: un setInterval propio).
  const result = useQuery({
    queryKey: ['batches'],
    queryFn: ({ signal }) => api.get<{ active: BatchSummary | null; recent: BatchSummary[] }>('/api/repositories/batches', { signal }),
    refetchInterval: query => query.state.data?.active ? 5000 : false,
  })
  const state = result.data ?? null
  const reload = useCallback(() => result.refetch(), [result])
  return { active: state?.active ?? null, last: state?.recent[0] ?? null, reload }
}

// `viewer`: quién mira. Cancelar es cosa de quien lanzó el lote o de un administrador; sin `viewer`, se muestra siempre.
export function BatchPanel({ active, last, onChanged, viewer }: { active: BatchSummary | null; last: BatchSummary | null; onChanged: () => void; viewer?: { username: string; admin: boolean } }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  if (!active && !last) return null
  if (!active && last) return <p className="text-xs text-app-muted">Último lote · {last.label}: {last.done} analizados{last.failed ? `, ${last.failed} fallidos` : ''}{last.status === 'cancelled' ? ' · cancelado' : ''}{last.critical ? ` · ${last.critical} críticos` : ''}.</p>
  const batch = active!
  const finished = batch.done + batch.failed
  const percent = batch.total ? Math.round((finished / batch.total) * 100) : 0
  const cancel = async () => {
    if (!window.confirm('¿Cancelar el lote? Lo ya analizado se conserva; el análisis en curso termina.')) return
    setBusy(true); setError('')
    try { await api.post('/api/repositories/batches/cancel', 'cancel-batch', { id: batch.id }); onChanged() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <div className="space-y-2 rounded-xl border border-brand/30 bg-brand/[0.06] p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="flex items-center gap-2 text-sm font-medium"><Layers3 className="size-4 text-brand" />Lote en curso · {batch.label}</p>
      {(!viewer || viewer.admin || viewer.username === batch.by) && <Button size="sm" variant="ghost" disabled={busy} onClick={() => void cancel()}>{busy && <LoaderCircle className="animate-spin" />}Cancelar lote</Button>}
    </div>
    <div role="progressbar" aria-label={`Lote: ${finished} de ${batch.total} analizados`} aria-valuemin={0} aria-valuemax={batch.total} aria-valuenow={finished}
      className="h-1.5 overflow-hidden rounded-full bg-app-soft"><div className="h-full rounded-full bg-brand transition-all" style={{ width: `${Math.max(2, percent)}%` }} /></div>
    <p role="status" className="text-xs text-app-muted">{finished} de {batch.total} analizados{batch.failed ? ` (${batch.failed} fallidos)` : ''} · {batch.critical} críticos y {batch.high} altos hasta ahora · quedan {duration(batch.eta_seconds)}. Avanza cuando no hay otros análisis: puedes seguir usando el panel.</p>
    {batch.failed_items.length > 0 && <details className="text-xs text-app-muted"><summary className="cursor-pointer">Ver fallidos</summary><ul className="mt-1 space-y-0.5">{batch.failed_items.map(item => <li key={item.name}><span className="font-medium">{item.name}</span>: {item.error}</li>)}</ul></details>}
    {error && <p role="alert" className="text-xs text-danger">{error}</p>}
  </div>
}

// Confirmación antes de analizar una organización entera: cuántos repositorios y cuánto tardará.
export function OrganizationScanDialog({ account, onClose, onStarted }: { account: string | null; onClose: () => void; onStarted: () => void }) {
  const [total, setTotal] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    if (!account) return
    setTotal(null); setError('')
    api.get<{ total: number }>(`/api/sources?${query({ account, provider: 'github', per_page: 1 })}`).then(data => setTotal(data.total)).catch(caught => setError(String(caught)))
  }, [account])
  const start = async () => {
    setBusy(true); setError('')
    try { await api.post('/api/repositories/batches', 'scan-batch', { account }); onStarted(); onClose() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Dialog open={!!account} onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>Analizar la organización {account}</DialogTitle>
      <DialogDescription>Se analizan todos sus repositorios (salvo los archivados), de uno en uno y solo cuando no hay otros análisis: los tuyos y las revisiones de PR no esperan. Puedes seguir usando el panel y cancelarlo cuando quieras.</DialogDescription></DialogHeader>
    <p className="rounded-lg border border-app-line bg-inset p-3 text-sm">{total === null ? 'Contando repositorios…' : <><strong>{total}</strong> repositorios · tiempo estimado {duration(total * 60)} (≈1 min por repositorio; se ajusta con lo que tarden de verdad).</>}</p>
    {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    <DialogFooter><Button variant="ghost" onClick={onClose}>Cancelar</Button>
      <Button disabled={busy || !total} onClick={() => void start()} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}Analizar {total ?? ''} repositorios</Button></DialogFooter>
  </DialogContent></Dialog>
}
