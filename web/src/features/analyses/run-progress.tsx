import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { runQuery } from '@/shared/api/queries'
import { BRAND } from '@/shared/lib/brand'
import { CircleAlert, CircleCheck, LoaderCircle, Terminal, X } from 'lucide-react'
import { Card, CardContent } from '@/shared/ui/card'

export type ProgressEvent = { at: string; level: 'info' | 'ok' | 'warn' | 'error'; message: string }
export type RunningRun = { id: string; status: string; created_at: string; started_at?: string; finished_at?: string; source?: { name: string }; progress?: ProgressEvent[] }

// Consola de progreso del escaneo: solo eventos pensados para el usuario, nunca salida del servidor.
export function RunProgress({ run, onFinished }: { run: RunningRun; onFinished: (run: RunningRun) => void }) {
  // La consulta sondea sola mientras la ejecución está en cola o corriendo (ver runQuery) y comparte caché.
  const { data } = useQuery({ ...runQuery<RunningRun>(run.id), initialData: run })
  const live = data ?? run
  const bottom = useRef<HTMLDivElement>(null)
  const notified = useRef(false)
  useEffect(() => {
    if (!notified.current && !['queued', 'running'].includes(live.status) && ['queued', 'running'].includes(run.status)) {
      notified.current = true
      onFinished(live)
    }
  }, [live, run.status, onFinished])
  useEffect(() => { bottom.current?.scrollIntoView({ block: 'nearest' }) }, [live.progress?.length])
  const active = ['queued', 'running'].includes(live.status)
  const elapsed = live.started_at ? Math.max(0, Math.round((Date.now() - Date.parse(live.started_at)) / 1000)) : 0
  return <Card className="overflow-hidden border-app-line bg-console">
    <div className="flex items-center justify-between gap-3 border-b border-app-line bg-console-top px-4 py-3 text-xs">
      <span className="flex items-center gap-2 font-mono text-app-muted"><Terminal className="size-3.5" />{live.source?.name ?? 'escaneo'} · {live.id.slice(0, 8)}</span>
      <span role="status" aria-live="polite" className={`flex items-center gap-1.5 ${active ? 'text-brand' : live.status === 'failed' ? 'text-danger' : 'text-app-muted'}`}>
        {active ? <LoaderCircle className="size-3.5 animate-spin" /> : live.status === 'failed' ? <CircleAlert className="size-3.5" /> : <CircleCheck className="size-3.5" />}
        {live.status === 'queued' ? 'En cola' : live.status === 'running' ? `Analizando · ${elapsed}s` : live.status === 'failed' ? 'Falló' : 'Terminado'}
      </span>
    </div>
    {/* 4.1.3: cada paso nuevo se anuncia; el nivel no depende solo del color (1.4.1). */}
    <CardContent role="log" aria-live="polite" aria-label="Progreso del análisis" tabIndex={0} className="max-h-72 overflow-y-auto p-4 font-mono text-xs leading-6">
      {(live.progress ?? []).map((event, index) => <div key={index} className="flex gap-3"><span className="shrink-0 text-app-subtle">{new Date(event.at).toLocaleTimeString('es-CO')}</span><span className={event.level === 'ok' ? 'text-brand' : event.level === 'warn' ? 'text-warning' : event.level === 'error' ? 'text-danger' : 'text-app-secondary'}>{event.level === 'warn' ? <span className="font-semibold">Aviso: </span> : event.level === 'error' ? <span className="font-semibold">Error: </span> : null}{event.message}</span></div>)}
      {active && <div aria-hidden className="flex gap-3 text-app-subtle"><span className="shrink-0">{new Date().toLocaleTimeString('es-CO')}</span><span className="motion-safe:animate-pulse">…</span></div>}
      <div ref={bottom} />
    </CardContent>
  </Card>
}

export function useToasts() {
  const [toasts, setToasts] = useState<{ id: number; tone: 'ok' | 'error'; text: string }[]>([])
  // 2.2.1: el aviso se pausa mientras el puntero o el foco están encima, y se puede cerrar.
  const timers = useRef(new Map<number, number>())
  const dismiss = (id: number) => { window.clearTimeout(timers.current.get(id)); timers.current.delete(id); setToasts(previous => previous.filter(item => item.id !== id)) }
  const schedule = (id: number) => { window.clearTimeout(timers.current.get(id)); timers.current.set(id, window.setTimeout(() => dismiss(id), 8000)) }
  const hold = (id: number) => { window.clearTimeout(timers.current.get(id)); timers.current.delete(id) }
  const push = (tone: 'ok' | 'error', text: string) => {
    const id = Date.now() + Math.random()
    setToasts(previous => [...previous, { id, tone, text }])
    schedule(id)
    // Aviso del navegador solo si el usuario ya lo permitió; nunca se pide permiso sin acción suya.
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') { try { new Notification(BRAND.name, { body: text, icon: '/assets/favicon.svg' }) } catch { /* sin notificaciones */ } }
  }
  const view = <div aria-live="polite" className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2">{toasts.map(item =>
    <div key={item.id} role={item.tone === 'error' ? 'alert' : 'status'} onMouseEnter={() => hold(item.id)} onMouseLeave={() => schedule(item.id)} onFocus={() => hold(item.id)} onBlur={() => schedule(item.id)}
      className={`pointer-events-auto flex items-start gap-2 rounded-xl border px-4 py-3 text-sm shadow-xl ${item.tone === 'ok' ? 'border-brand/30 bg-panel text-app-fg' : 'border-danger-line bg-panel text-danger'}`}>
      <span className="min-w-0 flex-1">{item.text}</span>
      <button type="button" onClick={() => dismiss(item.id)} aria-label="Cerrar aviso" className="-m-1 grid size-6 shrink-0 place-items-center rounded-md text-app-muted hover:bg-app-soft hover:text-app-fg"><X className="size-3.5" /></button>
    </div>)}</div>
  return { push, view }
}
