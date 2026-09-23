import { useEffect, useRef, useState } from 'react'
import { api } from '@/lib/api'
import { BRAND } from '@/lib/brand'
import { CircleAlert, CircleCheck, LoaderCircle, Terminal } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'

export type ProgressEvent = { at: string; level: 'info' | 'ok' | 'warn' | 'error'; message: string }
export type RunningRun = { id: string; status: string; created_at: string; started_at?: string; finished_at?: string; source?: { name: string }; progress?: ProgressEvent[] }

// Consola de progreso del escaneo: solo eventos pensados para el usuario, nunca salida del servidor.
export function RunProgress({ run, onFinished }: { run: RunningRun; onFinished: (run: RunningRun) => void }) {
  const [live, setLive] = useState<RunningRun>(run)
  const bottom = useRef<HTMLDivElement>(null)
  useEffect(() => { setLive(run) }, [run])
  useEffect(() => {
    if (!['queued', 'running'].includes(live.status)) return
    const timer = window.setInterval(async () => {
      try {
        const next = await api.get<RunningRun>(`/api/runs/${encodeURIComponent(live.id)}`)
        setLive(next)
        if (!['queued', 'running'].includes(next.status)) { window.clearInterval(timer); onFinished(next) }
      } catch { /* la siguiente vuelta reintenta */ }
    }, 2000)
    return () => window.clearInterval(timer)
  }, [live.id, live.status, onFinished])
  useEffect(() => { bottom.current?.scrollIntoView({ block: 'nearest' }) }, [live.progress?.length])
  const active = ['queued', 'running'].includes(live.status)
  const elapsed = live.started_at ? Math.max(0, Math.round((Date.now() - Date.parse(live.started_at)) / 1000)) : 0
  return <Card className="overflow-hidden border-app-line bg-console">
    <div className="flex items-center justify-between gap-3 border-b border-app-line bg-console-top px-4 py-3 text-xs">
      <span className="flex items-center gap-2 font-mono text-app-muted"><Terminal className="size-3.5" />{live.source?.name ?? 'escaneo'} · {live.id.slice(0, 8)}</span>
      <span className={`flex items-center gap-1.5 ${active ? 'text-brand' : live.status === 'failed' ? 'text-rose-700 dark:text-rose-300' : 'text-app-muted'}`}>
        {active ? <LoaderCircle className="size-3.5 animate-spin" /> : live.status === 'failed' ? <CircleAlert className="size-3.5" /> : <CircleCheck className="size-3.5" />}
        {live.status === 'queued' ? 'En cola' : live.status === 'running' ? `Analizando · ${elapsed}s` : live.status === 'failed' ? 'Falló' : 'Terminado'}
      </span>
    </div>
    <CardContent className="max-h-72 overflow-y-auto p-4 font-mono text-xs leading-6">
      {(live.progress ?? []).map((event, index) => <div key={index} className="flex gap-3"><span className="shrink-0 text-app-faint">{new Date(event.at).toLocaleTimeString('es-CO')}</span><span className={event.level === 'ok' ? 'text-brand' : event.level === 'warn' ? 'text-amber-700 dark:text-amber-300' : event.level === 'error' ? 'text-rose-700 dark:text-rose-300' : 'text-app-secondary'}>{event.message}</span></div>)}
      {active && <div className="flex gap-3 text-app-subtle"><span className="shrink-0 text-app-faint">{new Date().toLocaleTimeString('es-CO')}</span><span className="animate-pulse">…</span></div>}
      <div ref={bottom} />
    </CardContent>
  </Card>
}

export function useToasts() {
  const [toasts, setToasts] = useState<{ id: number; tone: 'ok' | 'error'; text: string }[]>([])
  const push = (tone: 'ok' | 'error', text: string) => {
    const id = Date.now() + Math.random()
    setToasts(previous => [...previous, { id, tone, text }])
    window.setTimeout(() => setToasts(previous => previous.filter(item => item.id !== id)), 8000)
    // Aviso del navegador solo si el usuario ya lo permitió; nunca se pide permiso sin acción suya.
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') { try { new Notification(BRAND.name, { body: text, icon: '/assets/favicon.svg' }) } catch { /* sin notificaciones */ } }
  }
  const view = <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2">{toasts.map(item => <div key={item.id} className={`pointer-events-auto rounded-xl border px-4 py-3 text-sm shadow-xl ${item.tone === 'ok' ? 'border-brand/30 bg-panel text-app-fg' : 'border-rose-500/30 bg-panel text-rose-700 dark:text-rose-300'}`}>{item.text}</div>)}</div>
  return { push, view }
}
