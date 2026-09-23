import { useState, type FormEvent } from 'react'
import { ArrowRight, ChevronRight, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { api } from '@/lib/api'
import type { RunDetail, RunRow, Summary } from '@/lib/runs'

type LogEntry = { at: string; level: 'info' | 'ok' | 'warn' | 'error'; message: string }
const clip = (value: string) => value.slice(0, 8)
const statusText = (status: string) => ({ completed: 'Completada', incomplete: 'Incompleta', failed: 'Fallida', reported: 'Reproducido', no_issue_observed: 'No observado', needs_follow_up: 'Pendiente' }[status] ?? status)

// Consola guiada: una lista cerrada de comandos sobre el laboratorio propio, nunca un shell.
export function Console({ refresh }: { refresh: () => Promise<RunRow[]> }) {
  const [command, setCommand] = useState('scan lab both')
  const [busy, setBusy] = useState(false)
  const [logs, setLogs] = useState<LogEntry[]>([{ at: new Date().toLocaleTimeString('es-CO'), level: 'info', message: 'Consola lista. Escribe help para ver los comandos permitidos.' }])
  const appendLog = (level: LogEntry['level'], message: string) => setLogs(previous => [...previous, { at: new Date().toLocaleTimeString('es-CO'), level, message }])

  const startScan = async (variant: 'both' | 'vulnerable' | 'fixed') => {
    if (busy) return
    setBusy(true)
    appendLog('info', `Iniciando scan lab ${variant} sobre el fixture autorizado…`)
    try {
      const payload = await api.post<{ runs: { id: string; variant: string; status: string; summary: Summary }[] }>('/api/lab/scans', 'scan-lab', { variant })
      for (const run of payload.runs) appendLog(run.status === 'completed' ? 'ok' : 'warn', `${run.variant}: ${run.summary.confirmed ?? 0} hallazgos, ${run.summary.executed ?? 0}/${run.summary.planned ?? 0} pruebas · run ${clip(run.id)}`)
      await refresh()
      const target = payload.runs.find(run => run.variant === 'vulnerable') ?? payload.runs[0]
      const run = await api.get<RunDetail>(`/api/runs/${encodeURIComponent(target.id)}`)
      for (const item of run.coverage ?? []) {
        const level = item.status === 'reported' ? 'warn' : item.status === 'needs_follow_up' ? 'error' : 'ok'
        appendLog(level, `${item.probe_id} · ${item.endpoint} · ${statusText(item.status)}${item.reason ? ` · ${item.reason}` : ''}`)
      }
      appendLog('info', `Reporte: /api/runs/${target.id}/report.md`)
    } catch (caught) { appendLog('error', caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(false) }
  }
  const execute = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const normalized = command.trim().toLowerCase().replace(/\s+/g, ' ')
    appendLog('info', `$ ${normalized}`)
    if (normalized === 'help') appendLog('ok', 'Comandos: help · runs · scan lab both · scan lab vulnerable · scan lab fixed')
    else if (normalized === 'runs') { try { const data = await refresh(); appendLog('ok', `${data.length} ejecuciones locales registradas`) } catch (caught) { appendLog('error', String(caught)) } }
    else if (normalized === 'scan lab both' || normalized === 'scan lab vulnerable' || normalized === 'scan lab fixed') await startScan(normalized.split(' ')[2] as 'both' | 'vulnerable' | 'fixed')
    else appendLog('warn', 'Comando desconocido. No se ejecuta shell arbitrario; usa help.')
    setCommand('')
  }
  return <div className="grid gap-5 xl:grid-cols-[1.45fr_0.8fr]">
      <Card className="overflow-hidden border-app-line bg-console"><CardHeader className="border-b border-app-line bg-console-top"><div className="flex items-center gap-2"><span className="size-2 rounded-full bg-rose-400/80" /><span className="size-2 rounded-full bg-amber-400/80" /><span className="size-2 rounded-full bg-brand/80" /><span className="ml-3 font-mono text-xs text-app-muted">appsec-agent / consola guiada</span></div></CardHeader><CardContent className="p-0"><ScrollArea className="h-[420px] p-5"><div className="space-y-2 font-mono text-xs leading-6">{logs.map((entry, index) => <div key={index} className="flex gap-3"><span className="shrink-0 text-app-faint">{entry.at}</span><span className={entry.level === 'ok' ? 'text-brand' : entry.level === 'warn' ? 'text-amber-700 dark:text-amber-300' : entry.level === 'error' ? 'text-rose-700 dark:text-rose-300' : 'text-app-secondary'}>{entry.message}</span></div>)}</div></ScrollArea><form onSubmit={execute} className="flex items-center gap-2 border-t border-app-line p-4"><span className="font-mono text-brand">$</span><Input aria-label="Comando" value={command} onChange={event => setCommand(event.target.value)} placeholder="help o scan lab both" className="border-0 bg-transparent font-mono text-xs shadow-none focus-visible:ring-0" /><Button aria-label="Ejecutar comando" type="submit" disabled={busy || !command.trim()}>{busy ? <RefreshCw className="animate-spin" /> : <ArrowRight />}</Button></form></CardContent></Card>
      <div className="space-y-5"><Card className="border-app-line bg-panel"><CardHeader><CardTitle>Comandos permitidos</CardTitle><CardDescription>Ejecutan únicamente el fixture propio.</CardDescription></CardHeader><CardContent className="space-y-2">{['scan lab both', 'scan lab vulnerable', 'scan lab fixed', 'runs', 'help'].map(value => <button key={value} onClick={() => setCommand(value)} className="flex w-full items-center justify-between rounded-lg border border-app-line bg-inset px-3 py-2 font-mono text-xs text-app-secondary hover:border-brand/40"><span>{value}</span><ChevronRight className="size-3" /></button>)}</CardContent></Card><Card className="border-app-line bg-panel"><CardContent className="pt-6 text-sm leading-6 text-app-muted">La CLI real se ejecuta en la terminal del equipo y guarda resultados en este dashboard: <code className="mt-2 block rounded-lg bg-inset p-3 font-mono text-xs text-brand">python3 -m appsec_agent sources<br />python3 -m appsec_agent scan-repository --source-id local:appsec-agent</code></CardContent></Card></div>
    </div>
}
