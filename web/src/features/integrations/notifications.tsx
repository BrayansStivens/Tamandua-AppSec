import { useEffect, useState, type FormEvent } from 'react'
import { BellRing, LoaderCircle, Plus, Send, ShieldCheck, Trash2 } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import { formatDate } from '@/shared/lib/types'
import { SkeletonList } from '@/shared/ui/loading'
import { CodeBlock } from '@/features/findings/fix-guide'

type Kind = 'slack' | 'teams' | 'webhook'
type Channel = { id: string; kind: Kind; name: string; host: string; events: string[]; threshold: string; signed: boolean
  created_by?: string; created_at?: string; last?: { at: string; ok: boolean; detail: string } | null }
type Listing = { channels: Channel[]; kinds: Record<Kind, string>; events: Record<string, string>; thresholds: string[]; links: boolean }

const THRESHOLD = { critical: 'Solo críticos', high: 'Altos o superior', medium: 'Medios o superior' } as Record<string, string>
const HINT: Record<Kind, string> = {
  slack: 'En Slack: Apps → Incoming Webhooks → Add to Slack, elige el canal y copia la URL (https://hooks.slack.com/…).',
  teams: 'En Teams: en el canal, … → Workflows → «Publicar en un canal cuando se reciba una solicitud de webhook» y copia la URL.',
  webhook: 'Cualquier servicio que acepte un POST con JSON. Cada aviso lleva la cabecera X-Tamandua-Signature (HMAC-SHA256 del cuerpo).',
}

// Avisos a Slack, Teams o un webhook cuando aparece algo que importa, sin tener que abrir el panel.
export function NotificationsCard() {
  const [data, setData] = useState<Listing | null>(null)
  const [adding, setAdding] = useState(false)
  const [kind, setKind] = useState<Kind>('slack')
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [events, setEvents] = useState<string[]>(['findings'])
  const [threshold, setThreshold] = useState('high')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [secret, setSecret] = useState<string | null>(null)
  useEffect(() => { api.get<Listing>('/api/notifications').then(setData).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [])
  const formOpen = adding || (data !== null && data.channels.length === 0)

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('save'); setError(''); setNotice('')
    try {
      const result = await api.post<{ channel: Channel; secret: string | null }>('/api/notifications', 'notifications', { op: 'save', kind, name: name.trim(), url: url.trim(), events, threshold })
      setData(previous => previous ? { ...previous, channels: [...previous.channels, result.channel] } : previous)
      setSecret(result.secret); setName(''); setUrl(''); setAdding(false)
      setNotice(`Canal «${result.channel.name}» guardado. Envía una prueba para comprobarlo.`)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const act = async (op: 'remove' | 'test', channel: Channel) => {
    // La URL no vuelve al navegador: quitar un canal obliga a pedirla de nuevo en Slack o Teams.
    if (op === 'remove' && !window.confirm(`¿Quitar «${channel.name}»? Para volver a añadirlo necesitarás la URL del webhook otra vez.`)) return
    setBusy(`${op}:${channel.id}`); setError(''); setNotice('')
    try {
      const result = await api.post<{ channels: Channel[]; ok?: boolean; detail?: string }>('/api/notifications', 'notifications', { op, id: channel.id })
      setData(previous => previous ? { ...previous, channels: result.channels } : previous)
      if (op === 'test' && result.ok) setNotice(`Prueba entregada a «${channel.name}» (${result.detail}).`)
      if (op === 'test' && !result.ok) setError(`La prueba a «${channel.name}» falló: ${result.detail}. Revisa la URL o crea el webhook de nuevo.`)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }

  return <Card className="border-app-line bg-panel">
    <CardHeader><CardTitle className="flex items-center gap-2"><BellRing className="size-5 text-app-muted" />Avisos</CardTitle>
      <CardDescription>Un mensaje en Slack, Teams o un webhook cuando un análisis (manual, en lote o automático) encuentra algo nuevo que importa, o cuando termina un lote. Las revisiones de PR ya avisan en el propio PR.</CardDescription></CardHeader>
    <CardContent className="space-y-4">
      {!data && !error && <SkeletonList rows={2} dense label="Cargando canales" />}
      {data && data.channels.length > 0 && <div className="divide-y divide-app-line rounded-xl border border-app-line">{data.channels.map(channel => <div key={channel.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <span className="min-w-0"><span className="block text-sm font-medium">{channel.name} <span className="font-normal text-app-subtle">· {data.kinds[channel.kind]}</span></span>
          <span className="block text-xs text-app-subtle">{channel.host} · {channel.events.map(item => data.events[item]).join(' y ').toLowerCase()} · {THRESHOLD[channel.threshold]?.toLowerCase()}{channel.signed ? ' · firmado' : ''}</span>
          {channel.last && <span className={`block text-xs ${channel.last.ok ? 'text-app-subtle' : 'text-danger'}`}>Último envío {formatDate(channel.last.at)}: {channel.last.ok ? 'entregado' : `falló (${channel.last.detail})`}</span>}</span>
        <span className="flex gap-1">
          <Button variant="ghost" size="sm" aria-label={`Probar ${channel.name}`} disabled={!!busy} onClick={() => void act('test', channel)}>{busy === `test:${channel.id}` ? <LoaderCircle className="animate-spin" /> : <Send />}Probar</Button>
          <Button variant="ghost" size="sm" aria-label={`Quitar ${channel.name}`} disabled={!!busy} onClick={() => void act('remove', channel)}>{busy === `remove:${channel.id}` ? <LoaderCircle className="animate-spin" /> : <Trash2 />}Quitar</Button></span>
      </div>)}</div>}
      {secret && <div className="space-y-2 rounded-xl border border-warning-line bg-warning-soft p-3 text-xs text-warning">
        <p className="font-medium">Secreto de firma de este webhook: guárdalo ahora, no se vuelve a mostrar.</p>
        <CodeBlock code={secret} label="secreto de firma" />
        <p>El receptor calcula HMAC-SHA256 del cuerpo con este secreto y lo compara con la cabecera X-Tamandua-Signature.</p>
        <Button size="sm" variant="ghost" onClick={() => setSecret(null)}>Ya lo guardé</Button></div>}
      {data && !formOpen && <Button variant="outline" onClick={() => setAdding(true)} className="border-app-line bg-app-soft"><Plus />Añadir canal</Button>}
      {data && formOpen && <form onSubmit={save} className="space-y-4 rounded-xl border border-app-line bg-inset p-4">
        <fieldset className="space-y-2"><legend className="text-xs text-app-muted">Dónde</legend>
          <div className="grid gap-2 sm:grid-cols-3">{(Object.keys(data.kinds) as Kind[]).map(item => <label key={item} className={`flex cursor-pointer items-center gap-2 rounded-lg border p-3 text-sm ${kind === item ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-panel'}`}>
            <input type="radio" name="notify-kind" value={item} checked={kind === item} onChange={() => setKind(item)} className="size-4 accent-brand" />{data.kinds[item]}</label>)}</div>
          <p className="text-xs text-app-subtle">{HINT[kind]}</p></fieldset>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-1.5"><label htmlFor="notify-name" className="text-xs text-app-muted">Nombre</label><Input id="notify-name" required maxLength={60} value={name} onChange={event => setName(event.target.value)} placeholder="p. ej. #seguridad" className="border-app-line bg-app-soft" /></div>
          <div className="space-y-1.5"><label htmlFor="notify-url" className="text-xs text-app-muted">URL del webhook</label><Input id="notify-url" required type="password" autoComplete="off" maxLength={2048} value={url} onChange={event => setUrl(event.target.value)} placeholder="https://…" className="border-app-line bg-app-soft font-mono" /></div>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <fieldset className="space-y-1.5"><legend className="text-xs text-app-muted">Avisar de</legend>{Object.entries(data.events).map(([id, label]) => <label key={id} className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={events.includes(id)} onChange={event => setEvents(previous => event.target.checked ? [...previous, id] : previous.filter(item => item !== id))} className="size-4 accent-brand" />{label}</label>)}</fieldset>
          <div className="space-y-1.5"><label htmlFor="notify-threshold" className="text-xs text-app-muted">Hallazgos desde</label>
            <select id="notify-threshold" value={threshold} disabled={!events.includes('findings')} onChange={event => setThreshold(event.target.value)} className="h-9 w-full rounded-lg border border-app-line bg-app-soft px-2 text-sm">{data.thresholds.map(item => <option key={item} value={item}>{THRESHOLD[item]}</option>)}</select></div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={!!busy || !events.length} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'save' ? <LoaderCircle className="animate-spin" /> : <BellRing />}Guardar canal</Button>
          {data.channels.length > 0 && <Button type="button" variant="ghost" onClick={() => setAdding(false)}>Cancelar</Button>}
          <span className="flex items-center gap-1.5 text-xs text-app-subtle"><ShieldCheck className="size-3.5" />La URL se guarda cifrada y nunca vuelve al navegador.</span>
        </div>
        {!data.links && <p className="text-xs text-app-subtle">Para que los mensajes enlacen al hallazgo, define TAMANDUA_PUBLIC_URL con la dirección del panel.</p>}
      </form>}
      {/* Regiones vivas siempre montadas: así se anuncia el texto cuando cambia. */}
      <p role="status" className="text-xs text-app-muted empty:hidden">{notice}</p>
      <div role="alert" className={error ? 'rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger' : 'hidden'}>{error}</div>
    </CardContent>
  </Card>
}
