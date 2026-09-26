import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { BellRing, LoaderCircle, Plus, Send, ShieldCheck, Trash2 } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import { intlLocale } from '@/shared/i18n'
import { formatDate } from '@/shared/lib/types'
import { SkeletonList } from '@/shared/ui/loading'
import { CodeBlock } from '@/features/findings/fix-guide'

type Kind = 'slack' | 'teams' | 'webhook'
type Channel = { id: string; kind: Kind; name: string; host: string; events: string[]; threshold: string; signed: boolean
  created_by?: string; created_at?: string; last?: { at: string; ok: boolean; detail: string } | null }
type Listing = { channels: Channel[]; kinds: Record<Kind, string>; events: Record<string, string>; thresholds: string[]; links: boolean }

const THRESHOLD: Record<string, string> = { critical: 'notifications.threshold.critical', high: 'notifications.threshold.high', medium: 'notifications.threshold.medium' }
const HINT = { slack: 'notifications.hint.slack', teams: 'notifications.hint.teams', webhook: 'notifications.hint.webhook' } as const

// Avisos a Slack, Teams o un webhook cuando aparece algo que importa, sin tener que abrir el panel.
export function NotificationsCard() {
  const { t } = useTranslation('integrations')
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
  const thresholdLabel = (value: string) => THRESHOLD[value] ? t(THRESHOLD[value]) : value

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('save'); setError(''); setNotice('')
    try {
      const result = await api.post<{ channel: Channel; secret: string | null }>('/api/notifications', 'notifications', { op: 'save', kind, name: name.trim(), url: url.trim(), events, threshold })
      setData(previous => previous ? { ...previous, channels: [...previous.channels, result.channel] } : previous)
      setSecret(result.secret); setName(''); setUrl(''); setAdding(false)
      setNotice(t('notifications.saved', { name: result.channel.name }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const act = async (op: 'remove' | 'test', channel: Channel) => {
    // La URL no vuelve al navegador: quitar un canal obliga a pedirla de nuevo en Slack o Teams.
    if (op === 'remove' && !window.confirm(t('notifications.confirm_remove', { name: channel.name }))) return
    setBusy(`${op}:${channel.id}`); setError(''); setNotice('')
    try {
      const result = await api.post<{ channels: Channel[]; ok?: boolean; detail?: string }>('/api/notifications', 'notifications', { op, id: channel.id })
      setData(previous => previous ? { ...previous, channels: result.channels } : previous)
      if (op === 'test' && result.ok) setNotice(t('notifications.test_ok', { name: channel.name, detail: result.detail ?? '' }))
      if (op === 'test' && !result.ok) setError(t('notifications.test_failed', { name: channel.name, detail: result.detail ?? '' }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }

  return <Card className="border-app-line bg-panel">
    <CardHeader><CardTitle className="flex items-center gap-2"><BellRing className="size-5 text-app-muted" />{t('notifications.title')}</CardTitle>
      <CardDescription>{t('notifications.description')}</CardDescription></CardHeader>
    <CardContent className="space-y-4">
      {!data && !error && <SkeletonList rows={2} dense label={t('notifications.loading')} />}
      {data && data.channels.length > 0 && <div className="divide-y divide-app-line rounded-xl border border-app-line">{data.channels.map(channel => <div key={channel.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <span className="min-w-0"><span className="block text-sm font-medium">{channel.name} <span className="font-normal text-app-subtle">· {data.kinds[channel.kind]}</span></span>
          <span className="block text-xs text-app-subtle">{channel.host} · {new Intl.ListFormat(intlLocale(), { type: 'conjunction' }).format(channel.events.map(item => data.events[item] ?? item)).toLowerCase()} · {thresholdLabel(channel.threshold).toLowerCase()}{channel.signed ? ` · ${t('notifications.signed')}` : ''}</span>
          {channel.last && <span className={`block text-xs ${channel.last.ok ? 'text-app-subtle' : 'text-danger'}`}>{channel.last.ok ? t('notifications.last_ok', { date: formatDate(channel.last.at) }) : t('notifications.last_failed', { date: formatDate(channel.last.at), detail: channel.last.detail })}</span>}</span>
        <span className="flex gap-1">
          <Button variant="ghost" size="sm" aria-label={t('notifications.test_label', { name: channel.name })} disabled={!!busy} onClick={() => void act('test', channel)}>{busy === `test:${channel.id}` ? <LoaderCircle className="animate-spin" /> : <Send />}{t('notifications.test')}</Button>
          <Button variant="ghost" size="sm" aria-label={t('notifications.remove_label', { name: channel.name })} disabled={!!busy} onClick={() => void act('remove', channel)}>{busy === `remove:${channel.id}` ? <LoaderCircle className="animate-spin" /> : <Trash2 />}{t('common:actions.remove')}</Button></span>
      </div>)}</div>}
      {secret && <div className="space-y-2 rounded-xl border border-warning-line bg-warning-soft p-3 text-xs text-warning">
        <p className="font-medium">{t('notifications.secret_title')}</p>
        <CodeBlock code={secret} label={t('notifications.secret_label')} />
        <p>{t('notifications.secret_help')}</p>
        <Button size="sm" variant="ghost" onClick={() => setSecret(null)}>{t('notifications.secret_saved')}</Button></div>}
      {data && !formOpen && <Button variant="outline" onClick={() => setAdding(true)} className="border-app-line bg-app-soft"><Plus />{t('notifications.add')}</Button>}
      {data && formOpen && <form onSubmit={save} className="space-y-4 rounded-xl border border-app-line bg-inset p-4">
        <fieldset className="space-y-2"><legend className="text-xs text-app-muted">{t('notifications.where')}</legend>
          <div className="grid gap-2 sm:grid-cols-3">{(Object.keys(data.kinds) as Kind[]).map(item => <label key={item} className={`flex cursor-pointer items-center gap-2 rounded-lg border p-3 text-sm ${kind === item ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-panel'}`}>
            <input type="radio" name="notify-kind" value={item} checked={kind === item} onChange={() => setKind(item)} className="size-4 accent-brand" />{data.kinds[item]}</label>)}</div>
          <p className="text-xs text-app-subtle">{t(HINT[kind])}</p></fieldset>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-1.5"><label htmlFor="notify-name" className="text-xs text-app-muted">{t('notifications.name')}</label><Input id="notify-name" required maxLength={60} value={name} onChange={event => setName(event.target.value)} placeholder={t('notifications.name_placeholder')} className="border-app-line bg-app-soft" /></div>
          <div className="space-y-1.5"><label htmlFor="notify-url" className="text-xs text-app-muted">{t('notifications.url')}</label><Input id="notify-url" required type="password" autoComplete="off" maxLength={2048} value={url} onChange={event => setUrl(event.target.value)} placeholder="https://…" className="border-app-line bg-app-soft font-mono" /></div>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <fieldset className="space-y-1.5"><legend className="text-xs text-app-muted">{t('notifications.events')}</legend>{Object.entries(data.events).map(([id, label]) => <label key={id} className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={events.includes(id)} onChange={event => setEvents(previous => event.target.checked ? [...previous, id] : previous.filter(item => item !== id))} className="size-4 accent-brand" />{label}</label>)}</fieldset>
          <div className="space-y-1.5"><label htmlFor="notify-threshold" className="text-xs text-app-muted">{t('notifications.threshold_label')}</label>
            <select id="notify-threshold" value={threshold} disabled={!events.includes('findings')} onChange={event => setThreshold(event.target.value)} className="h-9 w-full rounded-lg border border-app-line bg-app-soft px-2 text-sm">{data.thresholds.map(item => <option key={item} value={item}>{thresholdLabel(item)}</option>)}</select></div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={!!busy || !events.length} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'save' ? <LoaderCircle className="animate-spin" /> : <BellRing />}{t('notifications.save')}</Button>
          {data.channels.length > 0 && <Button type="button" variant="ghost" onClick={() => setAdding(false)}>{t('common:actions.cancel')}</Button>}
          <span className="flex items-center gap-1.5 text-xs text-app-subtle"><ShieldCheck className="size-3.5" />{t('notifications.url_note')}</span>
        </div>
        {!data.links && <p className="text-xs text-app-subtle">{t('notifications.links_note')}</p>}
      </form>}
      {/* Regiones vivas siempre montadas: así se anuncia el texto cuando cambia. */}
      <p role="status" className="text-xs text-app-muted empty:hidden">{notice}</p>
      <div role="alert" className={error ? 'rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger' : 'hidden'}>{error}</div>
    </CardContent>
  </Card>
}
