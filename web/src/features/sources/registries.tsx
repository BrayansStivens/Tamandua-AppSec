import { useEffect, useState, type FormEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { Boxes, KeyRound, LoaderCircle, ShieldCheck, Trash2 } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import { formatDate } from '@/shared/lib/types'
import { SkeletonList } from '@/shared/ui/loading'

type Registry = { registry: string; username: string; last4: string; saved_at: string | null; saved_by: string | null }

const HINTS = [
  ['registries.hints.ghcr.host', 'registries.hints.ghcr.user', 'registries.hints.ghcr.token'],
  ['registries.hints.docker.host', 'registries.hints.docker.user', 'registries.hints.docker.token'],
  ['registries.hints.ecr.host', 'registries.hints.ecr.user', 'registries.hints.ecr.token'],
  ['registries.hints.gar.host', 'registries.hints.gar.user', 'registries.hints.gar.token'],
] as const

// Credenciales de solo lectura para analizar imágenes de registros privados. Se guardan cifradas y no vuelven.
export function RegistriesCard({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation('sources')
  const [rows, setRows] = useState<Registry[] | null>(null)
  const [allowPrivate, setAllowPrivate] = useState(false)
  const [registry, setRegistry] = useState('')
  const [username, setUsername] = useState('')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  useEffect(() => { api.get<{ registries: Registry[]; allow_private: boolean }>('/api/registries').then(data => { setRows(data.registries); setAllowPrivate(data.allow_private) }).catch(caught => setError(String(caught))) }, [])

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('save'); setError('')
    try {
      const data = await api.post<{ registries: Registry[] }>('/api/registries', 'save-registry', { action: 'save', registry: registry.trim(), username: username.trim(), token })
      setRows(data.registries); setRegistry(''); setUsername(''); setToken('')
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const remove = async (host: string) => {
    setBusy(host); setError('')
    try { setRows((await api.post<{ registries: Registry[] }>('/api/registries', 'save-registry', { action: 'remove', registry: host })).registries) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const saved = (row: Registry) => row.saved_at && row.saved_by ? t('registries.saved_on_by', { date: formatDate(row.saved_at), name: row.saved_by })
    : row.saved_at ? formatDate(row.saved_at) : row.saved_by ? t('registries.saved_by', { name: row.saved_by }) : null

  return <Card className="border-app-line bg-panel">
    <CardHeader><CardTitle className="flex items-center gap-2"><Boxes className="size-5 text-app-muted" />{t('registries.title')}</CardTitle>
      <CardDescription><Trans t={t} i18nKey="registries.description" components={{ b: <strong className="font-medium" /> }} /></CardDescription></CardHeader>
    <CardContent className="space-y-4">
      {!rows && <SkeletonList rows={2} dense label={t('registries.loading')} />}
      {rows && rows.length > 0 && <div className="divide-y divide-app-line rounded-xl border border-app-line">{rows.map(row => <div key={row.registry} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <span className="min-w-0"><span className="block font-mono text-sm">{row.registry}</span><span className="text-xs text-app-subtle">{[row.username, t('registries.token_last4', { last4: row.last4 }), saved(row)].filter(Boolean).join(' · ')}</span></span>
        {canManage && <Button variant="ghost" size="sm" disabled={!!busy} onClick={() => void remove(row.registry)}>{busy === row.registry ? <LoaderCircle className="animate-spin" /> : <Trash2 />}{t('common:actions.remove')}</Button>}
      </div>)}</div>}
      {rows && rows.length === 0 && <p className="text-sm text-app-muted">{t('registries.empty')}</p>}
      {canManage ? <form onSubmit={save} className="grid gap-3 rounded-xl border border-app-line bg-inset p-4 md:grid-cols-3">
        <div className="space-y-1.5"><label htmlFor="registry-host" className="text-xs text-app-muted">{t('registries.host')}</label><Input id="registry-host" required value={registry} onChange={event => setRegistry(event.target.value)} maxLength={200} placeholder="ghcr.io" className="border-app-line bg-app-soft font-mono" /></div>
        <div className="space-y-1.5"><label htmlFor="registry-user" className="text-xs text-app-muted">{t('registries.username')}</label><Input id="registry-user" required value={username} onChange={event => setUsername(event.target.value)} maxLength={200} autoComplete="off" className="border-app-line bg-app-soft" /></div>
        <div className="space-y-1.5"><label htmlFor="registry-token" className="text-xs text-app-muted">{t('registries.token')}</label><Input id="registry-token" required type="password" autoComplete="new-password" value={token} onChange={event => setToken(event.target.value)} minLength={8} maxLength={4096} className="border-app-line bg-app-soft" /></div>
        <div className="flex flex-wrap items-center gap-3 md:col-span-3"><Button type="submit" disabled={!!busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'save' ? <LoaderCircle className="animate-spin" /> : <KeyRound />}{t('common:actions.save')}</Button>
          <span className="flex items-center gap-1.5 text-xs text-app-subtle"><ShieldCheck className="size-3.5" />{t('registries.stored_note')}</span></div>
      </form> : <p className="text-xs text-app-subtle">{t('registries.admin_only')}</p>}
      <details className="text-xs text-app-muted"><summary className="cursor-pointer">{t('registries.help')}</summary>
        <table className="mt-2 w-full text-left"><thead><tr className="text-app-subtle"><th scope="col" className="py-1.5 pr-3 font-medium">{t('registries.columns.registry')}</th><th scope="col" className="py-1.5 pr-3 font-medium">{t('registries.columns.username')}</th><th scope="col" className="py-1.5 font-medium">{t('registries.columns.token')}</th></tr></thead><tbody>{HINTS.map(([host, user, secret]) => <tr key={host} className="border-t border-app-line"><td className="py-1.5 pr-3 font-mono">{t(host)}</td><td className="py-1.5 pr-3">{t(user)}</td><td className="py-1.5">{t(secret)}</td></tr>)}</tbody></table>
        {!allowPrivate && <p className="mt-2"><Trans t={t} i18nKey="registries.private_blocked" components={{ code: <span className="font-mono" /> }} /></p>}
      </details>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
    </CardContent>
  </Card>
}
