import { useEffect, useState, type ComponentProps, type FormEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { ExternalLink, LoaderCircle, PlugZap, Ticket } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import { formatDate } from '@/shared/lib/types'
import { SkeletonCard } from '@/shared/ui/loading'

export type JiraStatus = { configured: false } | { configured: true; site: string; email: string; project: string; project_name?: string | null; issue_type: string; last4: string; saved_at?: string; saved_by?: string }
export type TicketLink = { key: string; url: string; by?: string; linked_at?: string }
type ExportResult = { created: (TicketLink & { fingerprint: string })[]; existing: (TicketLink & { fingerprint: string })[]; failed: { fingerprint: string; error: string }[] }
type LinkState = 'created' | 'existing'
const STATE_LABEL = { created: 'jira.export.state.created', existing: 'jira.export.state.existing' } as const

export function useJiraStatus() {
  const [status, setStatus] = useState<JiraStatus | null>(null)
  useEffect(() => { api.get<JiraStatus>('/api/integrations/jira').then(setStatus).catch(() => setStatus({ configured: false })) }, [])
  return [status, setStatus] as const
}

// Tarjeta de Integraciones. Solo un administrador guarda o retira la credencial.
export function JiraCard({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation('integrations')
  const [status, setStatus] = useJiraStatus()
  const [form, setForm] = useState({ site: '', email: '', token: '', project: '', issue_type: 'Task' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const set = (key: keyof typeof form) => (event: { target: { value: string } }) => setForm(previous => ({ ...previous, [key]: event.target.value }))
  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    try { setStatus(await api.post<JiraStatus>('/api/integrations/jira', 'connect-jira', { action: 'save', ...form })); setForm(previous => ({ ...previous, token: '' })) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const remove = async () => {
    setBusy(true); setError('')
    try { setStatus(await api.post<JiraStatus>('/api/integrations/jira', 'connect-jira', { action: 'remove' })) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const configured = status?.configured ? status : null
  const configuredBy = !configured ? null
    : configured.saved_by && configured.saved_at ? t('jira.configured_by_on', { name: configured.saved_by, date: formatDate(configured.saved_at) })
    : configured.saved_by ? t('jira.configured_by', { name: configured.saved_by })
    : configured.saved_at ? t('jira.configured_on', { date: formatDate(configured.saved_at) }) : null
  return <div className="rounded-xl border border-app-line bg-inset p-5">
    <div className="flex items-start justify-between gap-3"><div className="flex items-center gap-3"><div className="rounded-xl bg-brand/10 p-2 text-brand"><Ticket className="size-5" /></div><div><h3 className="font-semibold">Jira Cloud</h3><p className="text-xs text-app-subtle">{configured
      ? configured.project_name ? t('jira.site_project_named', { site: configured.site, project: configured.project, name: configured.project_name }) : t('jira.site_project', { site: configured.site, project: configured.project })
      : t('jira.tagline')}</p></div></div>
      {status && <Badge variant="outline" className={status.configured ? 'border-brand/30 text-brand' : 'border-app-line text-app-muted'}>{status.configured ? t('jira.status.connected') : t('jira.status.not_configured')}</Badge>}</div>
    {!status ? <div className="mt-5"><SkeletonCard lines={2} label={t('jira.loading')} /></div> : configured ? <div className="mt-5 space-y-3 text-sm text-app-muted">
      <p>{[t('jira.account', { email: configured.email, last4: configured.last4, type: configured.issue_type }), configuredBy].filter(Boolean).join(' · ')}</p>
      <p className="text-xs leading-5 text-app-subtle"><Trans t={t} i18nKey="jira.label_note" shouldUnescape components={{ code: <code className="font-mono" /> }} /></p>
      {canManage && <Button variant="ghost" disabled={busy} onClick={() => void remove()}>{t('jira.remove')}</Button>}
    </div> : canManage ? <form className="mt-5 grid gap-3 sm:grid-cols-2" onSubmit={save}>
      <Field id="jira-site" label={t('jira.site')} placeholder={t('jira.site_placeholder')} value={form.site} onChange={set('site')} />
      <Field id="jira-email" label={t('jira.email')} type="email" autoComplete="username" value={form.email} onChange={set('email')} />
      <Field id="jira-token" label={t('jira.token')} type="password" autoComplete="new-password" minLength={16} value={form.token} onChange={set('token')} />
      <div className="grid grid-cols-2 gap-3"><Field id="jira-project" label={t('jira.project')} placeholder="SEC" maxLength={10} value={form.project} onChange={set('project')} /><Field id="jira-type" label={t('jira.issue_type')} value={form.issue_type} onChange={set('issue_type')} /></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger sm:col-span-2">{error}</div>}
      <div className="flex flex-wrap items-center gap-3 sm:col-span-2"><Button type="submit" disabled={busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <PlugZap />}{t('jira.submit')}</Button>
        <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand hover:underline">{t('jira.create_token')} <ExternalLink className="size-3" /></a></div>
      <p className="text-xs leading-5 text-app-subtle sm:col-span-2">{t('jira.validate_note')}</p>
    </form> : <p className="mt-5 text-sm text-app-muted">{t('jira.admin_only')}</p>}
  </div>
}

function Field({ id, label, ...props }: { id: string; label: string } & ComponentProps<typeof Input>) {
  return <div className="space-y-1.5"><label htmlFor={id} className="text-xs text-app-muted">{label}</label><Input id={id} required {...props} className="border-app-line bg-app-soft" /></div>
}

// Resultado de una exportación: qué se creó, qué ya existía y qué falló, con enlace a cada incidencia.
export function JiraExportDialog({ runId, fingerprints, onClose, onDone }: { runId: string; fingerprints: string[] | null; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation('integrations')
  const [result, setResult] = useState<ExportResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (!fingerprints) return null
  const run = async () => {
    setBusy(true); setError('')
    try { setResult(await api.post<ExportResult>('/api/integrations/jira/issues', 'export-jira', { run_id: runId, fingerprints })); onDone() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  // Varios hallazgos de un paquete comparten incidencia: se cuenta y se lista cada incidencia una vez.
  const byKey = new Map<string, TicketLink & { state: LinkState; findings: number }>()
  for (const [items, state] of [[result?.created ?? [], 'created'], [result?.existing ?? [], 'existing']] as const)
    for (const item of items) { const entry = byKey.get(item.key); if (entry) entry.findings++; else byKey.set(item.key, { ...item, state, findings: 1 }) }
  const links = [...byKey.values()]
  const createdIssues = links.filter(item => item.state === 'created').length
  const summary = result ? `${[
    t('jira.export.created', { count: createdIssues }),
    t('jira.export.existing', { count: links.length - createdIssues }),
    ...(result.failed.length ? [t('jira.export.failed', { count: result.failed.length })] : []),
  ].join(', ')} · ${t('jira.export.linked', { count: result.created.length + result.existing.length })}` : t('jira.export.intro')
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>{t('jira.export.title', { count: fingerprints.length })}</DialogTitle><DialogDescription>{summary}</DialogDescription></DialogHeader>
    {links.length > 0 && <ul className="max-h-60 space-y-1 overflow-y-auto text-sm">{links.map(item => <li key={item.key} className="flex items-center justify-between gap-2"><a href={item.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-mono text-brand hover:underline">{item.key}<ExternalLink className="size-3" /></a><span className="text-xs text-app-subtle">{t(STATE_LABEL[item.state])}{item.findings > 1 ? ` · ${t('common:count.findings', { count: item.findings })}` : ''}</span></li>)}</ul>}
    {result?.failed.length ? <ul className="space-y-1 text-xs text-danger">{result.failed.slice(0, 5).map(item => <li key={item.fingerprint}>{item.fingerprint.slice(0, 12)} · {item.error}</li>)}</ul> : null}
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
    <DialogFooter>{result ? <Button onClick={onClose} className="bg-primary text-primary-foreground hover:bg-primary/90">{t('jira.export.done')}</Button> : <><Button variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button disabled={busy} onClick={() => void run()} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <Ticket />}{t('jira.export.submit')}</Button></>}</DialogFooter>
  </DialogContent></Dialog>
}
