import { useState, type ComponentProps, type FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { ExternalLink, LoaderCircle, PlugZap, Ticket } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { SkeletonCard, SkeletonList } from '@/shared/ui/loading'
import { apiPost } from '@/shared/api/client'
import { jiraBackfillQuery, jiraRoutingQuery, jiraStatusQuery, keys, type JiraStatus } from '@/shared/api/queries'
import { formatDate } from '@/shared/i18n/format'
import { DestinationsSection } from '@/features/integrations/jira-destinations'
import { RoutingHistory, RulesSection } from '@/features/integrations/jira-rules'
import type { JiraDestination, JiraRule } from '@/features/integrations/jira-routing'

// Integrations → Jira: the connection and, for administrators, where each finding's issue goes.
export function JiraCard({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation('integrations')
  const status = useQuery(jiraStatusQuery())
  const data = status.data
  return <div className="space-y-5">
    <ConnectionCard status={data} error={status.isError ? status.error.message : ''} canManage={canManage} />
    {data?.configured && (canManage ? <Routing /> : <p className="text-sm text-app-muted">{memberSummary(data, t)}</p>)}
  </div>
}

const memberSummary = (status: JiraStatus, t: ReturnType<typeof useTranslation>['t']) => [
  t('jira.summary.destinations', { count: status.destinations ?? 0 }), t('jira.summary.rules', { count: status.rules ?? 0 }),
  status.automatic ? t('jira.summary.automatic') : t('jira.summary.manual_only'),
].join(' · ')

function ConnectionCard({ status, error, canManage }: { status: JiraStatus | undefined; error: string; canManage: boolean }) {
  const { t } = useTranslation('integrations')
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ site: '', email: '', token: '' })
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState('')
  const [confirm, setConfirm] = useState(false)
  const set = (key: keyof typeof form) => (event: { target: { value: string } }) => setForm(previous => ({ ...previous, [key]: event.target.value }))
  const post = async (body: { action: 'save'; site: string; email: string; token: string } | { action: 'remove' }) => {
    setBusy(true); setFailure('')
    try {
      queryClient.setQueryData(keys.jira, await apiPost('/api/integrations/jira', 'connect-jira', body))
      void queryClient.invalidateQueries({ queryKey: keys.jira, predicate: query => query.queryKey.length > 1 })
      setForm(previous => ({ ...previous, token: '' })); setConfirm(false)
    } catch (caught) { setFailure(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const save = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (!busy) void post({ action: 'save', ...form }) }
  const configured = status?.configured ? status : null
  const configuredBy = !configured ? null
    : configured.saved_by && configured.saved_at ? t('jira.configured_by_on', { name: configured.saved_by, date: formatDate(configured.saved_at) })
    : configured.saved_by ? t('jira.configured_by', { name: configured.saved_by })
    : configured.saved_at ? t('jira.configured_on', { date: formatDate(configured.saved_at) }) : null
  return <div className="rounded-xl border border-app-line bg-inset p-5">
    <div className="flex items-start justify-between gap-3"><div className="flex items-center gap-3"><div className="rounded-xl bg-brand/10 p-2 text-brand"><Ticket className="size-5" /></div>
      <div><h3 className="font-semibold">Jira Cloud</h3><p className="text-xs text-app-subtle">{configured?.site ?? t('jira.tagline')}</p></div></div>
      {status && <Badge variant="outline" className={status.configured ? 'border-brand/30 text-brand' : 'border-app-line text-app-muted'}>{status.configured ? t('jira.status.connected') : t('jira.status.not_configured')}</Badge>}</div>
    {error ? <p role="alert" className="mt-5 text-sm text-danger">{error}</p>
      : !status ? <div className="mt-5"><SkeletonCard lines={2} label={t('jira.loading')} /></div>
      : configured ? <div className="mt-5 space-y-3 text-sm text-app-muted">
        <p>{[t('jira.account', { email: configured.email ?? '', last4: configured.last4 ?? '' }), configuredBy].filter(Boolean).join(' · ')}</p>
        <p className="text-xs leading-5 text-app-subtle"><Trans t={t} i18nKey="jira.label_note" shouldUnescape components={{ code: <code className="font-mono" /> }} /></p>
        {failure && <p role="alert" className="text-xs text-danger">{failure}</p>}
        {canManage && <Button variant="ghost" disabled={busy} onClick={() => setConfirm(true)}>{t('jira.remove')}</Button>}
      </div>
      : canManage ? <form className="mt-5 grid gap-3 sm:grid-cols-2" onSubmit={save}>
        <Field id="jira-site" label={t('jira.site')} placeholder={t('jira.site_placeholder')} value={form.site} onChange={set('site')} />
        <Field id="jira-email" label={t('jira.email')} type="email" autoComplete="username" value={form.email} onChange={set('email')} />
        <Field id="jira-token" label={t('jira.token')} type="password" autoComplete="new-password" minLength={16} value={form.token} onChange={set('token')} />
        {failure && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger sm:col-span-2">{failure}</div>}
        <div className="flex flex-wrap items-center gap-3 sm:col-span-2"><Button type="submit" disabled={busy}>{busy ? <LoaderCircle className="motion-safe:animate-spin" /> : <PlugZap />}{t('jira.submit')}</Button>
          <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand hover:underline">{t('jira.create_token')} <ExternalLink className="size-3" /></a></div>
        <p className="text-xs leading-5 text-app-subtle sm:col-span-2">{t('jira.validate_note')}</p>
      </form> : <p className="mt-5 text-sm text-app-muted">{t('jira.admin_only')}</p>}
    <Dialog open={confirm} onOpenChange={setConfirm}><DialogContent className="max-w-md">
      <DialogHeader><DialogTitle>{t('jira.remove_title')}</DialogTitle><DialogDescription>{t('jira.remove_help')}</DialogDescription></DialogHeader>
      {failure && <p role="alert" className="text-xs text-danger">{failure}</p>}
      <DialogFooter><Button variant="ghost" onClick={() => setConfirm(false)}>{t('common:actions.cancel')}</Button>
        <Button variant="destructive" disabled={busy} onClick={() => void post({ action: 'remove' })}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('jira.remove')}</Button></DialogFooter>
    </DialogContent></Dialog>
  </div>
}

function Field({ id, label, ...props }: { id: string; label: string } & ComponentProps<typeof Input>) {
  return <div className="space-y-1.5"><label htmlFor={id} className="text-xs text-app-muted">{label}</label><Input id={id} required {...props} className="border-app-line bg-app-soft" /></div>
}

type Removal = { kind: 'destination'; item: JiraDestination } | { kind: 'rule'; item: JiraRule }

// Destinations, the ordered rules, backfills and the change log (administrators).
function Routing() {
  const { t } = useTranslation('integrations')
  const queryClient = useQueryClient()
  const routing = useQuery(jiraRoutingQuery())
  const backfills = useQuery(jiraBackfillQuery())
  const [removing, setRemoving] = useState<Removal | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const remove = async () => {
    if (!removing) return
    setBusy(true); setError('')
    try {
      const next = removing.kind === 'destination'
        ? await apiPost('/api/integrations/jira/destinations/remove', 'jira-routing', { id: removing.item.id })
        : await apiPost('/api/integrations/jira/rules/remove', 'jira-routing', { id: removing.item.id })
      queryClient.setQueryData(keys.jiraRouting, next)
      void queryClient.invalidateQueries({ queryKey: keys.jira, exact: true })
      setRemoving(null)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  if (routing.isError) return <div role="alert" className="flex flex-wrap items-center gap-3 rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{routing.error.message}
    <Button size="xs" variant="outline" onClick={() => void routing.refetch()}>{t('common:actions.retry')}</Button></div>
  if (!routing.data) return <SkeletonList rows={4} action label={t('jira.routing_loading')} />
  return <div className="space-y-6">
    <DestinationsSection routing={routing.data} onRemove={item => { setError(''); setRemoving({ kind: 'destination', item }) }} />
    <RulesSection routing={routing.data} backfills={backfills.data?.items ?? []} onRemove={item => { setError(''); setRemoving({ kind: 'rule', item }) }} />
    <RoutingHistory routing={routing.data} />
    <Dialog open={!!removing} onOpenChange={next => { if (!next) setRemoving(null) }}><DialogContent className="max-w-md">
      <DialogHeader><DialogTitle>{removing?.kind === 'destination' ? t('jira.destinations.remove_title', { name: removing.item.name }) : t('jira.rules.remove_title', { name: removing?.item.name ?? '' })}</DialogTitle>
        <DialogDescription>{removing?.kind === 'destination' ? t('jira.destinations.remove_help') : t('jira.rules.remove_help')}</DialogDescription></DialogHeader>
      {error && <p role="alert" className="text-xs text-danger">{error}</p>}
      <DialogFooter><Button variant="ghost" onClick={() => setRemoving(null)}>{t('common:actions.cancel')}</Button>
        <Button variant="destructive" disabled={busy} onClick={() => void remove()}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.remove')}</Button></DialogFooter>
    </DialogContent></Dialog>
  </div>
}
