import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '@/shared/api/http'
import { ChevronDown, ExternalLink, FileCheck2, GitBranch, Layers3, LoaderCircle, LockKeyhole, RefreshCw, Search, ShieldCheck } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { Button, buttonVariants } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { GitHubAppGuide, GitHubInstall, type GitHubStatus } from '@/features/sources/github-setup'
import { Pager } from '@/features/sources/source-search'
import { SkeletonCard, SkeletonList } from '@/shared/ui/loading'
import { BatchPanel, OrganizationScanDialog, useBatches } from '@/features/analyses/batches'
import { AuditReportDialog } from '@/features/findings/audit-report'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { formatDay } from '@/shared/i18n/format'
import { useSourcePage } from '@/features/sources/sources'

export type { Source, SourcePage } from '@/features/sources/sources'
type Run = { created_at: string; source?: { id?: string; name: string } }

// Proveedores que vendrán. Se ven en gris para que se sepa que están en camino, pero no ofrecen nada todavía.
const pending = [
  { id: 'gitlab', name: 'GitLab', reason: 'providers.pending.gitlab' },
  { id: 'bitbucket', name: 'Bitbucket', reason: 'providers.pending.bitbucket' },
  { id: 'azure', name: 'Azure DevOps', reason: 'providers.pending.azure' },
] as const
const PAGE_SIZE = 25

export function CodeSources({ showRepositories = false, onScan, runs = [], canManage = false }: { showRepositories?: boolean; onScan?: (id: string) => void; runs?: Run[]; canManage?: boolean }) {
  const { t } = useTranslation('sources')
  const [github, setGithub] = useState<GitHubStatus | null>(null)
  const [filter, setFilter] = useState('')
  const [accountFilter, setAccountFilter] = useState('')
  const [page, setPage] = useState(1)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmForget, setConfirmForget] = useState(false)
  // Varios repositorios de una vez: selección a mano (lote) o una organización entera (administración).
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [organization, setOrganization] = useState<string | null>(null)
  const [reportFor, setReportFor] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)
  const { active: batch, last: lastBatch, reload: reloadBatches } = useBatches()
  const startSelected = async () => {
    setStarting(true); setError('')
    try { await api.post('/api/repositories/batches', 'scan-batch', { source_ids: [...selected] }); setSelected(new Set()); void reloadBatches() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setStarting(false) }
  }
  // Solo la página visible: con cientos de repositorios la respuesta tarda lo mismo que con diez.
  const { data, error: sourcesError, loading, reload } = useSourcePage({ query: filter, account: accountFilter || undefined, page, perPage: PAGE_SIZE })
  const loadAll = async () => { reload(); setGithub(await api.get<GitHubStatus>('/api/integrations/github')) }
  useEffect(() => { void api.get<GitHubStatus>('/api/integrations/github').then(setGithub).catch(caught => setError(String(caught))) }, [])

  const act = async (action: 'disconnect' | 'forget_app', installationId?: number) => {
    setBusy(true); setError('')
    try {
      setGithub(await api.post<GitHubStatus>('/api/integrations/github', 'connect-github', { action, ...(installationId ? { installation_id: installationId } : {}) }))
      setConfirmForget(false)
      await loadAll()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(false) }
  }
  const changed = (next: GitHubStatus) => { setGithub(next); reload() }

  const installations = github?.installations ?? []
  const selectable = (data?.sources ?? []).filter(source => source.installation_id).map(source => source.id)
  const accounts = Array.from(new Set([...installations.map(item => item.account), ...(data?.accounts ?? [])].filter((account): account is string => !!account))).sort()

  return <div className="space-y-5">
    {!showRepositories && <Card className="border-app-line bg-panel">
      <CardHeader><CardTitle>{t('providers.title')}</CardTitle><CardDescription>{t('providers.description')}</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-xl border border-app-line bg-inset p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-3"><GitBranch className="size-5 text-brand" /><div><h3 className="font-semibold">GitHub</h3><p className="text-xs text-app-subtle">{t('providers.github_tagline')}</p></div></div>
            {github && <Badge variant="outline" className={github.connected ? 'border-brand/40 text-brand' : 'border-app-line text-app-muted'}>{github.connected ? t('providers.status.connected') : github.configured ? t('providers.status.not_connected') : t('providers.status.not_configured')}</Badge>}
          </div>

          {!github && <div className="mt-4"><SkeletonCard lines={3} label={t('providers.loading')} /></div>}
          {github?.connected && <div className="mt-4 space-y-3">
            <p className="text-sm font-medium">{t('providers.accounts_connected', { count: installations.length })}</p>
            <div className="grid gap-3 lg:grid-cols-2">{installations.map(installation => {
              const manageUrl = installation.account_type === 'Organization' && installation.account
                ? `https://github.com/organizations/${encodeURIComponent(installation.account)}/settings/installations/${installation.installation_id}`
                : `https://github.com/settings/installations/${installation.installation_id}`
              const account = installation.account ?? '—'
              return <div key={installation.installation_id} className="space-y-3 rounded-lg border border-app-line bg-app-soft p-3">
                <div className="grid gap-2 text-sm sm:grid-cols-2">
                  <Field label={t('providers.field.account')} value={installation.account_type === 'Organization' ? t('providers.organization_account', { account }) : account} />
                  <Field label={t('providers.field.scope')} value={installation.repository_selection === 'selected' ? t('providers.scope.selected') : installation.repository_selection === 'all' ? t('providers.scope.all') : '—'} />
                  <Field label={t('providers.field.connected_by')} value={installation.connected_by ?? t('providers.unknown_person')} />
                  <Field label={t('providers.field.installation')} value={`#${installation.installation_id}`} />
                </div>
                <div className="flex flex-wrap gap-2"><a href={manageUrl} target="_blank" rel="noopener noreferrer" className={buttonVariants({ size: 'sm', variant: 'outline', className: 'border-app-line bg-panel' })}>{t('providers.change_repositories')} <ExternalLink /><span className="sr-only">{t('new_tab')}</span></a>
                  {canManage && <Button size="sm" variant="ghost" disabled={busy} onClick={() => void act('disconnect', installation.installation_id)}>{t('providers.disconnect_account')}</Button>}</div>
              </div>
            })}</div>
            <p className="flex items-start gap-2 text-xs leading-5 text-app-subtle"><ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-brand" />{t('providers.key_note')}</p>
          </div>}

          {github?.configured && <GitHubInstall status={github} canManage={canManage} onChanged={changed} />}
          {github && !github.configured && <GitHubAppGuide status={github} canManage={canManage} onSaved={changed} />}
          {github?.configured && github.source === 'vault' && canManage && <div className="mt-4 border-t border-app-line pt-3 text-xs">
            {confirmForget ? <div className="flex flex-wrap items-center gap-2"><span className="text-app-muted">{t('providers.forget_confirm')}</span>
              <Button size="sm" variant="destructive" disabled={busy} onClick={() => void act('forget_app')}>{t('providers.forget')}</Button><Button size="sm" variant="ghost" onClick={() => setConfirmForget(false)}>{t('common:actions.cancel')}</Button></div>
              : <button type="button" onClick={() => setConfirmForget(true)} className="text-app-subtle hover:text-app-fg">{t('providers.use_other_app')}</button>}
          </div>}
        </div>

        {/* Lo que aún no funciona no compite con lo que sí: una línea plegable en lugar de tres tarjetas. */}
        <details className="rounded-xl border border-dashed border-app-line px-4 py-3 text-sm"><summary className="cursor-pointer text-app-muted">{t('providers.coming_soon', { names: pending.map(item => item.name).join(', ') })}</summary>
          <ul className="mt-2 space-y-1 text-xs leading-5 text-app-subtle">{pending.map(item => <li key={item.id}><strong className="font-medium text-app-secondary">{item.name}:</strong> {t(item.reason)}</li>)}</ul></details>
      </CardContent>
    </Card>}
    {showRepositories && <p className="text-sm text-app-muted">{t('providers.accounts_connected', { count: installations.length })} · <a className="font-medium text-brand hover:underline" href="#/integraciones">{t('providers.manage_github')}</a></p>}
    {(error || sourcesError) && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft p-3 text-sm text-danger">{error || sourcesError}</div>}
    {data?.providers.github?.error && <div role="alert" className="rounded-xl border border-warning-line bg-warning-soft p-3 text-sm text-warning">{data.providers.github.error}</div>}

    {showRepositories && <Card className="border-app-line bg-panel">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>{t('repositories.title')}</CardTitle><CardDescription>{t('repositories.description')}</CardDescription></div><Button variant="outline" disabled={loading} onClick={() => reload(true)} className="border-app-line bg-app-soft"><RefreshCw className={loading ? 'animate-spin' : ''} /> {t('repositories.refresh')}</Button>
        {canManage && accounts.length > 0 && <Menu><MenuTrigger render={<Button variant="outline" disabled={!!batch} className="border-app-line bg-app-soft" />}><Layers3 />{t('repositories.scan_organization')}<ChevronDown className="size-3.5" /></MenuTrigger>
          <MenuContent>{accounts.map(account => <MenuItem key={account} onClick={() => setOrganization(account)}>{account}</MenuItem>)}</MenuContent></Menu>}
        {accounts.length > 0 && <Menu><MenuTrigger render={<Button variant="outline" className="border-app-line bg-app-soft" />}><FileCheck2 />{t('repositories.organization_report')}<ChevronDown className="size-3.5" /></MenuTrigger>
          <MenuContent>{accounts.map(account => <MenuItem key={account} onClick={() => setReportFor(account)}>{account}</MenuItem>)}</MenuContent></Menu>}</CardHeader>
      <CardContent className="space-y-4">
        <BatchPanel active={batch} last={lastBatch} onChanged={() => void reloadBatches()} />
        <div className="flex flex-wrap items-center gap-3"><div className="relative w-full max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label={t('repositories.search')} placeholder={t('repositories.search_placeholder')} value={filter} onChange={event => { setFilter(event.target.value); setPage(1) }} className="border-app-line bg-app-soft pl-9" /></div>
          {data && <span className="text-xs text-app-muted">{t('common:count.repositories', { count: data.total })}{data.partial ? ` · ${t('repositories.partial')}` : ''}</span>}</div>
        {accounts.length > 1 && <div role="group" aria-label={t('repositories.filter_by_organization')} className="flex flex-wrap gap-2">
          <Button size="sm" aria-pressed={accountFilter === ''} variant={accountFilter === '' ? 'default' : 'outline'} onClick={() => { setAccountFilter(''); setPage(1) }}>{t('repositories.all_organizations')}</Button>
          {accounts.map(account => <Button key={account} size="sm" aria-pressed={accountFilter === account} variant={accountFilter === account ? 'default' : 'outline'} onClick={() => { setAccountFilter(account); setPage(1) }}>{account}</Button>)}
        </div>}
        {selected.size > 0 && <div className="sticky top-16 z-10 flex flex-wrap items-center gap-3 rounded-xl border border-brand/30 bg-panel px-4 py-2.5 shadow-lg">
          <span className="text-sm font-medium">{t('repositories.selected', { count: selected.size })}</span>
          <Button size="sm" disabled={starting || !!batch || selected.size > 100} onClick={() => void startSelected()} className="bg-primary text-primary-foreground hover:bg-primary/90">{starting && <LoaderCircle className="animate-spin" />}{t('repositories.scan_selected')}</Button>
          {(batch || selected.size > 100) && <span className="text-xs text-app-muted">{batch ? t('repositories.batch_running') : t('repositories.batch_limit')}</span>}
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())} className="ml-auto">{t('repositories.clear_selection')}</Button>
        </div>}
        <div className="overflow-hidden rounded-xl border border-app-line">
          <div className="hidden grid-cols-[20px_minmax(0,1fr)_120px_130px_130px] items-center gap-3 border-b border-app-line px-4 py-3 text-xs text-app-subtle md:grid">
            <input type="checkbox" aria-label={t('repositories.select_page')} className="size-4 accent-brand" checked={selectable.length > 0 && selectable.every(id => selected.has(id))}
              onChange={event => setSelected(previous => { const next = new Set(previous); for (const id of selectable) { if (event.target.checked) next.add(id); else next.delete(id) } return next })} />
            <span>{t('repositories.columns.repository')}</span><span>{t('repositories.columns.origin')}</span><span>{t('repositories.columns.last_scan')}</span><span>{t('repositories.columns.action')}</span></div>
          {!data && <SkeletonList rows={8} action label={t('repositories.loading')} />}
          {data?.sources.map(source => {
            const last = runs.find(run => run.source?.name === source.name)
            return <div key={source.id} className="grid gap-2 border-b border-app-line px-4 py-3 last:border-b-0 md:grid-cols-[20px_minmax(0,1fr)_120px_130px_130px] md:items-center">
              {source.installation_id ? <input type="checkbox" aria-label={t('repositories.select_one', { name: source.name })} className="size-4 accent-brand" checked={selected.has(source.id)}
                onChange={event => setSelected(previous => { const next = new Set(previous); if (event.target.checked) next.add(source.id); else next.delete(source.id); return next })} /> : <span />}
              <div className="flex min-w-0 items-center gap-2"><GitBranch className="size-4 shrink-0 text-app-muted" /><span className="truncate text-sm font-medium">{source.name}</span>{source.private && <LockKeyhole className="size-3 shrink-0 text-app-subtle" />}</div>
              <span className="text-xs text-app-muted">{source.account ?? source.provider.toUpperCase()}</span>
              <span className="text-xs text-app-muted">{last ? formatDay(last.created_at, { dateStyle: 'short' }) : t('repositories.not_scanned')}</span>
              <Button variant="outline" size="sm" onClick={() => onScan?.(source.id)} className="w-fit border-app-line bg-app-soft">{t('repositories.scan')}</Button>
            </div>
          })}
          {data && !data.sources.length && !loading && <p className="p-6 text-center text-sm text-app-muted">{t('repositories.no_match')}</p>}
        </div>
        {data && <Pager page={page} perPage={PAGE_SIZE} total={data.total} onPage={setPage} loading={loading} />}
      </CardContent>
    </Card>}
    <OrganizationScanDialog account={organization} onClose={() => setOrganization(null)} onStarted={() => void reloadBatches()} />
    {reportFor && <AuditReportDialog open onClose={() => setReportFor(null)} target={{ account: reportFor }} name={reportFor} selected={[]} filtered={[]} total={0} />}
  </div>
}

function Field({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><span className="block text-xs text-app-subtle">{label}</span><span className="block truncate text-sm text-app-secondary" title={value}>{value}</span></div>
}
