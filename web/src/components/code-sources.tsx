import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { ExternalLink, GitBranch, LockKeyhole, RefreshCw, Search, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { GitHubAppGuide, GitHubInstall, type GitHubStatus } from '@/components/github-setup'
import { Pager } from '@/components/source-search'
import { useSourcePage } from '@/lib/sources'
import { ComingSoonCard } from '@/components/coming-soon'

export type { Source, SourcePage } from '@/lib/sources'
type Run = { created_at: string; source?: { id?: string; name: string } }

// Proveedores que vendrán. Se ven en gris para que se sepa que están en camino, pero no ofrecen nada todavía.
const pending = [
  { id: 'gitlab', name: 'GitLab', reason: 'Con un token de proyecto de solo lectura, para limitar el acceso a los proyectos que elijas.' },
  { id: 'bitbucket', name: 'Bitbucket', reason: 'Con un token de acceso de repositorio de solo lectura.' },
  { id: 'azure', name: 'Azure DevOps', reason: 'Mediante Microsoft Entra ID, que es la vía que Microsoft admite desde 2025.' },
]
const PAGE_SIZE = 25

export function CodeSources({ showRepositories = false, onScan, runs = [], canManage = false }: { showRepositories?: boolean; onScan?: (id: string) => void; runs?: Run[]; canManage?: boolean }) {
  const [github, setGithub] = useState<GitHubStatus | null>(null)
  const [filter, setFilter] = useState('')
  const [accountFilter, setAccountFilter] = useState('')
  const [page, setPage] = useState(1)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmForget, setConfirmForget] = useState(false)
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
  const accounts = Array.from(new Set([...installations.map(item => item.account), ...(data?.accounts ?? [])].filter((account): account is string => !!account))).sort()

  return <div className="space-y-5">
    {!showRepositories && <Card className="border-app-line bg-panel">
      <CardHeader><CardTitle>Proveedores de código</CardTitle><CardDescription>Conecta la GitHub App a una o varias organizaciones y elige en GitHub los repositorios que se analizan.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-xl border border-app-line bg-inset p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-3"><GitBranch className="size-5 text-brand" /><div><h3 className="font-semibold">GitHub</h3><p className="text-xs text-app-subtle">GitHub App · lee el código y comenta en los pull requests</p></div></div>
            {github && <Badge variant="outline" className={github.connected ? 'border-brand/40 text-brand' : 'border-app-line text-app-muted'}>{github.connected ? 'Conectado' : github.configured ? 'Sin conectar' : 'Sin configurar'}</Badge>}
          </div>

          {github?.connected && <div className="mt-4 space-y-3">
            <p className="text-sm font-medium">{installations.length} {installations.length === 1 ? 'cuenta conectada' : 'cuentas conectadas'}</p>
            <div className="grid gap-3 lg:grid-cols-2">{installations.map(installation => {
              const manageUrl = installation.account_type === 'Organization' && installation.account
                ? `https://github.com/organizations/${encodeURIComponent(installation.account)}/settings/installations/${installation.installation_id}`
                : `https://github.com/settings/installations/${installation.installation_id}`
              return <div key={installation.installation_id} className="space-y-3 rounded-lg border border-app-line bg-app-soft p-3">
                <div className="grid gap-2 text-sm sm:grid-cols-2">
                  <Field label="Cuenta" value={`${installation.account ?? '—'}${installation.account_type === 'Organization' ? ' (organización)' : ''}`} />
                  <Field label="Alcance" value={installation.repository_selection === 'selected' ? 'Solo repositorios seleccionados' : installation.repository_selection === 'all' ? 'Todos los repositorios de la cuenta' : '—'} />
                  <Field label="Conectó" value={installation.connected_by ?? 'sin identificar'} />
                  <Field label="Instalación" value={`#${installation.installation_id}`} />
                </div>
                <div className="flex flex-wrap gap-2"><a href={manageUrl} target="_blank" rel="noopener noreferrer"><Button size="sm" variant="outline" className="border-app-line bg-panel">Cambiar repositorios <ExternalLink /></Button></a>
                  {canManage && <Button size="sm" variant="ghost" disabled={busy} onClick={() => void act('disconnect', installation.installation_id)}>Desconectar cuenta</Button>}</div>
              </div>
            })}</div>
            <p className="flex items-start gap-2 text-xs leading-5 text-app-subtle"><ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-brand" />La clave privada de la App está cifrada en el servidor. Cada análisis acuña un token de una hora que vive solo en memoria.</p>
          </div>}

          {github?.configured && <GitHubInstall status={github} canManage={canManage} onChanged={changed} />}
          {github && !github.configured && <GitHubAppGuide status={github} canManage={canManage} onSaved={changed} />}
          {github?.configured && github.source === 'almacén cifrado' && canManage && <div className="mt-4 border-t border-app-line pt-3 text-xs">
            {confirmForget ? <div className="flex flex-wrap items-center gap-2"><span className="text-app-muted">Se borran de este servidor la clave y la conexión. En GitHub la App sigue existiendo: bórrala allí si ya no la usas.</span>
              <Button size="sm" variant="destructive" disabled={busy} onClick={() => void act('forget_app')}>Olvidar la App</Button><Button size="sm" variant="ghost" onClick={() => setConfirmForget(false)}>Cancelar</Button></div>
              : <button type="button" onClick={() => setConfirmForget(true)} className="text-app-subtle hover:text-app-fg">Usar otra GitHub App…</button>}
          </div>}
        </div>

        <div className="grid gap-3 sm:grid-cols-3">{pending.map(item => <ComingSoonCard key={item.id} title={item.name} icon={<GitBranch className="size-4" />} description={item.reason} />)}</div>
      </CardContent>
    </Card>}
    {showRepositories && <p className="text-sm text-app-muted">{installations.length} {installations.length === 1 ? 'cuenta conectada' : 'cuentas conectadas'} · <a className="font-medium text-brand hover:underline" href="#/integraciones">Gestionar integración de GitHub</a></p>}
    {(error || sourcesError) && <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-200">{error || sourcesError}</div>}
    {data?.providers.github?.error && <div role="alert" className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-200">{data.providers.github.error}</div>}

    {showRepositories && <Card className="border-app-line bg-panel">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>Repositorios</CardTitle><CardDescription>Repositorios concedidos en todas las organizaciones conectadas.</CardDescription></div><Button variant="outline" disabled={loading} onClick={() => reload(true)} className="border-app-line bg-app-soft"><RefreshCw className={loading ? 'animate-spin' : ''} /> Actualizar lista</Button></CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-3"><div className="relative w-full max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label="Buscar repositorios" placeholder="Buscar repositorios…" value={filter} onChange={event => { setFilter(event.target.value); setPage(1) }} className="border-app-line bg-app-soft pl-9" /></div>
          {data && <span className="text-xs text-app-muted">{data.total} {data.total === 1 ? 'repositorio' : 'repositorios'}{data.partial ? ' · resultados parciales, se completan solos' : ''}</span>}</div>
        {accounts.length > 1 && <div aria-label="Filtrar por organización" className="flex flex-wrap gap-2">
          <Button size="sm" variant={accountFilter === '' ? 'default' : 'outline'} onClick={() => { setAccountFilter(''); setPage(1) }}>Todas</Button>
          {accounts.map(account => <Button key={account} size="sm" variant={accountFilter === account ? 'default' : 'outline'} onClick={() => { setAccountFilter(account); setPage(1) }}>{account}</Button>)}
        </div>}
        <div className="overflow-hidden rounded-xl border border-app-line">
          <div className="hidden grid-cols-[minmax(0,1fr)_120px_130px_130px] gap-3 border-b border-app-line px-4 py-3 text-xs text-app-subtle md:grid"><span>Repositorio</span><span>Origen</span><span>Último análisis</span><span>Acción</span></div>
          {!data && <p className="p-6 text-center text-sm text-app-subtle">Cargando repositorios…</p>}
          {data?.sources.map(source => {
            const last = runs.find(run => run.source?.name === source.name)
            return <div key={source.id} className="grid gap-2 border-b border-app-line px-4 py-3 last:border-b-0 md:grid-cols-[minmax(0,1fr)_120px_130px_130px] md:items-center">
              <div className="flex min-w-0 items-center gap-2"><GitBranch className="size-4 shrink-0 text-app-muted" /><span className="truncate text-sm font-medium">{source.name}</span>{source.private && <LockKeyhole className="size-3 shrink-0 text-app-subtle" />}</div>
              <span className="text-xs text-app-muted">{source.account ?? source.provider.toUpperCase()}</span>
              <span className="text-xs text-app-muted">{last ? new Date(last.created_at).toLocaleDateString('es-CO') : 'No probado'}</span>
              <Button variant="outline" size="sm" onClick={() => onScan?.(source.id)} className="w-fit border-app-line bg-app-soft">Analizar</Button>
            </div>
          })}
          {data && !data.sources.length && !loading && <p className="p-6 text-center text-sm text-app-muted">No hay repositorios que coincidan.</p>}
        </div>
        {data && <Pager page={page} perPage={PAGE_SIZE} total={data.total} onPage={setPage} loading={loading} />}
      </CardContent>
    </Card>}
  </div>
}

function Field({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><span className="block text-xs text-app-subtle">{label}</span><span className="block truncate text-sm text-app-secondary" title={value}>{value}</span></div>
}
