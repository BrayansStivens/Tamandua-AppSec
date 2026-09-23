import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { ExternalLink, GitBranch, LockKeyhole, RefreshCw, Search, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { GitHubAppGuide, GitHubInstall, PermissionWarning, type GitHubStatus } from '@/components/github-setup'

export type Source = { id: string; name: string; provider: 'local' | 'github' | 'gitlab'; private: boolean; branch: string | null }
export type SourceList = { sources: Source[]; providers: Record<'github' | 'gitlab', { configured: boolean; origin: 'session' | 'environment' | 'github_app' | null; error?: string }> }
type Run = { created_at: string; source?: { id?: string; name: string } }

// Solo GitHub ofrece una pantalla del proveedor para elegir repositorios concretos;
// en el resto el consentimiento es por scopes de cuenta, así que no se anuncia como disponible.
const pending = [
  { id: 'gitlab', name: 'GitLab', reason: 'OAuth con PKCE pendiente. GitLab no permite elegir proyectos concretos: el consentimiento es por scopes de toda la cuenta.' },
  { id: 'bitbucket', name: 'Bitbucket', reason: 'Pendiente. No tiene selección por repositorio ni device flow, y exige client secret con callback.' },
  { id: 'azure', name: 'Azure DevOps', reason: 'Pendiente y por vía Microsoft Entra ID: Microsoft dejó de aceptar registros de OAuth apps de Azure DevOps en abril de 2025.' },
]

export function CodeSources({ showRepositories = false, onScan, runs = [], canManage = false }: { showRepositories?: boolean; onScan?: (id: string) => void; runs?: Run[]; canManage?: boolean }) {
  const [data, setData] = useState<SourceList | null>(null)
  const [github, setGithub] = useState<GitHubStatus | null>(null)
  const [filter, setFilter] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [confirmForget, setConfirmForget] = useState(false)
  const loadAll = async () => {
    const [sources, status] = await Promise.all([api.get<SourceList>('/api/sources'), api.get<GitHubStatus>('/api/integrations/github')])
    setData(sources)
    setGithub(status)
  }
  useEffect(() => { loadAll().catch(caught => setError(String(caught))) }, [])

  const act = async (action: 'disconnect' | 'forget_app') => {
    setBusy(true); setError('')
    try {
      setGithub(await api.post<GitHubStatus>('/api/integrations/github', 'connect-github', { action }))
      setConfirmForget(false)
      await loadAll()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(false) }
  }
  const changed = (next: GitHubStatus) => { setGithub(next); void api.get<SourceList>('/api/sources').then(setData).catch(() => undefined) }

  const installation = github?.installation ?? null
  const manageUrl = installation && (installation.account_type === 'Organization' && installation.account
    ? `https://github.com/organizations/${installation.account}/settings/installations/${installation.installation_id}`
    : `https://github.com/settings/installations/${installation.installation_id}`)

  return <div className="space-y-5">
    <Card className="border-app-line bg-panel">
      <CardHeader><CardTitle>Proveedores de código</CardTitle><CardDescription>Creas tu propia GitHub App (privada, solo en tu cuenta), la conectas aquí y eliges en GitHub los repositorios que se analizan.</CardDescription></CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-xl border border-app-line bg-inset p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-3"><GitBranch className="size-5 text-brand" /><div><h3 className="font-semibold">GitHub</h3><p className="text-xs text-app-subtle">GitHub App · lee el código y comenta en los pull requests</p></div></div>
            {github && <Badge variant="outline" className={github.connected ? 'border-brand/40 text-brand' : 'border-app-line text-app-muted'}>{github.connected ? 'Conectado' : github.configured ? 'Sin conectar' : 'Sin configurar'}</Badge>}
          </div>

          {github?.connected && installation && <div className="mt-4 space-y-3">
            <div className="grid gap-2 text-sm sm:grid-cols-2">
              <Field label="Cuenta" value={`${installation.account ?? '—'}${installation.account_type === 'Organization' ? ' (organización)' : ''}`} />
              <Field label="Alcance" value={installation.repository_selection === 'selected' ? 'Solo los repositorios seleccionados' : installation.repository_selection === 'all' ? 'Todos los repositorios de la cuenta' : '—'} />
              <Field label="Permisos" value={Object.entries(installation.permissions).map(([name, level]) => `${name}: ${level}`).join(' · ') || '—'} />
              {github.permissions && (github.permissions.excess.length > 0 || github.permissions.missing.length > 0) && <div className="sm:col-span-2"><PermissionWarning review={github.permissions} /></div>}
              <Field label="App" value={`${github.name ?? github.slug}${github.owner ? ` · ${github.owner}` : ''}`} />
              <Field label="Conectó" value={installation.connected_by ?? 'sin identificar'} />
            </div>
            <p className="flex items-start gap-2 text-xs leading-5 text-app-subtle"><ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-brand" />La clave privada de la App está cifrada en el servidor. Cada análisis acuña un token de una hora que vive solo en memoria.</p>
            <div className="flex flex-wrap gap-2">
              {manageUrl && <a href={manageUrl} target="_blank" rel="noopener noreferrer"><Button variant="outline" className="border-app-line bg-panel">Cambiar repositorios en GitHub <ExternalLink /></Button></a>}
              {canManage && <Button variant="ghost" disabled={busy} onClick={() => void act('disconnect')}>Desconectar</Button>}
            </div>
          </div>}

          {github && !github.connected && github.configured && <GitHubInstall status={github} canManage={canManage} onChanged={changed} />}
          {github && !github.configured && <GitHubAppGuide status={github} canManage={canManage} onSaved={changed} />}
          {github?.configured && github.source === 'almacén cifrado' && canManage && <div className="mt-4 border-t border-app-line pt-3 text-xs">
            {confirmForget ? <div className="flex flex-wrap items-center gap-2"><span className="text-app-muted">Se borran de este servidor la clave y la conexión. En GitHub la App sigue existiendo: bórrala allí si ya no la usas.</span>
              <Button size="sm" variant="destructive" disabled={busy} onClick={() => void act('forget_app')}>Olvidar la App</Button><Button size="sm" variant="ghost" onClick={() => setConfirmForget(false)}>Cancelar</Button></div>
              : <button type="button" onClick={() => setConfirmForget(true)} className="text-app-subtle hover:text-app-fg">Usar otra GitHub App…</button>}
          </div>}
        </div>

        <div className="grid gap-3 sm:grid-cols-3">{pending.map(item => <div key={item.id} className="rounded-xl border border-app-line bg-inset p-4"><div className="flex items-center justify-between gap-2"><span className="text-sm font-medium text-app-secondary">{item.name}</span><Badge variant="outline" className="border-app-line text-app-subtle">Pendiente</Badge></div><p className="mt-2 text-xs leading-5 text-app-subtle">{item.reason}</p></div>)}</div>
      </CardContent>
    </Card>
    {error && <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
    {data?.providers.github?.error && <div role="alert" className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-200">{data.providers.github.error}</div>}

    {showRepositories && <Card className="border-app-line bg-panel">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>Repositorios</CardTitle><CardDescription>Los que la instalación de GitHub tiene concedidos, más el workspace local.</CardDescription></div><Button variant="outline" onClick={() => void loadAll().catch(caught => setError(String(caught)))} className="border-app-line bg-app-soft"><RefreshCw /> Actualizar lista</Button></CardHeader>
      <CardContent className="space-y-4">
        <div className="relative max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label="Buscar repositorios" placeholder="Buscar repositorios…" value={filter} onChange={event => setFilter(event.target.value)} className="border-app-line bg-app-soft pl-9" /></div>
        <div className="overflow-hidden rounded-xl border border-app-line">
          <div className="hidden grid-cols-[minmax(0,1fr)_120px_130px_130px] gap-3 border-b border-app-line px-4 py-3 text-xs text-app-subtle md:grid"><span>Repositorio</span><span>Origen</span><span>Último análisis</span><span>Acción</span></div>
          {data?.sources.filter(source => source.name.toLowerCase().includes(filter.trim().toLowerCase())).map(source => {
            const last = runs.find(run => run.source?.name === source.name)
            return <div key={source.id} className="grid gap-2 border-b border-app-line px-4 py-3 last:border-b-0 md:grid-cols-[minmax(0,1fr)_120px_130px_130px] md:items-center">
              <div className="flex min-w-0 items-center gap-2"><GitBranch className="size-4 shrink-0 text-app-muted" /><span className="truncate text-sm font-medium">{source.name}</span>{source.private && <LockKeyhole className="size-3 shrink-0 text-app-subtle" />}</div>
              <span className="text-xs text-app-muted">{source.provider.toUpperCase()}</span>
              <span className="text-xs text-app-muted">{last ? new Date(last.created_at).toLocaleDateString('es-CO') : 'No probado'}</span>
              <Button variant="outline" size="sm" onClick={() => onScan?.(source.id)} className="w-fit border-app-line bg-app-soft">Analizar</Button>
            </div>
          })}
          {data && !data.sources.filter(source => source.name.toLowerCase().includes(filter.trim().toLowerCase())).length && <p className="p-6 text-center text-sm text-app-muted">No hay repositorios que coincidan.</p>}
        </div>
      </CardContent>
    </Card>}
  </div>
}

function Field({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0"><span className="block text-xs text-app-subtle">{label}</span><span className="block truncate text-sm text-app-secondary" title={value}>{value}</span></div>
}
