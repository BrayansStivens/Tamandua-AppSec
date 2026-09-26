import { useQuery, useQueryClient } from '@tanstack/react-query'
import { keys, runsQuery } from '@/shared/api/queries'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ChevronRight, Clock3, GitPullRequest, LayoutDashboard, Network,
  Landmark, LogOut, Menu, Monitor, Moon, Play, PlugZap, Radar, SearchCheck, Shield, ShieldAlert, Sun, Layers3, UserRound, UsersRound,
  Bug,
} from 'lucide-react'
import { BrandLockup } from '@/shared/ui/brand-mark'
import { BRAND } from '@/shared/lib/brand'
import { CodeSources } from '@/features/sources/code-sources'
import { ComingSoonPage } from '@/shared/ui/coming-soon'
import { AnalysisList } from '@/features/analyses/analysis-list'
import { AnalysisWizard } from '@/features/analyses/analysis-wizard'
import { useToasts } from '@/features/analyses/run-progress'
import { TopProgress } from '@/shared/ui/loading'
import { UpdateNotice } from '@/app/update-notice'
import type { SessionActions, SessionUser } from '@/features/auth/session'
import { api } from '@/shared/api/http'
import { readRoute, writeRoute } from '@/shared/lib/route'
import { Account } from '@/features/auth/account'
import { Dashboard } from '@/pages/Dashboard'
import { Findings } from '@/pages/Findings'
import { CveTracker } from '@/pages/CveTracker'
import { Users } from '@/pages/Users'
import { CoverageView } from '@/pages/Coverage'
import { Integrations } from '@/pages/Integrations'
import { PullRequests } from '@/pages/PullRequests'
import { ThreatModels } from '@/pages/ThreatModels'
import { Compliance } from '@/pages/Compliance'
import type { RunRow } from '@/shared/lib/types'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from '@/shared/ui/sheet'

type View = 'overview' | 'analyses' | 'new' | 'findings' | 'coverage' | 'repositories' | 'domains' | 'integrations' | 'account' | 'users' | 'pulls' | 'threats' | 'cves' | 'compliance'
type Theme = 'system' | 'light' | 'dark'

// Ley de Hick: tres grupos con nombre en vez de once opciones seguidas. Lo que aún no funciona
// (Pruebas web) no ocupa sitio en el menú; su página sigue existiendo para quien llegue por enlace.
const navigation: { label: string; items: { id: View; label: string; icon: typeof Shield }[] }[] = [
  { label: 'Riesgo', items: [
    { id: 'overview', label: 'Resumen', icon: LayoutDashboard },
    { id: 'findings', label: 'Hallazgos', icon: ShieldAlert },
    { id: 'threats', label: 'Amenazas', icon: Network },
    { id: 'coverage', label: 'Cobertura', icon: Radar },
    { id: 'cves', label: 'CVE tracker', icon: Bug },
    { id: 'compliance', label: 'Cumplimiento', icon: Landmark },
  ] },
  { label: 'Escaneo', items: [
    { id: 'analyses', label: 'Análisis', icon: SearchCheck },
    { id: 'repositories', label: 'Repositorios', icon: Layers3 },
    { id: 'pulls', label: 'Pull requests', icon: GitPullRequest },
  ] },
  { label: 'Ajustes', items: [
    { id: 'integrations', label: 'Integraciones', icon: PlugZap },
    { id: 'users', label: 'Usuarios', icon: UsersRound },
  ] },
]
const isoDate = (date: string) => new Date(date).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })

function App({ user, session }: { user: SessionUser; session: SessionActions }) {
  const [view, setView] = useState<View>(() => (readRoute().view as View | null) ?? 'overview')
  const runsResult = useQuery(runsQuery())
  const rows = useMemo(() => runsResult.data ?? [], [runsResult.data])
  const queryClient = useQueryClient()
  const [detail, setDetail] = useState<RunRow | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(() => readRoute().params.get('run'))
  // La URL manda: Atrás, Adelante y refrescar restauran vista y ejecución.
  useEffect(() => {
    const sync = () => { const route = readRoute(); if (route.view) { setView(route.view as View); setSelectedId(route.params.get('run')) } }
    window.addEventListener('popstate', sync)
    return () => window.removeEventListener('popstate', sync)
  }, [])
  useEffect(() => { if (!readRoute().view) writeRoute(view, {}, { replace: true }) }, [view])
  // Cada vista empieza arriba: sin esto hereda el scroll de la anterior (p. ej. el CVE tracker abría al pie).
  useEffect(() => { window.scrollTo({ top: 0 }) }, [view])
  const [error, setError] = useState<string | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [selectedSource, setSelectedSource] = useState<string | null>(null)
  const toasts = useToasts()
  // Aviso al terminar un análisis: se compara con el estado anterior de cada fila (el sondeo lo hace la consulta).
  const previous = useRef<Map<string, string>>(new Map())
  useEffect(() => {
    for (const row of rows) {
      const before = previous.current.get(row.id)
      if ((before === 'queued' || before === 'running') && row.status !== 'queued' && row.status !== 'running') {
        const name = row.type === 'repository_scan' ? row.source?.name ?? 'repositorio' : row.type === 'image_scan' ? row.target ?? 'imagen' : row.target
        toasts.push(row.status === 'failed' ? 'error' : 'ok', row.status === 'failed'
          ? `El escaneo de ${name} falló.`
          : `Escaneo de ${name} terminado: ${row.summary.candidates ?? 0} hallazgos${row.summary.severities ? ` (${row.summary.severities.critical ?? 0} críticos, ${row.summary.severities.high ?? 0} altos)` : ''}.`)
        if (detail?.id === row.id) void openRun(row.id, 'findings')
      }
    }
    previous.current = new Map(rows.map(row => [row.id, row.status]))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows])
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('tamandua-theme')
    return saved === 'light' || saved === 'system' ? saved : 'dark'
  })
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const apply = () => {
      const dark = theme === 'dark' || (theme === 'system' && media.matches)
      document.documentElement.classList.toggle('dark', dark)
    }
    apply()
    media.addEventListener('change', apply)
    localStorage.setItem('tamandua-theme', theme)
    return () => media.removeEventListener('change', apply)
  }, [theme])

  const refresh = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: keys.runs })
    return queryClient.getQueryData<RunRow[]>(keys.runs) ?? []
  }, [queryClient])
  useEffect(() => { if (runsResult.error) setError(runsResult.error instanceof Error ? runsResult.error.message : String(runsResult.error)) }, [runsResult.error])
  const latest = rows.find(row => row.type === 'repository_scan' || row.type === 'image_scan')
  const currentTitle = view === 'new' ? 'Nuevo análisis' : view === 'account' ? 'Cuenta' : navigation.flatMap(group => group.items).find(item => item.id === view)?.label ?? (view === 'domains' ? 'Pruebas web' : 'Resumen')

  const openRun = useCallback(async (id: string, nextView: View = 'findings') => {
    setSelectedId(id)
    setView(nextView)
    writeRoute(nextView, { run: id })
    try {
      const run = await api.get<RunRow>(`/api/runs/${encodeURIComponent(id)}`)
      setDetail(run)
      setError(null)
      return run
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }, [])
  // Entrar en Hallazgos desde el menú muestra el estado actual; abrir una ejecución concreta pasa por openRun.
  const selectView = (next: View) => { if (next === 'new') setSelectedSource(null); if (next === 'findings') setSelectedId(null); setView(next); setMobileOpen(false); writeRoute(next) }
  // Un CVE concreto del Resumen: la URL lleva su id (lo lee el tracker al montarse) y la vista cambia a la vez.
  const openTracker = (id?: string) => { if (!id) return selectView('cves'); writeRoute('cves', { id }); setView('cves'); setMobileOpen(false) }
  const scanSource = (id: string) => { setSelectedSource(id); setView('new'); setMobileOpen(false) }
  const completedRepositoryScan = async (id: string) => { await refresh(); await openRun(id, 'findings') }

  // El asistente vive dentro de Análisis: la sección sigue marcada mientras se crea una ejecución.
  const activeNav: View = view === 'new' ? 'analyses' : view
  // Usuarios es solo para administradores; el servidor lo impone igualmente.
  const nav = <nav aria-label="Principal" className="space-y-5">{navigation.map(group => {
    const items = group.items.filter(item => item.id !== 'users' || user.role === 'admin')
    const id = `nav-${group.label.toLowerCase()}`
    return <div key={group.label} role="group" aria-labelledby={id} className="space-y-1">
      <p id={id} className="px-3 pb-1 text-xs font-medium text-app-subtle">{group.label}</p>
      {items.map(item => <button key={item.id} onClick={() => selectView(item.id)} aria-current={activeNav === item.id ? 'page' : undefined} className={`flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left text-sm transition ${activeNav === item.id ? 'bg-accent font-medium text-accent-foreground' : 'text-app-muted hover:bg-app-soft hover:text-app-fg'}`}><item.icon aria-hidden className="size-4" />{item.label}</button>)}
    </div>
  })}</nav>

  const userCard = <div className="space-y-3 rounded-xl border border-app-line bg-app-soft p-3">
    <button onClick={() => selectView('account')} className={`flex w-full items-center gap-3 rounded-lg p-1 text-left transition hover:bg-app-soft ${view === 'account' ? 'text-brand' : ''}`}>
      <span className="grid size-8 shrink-0 place-items-center rounded-full bg-brand/15 text-brand"><UserRound className="size-4" /></span>
      <span className="min-w-0"><span className="block truncate text-sm font-medium">{user.display_name}</span><span className="block truncate text-xs text-app-subtle">{user.role === 'admin' ? 'Administrador' : 'Miembro'}{user.totp_enabled ? '' : ' · sin 2FA'}</span></span>
      {!user.totp_enabled && <span role="img" aria-label="Segundo factor sin activar" className="ml-auto size-2 shrink-0 rounded-full bg-warning" />}
    </button>
    <Button variant="ghost" size="sm" onClick={() => void session.logout()} className="w-full justify-start text-app-muted"><LogOut />Cerrar sesión</Button>
  </div>

  const renderMain = () => {
    if (view === 'new') return <AnalysisWizard key={selectedSource ?? 'new'} initialSourceId={selectedSource} isAdmin={user.role === 'admin'} onBatchStarted={() => selectView('analyses')} onComplete={completedRepositoryScan} onManageConnections={() => selectView('integrations')} onCancel={() => selectView('analyses')} />
    if (view === 'analyses') return <AnalysisList refreshKey={rows.length * 1000 + rows.filter(row => row.status === 'running' || row.status === 'queued').length} onOpen={id => openRun(id, 'findings')} onNew={() => selectView('new')} viewer={{ username: user.username, admin: user.role === 'admin' }} />
    if (view === 'repositories') return <CodeSources showRepositories runs={rows} onScan={scanSource} canManage={user.role === 'admin'} />
    if (view === 'domains') return <ComingSoonPage title="Pruebas dinámicas de aplicaciones web y API (DAST)" description="Pruebas dinámicas (DAST) contra tus aplicaciones en marcha, solo sobre dominios cuya propiedad hayas demostrado." plan={['Verificación de propiedad del dominio por DNS TXT (ya implementada, se activará con el resto)', 'Escaneo activo con ZAP o Nuclei en un contenedor aislado, con límites de velocidad y de alcance', 'Autenticación en la aplicación con una cuenta de prueba que tú declares', 'Hallazgos con la petición y la respuesta que los demuestran, en el mismo ciclo de vida que los del código']} />
    if (view === 'overview') return <Dashboard onOpenRun={id => openRun(id, 'findings')} onNew={() => selectView('new')} onNavigate={view => selectView(view as View)} onTracker={openTracker} />
    if (view === 'threats') return <ThreatModels user={user} onOpenRun={id => openRun(id, 'findings')} />
    if (view === 'cves') return <CveTracker onNew={() => selectView('new')} />
    if (view === 'compliance') return <Compliance user={user} onNew={() => selectView('new')} />
    if (view === 'pulls') return <PullRequests user={user} onOpenRun={id => openRun(id, 'findings')} />
    if (view === 'findings') return <Findings key={selectedId ?? 'current'} user={user} requestedRun={selectedId} onNew={() => selectView('new')} />
    if (view === 'coverage') return <CoverageView />
    if (view === 'account') return <Account user={user} onChanged={session.reload} />
    if (view === 'users' && user.role === 'admin') return <Users me={user} />
    if (view === 'integrations') return <Integrations user={user} />
    return <Dashboard onOpenRun={id => openRun(id, 'findings')} onNew={() => selectView('new')} onNavigate={view => selectView(view as View)} onTracker={openTracker} />
  }

  return <div className="min-h-screen bg-app text-app-fg"><TopProgress /><div className="flex min-h-screen">
    <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-app-line bg-inset px-4 py-6 lg:flex"><div className="mb-9 px-2"><BrandLockup subtitle={BRAND.tagline} /></div>{nav}<div className="mt-auto">{userCard}</div></aside>
    <div className="min-w-0 flex-1"><header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-app-line bg-app px-4 backdrop-blur-md sm:px-8"><div className="flex items-center gap-3"><Sheet open={mobileOpen} onOpenChange={setMobileOpen}><SheetTrigger render={<Button aria-label="Abrir navegación" variant="ghost" size="icon" className="lg:hidden" />}><Menu /></SheetTrigger><SheetContent side="left" className="w-72 border-app-line bg-inset"><SheetHeader><SheetTitle className="text-left"><BrandLockup size={32} subtitle={BRAND.tagline} /></SheetTitle></SheetHeader><div className="space-y-6 px-3">{nav}{userCard}</div></SheetContent></Sheet><span className="hidden text-sm text-app-muted sm:inline">Workspace</span><ChevronRight className="hidden size-3 text-app-subtle sm:block" /><span className="text-sm font-medium">{currentTitle}</span></div><div className="flex items-center gap-3"><Select value={theme} onValueChange={value => setTheme(value as Theme)}><SelectTrigger aria-label="Apariencia" size="sm" className="min-w-28 border-app-line bg-app-soft text-app-secondary sm:min-w-32">{theme === 'dark' ? <Moon className="size-3.5" /> : theme === 'light' ? <Sun className="size-3.5" /> : <Monitor className="size-3.5" />}<span className="min-w-0 flex-1 text-left">{theme === 'system' ? 'Sistema' : theme === 'light' ? 'Claro' : 'Oscuro'}</span></SelectTrigger><SelectContent align="end" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="system">Sistema</SelectItem><SelectItem value="light">Claro</SelectItem><SelectItem value="dark">Oscuro</SelectItem></SelectContent></Select><Badge variant="outline" className="hidden border-app-line text-app-muted sm:inline-flex">Local · v0.9</Badge><Button aria-label="Nuevo análisis" onClick={() => selectView('new')} className="bg-primary text-primary-foreground hover:bg-primary/90"><Play /><span className="hidden sm:inline">Nuevo análisis</span></Button></div></header>
    <main className="mx-auto max-w-[1520px] space-y-7 px-4 py-7 sm:px-8 sm:py-9"><div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"><div><div className="mb-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.22em] text-brand"><span className="size-1.5 rounded-full bg-brand" />Security workspace / 01</div><h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">{currentTitle}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-app-muted">{view === 'overview' ? 'Qué riesgos tiene tu código, sus dependencias y tus imágenes, por qué importan y cómo se corrigen.' : view === 'analyses' ? 'Historial de análisis de este workspace, con su tipo, estado y resultados.' : view === 'new' ? 'Define el objetivo, declara el alcance y revisa qué se ejecuta antes de lanzar.' : view === 'repositories' ? 'Conecta tus repositorios y elige el código que quieres analizar.' : view === 'domains' ? 'Esta parte todavía no da resultados reales: la verás aquí cuando esté lista.' : view === 'integrations' ? 'Administra los proveedores de código y consulta el estado de la IA.' : view === 'account' ? 'Tu acceso: contraseña y segundo factor.' : view === 'users' ? 'Invita a tu equipo, asigna roles y retira accesos.' : view === 'pulls' ? 'Cada PR se revisa por lo que introduce, no por lo que ya había.' : view === 'cves' ? 'Todas las vulnerabilidades publicadas en NVD, con explotación activa (KEV) y probabilidad de explotación (EPSS), buscables en local.' : view === 'compliance' ? 'Plazos de notificación del Reglamento de Ciberresiliencia de la UE para tus productos, con el borrador listo. El SBOM y el VEX se exportan desde Hallazgos.' : view === 'threats' ? 'Modela el sistema con el enfoque que prefieras (STRIDE, LINDDUN, PASTA, árboles de ataque, ATT&CK) y contrasta las amenazas con los análisis.' : 'Resultados del objetivo seleccionado, con pasos y límites de cobertura visibles.'}</p></div>{latest && <div className="flex items-center gap-2 text-xs text-app-subtle"><Clock3 className="size-3.5" />Última ejecución {isoDate(latest.created_at)}</div>}</div>
      {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
      {renderMain()}
      <footer className="border-t border-app-line pt-5 text-xs text-app-subtle">{BRAND.name} · software libre bajo <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener noreferrer" className="underline-offset-2 hover:underline">AGPL-3.0</a> · <a href={BRAND.repo} target="_blank" rel="noopener noreferrer" className="underline-offset-2 hover:underline">código fuente</a> · los resultados negativos no prueban ausencia de vulnerabilidades.</footer>
    </main></div>
  </div>{toasts.view}<UpdateNotice /></div>
}

export default App
