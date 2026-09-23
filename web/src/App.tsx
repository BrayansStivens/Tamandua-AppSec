import { useCallback, useEffect, useState } from 'react'
import {
  BookOpen, ChevronRight, Clock3, GitPullRequest, LayoutDashboard, Network,
  LogOut, Menu, Monitor, Moon, Play, PlugZap, Radar, SearchCheck, Shield, ShieldAlert, Sun, Terminal, Globe2, Layers3, UserRound, UsersRound,
  Bug,
} from 'lucide-react'
import { BrandMark } from '@/components/brand-mark'
import { CodeSources } from '@/components/code-sources'
import { DomainAssets } from '@/components/domain-assets'
import { PentestList } from '@/components/pentest-list'
import { PentestWizard } from '@/components/pentest-wizard'
import { useToasts } from '@/components/run-progress'
import { TopProgress } from '@/components/loading'
import type { SessionActions, SessionUser } from '@/components/auth/session'
import { api } from '@/lib/api'
import { readRoute, writeRoute } from '@/lib/route'
import { Account } from '@/views/Account'
import { Dashboard } from '@/views/Dashboard'
import { Findings } from '@/views/Findings'
import { CveTracker } from '@/views/CveTracker'
import { Users } from '@/views/Users'
import { Console } from '@/views/Console'
import { CoverageView } from '@/views/Coverage'
import { Integrations } from '@/views/Integrations'
import { LabFindings } from '@/views/LabFindings'
import { PullRequests } from '@/views/PullRequests'
import { Roadmap } from '@/views/Roadmap'
import { ThreatModels } from '@/views/ThreatModels'
import type { Finding, RunDetail, RunRow } from '@/lib/runs'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/components/ui/select'
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

type View = 'overview' | 'pentests' | 'new' | 'findings' | 'coverage' | 'repositories' | 'domains' | 'console' | 'integrations' | 'roadmap' | 'account' | 'users' | 'pulls' | 'threats' | 'cves'
type Theme = 'system' | 'light' | 'dark'

const navigation: { id: View; label: string; icon: typeof Shield }[] = [
  { id: 'overview', label: 'Resumen', icon: LayoutDashboard },
  { id: 'pentests', label: 'Pentests', icon: SearchCheck },
  { id: 'findings', label: 'Hallazgos', icon: ShieldAlert },
  { id: 'coverage', label: 'Cobertura', icon: Radar },
  { id: 'threats', label: 'Amenazas', icon: Network },
  { id: 'repositories', label: 'Repositorios', icon: Layers3 },
  { id: 'pulls', label: 'Pull requests', icon: GitPullRequest },
  { id: 'cves', label: 'CVE tracker', icon: Bug },
  { id: 'domains', label: 'Dominios', icon: Globe2 },
  { id: 'console', label: 'Consola', icon: Terminal },
  { id: 'integrations', label: 'Integraciones', icon: PlugZap },
  { id: 'users', label: 'Usuarios', icon: UsersRound },
  { id: 'roadmap', label: 'Próximamente', icon: BookOpen },
]
const isoDate = (date: string) => new Date(date).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })

function App({ user, session }: { user: SessionUser; session: SessionActions }) {
  const [view, setView] = useState<View>(() => (readRoute().view as View | null) ?? 'overview')
  const [rows, setRows] = useState<RunRow[]>([])
  const [detail, setDetail] = useState<RunDetail | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(() => readRoute().params.get('run'))
  // La URL manda: Atrás, Adelante y refrescar restauran vista y ejecución.
  useEffect(() => {
    const sync = () => { const route = readRoute(); if (route.view) { setView(route.view as View); setSelectedId(route.params.get('run')) } }
    window.addEventListener('popstate', sync)
    return () => window.removeEventListener('popstate', sync)
  }, [])
  useEffect(() => { if (!readRoute().view) writeRoute(view, {}, { replace: true }) }, [view])
  const [error, setError] = useState<string | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [selectedSource, setSelectedSource] = useState<string | null>(null)
  const toasts = useToasts()
  const runningIds = rows.filter(row => row.status === 'queued' || row.status === 'running').map(row => row.id).join(',')
  useEffect(() => {
    if (!runningIds) return
    const known = new Set(runningIds.split(','))
    const timer = window.setInterval(async () => {
      try {
        const data = await refresh()
        for (const row of data) if (known.has(row.id) && row.status !== 'queued' && row.status !== 'running') {
          known.delete(row.id)
          const name = row.type === 'repository_scan' ? row.source?.name ?? 'repositorio' : row.fixture
          toasts.push(row.status === 'failed' ? 'error' : 'ok', row.status === 'failed'
            ? `El escaneo de ${name} falló.`
            : `Escaneo de ${name} terminado: ${row.summary.candidates ?? 0} hallazgos${row.summary.severities ? ` (${row.summary.severities.critical ?? 0} críticos, ${row.summary.severities.high ?? 0} altos)` : ''}.`)
          if (detail?.id === row.id) void openRun(row.id, 'findings')
        }
      } catch { /* siguiente vuelta */ }
    }, 3000)
    return () => window.clearInterval(timer)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runningIds])
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('appsec-theme')
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
    localStorage.setItem('appsec-theme', theme)
    return () => media.removeEventListener('change', apply)
  }, [theme])

  const refresh = useCallback(async () => {
    const data = await api.get<RunRow[]>('/api/runs')
    setRows(data)
    return data
  }, [])
  useEffect(() => {
    refresh().then(async data => {
      const initial = data.find(row => row.type === 'repository_scan')
        ?? data.find(row => row.type === 'lab_scan' && row.variant === 'vulnerable')
        ?? data.find(row => row.type === 'lab_scan')
      if (!initial) return
      setDetail(await api.get<RunDetail>(`/api/runs/${encodeURIComponent(initial.id)}`))
    }).catch(caught => setError(caught instanceof Error ? caught.message : String(caught)))
  }, [refresh])
  const vulnerable = rows.find(row => row.type === 'lab_scan' && row.variant === 'vulnerable')
  const latestLab = rows.find(row => row.type === 'lab_scan')
  const latest = rows.find(row => row.type === 'repository_scan') ?? latestLab
  const activeRow = rows.find(row => row.id === selectedId) ?? latest ?? vulnerable
  const findings = detail && detail.id === activeRow?.id ? detail.findings ?? [] : []
  const labFindings = activeRow?.type === 'lab_scan' ? findings as Finding[] : []
  const currentTitle = view === 'new' ? 'Nuevo pentest' : view === 'account' ? 'Cuenta' : navigation.find(item => item.id === view)?.label ?? 'Resumen'

  const openRun = useCallback(async (id: string, nextView: View = 'findings') => {
    setSelectedId(id)
    setView(nextView)
    writeRoute(nextView, { run: id })
    try {
      const run = await api.get<RunDetail>(`/api/runs/${encodeURIComponent(id)}`)
      setDetail(run)
      setError(null)
      return run
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }, [])
  // Entrar en Hallazgos desde el menú muestra el estado actual; abrir una ejecución concreta pasa por openRun.
  const selectView = (next: View) => { if (next === 'new') setSelectedSource(null); if (next === 'findings') setSelectedId(null); setView(next); setMobileOpen(false); writeRoute(next) }
  const scanSource = (id: string) => { setSelectedSource(id); setView('new'); setMobileOpen(false) }
  const completedRepositoryScan = async (id: string) => { await refresh(); await openRun(id, 'findings') }

  // El asistente vive dentro de Pentests: la sección sigue marcada mientras se crea una ejecución.
  const activeNav: View = view === 'new' ? 'pentests' : view
  // Usuarios es solo para administradores; el servidor lo impone igualmente.
  const nav = <div className="space-y-1">{navigation.filter(item => item.id !== 'users' || user.role === 'admin').map(item => <button key={item.id} onClick={() => selectView(item.id)} className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left text-sm transition ${activeNav === item.id ? 'bg-accent font-medium text-accent-foreground' : 'text-app-muted hover:bg-app-soft hover:text-app-fg'}`}><item.icon className="size-4" />{item.label}{item.id === 'console' && <span className="ml-auto size-1.5 rounded-full bg-brand" />}</button>)}</div>

  const userCard = <div className="space-y-3 rounded-xl border border-app-line bg-app-soft p-3">
    <button onClick={() => selectView('account')} className={`flex w-full items-center gap-3 rounded-lg p-1 text-left transition hover:bg-app-soft ${view === 'account' ? 'text-brand' : ''}`}>
      <span className="grid size-8 shrink-0 place-items-center rounded-full bg-brand/15 text-brand"><UserRound className="size-4" /></span>
      <span className="min-w-0"><span className="block truncate text-sm font-medium">{user.display_name}</span><span className="block truncate text-xs text-app-subtle">{user.role === 'admin' ? 'Administrador' : 'Miembro'}{user.totp_enabled ? '' : ' · sin 2FA'}</span></span>
      {!user.totp_enabled && <span aria-label="Segundo factor sin activar" className="ml-auto size-2 shrink-0 rounded-full bg-amber-400" />}
    </button>
    <Button variant="ghost" size="sm" onClick={() => void session.logout()} className="w-full justify-start text-app-muted"><LogOut />Cerrar sesión</Button>
  </div>

  const renderMain = () => {
    if (view === 'new') return <PentestWizard key={selectedSource ?? 'new'} initialSourceId={selectedSource} onComplete={completedRepositoryScan} onManageConnections={() => selectView('integrations')} onCancel={() => selectView('pentests')} />
    if (view === 'pentests') return <PentestList refreshKey={rows.length * 1000 + rows.filter(row => row.status === 'running' || row.status === 'queued').length} onOpen={id => openRun(id, 'findings')} onNew={() => selectView('new')} />
    if (view === 'repositories') return <CodeSources showRepositories runs={rows} onScan={scanSource} canManage={user.role === 'admin'} />
    if (view === 'domains') return <DomainAssets onPentest={() => selectView('new')} />
    if (view === 'overview') return <Dashboard onOpenRun={id => openRun(id, 'findings')} onNew={() => selectView('new')} onTracker={id => id ? writeRoute('cves', { id }) : selectView('cves')} />
    if (view === 'threats') return <ThreatModels user={user} onOpenRun={id => openRun(id, 'findings')} />
    if (view === 'cves') return <CveTracker onNew={() => selectView('new')} />
    if (view === 'pulls') return <PullRequests user={user} onOpenRun={id => openRun(id, 'findings')} />
    // Los repositorios se ven agrupados; el laboratorio sintético conserva su propia vista.
    if (view === 'findings' && activeRow?.type !== 'lab_scan') return <Findings key={selectedId ?? 'current'} user={user} requestedRun={selectedId} onNew={() => selectView('new')} />
    if (view === 'coverage') return <CoverageView />
    if (view === 'account') return <Account user={user} onChanged={session.reload} />
    if (view === 'users' && user.role === 'admin') return <Users me={user} />
    if (view === 'integrations') return <Integrations user={user} />
    if (view === 'findings' && activeRow?.type === 'lab_scan') return <LabFindings activeRow={activeRow} findings={labFindings} onSelect={id => openRun(id, 'findings')} />
    if (view === 'console') return <Console refresh={refresh} />
    return <Roadmap />
  }

  return <div className="min-h-screen bg-app text-app-fg"><TopProgress /><div className="flex min-h-screen">
    <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-app-line bg-inset px-4 py-6 lg:flex"><div className="mb-9 flex items-center gap-3 px-2"><BrandMark size={40} /><div><div className="text-sm font-semibold tracking-wide">APPSEC AGENT</div><div className="text-xs text-app-subtle">Workspace local</div></div></div>{nav}<div className="mt-auto">{userCard}</div></aside>
    <div className="min-w-0 flex-1"><header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-app-line bg-app px-4 backdrop-blur-md sm:px-8"><div className="flex items-center gap-3"><Sheet open={mobileOpen} onOpenChange={setMobileOpen}><SheetTrigger render={<Button aria-label="Abrir navegación" variant="ghost" size="icon" className="lg:hidden" />}><Menu /></SheetTrigger><SheetContent side="left" className="w-72 border-app-line bg-inset"><SheetHeader><SheetTitle className="text-left">AppSec Agent</SheetTitle></SheetHeader><div className="space-y-6 px-3">{nav}{userCard}</div></SheetContent></Sheet><span className="hidden text-sm text-app-muted sm:inline">Workspace</span><ChevronRight className="hidden size-3 text-app-faint sm:block" /><span className="text-sm font-medium">{currentTitle}</span></div><div className="flex items-center gap-3"><Select value={theme} onValueChange={value => setTheme(value as Theme)}><SelectTrigger aria-label="Apariencia" size="sm" className="min-w-28 border-app-line bg-app-soft text-app-secondary sm:min-w-32">{theme === 'dark' ? <Moon className="size-3.5" /> : theme === 'light' ? <Sun className="size-3.5" /> : <Monitor className="size-3.5" />}<span className="min-w-0 flex-1 text-left">{theme === 'system' ? 'Sistema' : theme === 'light' ? 'Claro' : 'Oscuro'}</span></SelectTrigger><SelectContent align="end" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="system">Sistema</SelectItem><SelectItem value="light">Claro</SelectItem><SelectItem value="dark">Oscuro</SelectItem></SelectContent></Select><Badge variant="outline" className="hidden border-app-line text-app-muted sm:inline-flex">Local · v0.9</Badge><Button aria-label="Nuevo pentest" onClick={() => selectView('new')} className="bg-primary text-primary-foreground hover:bg-primary/90"><Play /><span className="hidden sm:inline">Nuevo pentest</span></Button></div></header>
    <main className="mx-auto max-w-[1520px] space-y-7 px-4 py-7 sm:px-8 sm:py-9"><div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"><div><div className="mb-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.22em] text-brand"><span className="size-1.5 rounded-full bg-brand" />Security workspace / 01</div><h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">{currentTitle}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-app-muted">{view === 'overview' ? 'Descubre, reproduce y explica cada riesgo con evidencia trazable.' : view === 'pentests' ? 'Historial de ejecuciones de este workspace, con su tipo, estado y resultados.' : view === 'new' ? 'Define el objetivo, declara el alcance y revisa qué se ejecuta antes de lanzar.' : view === 'repositories' ? 'Conecta tus repositorios y elige el código que quieres analizar.' : view === 'domains' ? 'Registra dominios y comprueba su propiedad antes de las pruebas web.' : view === 'integrations' ? 'Administra los proveedores de código y consulta el estado de la IA.' : view === 'console' ? 'Lanza pruebas acotadas y sigue sus resultados desde la consola.' : view === 'roadmap' ? 'Un mes para convertir el laboratorio en un piloto SaaS medible.' : view === 'account' ? 'Tu acceso: contraseña y segundo factor.' : view === 'users' ? 'Invita a tu equipo, asigna roles y retira accesos.' : view === 'pulls' ? 'Cada PR se revisa por lo que introduce, no por lo que ya había.' : view === 'cves' ? 'Todas las vulnerabilidades publicadas en NVD, con explotación activa (KEV) y probabilidad de explotación (EPSS), buscables en local.' : view === 'threats' ? 'Modela el sistema y contrasta cada amenaza STRIDE con lo que encuentran los escaneos.' : 'Resultados del objetivo seleccionado, con pasos y límites de cobertura visibles.'}</p></div>{latest && <div className="flex items-center gap-2 text-xs text-app-subtle"><Clock3 className="size-3.5" />Última ejecución {isoDate(latest.created_at)}</div>}</div>
      {error && <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-700 dark:text-rose-200">{error}</div>}
      <div className="lg:hidden"><Tabs value={activeNav} onValueChange={value => selectView(value as View)}><TabsList className="w-full overflow-x-auto bg-app-soft">{navigation.slice(0, 4).map(item => <TabsTrigger key={item.id} value={item.id} className="min-w-fit px-3">{item.label}</TabsTrigger>)}</TabsList></Tabs></div>
      {renderMain()}
      <footer className="border-t border-app-line pt-5 text-xs text-app-faint">AppSec Agent · software libre bajo <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener noreferrer" className="underline-offset-2 hover:underline">AGPL-3.0</a> · <a href="https://github.com/BrayansStivens/appsec-agent" target="_blank" rel="noopener noreferrer" className="underline-offset-2 hover:underline">código fuente</a> · los resultados negativos no prueban ausencia de vulnerabilidades.</footer>
    </main></div>
  </div>{toasts.view}</div>
}

export default App
