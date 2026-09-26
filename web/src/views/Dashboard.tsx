import { GettingStarted } from '@/components/getting-started'
import { lazy, Suspense, useEffect, useState } from 'react'
import { Activity, ArrowRight, ChevronDown, Clock3, Flame, RefreshCw, ShieldAlert, Wrench } from 'lucide-react'
import { ActivityHeatmap, FoundVsFixed, HBars, SeverityBar, StackedSeverityBars, sevColor, sevName } from '@/components/charts/charts'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/components/ui/select'
import { Bone, Skeleton } from '@/components/loading'
import { SeverityPill, type CveOverview } from '@/views/CveTracker'
import { api, query } from '@/lib/api'
import { slaText } from '@/lib/sla'
import { formatDate, statusLabel, type Dashboard as DashboardData } from '@/lib/types'

const SEVERITY_ES: Record<string, string> = { critical: 'crítica', high: 'alta', medium: 'media', low: 'baja', info: 'informativa' }

const SeveritySkyline = lazy(() => import('@/components/charts/skyline').then(module => ({ default: module.SeveritySkyline })))
const WINDOWS: [number, string][] = [[7, 'Últimos 7 días'], [30, 'Últimos 30 días'], [90, 'Últimos 90 días'], [365, 'Último año']]

export function Dashboard({ onOpenRun, onNew, onTracker, onNavigate }: { onOpenRun: (id: string) => void; onNew: () => void; onTracker: (id?: string) => void; onNavigate: (view: string) => void }) {
  const [days, setDays] = useState(30)
  const [data, setData] = useState<DashboardData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const load = () => api.get<DashboardData>(`/api/dashboard?${query({ days, tz: localZone() })}`).then(setData).catch(caught => setError(caught instanceof Error ? caught.message : String(caught)))
  useEffect(() => { void load() }, [days]) // eslint-disable-line react-hooks/exhaustive-deps
  if (error) return <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft p-4 text-sm text-danger">{error}</div>
  if (!data) return <Skeleton tiles={6} rows={4} />
  const { kpis } = data
  const empty = kpis.assets === 0
  return <div className="space-y-6">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-sm text-app-muted">{kpis.assets} {kpis.assets === 1 ? 'activo analizado' : 'activos analizados'} · {kpis.runs_in_window} ejecuciones en la ventana · actualizado {formatDate(data.generated_at)}</p>
      <div className="flex items-center gap-2"><Select value={String(days)} onValueChange={value => setDays(Number(value ?? 30))}><SelectTrigger size="sm" className="min-w-40 border-app-line bg-app-soft text-app-secondary">{WINDOWS.find(([value]) => value === days)?.[1]}</SelectTrigger><SelectContent align="end" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{WINDOWS.map(([value, label]) => <SelectItem key={value} value={String(value)}>{label}</SelectItem>)}</SelectContent></Select><Button variant="ghost" size="icon-sm" aria-label="Actualizar" onClick={() => void load()}><RefreshCw /></Button></div>
    </div>

    <GettingStarted onNavigate={onNavigate} />
    {empty && <Card className="border-app-line bg-panel"><CardContent className="flex flex-col items-center gap-3 py-12 text-center"><Activity className="size-7 text-app-subtle" /><p className="font-medium">Todavía no hay ejecuciones</p><p className="max-w-md text-sm text-app-muted">El panel se calcula a partir de tus escaneos: hallazgos abiertos por severidad, qué se corrigió entre ejecuciones, exploitabilidad y actividad.</p><Button variant="outline" onClick={onNew} className="border-app-line bg-app-soft">Nuevo análisis <ArrowRight /></Button></CardContent></Card>}

    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
      <Kpi label="Puntuación" value={kpis.security_score.value} suffix="/100" hint={kpis.security_score.formula} tone={kpis.security_score.value >= 80 ? 'teal' : kpis.security_score.value >= 50 ? 'amber' : 'rose'} />
      <Kpi label="Abiertos" value={kpis.open.total} hint={`${kpis.open.critical} críticos · ${kpis.open.high} altos`} tone={kpis.open.critical ? 'rose' : 'muted'} />
      <Kpi label="Fuera de plazo" value={kpis.sla?.overdue ?? '—'} hint={kpis.sla ? `${kpis.sla.soon} vencen en los próximos 7 días` : 'sin plazos'} tone={kpis.sla?.overdue ? 'rose' : 'muted'} icon={Clock3} />
      <Kpi label="Corregidos" value={kpis.fixed_in_window} hint={kpis.fix_rate !== null ? `tasa de corrección ${kpis.fix_rate}%` : 'sin ejecuciones comparables'} tone="teal" icon={Wrench} />
      <Kpi label="Tiempo medio de corrección" value={kpis.mttr_days ?? '—'} suffix={kpis.mttr_days !== null ? ' días' : ''} hint="entre detección y desaparición" tone="muted" />
      <Kpi label="En CISA KEV" value={kpis.kev_open} hint="abiertos con explotación activa" tone={kpis.kev_open ? 'rose' : 'muted'} icon={Flame} />
    </div>

    <div className="grid gap-5 xl:grid-cols-[1.5fr_1fr]">
      <Panel title="Hallazgos nuevos por día" description={`Primera vez que aparece cada huella, por severidad: ${kpis.found_in_window.toLocaleString('es-CO')} en la ventana.`}><StackedSeverityBars data={data.issues_over_time} /></Panel>
      <Panel title="Abiertos por severidad" description="Lo que hay en la última ejecución de cada activo."><SeverityBar counts={kpis.open} /></Panel>
    </div>
    <div className="grid gap-5 xl:grid-cols-[1fr_1fr_1fr]">
      <Panel title="Hallados frente a corregidos" description="Acumulado en la ventana. Corregido = la huella dejó de aparecer en el activo."><FoundVsFixed data={data.open_vs_fixed} /></Panel>
      <Panel title="Por tipo de vulnerabilidad" description="Los CWE más frecuentes entre los abiertos.">{data.by_cwe.length ? <HBars rows={data.by_cwe.slice(0, LIST).map(row => ({ label: row.name ? `CWE-${row.cwe} · ${row.name}` : `CWE-${row.cwe}`, hint: `CWE-${row.cwe}${row.name ? ` · ${row.name}` : ''}`, value: row.count }))} /> : <Empty text="Sin CWE todavía." />}</Panel>
      <Panel title="Exploitabilidad" description="Abiertos en CISA KEV o con EPSS ≥ 10 %, lo más urgente primero."><Exploitability data={data.exploitability} onMore={() => onNavigate('findings')} /></Panel>
    </div>
    <div className="grid gap-5 xl:grid-cols-[1fr_1fr_1fr]">
      <Panel title="Activos más afectados" description="Última ejecución de cada repositorio.">{data.top_assets.length ? <><div className="divide-y divide-app-line text-sm">{data.top_assets.slice(0, LIST).map(asset => <button key={asset.name} onClick={() => onOpenRun(asset.last_run)} className="flex w-full items-center justify-between gap-3 py-2 text-left hover:text-brand"><span className="min-w-0"><span className="block truncate">{asset.name}</span><span className="text-xs text-app-subtle">{asset.open} abiertos{asset.trend !== null ? ` · ${asset.trend > 0 ? '+' : ''}${asset.trend} vs anterior` : ''}</span></span><span className="flex shrink-0 gap-1 font-mono text-[11px]">{(['critical', 'high', 'medium', 'low'] as const).map(level => asset[level] ? <span key={level} className="rounded px-1.5 py-0.5 text-on-solid" style={{ background: sevColor[level] }} title={sevName[level]}>{asset[level]}</span> : null)}</span></button>)}</div><More shown={LIST} total={data.top_assets.length} label="Ver en Hallazgos" onClick={() => onNavigate('findings')} /></> : <Empty text="Sin activos analizados." />}</Panel>
      <Panel title="Hallazgos prioritarios" description="Los primeros por prioridad, severidad y EPSS.">{data.top_issues.length ? <><div className="divide-y divide-app-line text-sm">{data.top_issues.slice(0, LIST).map(issue => <button key={issue.fingerprint} onClick={() => issue.run_id && onOpenRun(issue.run_id)} className="flex w-full items-start gap-2 py-2 text-left hover:text-brand"><span className="mt-1 inline-block size-2.5 shrink-0 rounded-sm" style={{ background: sevColor[issue.severity] }} title={`Severidad ${SEVERITY_ES[issue.severity] ?? issue.severity}`} /><span className="sr-only">Severidad {SEVERITY_ES[issue.severity] ?? issue.severity}: </span><span className="min-w-0"><span className="block truncate">{issue.title}</span><span className="text-xs text-app-subtle">{issue.asset}{issue.sla && issue.sla.state !== 'ok' ? ` · ${slaText(issue.sla).toLowerCase()}` : ''}{issue.kev ? ' · KEV' : ''}{issue.epss ? ` · EPSS ${(issue.epss * 100).toFixed(1)}%` : ''}</span></span></button>)}</div><More shown={LIST} total={data.top_issues.length} label="Ver todos en Hallazgos" onClick={() => onNavigate('findings')} /></> : <Empty text="Nada abierto." />}</Panel>
      <Panel title="Ejecuciones recientes" description="Últimos escaneos.">{data.recent_runs.length ? <><div className="divide-y divide-app-line text-sm">{data.recent_runs.slice(0, LIST).map(run => <button key={run.id} onClick={() => onOpenRun(run.id)} className="flex w-full items-center justify-between gap-3 py-2 text-left hover:text-brand"><span className="min-w-0"><span className="block truncate">{run.source?.name ?? run.fixture}</span><span className="text-xs text-app-subtle">{formatDate(run.created_at)}</span></span><Badge variant="outline" className="shrink-0 text-[11px]">{statusLabel(run.status)}</Badge></button>)}</div><More shown={LIST} total={data.recent_runs.length} label="Ver todas en Análisis" onClick={() => onNavigate('analyses')} /></> : <Empty text="Sin ejecuciones." />}</Panel>
    </div>
    <Card className="border-app-line bg-panel"><CardHeader className="pb-3"><CardTitle className="text-base">Actividad de análisis</CardTitle><CardDescription className="text-xs">Ejecuciones por día, hasta hoy.</CardDescription></CardHeader>
      <CardContent className="flex flex-col gap-6 lg:flex-row lg:items-start"><div className="min-w-0 flex-1"><ActivityHeatmap days={data.activity} /></div><ActivityStats days={data.activity} /></CardContent></Card>
    <CyberNews news={data.cve_news} onTracker={onTracker} kev={<KevNews news={data.kev_news} onTracker={onTracker} />} />
    {data.tools.length ? <p className="flex flex-wrap gap-3 text-xs text-app-subtle"><ShieldAlert className="size-3.5" />Motores en la última ejecución: {data.tools.map(tool => `${tool.name} ${tool.version} (${tool.status})`).join(' · ')}</p> : null}
  </div>
}

function Kpi({ label, value, suffix = '', hint, tone, icon: Icon }: { label: string; value: number | string; suffix?: string; hint: string; tone: 'rose' | 'amber' | 'teal' | 'muted'; icon?: typeof Flame }) {
  const color = { rose: 'text-danger', amber: 'text-warning', teal: 'text-brand', muted: 'text-app-fg' }[tone]
  return <Card className="border-app-line bg-panel"><CardContent className="flex items-start justify-between p-4"><div className="min-w-0"><div className={`text-2xl font-semibold ${color}`}>{value}<span className="text-sm font-normal text-app-subtle">{suffix}</span></div><div className="mt-0.5 text-xs text-app-muted">{label}</div><div className="truncate text-[11px] text-app-subtle" title={hint}>{hint}</div></div>{Icon && <Icon className="size-4 shrink-0 text-app-subtle" />}</CardContent></Card>
}
// Novedades a dos columnas: a la izquierda las cifras y el «skyline» de severidad de los últimos
// 30 días (la base local de NVD); a la derecha lo último publicado, con salida al tracker.
function CyberNews({ news, onTracker, kev }: { news: DashboardData['cve_news']; onTracker: (id?: string) => void; kev: React.ReactNode }) {
  const [overview, setOverview] = useState<CveOverview | null>(null)
  useEffect(() => { api.get<CveOverview>('/api/cve-db/overview').then(setOverview).catch(() => undefined) }, [])
  const cells = overview?.daily ?? []
  const count = (value: number | null | undefined) => value !== null && value !== undefined ? value.toLocaleString('es-CO') : '—'
  return <div className="grid gap-5 lg:grid-cols-2 xl:grid-cols-3">
    <Card className="border-app-line bg-panel">
      <CardHeader className="pb-2"><CardTitle className="text-base">Novedades en ciberseguridad</CardTitle><CardDescription className="text-xs">Vulnerabilidades publicadas según NVD{news.refreshing ? ' · actualizando…' : ''}</CardDescription></CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-x-14 gap-y-3">
          <div><div className="text-5xl font-semibold tracking-tight tabular-nums">{count(news.published_7d)}</div><div className="mt-1 text-sm text-app-muted">últimos 7 días</div></div>
          <div><div className="text-5xl font-semibold tracking-tight tabular-nums">{count(news.published_30d)}</div><div className="mt-1 text-sm text-app-muted">últimos 30 días</div></div>
        </div>
        <div className="mt-6">{!overview ? <div role="status" aria-label="Cargando el skyline de severidad"><Bone className="h-[260px] rounded-xl" /></div> : cells.length ? <Suspense fallback={<Bone className="h-[260px] rounded-xl" />}><SeveritySkyline cells={cells} height={260} /></Suspense>
          : <div className="grid h-[260px] place-items-center rounded-xl border border-dashed border-app-line text-center text-xs text-app-subtle"><span>El skyline de severidad aparece en cuanto la base local<br />tenga los CVE de los últimos 30 días.</span></div>}</div>
      </CardContent>
    </Card>
    <Card className="border-app-line bg-panel">
      <CardHeader className="flex flex-row items-start justify-between gap-3 pb-2"><div><CardTitle className="text-base">Últimos CVE publicados</CardTitle><CardDescription className="text-xs">«Te afecta» cuando menciona un paquete o CVE de tus hallazgos abiertos.</CardDescription></div>
        <Button variant="ghost" size="sm" onClick={() => onTracker()} className="shrink-0 text-app-muted">CVE tracker <ArrowRight /></Button></CardHeader>
      <CardContent>{news.items.length ? <div className="divide-y divide-app-line">{news.items.slice(0, 6).map(item => <button key={item.cve} type="button" onClick={() => onTracker(item.cve)} className="flex w-full items-start gap-3 py-2.5 text-left hover:bg-app-soft/60">
        <span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs font-medium">{item.cve}</span><SeverityPill severity={item.severity} score={item.score} />{item.affects && <Badge variant="outline" className="border-transparent bg-danger-solid text-[11px] text-on-solid">te afecta</Badge>}</span>
          <span className="mt-0.5 block truncate text-xs text-app-muted" title={item.description}>{item.description}</span></span>
        <span className="shrink-0 pt-0.5 text-[11px] text-app-subtle">{item.published ? new Date(item.published).toLocaleDateString('es-CO', { day: 'numeric', month: 'short' }) : ''}</span></button>)}</div>
        : <Empty text="Sin feed de NVD todavía: se descarga en segundo plano." />}
        <Button variant="outline" onClick={() => onTracker()} className="mt-3 w-full border-app-line bg-app-soft">Buscar en todos los CVE <ArrowRight /></Button>
      </CardContent>
    </Card>
    {kev}
  </div>
}

function KevNews({ news, onTracker }: { news: DashboardData['kev_news']; onTracker: (id?: string) => void }) {
  return <Card className="border-app-line bg-panel lg:col-span-2 xl:col-span-1"><CardHeader className="pb-3"><CardTitle className="text-base">Novedades: explotación activa</CardTitle><CardDescription className="text-xs">Altas en CISA KEV · catálogo {news.catalog_version ?? '—'}</CardDescription></CardHeader>
    <CardContent>
      <div className="mb-3 flex gap-6"><Hero value={news.added_7d} label="añadidas en 7 días" /><Hero value={news.added_30d} label="en 30 días" /></div>
      <div className="divide-y divide-app-line text-sm">{news.items.slice(0, LIST).map(item => <button key={item.cve} type="button" onClick={() => onTracker(item.cve)} className="flex w-full items-start justify-between gap-3 py-2 text-left hover:bg-app-soft/60"><span className="min-w-0"><span className="font-mono text-xs text-brand">{item.cve}</span><span className="block truncate text-xs text-app-muted" title={item.name ?? ''}>{item.name}</span></span><span className="flex shrink-0 flex-col items-end gap-1 text-[11px] text-app-subtle">{item.date_added}{item.affects && <Badge variant="outline" className="border-transparent bg-danger-solid text-[11px] text-on-solid">te afecta</Badge>}{item.ransomware && <span className="text-danger">ransomware</span>}</span></button>)}</div>
      <More shown={LIST} total={news.items.length} label="Ver en el CVE tracker" onClick={() => onTracker()} />
    </CardContent>
  </Card>
}

// Junto al mapa: cifras que lo resumen, para no dejar la tarjeta a medio llenar.
function ActivityStats({ days }: { days: DashboardData['activity'] }) {
  const last30 = days.slice(-30)
  const active = days.filter(item => item.runs > 0)
  let streak = 0
  for (let index = days.length - 1; index >= 0 && days[index].runs > 0; index -= 1) streak += 1
  const stats: [string, string][] = [
    [last30.reduce((sum, item) => sum + item.runs, 0).toLocaleString('es-CO'), 'ejecuciones en 30 días'],
    [active.length.toLocaleString('es-CO'), 'días con actividad en el último año'],
    [streak ? `${streak} ${streak === 1 ? 'día' : 'días'}` : '—', 'racha actual'],
    [active.length ? new Date(`${active[active.length - 1].day}T00:00:00Z`).toLocaleDateString('es-CO', { day: 'numeric', month: 'short', timeZone: 'UTC' }) : '—', 'último día con análisis'],
  ]
  return <dl className="grid shrink-0 grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-4 lg:w-80 lg:grid-cols-2">{stats.map(([value, label]) => <div key={label} className="flex flex-col-reverse"><dt className="text-xs text-app-muted">{label}</dt><dd className="text-xl font-semibold tabular-nums">{value}</dd></div>)}</dl>
}

function Panel({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return <Card className="border-app-line bg-panel"><CardHeader className="pb-3"><CardTitle className="text-base">{title}</CardTitle><CardDescription className="text-xs">{description}</CardDescription></CardHeader><CardContent>{children}</CardContent></Card>
}
// La zona del navegador: «hoy» y los días de las gráficas son los de quien mira, no los del servidor.
const localZone = () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone } catch { return undefined } }
const LIST = 6  // filas por tarjeta: las tarjetas vecinas quedan de alto parecido y el resto está a un clic

function More({ shown, total, label, onClick }: { shown: number; total: number; label: string; onClick: () => void }) {
  if (total <= shown) return null
  return <button type="button" onClick={onClick} className="mt-2 flex min-h-6 items-center gap-1 text-xs text-app-muted hover:text-app-fg">{label} <ArrowRight className="size-3" /></button>
}

type Exploitable = DashboardData['exploitability']
// KEV primero (explotación confirmada) y después EPSS alto; seis filas y el resto al desplegar, sin estirar la fila.
function Exploitability({ data, onMore }: { data: Exploitable; onMore: () => void }) {
  const [all, setAll] = useState(false)
  const rows = [...data.kev.map(item => ({ key: `k-${item.cve}-${item.asset}`, cve: item.cve, where: item.package ?? item.asset,
    tag: <Badge variant="outline" className="border-transparent bg-danger-solid text-on-solid">KEV{item.ransomware ? ' · ransomware' : ''}</Badge> })),
  ...data.high_epss.filter(item => !data.kev.some(kev => kev.cve === item.cve && kev.asset === item.asset)).map(item => ({ key: `e-${item.cve}-${item.asset}`, cve: item.cve, where: item.package ?? item.asset,
    tag: <span className="font-mono text-xs text-app-secondary">EPSS {(item.epss * 100).toFixed(0)}%</span> }))]
  if (!rows.length) return <Empty text="Ningún hallazgo abierto tiene explotación conocida ni EPSS alto." />
  const total = (data.kev_total ?? data.kev.length) + (data.epss_total ?? data.high_epss.length)
  const visible = all ? rows : rows.slice(0, LIST)
  return <div className="text-sm">
    <div className={all ? 'max-h-80 overflow-y-auto pr-1' : ''} tabIndex={all ? 0 : undefined} role={all ? 'region' : undefined} aria-label={all ? 'Hallazgos explotables' : undefined}>{visible.map(row => <Row key={row.key} left={<span className="min-w-0 truncate"><span className="font-mono text-xs">{row.cve}</span> <span className="text-app-muted">· {row.where}</span></span>} right={row.tag} />)}</div>
    {rows.length > LIST && <button type="button" aria-expanded={all} onClick={() => setAll(value => !value)} className="mt-2 flex min-h-6 items-center gap-1 text-xs text-app-muted hover:text-app-fg">{all ? 'Ver menos' : `Ver los ${rows.length}`}<ChevronDown className={`size-3 motion-safe:transition motion-safe:duration-150 ${all ? 'rotate-180' : ''}`} /></button>}
    {total > rows.length && all && <button type="button" onClick={onMore} className="mt-1 flex min-h-6 items-center gap-1 text-xs text-app-muted hover:text-app-fg">Se muestran {rows.length} de {total}: el resto, en Hallazgos <ArrowRight className="size-3" /></button>}
  </div>
}

function Row({ left, right }: { left: React.ReactNode; right: React.ReactNode }) { return <div className="flex items-center justify-between gap-3 border-b border-app-line py-1.5 last:border-0">{left}{right}</div> }
function Hero({ value, label }: { value: number; label: string }) { return <div><div className="text-3xl font-semibold">{value}</div><div className="text-xs text-app-muted">{label}</div></div> }
function Empty({ text }: { text: string }) { return <p className="py-6 text-center text-sm text-app-subtle">{text}</p> }
