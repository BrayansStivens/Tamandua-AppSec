import { useQuery } from '@tanstack/react-query'
import { dashboardQuery } from '@/shared/api/queries'
import { GettingStarted } from '@/features/onboarding/getting-started'
import { lazy, Suspense, useEffect, useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { formatDay, formatNumber, formatPercent } from '@/shared/i18n/format'
import { Activity, ArrowRight, ChevronDown, Clock3, Flame, RefreshCw, ShieldAlert, Wrench } from 'lucide-react'
import { ActivityHeatmap, FoundVsFixed, HBars, SeverityBar, StackedSeverityBars, sevColor, sevName } from '@/shared/charts/charts'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { Bone, Skeleton } from '@/shared/ui/loading'
import { SeverityPill, type CveOverview } from '@/pages/CveTracker'
import { api } from '@/shared/api/http'
import { slaText } from '@/features/findings/sla'
import { formatDate, type Dashboard as DashboardData } from '@/shared/lib/types'

const SEVERITY = { critical: 'common:severity.critical', high: 'common:severity.high', medium: 'common:severity.medium', low: 'common:severity.low', info: 'common:severity.info' } as const
const STATUS = { completed: 'common:run_status.completed', incomplete: 'common:run_status.incomplete', failed: 'common:run_status.failed', queued: 'common:run_status.queued', running: 'common:run_status.running' } as const

const SeveritySkyline = lazy(() => import('@/shared/charts/skyline').then(module => ({ default: module.SeveritySkyline })))
const WINDOWS = [[7, 'window.days_7'], [30, 'window.days_30'], [90, 'window.days_90'], [365, 'window.days_365']] as const

export function Dashboard({ onOpenRun, onNew, onTracker, onNavigate }: { onOpenRun: (id: string) => void; onNew: () => void; onTracker: (id?: string) => void; onNavigate: (view: string) => void }) {
  const { t } = useTranslation('dashboard')
  const [days, setDays] = useState(30)
  const result = useQuery(dashboardQuery(days, localZone()))
  const data: DashboardData | undefined = result.data
  const error = result.error ? (result.error instanceof Error ? result.error.message : String(result.error)) : null
  const load = () => result.refetch()
  if (error) return <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft p-4 text-sm text-danger">{error}</div>
  if (!data) return <Skeleton tiles={6} rows={4} />
  const { kpis } = data
  const empty = kpis.assets === 0
  const severityName = (severity: string) => severity in SEVERITY ? t(SEVERITY[severity as keyof typeof SEVERITY]).toLowerCase() : severity
  const statusName = (status: string) => status in STATUS ? t(STATUS[status as keyof typeof STATUS]) : status
  return <div className="space-y-6">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-sm text-app-muted">{t('summary.assets', { count: kpis.assets })} · {t('summary.runs', { count: kpis.runs_in_window })} · {t('summary.updated', { date: formatDate(data.generated_at) })}</p>
      <div className="flex items-center gap-2"><Select value={String(days)} onValueChange={value => setDays(Number(value ?? 30))}><SelectTrigger size="sm" className="min-w-40 border-app-line bg-app-soft text-app-secondary">{t(WINDOWS.find(([value]) => value === days)?.[1] ?? 'window.days_30')}</SelectTrigger><SelectContent align="end" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{WINDOWS.map(([value, label]) => <SelectItem key={value} value={String(value)}>{t(label)}</SelectItem>)}</SelectContent></Select><Button variant="ghost" size="icon-sm" aria-label={t('common:actions.refresh')} onClick={() => void load()}><RefreshCw /></Button></div>
    </div>

    <GettingStarted onNavigate={onNavigate} />
    {empty && <Card className="border-app-line bg-panel"><CardContent className="flex flex-col items-center gap-3 py-12 text-center"><Activity className="size-7 text-app-subtle" /><p className="font-medium">{t('empty.title')}</p><p className="max-w-md text-sm text-app-muted">{t('empty.text')}</p><Button variant="outline" onClick={onNew} className="border-app-line bg-app-soft">{t('empty.new_analysis')} <ArrowRight /></Button></CardContent></Card>}

    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
      <Kpi label={t('kpi.score')} value={kpis.security_score.value} suffix="/100" hint={kpis.security_score.formula} tone={kpis.security_score.value >= 80 ? 'teal' : kpis.security_score.value >= 50 ? 'amber' : 'rose'} />
      <Kpi label={t('kpi.open')} value={kpis.open.total} hint={t('kpi.open_hint', { critical: kpis.open.critical, high: kpis.open.high })} tone={kpis.open.critical ? 'rose' : 'muted'} />
      <Kpi label={t('kpi.overdue')} value={kpis.sla?.overdue ?? '—'} hint={kpis.sla ? t('kpi.due_soon', { count: kpis.sla.soon }) : t('kpi.no_due_dates')} tone={kpis.sla?.overdue ? 'rose' : 'muted'} icon={Clock3} />
      <Kpi label={t('kpi.fixed')} value={kpis.fixed_in_window} hint={kpis.fix_rate !== null ? t('kpi.fix_rate', { rate: formatPercent(kpis.fix_rate / 100, 1) }) : t('kpi.no_comparable_runs')} tone="teal" icon={Wrench} />
      <Kpi label={t('kpi.mttr')} value={kpis.mttr_days ?? '—'} suffix={kpis.mttr_days !== null ? ` ${t('kpi.days', { count: kpis.mttr_days })}` : ''} hint={t('kpi.mttr_hint')} tone="muted" />
      <Kpi label={t('kpi.kev')} value={kpis.kev_open} hint={t('kpi.kev_hint')} tone={kpis.kev_open ? 'rose' : 'muted'} icon={Flame} />
    </div>

    <div className="grid gap-5 xl:grid-cols-[1.5fr_1fr]">
      <Panel title={t('panels.new_per_day.title')} description={t('panels.new_per_day.description', { total: formatNumber(kpis.found_in_window) })}><StackedSeverityBars data={data.issues_over_time} /></Panel>
      <Panel title={t('panels.open_by_severity.title')} description={t('panels.open_by_severity.description')}><SeverityBar counts={kpis.open} /></Panel>
    </div>
    <div className="grid gap-5 xl:grid-cols-[1fr_1fr_1fr]">
      <Panel title={t('panels.found_vs_fixed.title')} description={t('panels.found_vs_fixed.description')}><FoundVsFixed data={data.open_vs_fixed} /></Panel>
      <Panel title={t('panels.by_cwe.title')} description={t('panels.by_cwe.description')}>{data.by_cwe.length ? <HBars rows={data.by_cwe.slice(0, LIST).map(row => ({ label: row.name ? `CWE-${row.cwe} · ${row.name}` : `CWE-${row.cwe}`, hint: `CWE-${row.cwe}${row.name ? ` · ${row.name}` : ''}`, value: row.count }))} /> : <Empty text={t('panels.by_cwe.empty')} />}</Panel>
      <Panel title={t('panels.exploitability.title')} description={t('panels.exploitability.description')}><Exploitability data={data.exploitability} onMore={() => onNavigate('findings')} /></Panel>
    </div>
    <div className="grid gap-5 xl:grid-cols-[1fr_1fr_1fr]">
      <Panel title={t('panels.top_assets.title')} description={t('panels.top_assets.description')}>{data.top_assets.length ? <><div className="divide-y divide-app-line text-sm">{data.top_assets.slice(0, LIST).map(asset => <button key={asset.name} onClick={() => onOpenRun(asset.last_run)} className="flex w-full items-center justify-between gap-3 py-2 text-left hover:text-brand"><span className="min-w-0"><span className="block truncate">{asset.name}</span><span className="text-xs text-app-subtle">{t('panels.top_assets.open', { count: asset.open })}{asset.trend !== null ? ` · ${t('panels.top_assets.trend', { trend: `${asset.trend > 0 ? '+' : ''}${asset.trend}` })}` : ''}</span></span><span className="flex shrink-0 gap-1 font-mono text-[11px]">{(['critical', 'high', 'medium', 'low'] as const).map(level => asset[level] ? <span key={level} className="rounded px-1.5 py-0.5 text-on-solid" style={{ background: sevColor[level] }} title={sevName[level]}>{asset[level]}</span> : null)}</span></button>)}</div><More shown={LIST} total={data.top_assets.length} label={t('panels.top_assets.more')} onClick={() => onNavigate('findings')} /></> : <Empty text={t('panels.top_assets.empty')} />}</Panel>
      <Panel title={t('panels.top_issues.title')} description={t('panels.top_issues.description')}>{data.top_issues.length ? <><div className="divide-y divide-app-line text-sm">{data.top_issues.slice(0, LIST).map(issue => <button key={issue.fingerprint} onClick={() => issue.run_id && onOpenRun(issue.run_id)} className="flex w-full items-start gap-2 py-2 text-left hover:text-brand"><span className="mt-1 inline-block size-2.5 shrink-0 rounded-sm" style={{ background: sevColor[issue.severity] }} title={t('panels.top_issues.severity', { severity: severityName(issue.severity) })} /><span className="sr-only">{t('panels.top_issues.severity', { severity: severityName(issue.severity) })}: </span><span className="min-w-0"><span className="block truncate">{issue.title}</span><span className="text-xs text-app-subtle">{issue.asset}{issue.sla && issue.sla.state !== 'ok' ? ` · ${slaText(issue.sla).toLowerCase()}` : ''}{issue.kev ? ' · KEV' : ''}{issue.epss ? ` · EPSS ${formatPercent(issue.epss, 1)}` : ''}</span></span></button>)}</div><More shown={LIST} total={data.top_issues.length} label={t('panels.top_issues.more')} onClick={() => onNavigate('findings')} /></> : <Empty text={t('panels.top_issues.empty')} />}</Panel>
      <Panel title={t('panels.recent_runs.title')} description={t('panels.recent_runs.description')}>{data.recent_runs.length ? <><div className="divide-y divide-app-line text-sm">{data.recent_runs.slice(0, LIST).map(run => <button key={run.id} onClick={() => onOpenRun(run.id)} className="flex w-full items-center justify-between gap-3 py-2 text-left hover:text-brand"><span className="min-w-0"><span className="block truncate">{run.source?.name ?? run.target}</span><span className="text-xs text-app-subtle">{formatDate(run.created_at)}</span></span><Badge variant="outline" className="shrink-0 text-[11px]">{statusName(run.status)}</Badge></button>)}</div><More shown={LIST} total={data.recent_runs.length} label={t('panels.recent_runs.more')} onClick={() => onNavigate('analyses')} /></> : <Empty text={t('panels.recent_runs.empty')} />}</Panel>
    </div>
    <Card className="border-app-line bg-panel"><CardHeader className="pb-3"><CardTitle className="text-base">{t('activity.title')}</CardTitle><CardDescription className="text-xs">{t('activity.description')}</CardDescription></CardHeader>
      <CardContent className="flex flex-col gap-6 lg:flex-row lg:items-start"><div className="min-w-0 flex-1"><ActivityHeatmap days={data.activity} /></div><ActivityStats days={data.activity} /></CardContent></Card>
    <CyberNews news={data.cve_news} onTracker={onTracker} kev={<KevNews news={data.kev_news} onTracker={onTracker} />} />
    {data.tools.length ? <p className="flex flex-wrap gap-3 text-xs text-app-subtle"><ShieldAlert className="size-3.5" />{t('tools', { tools: data.tools.map(tool => `${tool.name} ${tool.version} (${tool.status})`).join(' · ') })}</p> : null}
  </div>
}

function Kpi({ label, value, suffix = '', hint, tone, icon: Icon }: { label: string; value: number | string; suffix?: string; hint: string; tone: 'rose' | 'amber' | 'teal' | 'muted'; icon?: typeof Flame }) {
  const color = { rose: 'text-danger', amber: 'text-warning', teal: 'text-brand', muted: 'text-app-fg' }[tone]
  return <Card className="border-app-line bg-panel"><CardContent className="flex items-start justify-between p-4"><div className="min-w-0"><div className={`text-2xl font-semibold ${color}`}>{value}<span className="text-sm font-normal text-app-subtle">{suffix}</span></div><div className="mt-0.5 text-xs text-app-muted">{label}</div><div className="truncate text-[11px] text-app-subtle" title={hint}>{hint}</div></div>{Icon && <Icon className="size-4 shrink-0 text-app-subtle" />}</CardContent></Card>
}
// Novedades a dos columnas: a la izquierda las cifras y el «skyline» de severidad de los últimos
// 30 días (la base local de NVD); a la derecha lo último publicado, con salida al tracker.
function CyberNews({ news, onTracker, kev }: { news: DashboardData['cve_news']; onTracker: (id?: string) => void; kev: React.ReactNode }) {
  const { t } = useTranslation('dashboard')
  const [overview, setOverview] = useState<CveOverview | null>(null)
  useEffect(() => { api.get<CveOverview>('/api/cve-db/overview').then(setOverview).catch(() => undefined) }, [])
  const cells = overview?.daily ?? []
  const count = (value: number | null | undefined) => value !== null && value !== undefined ? formatNumber(value) : '—'
  return <div className="grid gap-5 lg:grid-cols-2 xl:grid-cols-3">
    <Card className="border-app-line bg-panel">
      <CardHeader className="pb-2"><CardTitle className="text-base">{t('news.title')}</CardTitle><CardDescription className="text-xs">{news.refreshing ? t('news.description_refreshing') : t('news.description')}</CardDescription></CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-x-14 gap-y-3">
          <div><div className="text-5xl font-semibold tracking-tight tabular-nums">{count(news.published_7d)}</div><div className="mt-1 text-sm text-app-muted">{t('news.last_7_days')}</div></div>
          <div><div className="text-5xl font-semibold tracking-tight tabular-nums">{count(news.published_30d)}</div><div className="mt-1 text-sm text-app-muted">{t('news.last_30_days')}</div></div>
        </div>
        <div className="mt-6">{!overview ? <div role="status" aria-label={t('news.skyline_loading')}><Bone className="h-[260px] rounded-xl" /></div> : cells.length ? <Suspense fallback={<Bone className="h-[260px] rounded-xl" />}><SeveritySkyline cells={cells} height={260} /></Suspense>
          : <div className="grid h-[260px] place-items-center rounded-xl border border-dashed border-app-line text-center text-xs text-app-subtle"><span><Trans t={t} i18nKey="news.skyline_empty" components={{ br: <br /> }} /></span></div>}</div>
      </CardContent>
    </Card>
    <Card className="border-app-line bg-panel">
      <CardHeader className="flex flex-row items-start justify-between gap-3 pb-2"><div><CardTitle className="text-base">{t('news.latest_title')}</CardTitle><CardDescription className="text-xs">{t('news.latest_description')}</CardDescription></div>
        <Button variant="ghost" size="sm" onClick={() => onTracker()} className="shrink-0 text-app-muted">{t('news.tracker')} <ArrowRight /></Button></CardHeader>
      <CardContent>{news.items.length ? <div className="divide-y divide-app-line">{news.items.slice(0, 6).map(item => <button key={item.cve} type="button" onClick={() => onTracker(item.cve)} className="flex w-full items-start gap-3 py-2.5 text-left hover:bg-app-soft/60">
        <span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs font-medium">{item.cve}</span><SeverityPill severity={item.severity} score={item.score} />{item.affects && <Badge variant="outline" className="border-transparent bg-danger-solid text-[11px] text-on-solid">{t('news.affects_you')}</Badge>}</span>
          <span className="mt-0.5 block truncate text-xs text-app-muted" title={item.description}>{item.description}</span></span>
        <span className="shrink-0 pt-0.5 text-[11px] text-app-subtle">{item.published ? formatDay(item.published, { day: 'numeric', month: 'short' }) : ''}</span></button>)}</div>
        : <Empty text={t('news.feed_empty')} />}
        <Button variant="outline" onClick={() => onTracker()} className="mt-3 w-full border-app-line bg-app-soft">{t('news.search_all')} <ArrowRight /></Button>
      </CardContent>
    </Card>
    {kev}
  </div>
}

function KevNews({ news, onTracker }: { news: DashboardData['kev_news']; onTracker: (id?: string) => void }) {
  const { t } = useTranslation('dashboard')
  return <Card className="border-app-line bg-panel lg:col-span-2 xl:col-span-1"><CardHeader className="pb-3"><CardTitle className="text-base">{t('kev.title')}</CardTitle><CardDescription className="text-xs">{t('kev.description', { version: news.catalog_version ?? '—' })}</CardDescription></CardHeader>
    <CardContent>
      <div className="mb-3 flex gap-6"><Hero value={news.added_7d} label={t('kev.added_7d')} /><Hero value={news.added_30d} label={t('kev.added_30d')} /></div>
      <div className="divide-y divide-app-line text-sm">{news.items.slice(0, LIST).map(item => <button key={item.cve} type="button" onClick={() => onTracker(item.cve)} className="flex w-full items-start justify-between gap-3 py-2 text-left hover:bg-app-soft/60"><span className="min-w-0"><span className="font-mono text-xs text-brand">{item.cve}</span><span className="block truncate text-xs text-app-muted" title={item.name ?? ''}>{item.name}</span></span><span className="flex shrink-0 flex-col items-end gap-1 text-[11px] text-app-subtle">{item.date_added}{item.affects && <Badge variant="outline" className="border-transparent bg-danger-solid text-[11px] text-on-solid">{t('news.affects_you')}</Badge>}{item.ransomware && <span className="text-danger">ransomware</span>}</span></button>)}</div>
      <More shown={LIST} total={news.items.length} label={t('kev.more')} onClick={() => onTracker()} />
    </CardContent>
  </Card>
}

// Junto al mapa: cifras que lo resumen, para no dejar la tarjeta a medio llenar.
function ActivityStats({ days }: { days: DashboardData['activity'] }) {
  const { t } = useTranslation('dashboard')
  const last30 = days.slice(-30)
  const active = days.filter(item => item.runs > 0)
  let streak = 0
  for (let index = days.length - 1; index >= 0 && days[index].runs > 0; index -= 1) streak += 1
  const stats: [string, string][] = [
    [formatNumber(last30.reduce((sum, item) => sum + item.runs, 0)), t('activity.runs_30d')],
    [formatNumber(active.length), t('activity.active_days')],
    [streak ? t('activity.streak_days', { count: streak }) : '—', t('activity.streak')],
    [active.length ? formatDay(`${active[active.length - 1].day}T00:00:00Z`, { day: 'numeric', month: 'short', timeZone: 'UTC' }) : '—', t('activity.last_day')],
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
  const { t } = useTranslation('dashboard')
  const [all, setAll] = useState(false)
  const rows = [...data.kev.map(item => ({ key: `k-${item.cve}-${item.asset}`, cve: item.cve, where: item.package ?? item.asset,
    tag: <Badge variant="outline" className="border-transparent bg-danger-solid text-on-solid">KEV{item.ransomware ? ' · ransomware' : ''}</Badge> })),
  ...data.high_epss.filter(item => !data.kev.some(kev => kev.cve === item.cve && kev.asset === item.asset)).map(item => ({ key: `e-${item.cve}-${item.asset}`, cve: item.cve, where: item.package ?? item.asset,
    tag: <span className="font-mono text-xs text-app-secondary">EPSS {formatPercent(item.epss)}</span> }))]
  if (!rows.length) return <Empty text={t('exploitability.empty')} />
  const total = (data.kev_total ?? data.kev.length) + (data.epss_total ?? data.high_epss.length)
  const visible = all ? rows : rows.slice(0, LIST)
  return <div className="text-sm">
    <div className={all ? 'max-h-80 overflow-y-auto pr-1' : ''} tabIndex={all ? 0 : undefined} role={all ? 'region' : undefined} aria-label={all ? t('exploitability.region') : undefined}>{visible.map(row => <Row key={row.key} left={<span className="min-w-0 truncate"><span className="font-mono text-xs">{row.cve}</span> <span className="text-app-muted">· {row.where}</span></span>} right={row.tag} />)}</div>
    {rows.length > LIST && <button type="button" aria-expanded={all} onClick={() => setAll(value => !value)} className="mt-2 flex min-h-6 items-center gap-1 text-xs text-app-muted hover:text-app-fg">{all ? t('exploitability.show_less') : t('exploitability.show_all', { total: rows.length })}<ChevronDown className={`size-3 motion-safe:transition motion-safe:duration-150 ${all ? 'rotate-180' : ''}`} /></button>}
    {total > rows.length && all && <button type="button" onClick={onMore} className="mt-1 flex min-h-6 items-center gap-1 text-xs text-app-muted hover:text-app-fg">{t('exploitability.showing', { shown: rows.length, total })} <ArrowRight className="size-3" /></button>}
  </div>
}

function Row({ left, right }: { left: React.ReactNode; right: React.ReactNode }) { return <div className="flex items-center justify-between gap-3 border-b border-app-line py-1.5 last:border-0">{left}{right}</div> }
function Hero({ value, label }: { value: number; label: string }) { return <div><div className="text-3xl font-semibold">{value}</div><div className="text-xs text-app-muted">{label}</div></div> }
function Empty({ text }: { text: string }) { return <p className="py-6 text-center text-sm text-app-subtle">{text}</p> }
