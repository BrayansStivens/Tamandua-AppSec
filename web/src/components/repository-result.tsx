import { useMemo, useState } from 'react'
import { ArrowDownToLine, ArrowRight, ChevronRight, ExternalLink, Flame, Search, ShieldCheck, Ticket, Wrench } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Pagination } from '@/components/ui/pagination'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/components/ui/select'
import { JiraExportDialog, useJiraStatus, type TicketLink } from '@/components/jira'
import { SUPPRESSED, TriageActions, TriageBadge, TriageDialog, TriageHistory, triageLabel, type TriageState, type TriageStatus } from '@/components/triage'

export type Priority = { action: 'act' | 'attend' | 'track'; factors: string[] }
export type Package = { ecosystem: string; name: string; version: string; fixed_version: string | null; introduced: string | null; dev?: boolean; direct?: boolean | null }
export type Advisory = { id: string; aliases: string[]; summary: string; details: string; cvss_vector: string | null; cvss_score: number | null; published: string | null; modified: string | null; references: string[] }
export type RepositoryFinding = { finding_id: string; fingerprint: string; scanner: string; tool?: string; also_detected_by?: string[]; rule_id: string; title: string; path: string; line: number; severity: string; confidence: number; verdict: string; cwe: number[]; cve: string[]; ghsa: string[]; owasp: string[]; reason: string; remediation: string; package?: Package | null; advisory?: Advisory | null; kev?: { date_added: string | null; due_date: string | null; ransomware: boolean; name: string | null } | null; epss?: { score: number; percentile: number } | null; priority?: Priority; triage?: TriageState; ticket?: TicketLink; lifecycle?: Lifecycle }
export type Lifecycle = { status: 'open' | 'fixed'; origin?: { kind: 'scan' | 'pr'; pr?: number; branch?: string; merged?: boolean }; first_seen?: string; last_seen?: string; fixed?: { at: string; how: string; auto: boolean } | null; reopened_at?: string | null }
export type ScanStep = { id: string; name: string; status: string; detail: string }
export type PullReview = { baseline_run: string | null; gate: string; verdict: { state: 'success' | 'failure'; description: string; blocking: number }; delivery: { comment?: string; status?: string } }
export type RepositoryRun = { id: string; type?: string; pull_request?: { number: number; title: string; url: string; author: string; head_sha: string; head_ref: string; base_ref: string }; review?: PullReview; status: string; created_at: string; context?: string; progress?: { at: string; level: string; message: string }[]; started_at?: string; finished_at?: string; source?: { name: string; provider: string; sha256?: string; files?: number; image?: { reference: string; resolved_digest?: string | null; os?: string | null; user?: string } }; summary: { agreement?: { both: number; only_trivy: number; only_grype: number }; files?: number; dependencies?: number; candidates?: number; sast?: number; secrets?: number; sca?: number; severities?: Record<string, number>; priorities?: Record<string, number>; kev?: number; fixable?: number; triage?: Record<TriageStatus, number>; actionable?: number; preexisting?: number; changed_files?: number; lifecycle?: { open: number; fixed: number; suppressed: number; from_pr: number } }; steps?: ScanStep[]; findings?: RepositoryFinding[] }

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const ACTION_ORDER: Record<string, number> = { act: 0, attend: 1, track: 2 }
const severityLabel: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', info: 'Info' }
const actionLabel: Record<string, string> = { act: 'Actuar ya', attend: 'Atender', track: 'Seguimiento' }
const scannerLabel: Record<string, string> = { sca: 'Dependencia', sast: 'Código', secrets: 'Secreto', iac: 'Infraestructura' }
const toolLabel: Record<string, string> = { trivy: 'Trivy', gitleaks: 'Gitleaks', opengrep: 'Opengrep', grype: 'Grype', 'appsec-agent': 'Reglas propias' }
// Motor y, si otro lo confirmó, también ese: «Trivy + Grype».
const toolsOf = (finding: { tool?: string; also_detected_by?: string[] }) => [finding.tool, ...(finding.also_detected_by ?? [])].filter(Boolean).map(tool => toolLabel[tool as string] ?? tool).join(' + ')
const stepLabel = (status: string) => ({ completed: 'Completado', partial: 'Parcial', not_tested: 'No probado', inconclusive: 'Inconcluso', pending: 'Pendiente' }[status] ?? status)
const severityClass = (severity: string) => ({
  critical: 'border-transparent bg-rose-600 text-white', high: 'border-orange-500/30 bg-orange-500/15 text-orange-800 dark:text-orange-300',
  medium: 'border-amber-500/30 bg-amber-400/15 text-amber-800 dark:text-amber-300', low: 'border-sky-500/30 bg-sky-400/15 text-sky-800 dark:text-sky-300',
}[severity] ?? 'border-app-line text-app-muted')
const actionClass = (action: string) => ({
  act: 'border-transparent bg-rose-600 text-white', attend: 'border-amber-500/40 text-amber-800 dark:text-amber-300', track: 'border-app-line text-app-subtle',
}[action] ?? 'border-app-line text-app-subtle')
// Comparación tolerante de versiones para elegir la corrección que cierra todos los avisos de un paquete.
const versionKey = (value: string) => value.replace(/^v/i, '').split(/[.+-]/).map(part => { const number = parseInt(part, 10); return Number.isNaN(number) ? 0 : number })
const newer = (left: string, right: string) => { const a = versionKey(left), b = versionKey(right); for (let index = 0; index < Math.max(a.length, b.length); index++) { const diff = (a[index] ?? 0) - (b[index] ?? 0); if (diff) return diff > 0 } return false }
const worst = (findings: RepositoryFinding[]) => findings.reduce((best, item) => SEVERITY_ORDER[item.severity] < SEVERITY_ORDER[best] ? item.severity : best, 'info')
const urgent = (findings: RepositoryFinding[]) => findings.reduce((best, item) => (ACTION_ORDER[item.priority?.action ?? 'track'] ?? 3) < (ACTION_ORDER[best] ?? 3) ? item.priority?.action ?? 'track' : best, 'track')

type Group = { key: string; label: string; meta: string; scanner: string; findings: RepositoryFinding[]; severity: string; action: string; fix: string | null; epss: number | null; kev: boolean }

// Un paquete con tres avisos es un solo trabajo de remediación: se agrupa y se dice la versión que cierra todos.
function groupFindings(findings: RepositoryFinding[]): Group[] {
  const groups = new Map<string, RepositoryFinding[]>()
  for (const finding of findings) {
    const key = finding.package ? `${finding.package.ecosystem}:${finding.package.name}@${finding.package.version}` : `${finding.scanner}:${finding.finding_id}`
    groups.set(key, [...(groups.get(key) ?? []), finding])
  }
  return Array.from(groups.entries()).map(([key, items]) => {
    const pkg = items[0].package
    const fix = pkg ? items.reduce<string | null>((best, item) => item.package?.fixed_version && (!best || newer(item.package.fixed_version, best)) ? item.package.fixed_version : best, null) : null
    const epss = items.reduce<number | null>((best, item) => item.epss && (best === null || item.epss.score > best) ? item.epss.score : best, null)
    return { key, findings: items, scanner: items[0].scanner, severity: worst(items), action: urgent(items), fix, epss, kev: items.some(item => item.kev),
      label: pkg ? `${pkg.name} ${pkg.version}` : items[0].title,
      meta: pkg ? `${items.length} ${items.length === 1 ? 'aviso' : 'avisos'} · ${pkg.ecosystem}${pkg.dev ? ' · de desarrollo' : pkg.direct === false ? ' · transitiva' : ''}${fix ? ` · actualizar a ${fix}` : ' · sin corrección publicada'}` : `${items[0].path}:${items[0].line}` }
  }).sort((left, right) => (ACTION_ORDER[left.action] - ACTION_ORDER[right.action]) || (SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]) || left.label.localeCompare(right.label))
}

// Remediado automáticamente (el registro ya no lo ve) cuenta igual que remediado a mano.
const statusOf = (finding: RepositoryFinding): TriageStatus => finding.lifecycle?.status === 'fixed' ? 'fixed' : finding.triage?.status ?? 'open'

export function RepositoryResult({ run, onNew, onChanged, canAccept, initialView = 'active' }: { run: RepositoryRun; onNew: () => void; onChanged: () => void; canAccept: boolean; initialView?: string }) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [action, setAction] = useState('all')
  const [scanner, setScanner] = useState('all')
  const [open, setOpen] = useState<string | null>(null)
  const [triageView, setTriageView] = useState(initialView)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [decision, setDecision] = useState<{ status: TriageStatus; fingerprints: string[] } | null>(null)
  const [exporting, setExporting] = useState<string[] | null>(null)
  const [jira] = useJiraStatus()
  const [offset, setOffset] = useState(0)
  const PAGE = 50
  const findings = useMemo(() => run.findings ?? [], [run.findings])
  // Las cifras de arriba cuentan solo lo pendiente: lo descartado en triage no es trabajo.
  const active = useMemo(() => findings.filter(item => !SUPPRESSED.includes(statusOf(item))), [findings])
  const count = (predicate: (item: RepositoryFinding) => boolean) => active.filter(predicate).length
  const discarded = findings.length - active.length
  const groups = useMemo(() => groupFindings(findings.filter(item =>
    (triageView === 'all' || (triageView === 'active' ? !SUPPRESSED.includes(statusOf(item)) : statusOf(item) === triageView))
    && (severity === 'all' || item.severity === severity) && (action === 'all' || item.priority?.action === action) && (scanner === 'all' || item.scanner === scanner)
    && (!query.trim() || `${item.title} ${item.package?.name ?? ''} ${item.path} ${item.cve.join(' ')} ${item.ghsa.join(' ')}`.toLowerCase().includes(query.trim().toLowerCase())))), [findings, triageView, severity, action, scanner, query])
  const page = groups.slice(offset, offset + PAGE)
  const pageFingerprints = page.flatMap(group => group.findings.map(item => item.fingerprint))
  const toggle = (fingerprints: string[], on: boolean) => setSelected(previous => { const next = new Set(previous); for (const item of fingerprints) { if (on) next.add(item); else next.delete(item) } return next })
  const allOnPage = pageFingerprints.length > 0 && pageFingerprints.every(item => selected.has(item))
  const decided = () => { setDecision(null); setSelected(new Set()); onChanged() }

  return <div className="space-y-6">
    {run.type === 'asset_state' ? <div className="space-y-2 rounded-2xl border border-app-line bg-panel p-5">
      <div className="text-xs font-semibold tracking-[0.18em] text-brand uppercase">Estado actual · {({ github: 'GitHub', registry: 'imagen de contenedor', local: 'local', gitlab: 'GitLab' } as Record<string, string>)[run.source?.provider ?? ''] ?? 'repositorio'}</div>
      <h2 className="truncate text-xl font-semibold">{run.source?.name ?? 'Repositorio'}</h2>
      {run.summary.lifecycle && <p className="text-sm text-app-muted"><strong className="text-app-fg">{run.summary.lifecycle.open}</strong> {run.summary.lifecycle.open === 1 ? 'pendiente' : 'pendientes'}{run.summary.lifecycle.from_pr ? ` (${run.summary.lifecycle.from_pr} ${run.summary.lifecycle.from_pr === 1 ? 'viene' : 'vienen'} de PRs abiertos)` : ''} · <strong className="text-brand">{run.summary.lifecycle.fixed}</strong> {run.summary.lifecycle.fixed === 1 ? 'remediado' : 'remediados'} · {run.summary.lifecycle.suppressed} {run.summary.lifecycle.suppressed === 1 ? 'descartado' : 'descartados'} en triage</p>}
      <p className="text-xs text-app-subtle">Junta los escaneos completos y las revisiones de PR. Se actualiza solo: lo que deja de aparecer queda remediado, lo que vuelve se reabre.</p>
    </div> : run.type === 'pr_review' && run.pull_request ? <div className="space-y-3 rounded-2xl border border-app-line bg-panel p-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="mb-1 text-xs font-semibold tracking-[0.18em] text-brand uppercase">Revisión de PR · {run.source?.name}</div><a href={run.pull_request.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-xl font-semibold hover:underline">#{run.pull_request.number} {run.pull_request.title}<ExternalLink className="size-4 text-app-subtle" /></a><p className="mt-1 text-xs text-app-subtle">{run.pull_request.author} · {run.pull_request.head_ref} → {run.pull_request.base_ref} · commit <span className="font-mono">{run.pull_request.head_sha.slice(0, 7)}</span> · {(run.summary.changed_files ?? 0) === 1 ? '1 fichero cambiado' : `${run.summary.changed_files ?? 0} ficheros cambiados`}</p></div>
        {run.review && <Badge variant="outline" className={run.review.verdict.state === 'failure' ? 'border-transparent bg-rose-600 text-white' : 'border-brand/30 text-brand'}>{run.review.verdict.state === 'failure' ? 'Bloquea' : 'Pasa'} · {run.review.verdict.description}</Badge>}</div>
      <p className="text-sm text-app-muted">Aquí solo aparece lo que <strong>introduce</strong> este PR{run.summary.preexisting ? `; ${run.summary.preexisting} hallazgos del código que toca ya existían en la rama principal y no se cuentan` : ''}.{run.review && !run.review.baseline_run ? ' Aún no había un escaneo de la rama principal: cuenta todo lo que cae en líneas cambiadas.' : ''}</p>
      {run.review?.delivery && <p className="text-xs text-app-subtle">GitHub · comentario: {run.review.delivery.comment ?? '—'} · estado del commit: {run.review.delivery.status ?? '—'}</p>}
    </div> : <div className="flex flex-col gap-4 rounded-2xl border border-app-line bg-panel p-5 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0"><div className="mb-1 text-xs font-semibold tracking-[0.18em] text-brand uppercase">{run.type === 'image_scan' ? 'Imagen de contenedor' : 'Revisión de código'} · {({ github: 'GitHub', registry: 'registro', local: 'local', gitlab: 'GitLab' } as Record<string, string>)[run.source?.provider ?? 'local'] ?? run.source?.provider}</div><h2 className="truncate text-xl font-semibold">{run.source?.name ?? 'Repositorio'}</h2><p className="mt-1 text-xs text-app-subtle">{new Date(run.created_at).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })} · {run.source?.image
        ? <><span className="font-mono">{run.source.image.reference}</span>{run.source.image.resolved_digest ? <> · digest <span className="font-mono">{run.source.image.resolved_digest.slice(7, 19)}</span></> : null}{run.source.image.os ? ` · ${run.source.image.os}` : ''} · usuario {run.source.image.user ?? 'root'}{run.summary.agreement ? ` · ${run.summary.agreement.both} avisos confirmados por Trivy y Grype` : ''}</>
        : <>snapshot <span className="font-mono">{run.source?.sha256?.slice(0, 12) ?? '—'}</span> · {run.summary.files ?? 0} archivos · {run.summary.dependencies ?? 0} dependencias</>}</p>{run.context && <p className="mt-2 text-sm text-app-muted">{run.context}</p>}</div><Button variant="outline" onClick={onNew} className="shrink-0 border-app-line bg-app-soft">Nuevo pentest <ArrowRight /></Button></div>}

    <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
      <Tile label="Actuar ya" value={count(item => item.priority?.action === 'act')} tone={count(item => item.priority?.action === 'act') ? 'rose' : 'muted'} icon={Flame} />
      <Tile label="Atender" value={count(item => item.priority?.action === 'attend')} tone={count(item => item.priority?.action === 'attend') ? 'amber' : 'muted'} />
      <Tile label="Críticas" value={count(item => item.severity === 'critical')} tone={count(item => item.severity === 'critical') ? 'rose' : 'muted'} />
      <Tile label="Altas" value={count(item => item.severity === 'high')} tone={count(item => item.severity === 'high') ? 'orange' : 'muted'} />
      <Tile label="En CISA KEV" value={count(item => !!item.kev)} tone={count(item => !!item.kev) ? 'rose' : 'muted'} hint="explotación activa" />
      <Tile label="Con corrección" value={count(item => !!item.package?.fixed_version)} tone="teal" hint={`de ${active.length} pendientes${discarded ? ` · ${discarded} descartados` : ''}`} icon={Wrench} />
    </div>

    <Card className="border-app-line bg-panel"><CardContent className="space-y-4 p-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="relative min-w-0 flex-1 lg:max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label="Buscar hallazgos" placeholder="Paquete, CVE, archivo…" value={query} onChange={event => setQuery(event.target.value)} className="border-app-line bg-app-soft pl-9" /></div>
        <Filter value={triageView} onChange={value => { setTriageView(value === 'all' ? 'all' : value); setOffset(0) }} all="Todos los estados" options={[['active', 'Pendientes'], ['open', 'Abiertos'], ['in_progress', 'En curso'], ['fixed', 'Remediados'], ['false_positive', 'Falsos positivos'], ['accepted', 'Riesgo aceptado']]} />
        <Filter value={action} onChange={setAction} all="Toda prioridad" options={[['act', 'Actuar ya'], ['attend', 'Atender'], ['track', 'Seguimiento']]} />
        <Filter value={severity} onChange={setSeverity} all="Toda severidad" options={[['critical', 'Crítica'], ['high', 'Alta'], ['medium', 'Media'], ['low', 'Baja']]} />
        <Filter value={scanner} onChange={setScanner} all="Toda fuente" options={[['sca', 'Dependencias'], ['sast', 'Código'], ['iac', 'Infraestructura'], ['secrets', 'Secretos']]} />
      </div>
      {selected.size > 0 && <div className="sticky top-16 z-10 flex flex-wrap items-center gap-3 rounded-xl border border-brand/30 bg-panel px-4 py-2.5 shadow-lg">
        <span className="text-sm font-medium">{selected.size} {selected.size === 1 ? 'seleccionado' : 'seleccionados'}</span>
        <TriageActions canAccept={canAccept} onPick={status => setDecision({ status, fingerprints: [...selected] })} />
        {jira?.configured && <Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={selected.size > 50 || findings.some(item => selected.has(item.fingerprint) && SUPPRESSED.includes(statusOf(item)))} title={selected.size > 50 ? 'Hasta 50 por exportación' : undefined} onClick={() => setExporting([...selected])}><Ticket />Crear en Jira</Button>}
        <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())} className="ml-auto">Quitar selección</Button>
      </div>}
      {findings.length === 0
        ? <div className="flex flex-col items-center gap-2 py-14 text-center"><ShieldCheck className="size-7 text-brand" /><p className="font-medium">Sin hallazgos en lo examinado</p><p className="max-w-md text-sm text-app-muted">Las reglas y dependencias cubiertas no produjeron avisos. Revisa la cobertura más abajo para saber qué quedó fuera.</p></div>
        : <div className="overflow-hidden rounded-xl border border-app-line">
          <div className="hidden grid-cols-[20px_120px_90px_minmax(0,1fr)_110px_110px] gap-3 border-b border-app-line px-4 py-2.5 text-xs text-app-subtle md:grid"><input type="checkbox" aria-label="Seleccionar la página" checked={allOnPage} onChange={event => toggle(pageFingerprints, event.target.checked)} className="size-4 accent-brand" /><span>Prioridad</span><span>Severidad</span><span>Hallazgo</span><span>EPSS</span><span>Fuente</span></div>
          {page.length === 0 && <div className="px-4 py-10 text-center text-sm text-app-subtle">Nada coincide con estos filtros{triageView === 'active' && discarded ? ` · ${discarded} descartados en triage (cambia el filtro de estado para verlos)` : ''}.</div>}
          {page.map(group => { const expanded = open === group.key
            const prints = group.findings.map(item => item.fingerprint)
            const statuses = new Set(group.findings.map(statusOf))
            const groupState = statuses.size === 1 ? group.findings[0].triage : undefined
            return <div key={group.key} className={`flex items-start border-b border-app-line last:border-b-0 ${SUPPRESSED.includes(statusOf(group.findings[0])) && statuses.size === 1 ? 'opacity-70' : ''}`}>
              <input type="checkbox" aria-label={`Seleccionar ${group.label}`} checked={prints.every(item => selected.has(item))} onChange={event => toggle(prints, event.target.checked)} className="mt-4 ml-4 size-4 shrink-0 accent-brand" />
              <div className="min-w-0 flex-1">
              <button onClick={() => setOpen(expanded ? null : group.key)} className="grid w-full gap-2 py-3 pr-4 pl-3 text-left transition hover:bg-app-soft md:grid-cols-[120px_90px_minmax(0,1fr)_110px_110px] md:items-center">
                <Badge variant="outline" className={`w-fit ${actionClass(group.action)}`}>{actionLabel[group.action]}</Badge>
                <Badge variant="outline" className={`w-fit ${severityClass(group.severity)}`}>{severityLabel[group.severity]}</Badge>
                <span className="flex min-w-0 items-start gap-2"><ChevronRight className={`mt-1 size-3.5 shrink-0 text-app-subtle transition ${expanded ? 'rotate-90' : ''}`} /><span className="min-w-0"><span className="block truncate text-sm font-medium">{group.label}</span><span className="block truncate text-xs text-app-subtle">{group.meta}{group.kev ? ' · CISA KEV' : ''}{group.findings.some(item => item.ticket) ? ` · ${[...new Set(group.findings.flatMap(item => item.ticket ? [item.ticket.key] : []))].join(', ')}` : ''}</span>{group.findings[0].lifecycle?.origin?.kind === 'pr' && <span className="mt-1 mr-1 inline-block rounded border border-sky-500/30 px-1.5 text-[10px] text-sky-700 dark:text-sky-300">PR #{group.findings[0].lifecycle.origin.pr}{group.findings[0].lifecycle.origin.merged ? ' · mergeado' : ''}</span>}{statuses.size > 1 ? <span className="mt-1 block text-[10px] text-app-subtle">Estados mixtos: {[...statuses].map(item => triageLabel[item]).join(', ')}</span> : <span className="mt-1 block"><TriageBadge state={groupState} /></span>}</span></span>
                <span className="font-mono text-xs text-app-muted">{group.epss !== null ? `${(group.epss * 100).toFixed(1)}%` : '—'}</span>
                <span className="text-xs text-app-muted">{scannerLabel[group.scanner] ?? group.scanner}{group.findings[0].tool ? <span className="block text-[10px] text-app-subtle">{toolsOf(group.findings[0])}</span> : null}</span>
              </button>
              {expanded && <div className="space-y-3 border-t border-app-line bg-inset py-4 pr-4 pl-3">{group.findings.map(finding => <FindingDetail key={finding.finding_id} finding={finding} canAccept={canAccept} onPick={status => setDecision({ status, fingerprints: [finding.fingerprint] })} />)}</div>}
              </div>
            </div> })}
          <Pagination total={groups.length} limit={PAGE} offset={Math.min(offset, Math.max(0, groups.length - 1))} onPrev={() => setOffset(current => Math.max(0, current - PAGE))} onNext={() => setOffset(current => current + PAGE)} noun={`elementos · ${findings.length} hallazgos`} />
        </div>}
    </CardContent></Card>

    <div className="flex flex-wrap gap-2">{[
      ['Tickets (Jira)', `/api/runs/${run.id}/tickets.json`], ['Markdown', `/api/runs/${run.id}/report.md`], ['SARIF', `/api/runs/${run.id}/findings.sarif`], ['JSON', `/api/runs/${run.id}`],
      ['SOC 2 Tipo II', `/api/runs/${run.id}/report-soc2.md`], ['ISO 27001', `/api/runs/${run.id}/report-iso27001.md`],
    ].map(([label, url]) => <a key={label} href={url} download><Button variant="outline" size="sm" className="border-app-line bg-app-soft"><ArrowDownToLine /> {label}</Button></a>)}</div>

    <JiraExportDialog key={exporting?.join(',') ?? 'none'} runId={run.id} fingerprints={exporting} onClose={() => { setExporting(null); setSelected(new Set()) }} onDone={onChanged} />
    <TriageDialog key={decision ? `${decision.status}:${decision.fingerprints.length}` : 'none'} runId={run.id} status={decision?.status ?? null} fingerprints={decision?.fingerprints ?? []} onClose={() => setDecision(null)} onDone={decided} />

    {run.progress?.length ? <details className="group rounded-2xl border border-app-line bg-panel"><summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-medium"><ChevronRight className="size-4 text-app-subtle transition group-open:rotate-90" />Registro del escaneo<span className="ml-2 text-xs font-normal text-app-subtle">{run.progress.length} eventos{run.started_at && run.finished_at ? ` · ${Math.round((Date.parse(run.finished_at) - Date.parse(run.started_at)) / 1000)} s` : ''}</span></summary><div className="space-y-1 px-5 pb-5 font-mono text-xs leading-6">{run.progress.map((event, index) => <div key={index} className="flex gap-3"><span className="shrink-0 text-app-faint">{new Date(event.at).toLocaleTimeString('es-CO')}</span><span className={event.level === 'ok' ? 'text-brand' : event.level === 'warn' ? 'text-amber-700 dark:text-amber-300' : event.level === 'error' ? 'text-rose-700 dark:text-rose-300' : 'text-app-secondary'}>{event.message}</span></div>)}</div></details> : null}
    <details className="group rounded-2xl border border-app-line bg-panel"><summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-medium"><ChevronRight className="size-4 text-app-subtle transition group-open:rotate-90" />Cobertura de esta ejecución<span className="ml-2 text-xs font-normal text-app-subtle">{run.steps?.filter(step => step.status === 'completed' || step.status === 'partial').length ?? 0} de {run.steps?.length ?? 0} pasos ejecutados</span></summary><div className="space-y-2 px-5 pb-5">{run.steps?.map(step => <div key={step.id} className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-app-line bg-inset p-3 text-sm"><span className="min-w-0"><span className="font-medium">{step.name}</span><span className="mt-0.5 block text-xs leading-5 text-app-muted">{step.detail}</span></span><Badge variant="outline" className={`shrink-0 text-[10px] ${step.status === 'completed' ? 'border-brand/30 text-brand' : step.status === 'partial' ? 'border-amber-500/30 text-amber-700 dark:text-amber-300' : 'border-app-line text-app-subtle'}`}>{stepLabel(step.status)}</Badge></div>)}</div></details>
  </div>
}

function FindingDetail({ finding, canAccept, onPick }: { finding: RepositoryFinding; canAccept: boolean; onPick: (status: TriageStatus) => void }) {
  const advisory = finding.advisory
  const pkg = finding.package
  return <div className="rounded-xl border border-app-line bg-panel p-4">
    <div className="flex flex-wrap items-start justify-between gap-2"><div className="min-w-0"><p className="text-sm font-medium">{advisory?.summary || finding.title}</p><p className="mt-1 flex flex-wrap gap-x-2 font-mono text-xs text-app-subtle"><span className="text-app-secondary">{finding.rule_id}</span>{finding.cve.filter(id => id !== finding.rule_id).map(id => <a key={id} href={`https://www.cve.org/CVERecord?id=${id}`} target="_blank" rel="noreferrer" className="text-brand hover:underline">{id}</a>)}{finding.ghsa.filter(id => id !== finding.rule_id).map(id => <a key={id} href={`https://github.com/advisories/${id}`} target="_blank" rel="noreferrer" className="text-brand hover:underline">{id}</a>)}{finding.cwe.map(id => <a key={id} href={`https://cwe.mitre.org/data/definitions/${id}.html`} target="_blank" rel="noreferrer" className="hover:underline">CWE-{id}</a>)}</p></div><Badge variant="outline" className={severityClass(finding.severity)}>{severityLabel[finding.severity]}{advisory?.cvss_score !== null && advisory?.cvss_score !== undefined ? ` · ${advisory.cvss_score}` : ''}</Badge></div>
    <div className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
      {pkg?.dev && <Fact label="Tipo"><span className="rounded border border-app-line px-1.5 py-0.5 text-xs">Dependencia de desarrollo</span> <span className="text-xs text-app-subtle">no llega a producción, pero se ejecuta en tu equipo y en la CI</span></Fact>}
      {pkg && <Fact label="Corrección">{pkg.fixed_version ? <><span className="font-mono">{pkg.version}</span> → <span className="font-mono font-medium text-brand">{pkg.fixed_version}</span></> : 'Sin versión corregida publicada'}</Fact>}
      {!pkg && <Fact label="Ubicación"><span className="font-mono text-xs">{finding.path}:{finding.line}</span></Fact>}
      {finding.epss && <Fact label="EPSS · probabilidad de explotación en 30 días">{(finding.epss.score * 100).toFixed(2)}% <span className="text-app-subtle">(percentil {(finding.epss.percentile * 100).toFixed(0)})</span></Fact>}
      {finding.kev && <Fact label="CISA KEV">En el catálogo desde {finding.kev.date_added}{finding.kev.ransomware ? ' · usado en campañas de ransomware' : ''}</Fact>}
      {advisory?.cvss_vector && <Fact label="Vector CVSS"><span className="font-mono text-xs break-all">{advisory.cvss_vector}</span></Fact>}
    </div>
    <div className="mt-3 rounded-lg border border-brand/20 bg-brand/[0.06] p-3 text-sm"><span className="font-medium text-brand">Remediación · </span>{finding.remediation}</div>
    {finding.priority && <p className="mt-3 text-xs leading-5 text-app-subtle"><span className="font-medium text-app-muted">Por qué esta prioridad: </span>{finding.priority.factors.join(' · ')}</p>}
    {(finding.tool || finding.also_detected_by?.length) && <p className="mt-2 text-xs text-app-subtle">Detectado por {toolLabel[finding.tool ?? ''] ?? finding.tool}{finding.also_detected_by?.length ? ` y ${finding.also_detected_by.map(tool => toolLabel[tool] ?? tool).join(', ')}` : ''}.</p>}
    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-app-line bg-inset p-3">
      <div className="min-w-0 text-xs text-app-muted"><span className="font-medium text-app-secondary">Triage: {finding.triage?.expired ? 'Abierto (la aceptación caducó)' : triageLabel[statusOf(finding)]}</span>{finding.triage?.by ? ` · ${finding.triage.by}` : ''}{finding.triage?.expires_at ? ` · caduca ${finding.triage.expires_at}` : ''}{finding.triage?.reason ? <span className="mt-0.5 block">{finding.triage.reason}</span> : null}</div>
      <div className="flex flex-wrap items-center gap-2">{finding.ticket && <a href={finding.ticket.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-mono text-xs text-brand hover:underline"><Ticket className="size-3" />{finding.ticket.key}</a>}<TriageActions current={statusOf(finding)} canAccept={canAccept} onPick={onPick} size="xs" /></div>
    </div>
    {finding.lifecycle && <p className="mt-2 text-xs leading-5 text-app-subtle"><span className="font-medium text-app-muted">Ciclo de vida: </span>{finding.lifecycle.origin?.kind === 'pr' ? `introducido en el PR #${finding.lifecycle.origin.pr}${finding.lifecycle.origin.branch ? ` (${finding.lifecycle.origin.branch})` : ''}${finding.lifecycle.origin.merged ? ', ya mergeado' : ''}` : 'detectado en la rama principal'}{finding.lifecycle.first_seen ? ` · visto por primera vez ${new Date(finding.lifecycle.first_seen).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })}` : ''}{finding.lifecycle.last_seen ? ` · última vez ${new Date(finding.lifecycle.last_seen).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })}` : ''}{finding.lifecycle.reopened_at ? ' · reabierto' : ''}{finding.lifecycle.fixed ? <span className="block text-brand">Remediado automáticamente: {finding.lifecycle.fixed.how}.</span> : null}</p>}
    <TriageHistory state={finding.triage} />
    {advisory?.details && <details className="mt-3"><summary className="cursor-pointer text-xs text-app-muted">Detalle del aviso</summary><p className="mt-2 text-xs leading-5 whitespace-pre-line text-app-muted">{advisory.details}</p></details>}
    {advisory?.references.length ? <p className="mt-3 flex flex-wrap gap-x-3 text-xs">{advisory.references.slice(0, 4).map(url => <a key={url} href={url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-brand hover:underline">{new URL(url).hostname} <ExternalLink className="size-3" /></a>)}</p> : null}
  </div>
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><span className="block text-xs text-app-subtle">{label}</span><span className="text-app-secondary">{children}</span></div>
}
function Tile({ label, value, tone, hint, icon: Icon }: { label: string; value: number; tone: 'rose' | 'amber' | 'orange' | 'teal' | 'muted'; hint?: string; icon?: typeof Flame }) {
  const color = { rose: 'text-rose-700 dark:text-rose-300', amber: 'text-amber-700 dark:text-amber-300', orange: 'text-orange-700 dark:text-orange-300', teal: 'text-brand', muted: 'text-app-fg' }[tone]
  return <Card className="border-app-line bg-panel"><CardContent className="flex items-start justify-between p-4"><div><div className={`text-2xl font-semibold tabular-nums ${color}`}>{value}</div><div className="mt-0.5 text-xs text-app-muted">{label}</div>{hint && <div className="text-[11px] text-app-subtle">{hint}</div>}</div>{Icon && <Icon className="size-4 text-app-subtle" />}</CardContent></Card>
}
function Filter({ value, onChange, all, options }: { value: string; onChange: (value: string) => void; all: string; options: [string, string][] }) {
  return <Select value={value} onValueChange={next => onChange(next ?? 'all')}><SelectTrigger size="sm" className="min-w-40 border-app-line bg-app-soft text-app-secondary">{value === 'all' ? all : options.find(([id]) => id === value)?.[1]}</SelectTrigger><SelectContent align="start" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="all">{all}</SelectItem>{options.map(([id, label]) => <SelectItem key={id} value={id}>{label}</SelectItem>)}</SelectContent></Select>
}
