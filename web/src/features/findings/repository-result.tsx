import { useEffect, useMemo, useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { ArrowDownToLine, ArrowRight, ChevronDown, ChevronRight, Clock3, ExternalLink, FileCheck2, Flame, Search, ShieldCheck, SlidersHorizontal, Ticket, Wrench } from 'lucide-react'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { SlaPill } from '@/features/findings/sla-pill'
import { slaText, type Sla } from '@/features/findings/sla'
import { Card, CardContent } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Menu, MenuContent, MenuGroup, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { AuditReportDialog } from '@/features/findings/audit-report'
import { Pagination } from '@/shared/ui/pagination'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { JIRA_QUEUE_MAX, JiraExportDialog, JiraFindingAction, type TicketLink } from '@/features/integrations/jira-export'
import { useJiraAvailability } from '@/features/integrations/jira-availability'
import { useJiraSettled } from '@/features/integrations/jira-batches'
import { SUPPRESSED, TRIAGE_LABEL, TriageActions, TriageBadge, TriageDialog, TriageHistory, type TriageState, type TriageStatus } from '@/features/findings/triage'
import { api, query as buildQuery } from '@/shared/api/http'
import {} from '@/shared/i18n'
import { formatDate, formatNumber, formatTime } from '@/shared/i18n/format'
import { FixSection, Reverify, type FixGuide, type Verification } from '@/features/findings/fix-guide'
import type { RunTrigger } from '@/shared/lib/types'

export type Priority = { action: 'act' | 'attend' | 'track'; factors: string[] }
export type Package = { ecosystem: string; name: string; version: string; fixed_version: string | null; introduced: string | null; dev?: boolean; direct?: boolean | null }
export type Advisory = { id: string; aliases: string[]; summary: string; details: string; cvss_vector: string | null; cvss_score: number | null; published: string | null; modified: string | null; references: string[] }
export type RepositoryFinding = { finding_id: string; fingerprint: string; scanner: string; tool?: string; also_detected_by?: string[]; related_rules?: string[]; framework?: string; rule_id: string; title: string; path: string; line: number; severity: string; confidence: number; verdict: string; cwe: number[]; cve: string[]; ghsa: string[]; owasp: string[]; reason: string; remediation: string; package?: Package | null; advisory?: Advisory | null; kev?: { date_added: string | null; due_date: string | null; ransomware: boolean; name: string | null } | null; epss?: { score: number; percentile: number } | null; priority?: Priority; triage?: TriageState; ticket?: TicketLink; lifecycle?: Lifecycle; source?: AdvisorySource | null; fix?: FixGuide | null; verification?: Verification | null; sla?: Sla | null; malicious?: boolean }
// Base de la que sale el aviso y su licencia (tamandua/modules/intel/data_sources.py): se atribuye donde se muestra.
export type AdvisorySource = { id: string; name: string; short?: string; url: string; license: string; terms: 'open' | 'attribution' | 'share-alike' | 'non-commercial' | 'unclear' }
export type Lifecycle = { status: 'open' | 'fixed' | 'excluded'; excluded?: { pattern: string | null; reason?: string; at: string } | null; origin?: { kind: 'scan' | 'pr' | 'advisory' | 'import'; pr?: number; branch?: string; merged?: boolean; tool?: string | null }; first_seen?: string; last_seen?: string; fixed?: { at: string; how: string; auto: boolean } | null; reopened_at?: string | null }
export type ScanStep = { id: string; name: string; status: string; detail: string }
export type PullReview = { baseline_run: string | null; gate: string; verdict: { state: 'success' | 'failure'; description: string; blocking: number }; delivery: { comment?: string; status?: string } }
export type RepositoryRun = { id: string; type?: string; trigger?: RunTrigger; pull_request?: { number: number; title: string; url: string; author: string; head_sha: string; head_ref: string; base_ref: string }; review?: PullReview; status: string; created_at: string; context?: string; progress?: { at: string; level: string; message: string }[]; started_at?: string; finished_at?: string; source?: { name: string; provider: string; sha256?: string; files?: number; branch?: string; commit?: string; image?: { reference: string; resolved_digest?: string | null; os?: string | null; user?: string } }; summary: { agreement?: { both: number; only_trivy: number; only_grype: number }; files?: number; dependencies?: number; candidates?: number; sast?: number; secrets?: number; sca?: number; severities?: Record<string, number>; priorities?: Record<string, number>; kev?: number; fixable?: number; triage?: Record<TriageStatus, number>; actionable?: number; preexisting?: number; changed_files?: number; lifecycle?: { open: number; fixed: number; suppressed: number; from_pr: number; excluded?: number } }; steps?: ScanStep[]; findings?: RepositoryFinding[] }

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const ACTION_ORDER: Record<string, number> = { act: 0, attend: 1, track: 2 }
// Catalog keys by value; unknown values are shown as they come.
const SEVERITY_LABEL: Record<string, string> = { critical: 'common:severity.critical', high: 'common:severity.high', medium: 'common:severity.medium', low: 'common:severity.low', info: 'common:severity.info' }
const ACTION_LABEL: Record<string, string> = { act: 'common:priority.act', attend: 'common:priority.attend', track: 'common:priority.track' }
const SCANNER_LABEL: Record<string, string> = { sca: 'scanner.sca', sast: 'scanner.sast', secrets: 'scanner.secrets', iac: 'scanner.iac', cicd: 'scanner.cicd' }
const STEP_LABEL: Record<string, string> = { completed: 'step.completed', partial: 'step.partial', not_tested: 'step.not_tested', inconclusive: 'step.inconclusive', pending: 'step.pending' }
const labelOf = (t: TFunction, keys: Record<string, string>, value: string) => keys[value] ? t(keys[value]) : value
const RUN_EXPORTS: { label: string; items: [string, string][] }[] = [
  { label: 'export.compliance', items: [['export.sbom', 'sbom.cdx.json'], ['export.vex', 'vex.openvex.json']] },
  { label: 'export.data', items: [['export.markdown', 'report.md'], ['export.sarif', 'findings.sarif'], ['export.json', 'run.json'], ['export.jira', 'tickets.json']] },
]
const TOOL_NAME: Record<string, string> = { trivy: 'Trivy', gitleaks: 'Gitleaks', opengrep: 'Opengrep', grype: 'Grype', 'osv-scanner': 'OSV-Scanner', checkov: 'Checkov', zizmor: 'zizmor' }
const toolName = (t: TFunction, tool: string) => tool === 'tamandua' ? t('findings:tool.tamandua') : TOOL_NAME[tool] ?? tool
// Motor y, si otro lo confirmó, también ese: «Trivy + Grype».
const toolsOf = (t: TFunction, finding: { tool?: string; also_detected_by?: string[] }) => [finding.tool, ...(finding.also_detected_by ?? [])].filter(Boolean).map(tool => toolName(t, tool as string)).join(' + ')
const severityClass = (severity: string) => ({
  critical: 'border-transparent bg-danger-solid text-on-solid', high: 'border-attention-line bg-attention-soft text-attention',
  medium: 'border-warning-line bg-warning-soft text-warning', low: 'border-info-line bg-info-soft text-info',
}[severity] ?? 'border-app-line text-app-muted')
const actionClass = (action: string) => ({
  act: 'border-transparent bg-danger-solid text-on-solid', attend: 'border-warning-line text-warning', track: 'border-app-line text-app-subtle',
}[action] ?? 'border-app-line text-app-subtle')
// Comparación tolerante de versiones para elegir la corrección que cierra todos los avisos de un paquete.
const versionKey = (value: string) => value.replace(/^v/i, '').split(/[.+-]/).map(part => { const number = parseInt(part, 10); return Number.isNaN(number) ? 0 : number })
const newer = (left: string, right: string) => { const a = versionKey(left), b = versionKey(right); for (let index = 0; index < Math.max(a.length, b.length); index++) { const diff = (a[index] ?? 0) - (b[index] ?? 0); if (diff) return diff > 0 } return false }
const worst = (findings: RepositoryFinding[]) => findings.reduce((best, item) => SEVERITY_ORDER[item.severity] < SEVERITY_ORDER[best] ? item.severity : best, 'info')
const urgent = (findings: RepositoryFinding[]) => findings.reduce((best, item) => (ACTION_ORDER[item.priority?.action ?? 'track'] ?? 3) < (ACTION_ORDER[best] ?? 3) ? item.priority?.action ?? 'track' : best, 'track')

type Group = { key: string; label: string; meta: string; scanner: string; findings: RepositoryFinding[]; severity: string; action: string; fix: string | null; epss: number | null; kev: boolean; sla: Sla | null }

// Un paquete con tres avisos es un solo trabajo de remediación: se agrupa y se dice la versión que cierra todos.
function groupFindings(findings: RepositoryFinding[], t: TFunction): Group[] {
  const groups = new Map<string, RepositoryFinding[]>()
  for (const finding of findings) {
    const key = finding.package ? `${finding.package.ecosystem}:${finding.package.name}@${finding.package.version}` : `${finding.scanner}:${finding.finding_id}`
    groups.set(key, [...(groups.get(key) ?? []), finding])
  }
  return Array.from(groups.entries()).map(([key, items]) => {
    const pkg = items[0].package
    const fix = pkg ? items.reduce<string | null>((best, item) => item.package?.fixed_version && (!best || newer(item.package.fixed_version, best)) ? item.package.fixed_version : best, null) : null
    const epss = items.reduce<number | null>((best, item) => item.epss && (best === null || item.epss.score > best) ? item.epss.score : best, null)
    // El plazo del grupo es el más apremiante de sus avisos.
    const sla = items.reduce<Sla | null>((best, item) => item.sla && (!best || item.sla.days_left < best.days_left) ? item.sla : best, null)
    return { key, findings: items, scanner: items[0].scanner, severity: worst(items), action: urgent(items), fix, epss, kev: items.some(item => item.kev), sla,
      label: pkg ? `${pkg.name} ${pkg.version}` : items[0].title,
      meta: pkg ? [t('findings:group.advisories', { count: items.length }), pkg.ecosystem, ...(pkg.dev ? [t('findings:group.dev')] : pkg.direct === false ? [t('findings:group.transitive')] : []),
        fix ? t('findings:group.upgrade', { version: fix }) : t('findings:group.no_fix')].join(' · ') : `${items[0].path}:${items[0].line}` }
  }).sort((left, right) => (ACTION_ORDER[left.action] - ACTION_ORDER[right.action]) || (SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]) || left.label.localeCompare(right.label))
}

// Remediado automáticamente (el registro ya no lo ve) cuenta igual que remediado a mano.
const statusOf = (finding: RepositoryFinding): TriageStatus => finding.lifecycle?.status === 'fixed' ? 'fixed' : finding.triage?.status ?? 'open'
const PAGE = 50
// Whether a finding shows under a status view: 'all', 'active' (not dismissed) or one status.
const inView = (finding: RepositoryFinding, view: string) => view === 'all' || (view === 'active' ? !SUPPRESSED.includes(statusOf(finding)) : statusOf(finding) === view)
// Still work to do: only these can get a Jira issue.
const isPending = (finding: RepositoryFinding) => finding.lifecycle?.status !== 'excluded' && !SUPPRESSED.includes(statusOf(finding))

// `focus`: a finding to open and scroll to (links from Jira issues carry its fingerprint).
export function RepositoryResult({ run, onNew, onChanged, canAccept, canManage = canAccept, initialView = 'active', exportStatus = 'open', focus = null }: { run: RepositoryRun; onNew: () => void; onChanged: () => void; canAccept: boolean; canManage?: boolean; initialView?: string; exportStatus?: 'open' | 'fixed' | 'excluded' | 'all'; focus?: string | null }) {
  const { t } = useTranslation('findings')
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [action, setAction] = useState('all')
  const [scanner, setScanner] = useState('all')
  const [deadline, setDeadline] = useState('all')
  const findings = useMemo(() => run.findings ?? [], [run.findings])
  // A linked finding opens in its group and page, with the status view that shows it (computed once, on arrival).
  const [arrival] = useState(() => {
    const target = focus ? findings.find(item => item.fingerprint === focus) : undefined
    if (!target) return null
    const view = initialView !== 'all' && !inView(target, initialView) ? 'all' : initialView
    const list = groupFindings(findings.filter(item => inView(item, view)), t)
    const index = list.findIndex(group => group.findings.some(item => item.fingerprint === target.fingerprint))
    return index < 0 ? null : { view, open: list[index].key, offset: Math.floor(index / PAGE) * PAGE, fingerprint: target.fingerprint }
  })
  const [open, setOpen] = useState<string | null>(arrival?.open ?? null)
  const [triageView, setTriageView] = useState(arrival?.view ?? initialView)
  const [auditOpen, setAuditOpen] = useState(false)
  // Filtros secundarios plegados; se abren solos si alguno ya está en uso.
  const hiddenActive = Number(triageView !== initialView) + Number(action !== 'all') + Number(scanner !== 'all') + Number(deadline !== 'all')
  const [moreFilters, setMoreFilters] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [decision, setDecision] = useState<{ status: TriageStatus; fingerprints: string[] } | null>(null)
  const [exporting, setExporting] = useState<string[] | null>(null)
  // The asset as the server routes it (key and name), for where its Jira issues go.
  const source = run.source as { id?: string; uid?: string | null; name?: string } | undefined
  const assetRef = source ? { key: source.uid || source.id || source.name || '', name: source.name } : null
  const jira = useJiraAvailability(canManage, assetRef)
  // Issues queued in the background land in the findings when their batch finishes.
  useJiraSettled(() => onChanged())
  const [offset, setOffset] = useState(arrival?.offset ?? 0)
  const [downloadError, setDownloadError] = useState('')
  const [downloading, setDownloading] = useState<string | null>(null)
  // Los plazos solo existen en el estado del registro (lo pendiente con fecha de detección), no en una ejecución suelta.
  const hasSla = useMemo(() => findings.some(item => item.sla), [findings])
  // El SBOM sale de un análisis completo terminado (o del último, en el estado del activo); una revisión de PR no lo tiene.
  const sbomAvailable = run.type === 'asset_state' || ((run.type === 'repository_scan' || run.type === 'image_scan') && run.status === 'completed')
  // Las cifras de arriba cuentan solo lo pendiente: lo descartado en triage no es trabajo.
  const active = useMemo(() => findings.filter(item => !SUPPRESSED.includes(statusOf(item))), [findings])
  const count = (predicate: (item: RepositoryFinding) => boolean) => active.filter(predicate).length
  const discarded = findings.length - active.length
  const groups = useMemo(() => groupFindings(findings.filter(item =>
    inView(item, triageView)
    && (severity === 'all' || item.severity === severity) && (action === 'all' || item.priority?.action === action) && (scanner === 'all' || item.scanner === scanner)
    && (deadline === 'all' || (deadline === 'overdue' ? item.sla?.state === 'overdue' : item.sla?.state === 'overdue' || item.sla?.state === 'soon'))
    && (!query.trim() || `${item.title} ${item.package?.name ?? ''} ${item.path} ${item.cve.join(' ')} ${item.ghsa.join(' ')}`.toLowerCase().includes(query.trim().toLowerCase()))), t), [findings, triageView, severity, action, scanner, deadline, query, t])
  const page = groups.slice(offset, offset + PAGE)
  useEffect(() => {
    if (!arrival) return
    const element = document.getElementById(`finding-${arrival.fingerprint}`)
    element?.scrollIntoView?.({ block: 'center' }); element?.focus({ preventScroll: true })
  }, [arrival])
  const pageFingerprints = page.flatMap(group => group.findings.map(item => item.fingerprint))
  const toggle = (fingerprints: string[], on: boolean) => setSelected(previous => { const next = new Set(previous); for (const item of fingerprints) { if (on) next.add(item); else next.delete(item) } return next })
  // Why the selection can't go to Jira, said next to the button (a title alone reaches neither keyboard nor touch).
  const jiraBlocked = jira.blocked ?? (selected.size > JIRA_QUEUE_MAX ? t('selection.jira_max', { max: formatNumber(JIRA_QUEUE_MAX) })
    : findings.some(item => selected.has(item.fingerprint) && !isPending(item)) ? t('selection.jira_dismissed') : null)
  const allOnPage = pageFingerprints.length > 0 && pageFingerprints.every(item => selected.has(item))
  const decided = () => { setDecision(null); setSelected(new Set()); onChanged() }
  // Mientras alguna verificación está en curso, se refresca la vista (una sola vez para todos los hallazgos).
  const verifying = findings.some(item => item.verification?.state === 'running')
  useEffect(() => { if (!verifying) return; const timer = window.setInterval(onChanged, 10_000); return () => window.clearInterval(timer) }, [verifying, onChanged])
  const exportFile = async (artifact: string) => {
    setDownloadError(''); setDownloading(artifact)
    try {
      const isState = run.type === 'asset_state'
      const source = run.source as { id?: string; name?: string } | undefined
      const path = isState
        ? `/api/assets/export?${buildQuery({ key: source?.id, status: exportStatus, artifact: artifact === 'run.json' ? 'record.json' : artifact })}`
        : artifact === 'run.json' ? `/api/runs/${run.id}` : `/api/runs/${run.id}/${artifact}`
      const name = (source?.name ?? t('export.file_fallback')).replace(/[^a-z0-9-]+/gi, '-').slice(0, 50) || t('export.file_fallback')
      await api.download(path, `${name}-${isState ? t('export.state_suffix') : run.id.slice(0, 8)}-${artifact}`)
    } catch (caught) { setDownloadError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setDownloading(null) }
  }

  return <div className="space-y-6">
    {run.type === 'asset_state' ? <div className="space-y-2 rounded-2xl border border-app-line bg-panel p-5">
      <div className="text-xs font-semibold tracking-[0.18em] text-brand uppercase">{t('state.eyebrow', { provider: ({ github: 'GitHub', registry: t('state.provider.registry'), local: t('state.provider.local'), gitlab: 'GitLab' } as Record<string, string>)[run.source?.provider ?? ''] ?? t('state.provider.repository') })}</div>
      <h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2>
      {run.summary.lifecycle && <p className="text-sm text-app-muted"><Trans t={t} i18nKey="state.pending" count={run.summary.lifecycle.open} components={{ strong: <strong className="text-app-fg" /> }} />{run.summary.lifecycle.from_pr ? ` ${t('state.from_pr', { count: run.summary.lifecycle.from_pr })}` : ''} · <Trans t={t} i18nKey="state.fixed" count={run.summary.lifecycle.fixed} components={{ strong: <strong className="text-brand" /> }} /> · {t('state.suppressed', { count: run.summary.lifecycle.suppressed })}{run.summary.lifecycle.excluded ? ` · ${t('state.excluded', { count: run.summary.lifecycle.excluded })}` : ''}</p>}
      <p className="text-xs text-app-subtle">{t('state.help')}</p>
    </div> : run.type === 'pr_review' && run.pull_request ? <div className="space-y-3 rounded-2xl border border-app-line bg-panel p-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div className="min-w-0"><div className="mb-1 text-xs font-semibold tracking-[0.18em] text-brand uppercase">{t('pr.eyebrow', { name: run.source?.name ?? '' })}</div><a href={run.pull_request.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-xl font-semibold hover:underline">#{run.pull_request.number} {run.pull_request.title}<ExternalLink className="size-4 text-app-subtle" /></a><p className="mt-1 text-xs text-app-subtle">{run.pull_request.author} · {run.pull_request.head_ref} → {run.pull_request.base_ref} · commit <span className="font-mono">{run.pull_request.head_sha.slice(0, 7)}</span> · {t('pr.changed_files', { count: run.summary.changed_files ?? 0 })}</p></div>
        {run.review && <Badge variant="outline" className={run.review.verdict.state === 'failure' ? 'border-transparent bg-danger-solid text-on-solid' : 'border-brand/30 text-brand'}>{run.review.verdict.state === 'failure' ? t('pr.blocks') : t('pr.passes')} · {run.review.verdict.description}</Badge>}</div>
      <p className="text-sm text-app-muted">{run.summary.preexisting ? <Trans t={t} i18nKey="pr.scope_preexisting" count={run.summary.preexisting} components={{ strong: <strong /> }} /> : <Trans t={t} i18nKey="pr.scope" components={{ strong: <strong /> }} />}{run.review && !run.review.baseline_run ? ` ${t('pr.no_baseline')}` : ''}</p>
      {run.review?.delivery && <p className="text-xs text-app-subtle">{t('pr.delivery', { comment: run.review.delivery.comment ?? '—', status: run.review.delivery.status ?? '—' })}</p>}
    </div> : run.type === 'sarif_import' ? <ImportHeader run={run} onNew={onNew} />
    : <div className="flex flex-col gap-4 rounded-2xl border border-app-line bg-panel p-5 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0"><div className="mb-1 text-xs font-semibold tracking-[0.18em] text-brand uppercase">{run.type === 'image_scan' ? t('scan.image') : t('scan.code')} · {({ github: 'GitHub', registry: t('scan.provider.registry'), local: t('scan.provider.local'), gitlab: 'GitLab' } as Record<string, string>)[run.source?.provider ?? 'local'] ?? run.source?.provider}</div><h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2><p className="mt-1 text-xs text-app-subtle">{formatDate(run.created_at)} · {run.source?.image
        ? <><span className="font-mono">{run.source.image.reference}</span>{run.source.image.resolved_digest ? <> · {t('scan.digest')} <span className="font-mono">{run.source.image.resolved_digest.slice(7, 19)}</span></> : null}{run.source.image.os ? ` · ${run.source.image.os}` : ''} · {t('scan.user', { user: run.source.image.user ?? 'root' })}{run.summary.agreement ? ` · ${t('scan.agreement', { count: run.summary.agreement.both })}` : ''}</>
        : <>{run.source?.branch && <>{run.source.commit
          ? <Trans t={t} i18nKey="scan.branch_commit" values={{ branch: run.source.branch, commit: run.source.commit.slice(0, 7) }} components={{ code: <span className="font-mono" /> }} />
          : <Trans t={t} i18nKey="scan.branch" values={{ branch: run.source.branch }} components={{ code: <span className="font-mono" /> }} />} · </>}{t('scan.snapshot')} <span className="font-mono">{run.source?.sha256?.slice(0, 12) ?? '—'}</span> · {t('scan.files', { count: run.summary.files ?? 0 })} · {t('scan.dependencies', { count: run.summary.dependencies ?? 0 })}</>}</p>{run.context && <p className="mt-2 text-sm text-app-muted">{run.context}</p>}</div><Button variant="outline" onClick={onNew} className="shrink-0 border-app-line bg-app-soft">{t('scan.new')} <ArrowRight /></Button></div>}

    <div className={`grid gap-3 ${hasSla ? 'grid-cols-2 sm:grid-cols-4 xl:grid-cols-7' : 'sm:grid-cols-3 xl:grid-cols-6'}`}>
      {hasSla && <Tile label={t('tiles.overdue')} value={count(item => item.sla?.state === 'overdue')} tone={count(item => item.sla?.state === 'overdue') ? 'rose' : 'muted'}
        hint={t('tiles.due_soon', { count: count(item => item.sla?.state === 'soon') })} icon={Clock3} />}
      <Tile label={t('common:priority.act')} value={count(item => item.priority?.action === 'act')} tone={count(item => item.priority?.action === 'act') ? 'rose' : 'muted'} icon={Flame} />
      <Tile label={t('common:priority.attend')} value={count(item => item.priority?.action === 'attend')} tone={count(item => item.priority?.action === 'attend') ? 'amber' : 'muted'} />
      <Tile label={t('tiles.critical')} value={count(item => item.severity === 'critical')} tone={count(item => item.severity === 'critical') ? 'rose' : 'muted'} />
      <Tile label={t('tiles.high')} value={count(item => item.severity === 'high')} tone={count(item => item.severity === 'high') ? 'orange' : 'muted'} />
      <Tile label={t('tiles.kev')} value={count(item => !!item.kev)} tone={count(item => !!item.kev) ? 'rose' : 'muted'} hint={t('tiles.kev_hint')} />
      <Tile label={t('tiles.fixable')} value={count(item => !!item.package?.fixed_version)} tone="teal" hint={`${findings.length > 0 && findings.every(item => item.lifecycle?.status === 'excluded') ? t('tiles.of_excluded', { count: active.length }) : t('tiles.of_pending', { count: active.length })}${discarded ? ` · ${t('tiles.dismissed', { count: discarded })}` : ''}`} icon={Wrench} />
    </div>

    <Card className="border-app-line bg-panel"><CardContent className="space-y-4 p-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="relative min-w-0 flex-1 lg:max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label={t('filters.search')} placeholder={t('filters.search_placeholder')} value={query} onChange={event => setQuery(event.target.value)} className="border-app-line bg-app-soft pl-9" /></div>
        <Filter label={t('filters.severity')} value={severity} onChange={setSeverity} all={t('filters.any_severity')} options={[['critical', t('common:severity.critical')], ['high', t('common:severity.high')], ['medium', t('common:severity.medium')], ['low', t('common:severity.low')]]} />
        {/* Ley de Hick: buscar y severidad a la vista; el resto, a demanda y con cuántos hay activos. */}
        <Button type="button" size="sm" variant="outline" aria-expanded={moreFilters} aria-controls="more-filters" onClick={() => setMoreFilters(!moreFilters)} className="w-fit border-app-line bg-app-soft"><SlidersHorizontal />{t('filters.more')}{hiddenActive ? ` · ${hiddenActive}` : ''}</Button>
      </div>
      {moreFilters && <div id="more-filters" className="flex flex-wrap gap-3">
        <Filter label={t('filters.status')} value={triageView} onChange={value => { setTriageView(value === 'all' ? 'all' : value); setOffset(0) }} all={t('filters.any_status')} options={[['active', t('filters.status_options.active')], ['open', t('filters.status_options.open')], ['in_progress', t('filters.status_options.in_progress')], ['fixed', t('filters.status_options.fixed')], ['false_positive', t('filters.status_options.false_positive')], ['accepted', t('filters.status_options.accepted')]]} />
        <Filter label={t('filters.priority')} value={action} onChange={setAction} all={t('filters.any_priority')} options={[['act', t('common:priority.act')], ['attend', t('common:priority.attend')], ['track', t('common:priority.track')]]} />
        <Filter label={t('filters.source')} value={scanner} onChange={setScanner} all={t('filters.any_source')} options={[['sca', t('filters.source_options.sca')], ['sast', t('filters.source_options.sast')], ['iac', t('filters.source_options.iac')], ['cicd', t('filters.source_options.cicd')], ['secrets', t('filters.source_options.secrets')]]} />
        {hasSla && <Filter label={t('filters.deadline')} value={deadline} onChange={value => { setDeadline(value); setOffset(0) }} all={t('filters.any_deadline')} options={[['overdue', t('filters.deadline_options.overdue')], ['soon', t('filters.deadline_options.soon')]]} />}
      </div>}
      {selected.size > 0 && <div className="sticky top-16 z-10 flex flex-wrap items-center gap-3 rounded-xl border border-brand/30 bg-panel px-4 py-2.5 shadow-lg">
        <span className="text-sm font-medium">{t('selection.count', { count: selected.size })}</span>
        <TriageActions canAccept={canAccept} onPick={status => setDecision({ status, fingerprints: [...selected] })} />
        {jira.configured && <span className="inline-flex flex-wrap items-center gap-1.5"><Button size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={!!jiraBlocked} aria-describedby={jiraBlocked ? 'jira-bulk-blocked' : undefined} onClick={() => setExporting([...selected])}><Ticket />{t('selection.jira')}</Button>
          {jiraBlocked && <span id="jira-bulk-blocked" className="text-xs text-app-subtle">{jiraBlocked}</span>}</span>}
        <Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => setAuditOpen(true)}><FileCheck2 />{t('selection.report')}</Button>
        <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())} className="ml-auto">{t('selection.clear')}</Button>
      </div>}
      {findings.length === 0
        ? <div className="flex flex-col items-center gap-2 py-14 text-center"><ShieldCheck className="size-7 text-brand" /><p className="font-medium">{t('empty.title')}</p><p className="max-w-md text-sm text-app-muted">{t('empty.body')}</p></div>
        : <div className="overflow-hidden rounded-xl border border-app-line">
          <div className="hidden grid-cols-[20px_120px_90px_minmax(0,1fr)_110px_110px] gap-3 border-b border-app-line px-4 py-2.5 text-xs text-app-subtle md:grid"><input type="checkbox" aria-label={t('table.select_page')} checked={allOnPage} onChange={event => toggle(pageFingerprints, event.target.checked)} className="size-4 accent-brand" /><span>{t('filters.priority')}</span><span>{t('filters.severity')}</span><span>{t('table.finding')}</span><span>EPSS</span><span>{t('filters.source')}</span></div>
          {page.length === 0 && <div className="px-4 py-10 text-center text-sm text-app-subtle">{triageView === 'active' && discarded ? t('table.no_match_dismissed', { count: discarded }) : t('table.no_match')}</div>}
          {page.map(group => { const expanded = open === group.key
            const prints = group.findings.map(item => item.fingerprint)
            const statuses = new Set(group.findings.map(statusOf))
            const groupState = statuses.size === 1 ? group.findings[0].triage : undefined
            return <div key={group.key} className={`flex items-start border-b border-app-line last:border-b-0 ${SUPPRESSED.includes(statusOf(group.findings[0])) && statuses.size === 1 ? 'opacity-70' : ''}`}>
              <input type="checkbox" aria-label={t('table.select_item', { name: group.label })} checked={prints.every(item => selected.has(item))} onChange={event => toggle(prints, event.target.checked)} className="mt-4 ml-4 size-4 shrink-0 accent-brand" />
              <div className="min-w-0 flex-1">
              <button type="button" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : group.key)} className="grid w-full gap-2 py-3 pr-4 pl-3 text-left transition hover:bg-app-soft md:grid-cols-[120px_90px_minmax(0,1fr)_110px_110px] md:items-center">
                <Badge variant="outline" className={`w-fit ${actionClass(group.action)}`}>{labelOf(t, ACTION_LABEL, group.action)}</Badge>
                <Badge variant="outline" className={`w-fit ${severityClass(group.severity)}`}>{labelOf(t, SEVERITY_LABEL, group.severity)}</Badge>
                <span className="flex min-w-0 items-start gap-2"><ChevronRight className={`mt-1 size-3.5 shrink-0 text-app-subtle transition ${expanded ? 'rotate-90' : ''}`} /><span className="min-w-0"><span className="block truncate text-sm font-medium">{group.label}</span><span className="block truncate text-xs text-app-subtle">{group.meta}{group.kev ? ' · CISA KEV' : ''}{group.findings.some(item => item.ticket) ? ` · ${[...new Set(group.findings.flatMap(item => item.ticket ? [item.ticket.key] : []))].join(', ')}` : ''}</span>{group.findings[0].lifecycle?.origin?.kind === 'pr' && <span className="mt-1 mr-1 inline-block rounded border border-info-line px-1.5 text-[11px] text-info">{group.findings[0].lifecycle.origin.merged ? t('group.pr_merged', { number: group.findings[0].lifecycle.origin.pr }) : t('group.pr', { number: group.findings[0].lifecycle.origin.pr })}</span>}{group.findings[0].lifecycle?.origin?.kind === 'import' && <span className="mt-1 mr-1 inline-block rounded border border-app-line px-1.5 text-[11px] text-app-muted">{t('group.imported')}</span>}<SlaPill sla={group.sla} />{group.findings.some(item => item.malicious) && <span className="mt-1 mr-1 inline-block rounded bg-danger-solid px-1.5 text-[11px] font-semibold text-on-solid" title={t('group.malicious_hint')}>{t('group.malicious')}</span>}{statuses.size > 1 ? <span className="mt-1 block text-[11px] text-app-subtle">{t('group.mixed', { statuses: [...statuses].map(item => t(TRIAGE_LABEL[item])).join(', ') })}</span> : <span className="mt-1 block"><TriageBadge state={groupState} /></span>}</span></span>
                <span className="font-mono text-xs text-app-muted">{group.epss !== null ? formatNumber(group.epss, { style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1 }) : '—'}</span>
                <span className="text-xs text-app-muted">{labelOf(t, SCANNER_LABEL, group.scanner)}{group.findings[0].tool ? <span className="block text-[11px] text-app-subtle">{toolsOf(t, group.findings[0])}</span> : null}</span>
              </button>
              {expanded && <div className="space-y-3 border-t border-app-line bg-inset py-4 pr-4 pl-3">{group.findings.map(finding => <FindingDetail key={finding.finding_id} finding={finding} runId={run.id} demo={(run.source as { id?: string } | undefined)?.id === 'local:demo-ejemplos'} canAccept={canAccept} onChanged={onChanged} onPick={status => setDecision({ status, fingerprints: [finding.fingerprint] })}
                jira={<JiraFindingAction ticket={finding.ticket} pending={isPending(finding)} availability={jira} name={finding.advisory?.summary || finding.title} onCreate={() => setExporting([finding.fingerprint])} />} />)}</div>}
              </div>
            </div> })}
          <Pagination total={groups.length} limit={PAGE} offset={Math.min(offset, Math.max(0, groups.length - 1))} onPrev={() => setOffset(current => Math.max(0, current - PAGE))} onNext={() => setOffset(current => current + PAGE)} noun={t('table.pagination', { count: findings.length })} />
        </div>}
    </CardContent></Card>

    {/* Ley de Hick: el informe habitual a mano y los demás formatos agrupados en un menú. */}
    <div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" disabled={downloading !== null} className="border-app-line bg-app-soft" onClick={() => void exportFile('report.pdf')}><ArrowDownToLine />{downloading === 'report.pdf' ? t('export.preparing') : t('export.pdf')}</Button>
      <Menu><MenuTrigger render={<Button variant="outline" size="sm" disabled={downloading !== null} className="border-app-line bg-app-soft" />}>{downloading && downloading !== 'report.pdf' ? t('export.preparing') : t('export.more')}<ChevronDown className="size-3.5" /></MenuTrigger>
        <MenuContent align="start"><MenuGroup label={t('export.audit_group')}><MenuItem onClick={() => setAuditOpen(true)}><FileCheck2 />{t('export.audit')}</MenuItem></MenuGroup>{RUN_EXPORTS.map(group => <MenuGroup key={group.label} label={t(group.label)}>{group.items.filter(([, artifact]) => artifact !== 'sbom.cdx.json' || sbomAvailable).map(([label, artifact]) => <MenuItem key={artifact} onClick={() => void exportFile(artifact)}>{t(label)}</MenuItem>)}</MenuGroup>)}</MenuContent></Menu></div>
    {downloadError && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('export.error', { error: downloadError })}</div>}

    {auditOpen && <AuditReportDialog open onClose={() => setAuditOpen(false)} name={(run.source as { name?: string } | undefined)?.name ?? t('export.file_fallback')}
      target={run.type === 'asset_state' ? { asset: (run.source as { id?: string } | undefined)?.id ?? '', status: exportStatus === 'fixed' || exportStatus === 'all' ? exportStatus : 'open' } : { runId: run.id }}
      selected={[...selected]} filtered={groups.flatMap(group => group.findings.map(item => item.fingerprint))} total={findings.length} />}
    <JiraExportDialog key={exporting?.join(',') ?? 'none'} selection={run.type === 'asset_state' && source?.id ? { asset: source.id } : { runId: run.id }} target={jira.target}
      findings={exporting && exporting.map(fingerprint => { const item = findings.find(entry => entry.fingerprint === fingerprint); return { fingerprint, label: item ? item.advisory?.summary || item.title : fingerprint.slice(0, 12) } })}
      onClose={() => { setExporting(null); setSelected(new Set()) }} onDone={onChanged} />
    <TriageDialog key={decision ? `${decision.status}:${decision.fingerprints.length}` : 'none'} runId={run.id} status={decision?.status ?? null} fingerprints={decision?.fingerprints ?? []} onClose={() => setDecision(null)} onDone={decided} />

    {run.progress?.length ? <details className="group rounded-2xl border border-app-line bg-panel"><summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-medium"><ChevronRight className="size-4 text-app-subtle transition group-open:rotate-90" />{t('log.title')}<span className="ml-2 text-xs font-normal text-app-subtle">{t('log.events', { count: run.progress.length })}{run.started_at && run.finished_at ? ` · ${t('log.seconds', { seconds: Math.round((Date.parse(run.finished_at) - Date.parse(run.started_at)) / 1000) })}` : ''}</span></summary><div className="space-y-1 px-5 pb-5 font-mono text-xs leading-6">{run.progress.map((event, index) => <div key={index} className="flex gap-3"><span className="shrink-0 text-app-subtle">{formatTime(event.at)}</span><span className={event.level === 'ok' ? 'text-brand' : event.level === 'warn' ? 'text-warning' : event.level === 'error' ? 'text-danger' : 'text-app-secondary'}>{event.message}</span></div>)}</div></details> : null}
    <details className="group rounded-2xl border border-app-line bg-panel"><summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-4 text-sm font-medium"><ChevronRight className="size-4 text-app-subtle transition group-open:rotate-90" />{t('coverage.title')}<span className="ml-2 text-xs font-normal text-app-subtle">{t('coverage.steps', { done: run.steps?.filter(step => step.status === 'completed' || step.status === 'partial').length ?? 0, total: run.steps?.length ?? 0 })}</span></summary><div className="space-y-2 px-5 pb-5">{run.steps?.map(step => <div key={step.id} className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-app-line bg-inset p-3 text-sm"><span className="min-w-0"><span className="font-medium">{step.name}</span><span className="mt-0.5 block text-xs leading-5 text-app-muted">{step.detail}</span></span><Badge variant="outline" className={`shrink-0 text-[11px] ${step.status === 'completed' ? 'border-brand/30 text-brand' : step.status === 'partial' ? 'border-warning-line text-warning' : 'border-app-line text-app-subtle'}`}>{labelOf(t, STEP_LABEL, step.status)}</Badge></div>)}</div></details>
  </div>
}

function FindingDetail({ finding, runId, demo, canAccept, onPick, onChanged, jira }: { finding: RepositoryFinding; runId: string; demo: boolean; canAccept: boolean; onPick: (status: TriageStatus) => void; onChanged: () => void; jira: React.ReactNode }) {
  const { t } = useTranslation('findings')
  const advisory = finding.advisory
  const pkg = finding.package
  return <div id={`finding-${finding.fingerprint}`} tabIndex={-1} className="rounded-xl border border-app-line bg-panel p-4">
    <div className="flex flex-wrap items-start justify-between gap-2"><div className="min-w-0"><p className="text-sm font-medium">{advisory?.summary || finding.title}</p><p className="mt-1 flex flex-wrap gap-x-2 font-mono text-xs text-app-subtle"><span className="text-app-secondary">{finding.rule_id}</span>{finding.cve.filter(id => id !== finding.rule_id).map(id => <a key={id} href={`https://www.cve.org/CVERecord?id=${id}`} target="_blank" rel="noreferrer" className="text-brand hover:underline">{id}</a>)}{finding.ghsa.filter(id => id !== finding.rule_id).map(id => <a key={id} href={`https://github.com/advisories/${id}`} target="_blank" rel="noreferrer" className="text-brand hover:underline">{id}</a>)}{finding.cwe.map(id => <a key={id} href={`https://cwe.mitre.org/data/definitions/${id}.html`} target="_blank" rel="noreferrer" className="hover:underline">CWE-{id}</a>)}</p></div><Badge variant="outline" className={severityClass(finding.severity)}>{labelOf(t, SEVERITY_LABEL, finding.severity)}{advisory?.cvss_score !== null && advisory?.cvss_score !== undefined ? ` · ${advisory.cvss_score}` : ''}</Badge></div>
    <div className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
      {pkg?.dev && <Fact label={t('detail.type')}><span className="rounded border border-app-line px-1.5 py-0.5 text-xs">{t('detail.dev_dependency')}</span> <span className="text-xs text-app-subtle">{t('detail.dev_hint')}</span></Fact>}
      {pkg && <Fact label={t('detail.fix')}>{pkg.fixed_version ? <><span className="font-mono">{pkg.version}</span> → <span className="font-mono font-medium text-brand">{pkg.fixed_version}</span></> : t('detail.no_fix')}</Fact>}
      {!pkg && <Fact label={t('detail.location')}><span className="font-mono text-xs">{finding.path}:{finding.line}</span></Fact>}
      {finding.framework && <Fact label={t('detail.technology')}>{finding.framework}</Fact>}
      {finding.epss && <Fact label={t('detail.epss')}>{formatNumber(finding.epss.score, { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 })} <span className="text-app-subtle">{t('detail.percentile', { value: formatNumber(Math.round(finding.epss.percentile * 100)) })}</span></Fact>}
      {finding.kev && <Fact label="CISA KEV">{t('detail.kev_since', { date: finding.kev.date_added ?? '' })}{finding.kev.ransomware ? ` · ${t('detail.kev_ransomware')}` : ''}</Fact>}
      {advisory?.cvss_vector && <Fact label={t('detail.cvss_vector')}><span className="font-mono text-xs break-all">{advisory.cvss_vector}</span></Fact>}
    </div>
    <FixSection fix={finding.fix} remediation={finding.remediation} />
    {finding.lifecycle?.status !== 'excluded' && (finding.lifecycle?.status !== 'fixed' || finding.verification) && <Reverify runId={runId} fingerprint={finding.fingerprint} verification={finding.verification}
      onChanged={onChanged} canVerify={finding.lifecycle?.status !== 'fixed'}
      blocked={demo ? t('verify.demo')
        : finding.lifecycle?.origin?.kind === 'pr' && !finding.lifecycle.origin.merged ? t('verify.open_pr')
        : finding.lifecycle?.origin?.kind === 'import' ? t('verify.imported', { tool: finding.lifecycle.origin.tool || finding.tool || 'SARIF' }) : null} />}
    {finding.priority && <p className="mt-3 text-xs leading-5 text-app-subtle"><span className="font-medium text-app-muted">{t('detail.why_priority')} </span>{finding.priority.factors.join(' · ')}</p>}
    {(finding.tool || finding.also_detected_by?.length) && <p className="mt-2 text-xs text-app-subtle">{finding.also_detected_by?.length
      ? t('detail.detected_by_also', { tool: toolName(t, finding.tool ?? ''), others: finding.also_detected_by.map(tool => toolName(t, tool)).join(', ') })
      : t('detail.detected_by', { tool: toolName(t, finding.tool ?? '') })}{finding.related_rules?.length ? <> · <Trans t={t} i18nKey="detail.related" values={{ rules: finding.related_rules.join(', ') }} components={{ mono: <span className="font-mono" /> }} /></> : null}.</p>}
    {finding.source?.name && <p className="mt-1 text-xs text-app-subtle">{t('detail.advisory_source')} {finding.source.url
      ? <a href={finding.source.url} target="_blank" rel="noreferrer" className="underline decoration-app-faint underline-offset-2 hover:text-app-fg">{finding.source.name}</a>
      : finding.source.name} · {finding.source.license}{finding.source.terms === 'non-commercial' && <span className="text-attention"> · {t('detail.non_commercial')}</span>}</p>}
    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-app-line bg-inset p-3">
      <div className="min-w-0 text-xs text-app-muted"><span className="font-medium text-app-secondary">{t('detail.triage', { status: finding.triage?.expired ? t('detail.triage_expired') : t(TRIAGE_LABEL[statusOf(finding)]) })}</span>{finding.triage?.by ? ` · ${finding.triage.by}` : ''}{finding.triage?.expires_at ? ` · ${t('triage.expires_on', { date: finding.triage.expires_at })}` : ''}{finding.triage?.reason ? <span className="mt-0.5 block">{finding.triage.reason}</span> : null}</div>
      <div className="flex flex-wrap items-center gap-2">{jira}<TriageActions current={statusOf(finding)} canAccept={canAccept} onPick={onPick} size="xs" /></div>
    </div>
    {finding.lifecycle && <p className="mt-2 text-xs leading-5 text-app-subtle"><span className="font-medium text-app-muted">{t('lifecycle.label')} </span>{finding.lifecycle.origin?.kind === 'pr'
      ? (finding.lifecycle.origin.branch
        ? t(finding.lifecycle.origin.merged ? 'lifecycle.from_pr_branch_merged' : 'lifecycle.from_pr_branch', { number: finding.lifecycle.origin.pr, branch: finding.lifecycle.origin.branch })
        : t(finding.lifecycle.origin.merged ? 'lifecycle.from_pr_merged' : 'lifecycle.from_pr', { number: finding.lifecycle.origin.pr }))
      : finding.lifecycle.origin?.kind === 'import' ? t('lifecycle.from_import', { tool: finding.lifecycle.origin.tool || finding.tool || 'SARIF' })
      : t('lifecycle.main')}{finding.lifecycle.first_seen ? ` · ${t('lifecycle.first_seen', { date: formatDate(finding.lifecycle.first_seen) })}` : ''}{finding.lifecycle.last_seen ? ` · ${t('lifecycle.last_seen', { date: formatDate(finding.lifecycle.last_seen) })}` : ''}{finding.lifecycle.reopened_at ? ` · ${t('lifecycle.reopened')}` : ''}{finding.sla ? <span className={`block ${finding.sla.state === 'overdue' ? 'text-danger' : finding.sla.state === 'soon' ? 'text-warning' : ''}`}>{t('lifecycle.sla', { count: finding.sla.days, due: finding.sla.due, status: slaText(finding.sla).toLowerCase() })}</span> : null}{finding.lifecycle.fixed ? <span className="block text-brand">{t('lifecycle.auto_fixed', { how: finding.lifecycle.fixed.how })}</span> : null}{finding.lifecycle.status === 'excluded' ? <span className="block">{finding.lifecycle.excluded?.reason ?? (finding.lifecycle.excluded?.pattern
      ? <Trans t={t} i18nKey="lifecycle.excluded_pattern" values={{ pattern: finding.lifecycle.excluded.pattern }} components={{ code: <code className="font-mono" /> }} />
      : t('lifecycle.excluded'))}</span> : null}</p>}
    <TriageHistory state={finding.triage} />
    {advisory?.details && <details className="mt-3"><summary className="cursor-pointer text-xs text-app-muted">{t('detail.advisory_details')}</summary><p className="mt-2 text-xs leading-5 whitespace-pre-line text-app-muted">{advisory.details}</p></details>}
    {advisory?.references.length ? <p className="mt-3 flex flex-wrap gap-x-3 text-xs">{advisory.references.slice(0, 4).map(url => <a key={url} href={url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-brand hover:underline">{new URL(url).hostname} <ExternalLink className="size-3" /></a>)}</p> : null}
  </div>
}

// Another tool's findings: which one, how far the import vouches for it, and against which code.
function ImportHeader({ run, onNew }: { run: RepositoryRun; onNew: () => void }) {
  const { t } = useTranslation('findings')
  const trigger = run.trigger ?? { kind: 'import' }
  const tool = trigger.tool || 'SARIF'
  const branch = trigger.branch ?? run.source?.branch
  const commit = trigger.commit ?? run.source?.commit
  const code = <span className="font-mono" />
  return <div className="flex flex-col gap-4 rounded-2xl border border-app-line bg-panel p-5 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0">
    <div className="mb-1 text-xs font-semibold tracking-[0.18em] text-brand uppercase">{t('import.eyebrow', { tool })}</div>
    <h2 className="truncate text-xl font-semibold">{run.source?.name ?? t('scan.repository')}</h2>
    <p className="mt-1 text-xs text-app-subtle">{formatDate(run.created_at)} · {trigger.scope === 'partial' ? t('import.partial') : t('import.full')}{branch || commit ? ' · ' : ''}{branch
      ? commit ? <Trans t={t} i18nKey="scan.branch_commit" values={{ branch, commit: commit.slice(0, 7) }} components={{ code }} /> : <Trans t={t} i18nKey="scan.branch" values={{ branch }} components={{ code }} />
      : commit ? <Trans t={t} i18nKey="import.commit" values={{ commit: commit.slice(0, 7) }} components={{ code }} /> : null}</p>
    <p className="mt-2 text-sm text-app-muted">{trigger.scope === 'partial' ? t('import.help_partial', { tool }) : t('import.help_full', { tool })}</p>
  </div><Button variant="outline" onClick={onNew} className="shrink-0 border-app-line bg-app-soft">{t('import.new')} <ArrowRight /></Button></div>
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><span className="block text-xs text-app-subtle">{label}</span><span className="text-app-secondary">{children}</span></div>
}
function Tile({ label, value, tone, hint, icon: Icon }: { label: string; value: number; tone: 'rose' | 'amber' | 'orange' | 'teal' | 'muted'; hint?: string; icon?: typeof Flame }) {
  const color = { rose: 'text-danger', amber: 'text-warning', orange: 'text-attention', teal: 'text-brand', muted: 'text-app-fg' }[tone]
  return <Card className="border-app-line bg-panel"><CardContent className="flex items-start justify-between p-4"><div><div className={`text-2xl font-semibold tabular-nums ${color}`}>{value}</div><div className="mt-0.5 text-xs text-app-muted">{label}</div>{hint && <div className="text-[11px] text-app-subtle">{hint}</div>}</div>{Icon && <Icon className="size-4 text-app-subtle" />}</CardContent></Card>
}
// El nombre accesible dice qué filtra y su valor («Severidad: Alta»), no solo el valor (1.3.1 / 2.5.3).
function Filter({ label, value, onChange, all, options }: { label: string; value: string; onChange: (value: string) => void; all: string; options: [string, string][] }) {
  const current = value === 'all' ? all : options.find(([id]) => id === value)?.[1] ?? all
  return <Select value={value} onValueChange={next => onChange(next ?? 'all')}><SelectTrigger aria-label={`${label}: ${current}`} size="sm" className="min-w-40 border-app-line bg-app-soft text-app-secondary">{value === 'all' ? all : options.find(([id]) => id === value)?.[1]}</SelectTrigger><SelectContent align="start" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="all">{all}</SelectItem>{options.map(([id, label]) => <SelectItem key={id} value={id}>{label}</SelectItem>)}</SelectContent></Select>
}
