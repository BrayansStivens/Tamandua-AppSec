import { useState } from 'react'
import { usePaged } from '@/hooks/usePaged'
import { Pagination } from '@/components/ui/pagination'
import { Boxes, Code2, FlaskConical, GitPullRequest, Plus, Radar, Search, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/components/ui/select'
import { SkeletonTable } from '@/components/loading'
import { BatchPanel, useBatches } from '@/components/batches'

export type AnalysisRow = { id: string; type: string; status: string; created_at: string; variant?: string; fixture?: string; source?: { name: string }; summary: { candidates?: number; confirmed?: number; executed?: number; planned?: number; severities?: Record<string, number>; kev?: number } }

const typeLabel = (type: string) => ({ repository_scan: 'Análisis de código', image_scan: 'Imagen de contenedor', pr_review: 'Revisión de PR', lab_scan: 'Laboratorio API', fixture_evaluation: 'Ground truth' }[type] ?? type)
const statusLabel = (status: string) => ({ completed: 'Completada', incomplete: 'Incompleta', failed: 'Fallida', queued: 'En cola', running: 'Analizando…' }[status] ?? status)
const typeIcon = (type: string) => type === 'repository_scan' ? Code2 : type === 'image_scan' ? Boxes : type === 'pr_review' ? GitPullRequest : type === 'lab_scan' ? FlaskConical : ShieldCheck
const rowName = (row: AnalysisRow) => row.type === 'repository_scan' ? row.source?.name ?? 'Repositorio' : row.type === 'image_scan' ? row.fixture ?? row.source?.name ?? 'Imagen' : row.type === 'pr_review' ? row.fixture ?? row.source?.name ?? 'Pull request' : row.type === 'lab_scan' ? `Laboratorio sintético · ${row.variant}` : 'Evaluación ground truth'
// Un laboratorio reproduce la condición; un análisis estático solo deja candidatos. La columna no los mezcla.
const rowIssues = (row: AnalysisRow) => row.type === 'pr_review'
  ? { value: row.summary.candidates ?? 0, hint: 'nuevos en el PR' }
  : row.type === 'repository_scan' || row.type === 'image_scan'
  ? { value: row.summary.candidates ?? 0, hint: 'candidatos' }
  : { value: row.summary.confirmed ?? 0, hint: 'reproducidos' }

export function AnalysisList({ refreshKey, onOpen, onNew, viewer }: { refreshKey: number; onOpen: (id: string) => void; onNew: () => void; viewer: { username: string; admin: boolean } }) {
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const [type, setType] = useState('all')
  // La lista se pide paginada al servidor: con mil ejecuciones no se cargan mil filas.
  const page = usePaged<AnalysisRow>('/api/runs/page', { q: query.trim() || undefined, status: status === 'all' ? undefined : status, type: type === 'all' ? undefined : type }, 25, refreshKey)
  const visible = page.items
  // Lotes (varios repositorios, una organización o varias imágenes): su progreso, arriba de la lista.
  const { active: batch, last: lastBatch, reload: reloadBatches } = useBatches()

  return <Card className="border-app-line bg-panel"><CardContent className="space-y-5 p-5">
    <BatchPanel active={batch} last={lastBatch} viewer={viewer} onChanged={() => void reloadBatches()} />
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <div className="relative min-w-0 flex-1 sm:max-w-xs"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label="Buscar análisis" placeholder="Buscar análisis…" value={query} onChange={event => setQuery(event.target.value)} className="border-app-line bg-app-soft pl-9" /></div>
      <Select value={status} onValueChange={value => setStatus(value ?? 'all')}><SelectTrigger aria-label="Filtrar por estado" size="sm" className="min-w-40 border-app-line bg-app-soft text-app-secondary">{status === 'all' ? 'Todos los estados' : statusLabel(status)}</SelectTrigger><SelectContent align="start" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="all">Todos los estados</SelectItem><SelectItem value="running">Analizando</SelectItem><SelectItem value="completed">Completada</SelectItem><SelectItem value="incomplete">Incompleta</SelectItem><SelectItem value="failed">Fallida</SelectItem></SelectContent></Select>
      <Select value={type} onValueChange={value => setType(value ?? 'all')}><SelectTrigger aria-label="Filtrar por tipo" size="sm" className="min-w-44 border-app-line bg-app-soft text-app-secondary">{type === 'all' ? 'Todos los tipos' : typeLabel(type)}</SelectTrigger><SelectContent align="start" className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="all">Todos los tipos</SelectItem><SelectItem value="repository_scan">Análisis de código</SelectItem><SelectItem value="image_scan">Imagen de contenedor</SelectItem><SelectItem value="pr_review">Revisión de PR</SelectItem></SelectContent></Select>
    </div>
    {page.error && <p role="alert" className="text-sm text-danger">{page.error}</p>}
    {page.total === 0 && page.loading ? <SkeletonTable rows={6} columns={5} label="Cargando análisis" />
      : page.total === 0
      ? <div className="flex flex-col items-center gap-3 py-16 text-center"><Radar className="size-7 text-app-subtle" /><p className="font-medium">Aún no hay análisis</p><p className="max-w-sm text-sm text-app-muted">Aquí aparecerán tus análisis. Lanza el primero sobre un repositorio o una imagen de contenedor.</p><Button onClick={onNew} className="mt-1 bg-primary text-primary-foreground hover:bg-primary/90"><Plus /> Nuevo análisis</Button></div>
      : <div className="overflow-hidden rounded-xl border border-app-line">
        <div className="hidden grid-cols-[110px_minmax(0,1fr)_170px_120px_150px] gap-3 border-b border-app-line px-4 py-3 text-xs text-app-subtle md:grid"><span>Estado</span><span>Análisis</span><span>Tipo</span><span>Hallazgos</span><span>Iniciado</span></div>
        {visible.map(row => { const Icon = typeIcon(row.type); const issues = rowIssues(row)
          return <button key={row.id} onClick={() => onOpen(row.id)} className="grid w-full gap-2 border-b border-app-line px-4 py-3 text-left transition last:border-b-0 hover:bg-app-soft md:grid-cols-[110px_minmax(0,1fr)_170px_120px_150px] md:items-center">
            <Badge variant="outline" className={`w-fit ${row.status === 'completed' ? 'border-brand/30 text-brand' : row.status === 'failed' ? 'border-danger-line text-danger' : row.status === 'running' || row.status === 'queued' ? 'animate-pulse border-brand/30 text-brand' : 'border-warning-line text-warning'}`}>{statusLabel(row.status)}</Badge>
            <span className="flex min-w-0 items-center gap-2"><Icon className="size-4 shrink-0 text-app-muted" /><span className="min-w-0"><span className="block truncate text-sm font-medium">{rowName(row)}</span><span className="font-mono text-xs text-app-subtle">{row.id.slice(0, 8)}</span></span></span>
            <span className="text-xs text-app-muted">{typeLabel(row.type)}</span>
            {row.summary.severities
              ? <span className="flex flex-wrap items-center gap-1 text-[11px]">{([['critical', 'C', 'bg-danger-solid text-on-solid'], ['high', 'A', 'bg-attention-soft text-attention'], ['medium', 'M', 'bg-warning-soft text-warning'], ['low', 'B', 'bg-info-soft text-info']] as const).map(([level, letter, cls]) => (row.summary.severities?.[level] ?? 0) > 0 ? <span key={level} className={`rounded px-1.5 py-0.5 font-mono ${cls}`} title={level}>{letter}{row.summary.severities?.[level]}</span> : null)}{row.summary.kev ? <span className="rounded bg-danger-solid px-1.5 py-0.5 font-mono text-on-solid" title="CISA KEV">KEV</span> : null}{issues.value === 0 && <span className="text-app-subtle">0</span>}</span>
              : <span className="text-xs text-app-muted"><span className="font-mono text-sm text-app-secondary">{issues.value}</span> {issues.hint}</span>}
            <span className="text-xs text-app-muted">{new Date(row.created_at).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })}</span>
          </button> })}
        <Pagination total={page.total} limit={page.limit} offset={page.offset} onPrev={page.prev} onNext={page.next} noun="análisis" />
      </div>}
  </CardContent></Card>
}
