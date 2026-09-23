import { useEffect, useState } from 'react'
import { CircleDashed, Clock3, TriangleAlert } from 'lucide-react'
import { AssetPicker, type Asset } from '@/components/asset-picker'
import { Skeleton } from '@/components/loading'
import { api } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { formatDate, type OwaspCoverage, type RunRow, type ScanStep } from '@/lib/types'

const stepLabel = (status: string) => ({ completed: 'Completado', partial: 'Parcial', not_tested: 'No probado', inconclusive: 'Inconcluso', pending: 'Pendiente' }[status] ?? status)

// Cobertura de la ejecución seleccionada: qué motores corrieron y qué categorías OWASP tocaron, con números.
export function Coverage({ run, coverage, steps }: { run: RunRow | null; coverage: OwaspCoverage[]; steps: ScanStep[] }) {
  const partial = coverage.filter(item => item.status === 'partial').length
  const notTested = coverage.filter(item => item.status === 'not_tested')
  return <div className="grid gap-5 xl:grid-cols-[1.15fr_1fr]">
    <Card className="border-app-line bg-panel"><CardHeader><div className="flex items-center justify-between gap-3"><CardTitle>OWASP Top 10:2025</CardTitle><Badge variant="outline" className={partial >= 7 ? 'border-brand/30 text-brand' : 'border-amber-500/30 text-amber-700 dark:text-amber-300'}>{partial}/10 con alguna prueba</Badge></div><CardDescription>Cada categoría dice qué motor o cuántas reglas la cubrieron y cuántos hallazgos produjo. Lo no probado dice por qué.</CardDescription></CardHeader><CardContent className="space-y-1">
      {coverage.map(item => <div key={item.id} className="flex items-start gap-3 border-b border-app-line py-3 last:border-0"><span className={`mt-0.5 font-mono text-xs ${item.status === 'partial' ? 'text-brand' : 'text-app-subtle'}`}>{item.id}</span><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2 text-sm text-app-primary">{item.title}{item.status === 'partial' && item.findings ? <Badge variant="outline" className="text-[10px]">{item.findings} hallazgo{item.findings === 1 ? '' : 's'}</Badge> : null}{item.rules ? <span className="text-[10px] text-app-subtle">{item.rules} reglas</span> : null}</div><div className="text-xs leading-5 text-app-subtle">{item.reason}</div></div>{item.status === 'partial' ? <CircleDashed className="size-4 shrink-0 text-brand" /> : item.status === 'inconclusive' ? <TriangleAlert className="size-4 shrink-0 text-amber-600" /> : <Clock3 className="size-4 shrink-0 text-app-faint" />}</div>)}
    </CardContent></Card>
    <div className="space-y-5">
      <Card className="border-app-line bg-panel"><CardHeader><CardTitle>Ejecución evaluada</CardTitle><CardDescription>{run ? `${run.source?.name ?? run.fixture} · ${formatDate(run.created_at)}` : 'Sin ejecución seleccionada'}</CardDescription></CardHeader><CardContent className="space-y-2">
        {steps.map(step => <div key={step.id} className="flex items-start justify-between gap-3 rounded-lg border border-app-line p-3 text-xs"><span className="min-w-0"><span className="font-mono text-app-secondary">{step.name}</span>{step.tool?.duration_s !== null && step.tool?.duration_s !== undefined ? <span className="ml-2 text-app-subtle">{step.tool.duration_s}s</span> : null}<span className="mt-1 block leading-5 text-app-subtle">{step.detail}</span></span><Badge variant="outline" className={`shrink-0 text-[10px] ${step.status === 'completed' ? 'border-brand/30 text-brand' : step.status === 'partial' ? 'border-amber-500/30 text-amber-700 dark:text-amber-300' : 'border-app-line text-app-subtle'}`}>{stepLabel(step.status)}</Badge></div>)}
        {!steps.length && <p className="text-sm text-app-muted">Elige una ejecución en Hallazgos para ver su cobertura.</p>}
      </CardContent></Card>
      {notTested.length > 0 && <Card className="border-app-line bg-panel"><CardHeader><CardTitle className="text-base">Qué no cubre un análisis estático</CardTitle></CardHeader><CardContent className="space-y-2 text-sm text-app-muted">{notTested.map(item => <p key={item.id}><span className="font-mono text-xs text-app-subtle">{item.id}</span> {item.reason}</p>)}<p className="text-xs text-app-subtle">Estas categorías se cubren con modelado de amenazas y pruebas dinámicas, que están en el plan.</p></CardContent></Card>}
    </div>
  </div>
}

const OWASP_TOP10 = [['A01', 'Broken Access Control'], ['A02', 'Security Misconfiguration'], ['A03', 'Software Supply Chain Failures'],
  ['A04', 'Cryptographic Failures'], ['A05', 'Injection'], ['A06', 'Insecure Design'], ['A07', 'Authentication Failures'],
  ['A08', 'Software or Data Integrity Failures'], ['A09', 'Security Logging & Alerting Failures'], ['A10', 'Mishandling of Exceptional Conditions']] as const

// Cobertura por repositorio: se mide sobre su último escaneo completo, no sobre la última ejecución de cualquier tipo.
export function CoverageView() {
  const [asset, setAsset] = useState<Asset | null>(null)
  const [detail, setDetail] = useState<(RunRow & { owasp_coverage?: OwaspCoverage[]; steps?: ScanStep[] }) | null>(null)
  const [loading, setLoading] = useState(false)
  const runId = asset?.latest_scan?.run_id
  useEffect(() => {
    if (!runId) { setDetail(null); return }
    setLoading(true)
    api.get<RunRow & { owasp_coverage?: OwaspCoverage[]; steps?: ScanStep[] }>(`/api/runs/${encodeURIComponent(runId)}`).then(setDetail).catch(() => setDetail(null)).finally(() => setLoading(false))
  }, [runId])
  const coverage = OWASP_TOP10.map(([id, title]) => detail?.owasp_coverage?.find(item => item.id === id) ?? { id, title, status: 'not_tested' as const, probe_ids: [], reason: 'Sin escaneo completo de este repositorio' })
  return <div className="space-y-5">
    <div className="max-w-xl space-y-1"><span className="text-xs text-app-muted">Repositorio</span><AssetPicker value={asset} onChange={setAsset} /></div>
    {asset && !runId ? <Card className="border-app-line bg-panel"><CardContent className="py-10 text-center text-sm text-app-muted">Este repositorio aún no tiene un escaneo completo terminado. La cobertura OWASP se mide sobre él: lanza uno desde «Nuevo análisis».</CardContent></Card>
      : loading ? <Skeleton rows={6} />
      : <Coverage run={detail} coverage={coverage} steps={detail?.steps ?? []} />}
  </div>
}
