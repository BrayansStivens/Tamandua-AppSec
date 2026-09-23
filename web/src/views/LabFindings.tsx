import { useState } from 'react'
import { ArrowDownToLine, CircleAlert, Radar, Shield, ShieldAlert } from 'lucide-react'
import { RunPicker } from '@/components/run-picker'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Separator } from '@/components/ui/separator'
import type { Finding, RunRow } from '@/lib/runs'

const severityClass = (severity: string) => severity === 'high' || severity === 'critical' ? 'text-rose-700 dark:text-rose-300 border-rose-500/30 bg-rose-500/10' : 'text-amber-700 dark:text-amber-300 border-amber-500/30 bg-amber-500/10'
const cveUrl = (id: string) => /^CVE-\d{4}-\d{4,}$/.test(id) ? `https://www.cve.org/CVERecord?id=${id}` : null
const ghsaUrl = (id: string) => /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i.test(id) ? `https://github.com/advisories/${id}` : null

// Resultados del laboratorio sintético: hallazgos reproducidos con sus pasos y observaciones.
export function LabFindings({ activeRow, findings, onSelect }: { activeRow?: RunRow; findings: Finding[]; onSelect: (id: string) => void }) {
  const [reportTitle, setReportTitle] = useState('Informe técnico personalizado')
  const labFindings = activeRow?.type === 'lab_scan' ? findings : []
  const highCount = findings.filter(finding => finding.severity === 'high' || finding.severity === 'critical').length
  return <div className="space-y-5">
      <RunPicker active={activeRow?.id} onSelect={onSelect} />
      <div className="grid gap-4 sm:grid-cols-3"><Metric icon={ShieldAlert} label="Confirmados" value={String(findings.length)} hint="Doble ejecución" tone="rose" /><Metric icon={CircleAlert} label="Altos" value={String(highCount)} hint="Severidad del laboratorio" /><Metric icon={Radar} label="Cobertura" value={activeRow ? `${activeRow.summary.executed}/${activeRow.summary.planned}` : '—'} hint="Escenarios ejecutados" /></div>
      {activeRow && <div className="space-y-3"><div className="flex flex-wrap gap-2">{[
        ['JSON', `/api/runs/${activeRow.id}`], ['Markdown', `/api/runs/${activeRow.id}/report.md`],
        ['SARIF', `/api/runs/${activeRow.id}/findings.sarif`], ['SOC 2 Tipo II', `/api/runs/${activeRow.id}/report-soc2.md`],
        ['ISO 27001', `/api/runs/${activeRow.id}/report-iso27001.md`],
      ].map(([label, href]) => <a key={label} href={href} download><Button variant="outline" className="border-app-line bg-app-soft"><ArrowDownToLine /> {label}</Button></a>)}</div><div className="flex flex-col gap-2 sm:flex-row sm:items-center"><Input aria-label="Título del reporte personalizado" value={reportTitle} onChange={event => setReportTitle(event.target.value)} maxLength={100} className="max-w-sm border-app-line bg-app-soft" /><a href={`/api/runs/${activeRow.id}/report-custom.md?title=${encodeURIComponent(reportTitle)}`} download><Button variant="outline" className="border-app-line bg-app-soft"><ArrowDownToLine /> Reporte personalizado</Button></a></div><p className="text-xs text-app-subtle">Los perfiles de cumplimiento organizan evidencia técnica; no constituyen certificación ni atestación.</p></div>}
      <div className="space-y-3">{labFindings.length ? labFindings.map(finding => <Card key={finding.finding_id} className="border-app-line bg-panel"><CardHeader className="gap-3"><div className="flex flex-wrap items-center justify-between gap-2"><div className="flex items-center gap-2"><ShieldAlert className="size-4 text-rose-700 dark:text-rose-300" /><CardTitle className="text-base">{finding.title}</CardTitle></div><Badge variant="outline" className={severityClass(finding.severity)}>{finding.severity.toUpperCase()}</Badge></div><CardDescription className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-xs"><span>{finding.endpoint}</span>{finding.cwe.map(id => <a key={id} href={`https://cwe.mitre.org/data/definitions/${id}.html`} target="_blank" rel="noopener noreferrer" className="text-brand hover:underline">CWE-{id} ↗</a>)}{finding.cve?.map(id => cveUrl(id) && <a key={id} href={cveUrl(id)!} target="_blank" rel="noopener noreferrer" className="text-brand hover:underline">{id} ↗</a>)}{finding.ghsa?.map(id => ghsaUrl(id) && <a key={id} href={ghsaUrl(id)!} target="_blank" rel="noopener noreferrer" className="text-brand hover:underline">{id} ↗</a>)}<span>{finding.owasp[0]} · confianza {finding.confidence}/10</span></CardDescription></CardHeader><CardContent className="space-y-4"><p className="text-sm text-app-secondary">{finding.impact}</p><details className="rounded-xl border border-app-line bg-inset p-4"><summary className="cursor-pointer text-sm font-medium text-brand">Ver pasos y observaciones</summary><div className="mt-4 space-y-3 text-xs text-app-secondary"><div className="font-medium uppercase tracking-widest text-app-subtle">Reproducción</div>{finding.reproduction_steps.map((step, index) => <div key={`${step.path}-${index}`} className="font-mono">{index + 1}. {step.token} → {step.method} {step.path}{step.json ? ` · ${JSON.stringify(step.json)}` : ''}</div>)}<Separator className="bg-white/10" />{finding.evidence.map(attempt => <div key={attempt.phase}><div className="mb-1 font-medium text-app-muted">{attempt.phase === 'discovery' ? 'Descubrimiento' : 'Verificación en proceso nuevo'}</div>{attempt.observations.map((observation, index) => <div key={index} className="font-mono text-app-subtle">HTTP {observation.status} · tenant {observation.tenant ?? '—'} · rol {observation.role ?? '—'} · documentos {observation.document_tenants.join(', ') || '—'}</div>)}</div>)}</div></details></CardContent></Card>) : <Card className="border-app-line bg-panel"><CardContent className="pt-6"><Empty text={activeRow ? 'No se observó la condición vulnerable en estos escenarios. No equivale a seguridad total.' : 'Selecciona un objetivo y ejecuta un pentest.'} /></CardContent></Card>}</div>
    </div>
}

function Metric({ icon: Icon, label, value, hint, tone = 'default' }: { icon: typeof Shield; label: string; value: string; hint: string; tone?: 'default' | 'rose' | 'teal' }) {
  return <Card className="border-app-line bg-panel"><CardContent className="flex items-start justify-between px-5 py-5"><div><p className="text-xs text-app-muted">{label}</p><div className={`mt-3 text-3xl font-semibold tabular-nums ${tone === 'rose' ? 'text-rose-700 dark:text-rose-300' : tone === 'teal' ? 'text-brand' : 'text-app-fg'}`}>{value}</div><p className="mt-1 text-xs text-app-subtle">{hint}</p></div><div className="rounded-lg border border-app-line bg-app-soft p-2"><Icon className="size-4 text-app-secondary" /></div></CardContent></Card>
}
function Empty({ text }: { text: string }) { return <div className="py-10 text-center text-sm text-app-subtle">{text}</div> }
