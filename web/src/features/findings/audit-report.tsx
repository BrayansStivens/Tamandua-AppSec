import { useState, type FormEvent } from 'react'
import { FileCheck2, LoaderCircle } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'

type Framework = 'soc2' | 'iso27001' | 'pci' | 'cra' | 'br-cmn' | 'cl-21663' | 'co-sfc' | 'general'
type Detail = 'none' | 'high' | 'all'
type Scope = 'selected' | 'filtered' | 'all'
export type AuditTarget = { runId: string } | { asset: string; status: 'open' | 'fixed' | 'all' } | { account: string }

const FRAMEWORKS: [Framework, string, string][] = [
  ['soc2', 'SOC 2 Tipo II', 'Relaciona la evidencia con CC3.2, CC7.1 y CC8.1'],
  ['iso27001', 'ISO/IEC 27001:2022', 'Relaciona la evidencia con A.8.8, A.8.9, A.8.28 y A.8.29'],
  ['pci', 'PCI DSS 4.0.1', 'Requisitos 6.2.4, 6.3.1, 6.3.2 (inventario) y 6.3.3 (parches en un mes)'],
  ['cra', 'Ciberresiliencia de la UE (CRA)', 'Anexo I, parte II (vulnerabilidades, SBOM, pruebas) y artículo 14'],
  ['br-cmn', 'Brasil · Res. CMN 4.893 / 5.274', 'Gestión continua de vulnerabilidades, pruebas y trazabilidad'],
  ['cl-21663', 'Chile · Ley 21.663', 'Gestión de riesgos, revisión periódica y registro de decisiones'],
  ['co-sfc', 'Colombia · SFC, CE 007 de 2018', 'Vulnerabilidades técnicas, desarrollo seguro y evidencia para supervisión'],
  ['general', 'General', 'Sin marco: gestión de vulnerabilidades'],
]
const MEMORY = 'tamandua-audit-report'
// Lo que no cambia entre informes se recuerda en este navegador (solo comodidad; nada sale de aquí).
const remembered = (): Partial<Record<string, string>> => { try { return JSON.parse(localStorage.getItem(MEMORY) ?? '{}') } catch { return {} } }
const field = 'space-y-1.5'
const label = 'text-xs font-medium text-app-secondary'

// Informe de evidencia para auditoría: formulario corto con valores por defecto y alcance elegido
// (seleccionados, lo que se ve con los filtros o todo), en un solo documento.
export function AuditReportDialog({ open, onClose, target, name, selected, filtered, total }: {
  open: boolean; onClose: () => void; target: AuditTarget; name: string; selected: string[]; filtered: string[]; total: number
}) {
  const memory = remembered()
  const [framework, setFramework] = useState<Framework>((memory.framework as Framework) || 'soc2')
  const [scope, setScope] = useState<Scope>(selected.length ? 'selected' : filtered.length < total ? 'filtered' : 'all')
  const [title, setTitle] = useState('')
  const [organization, setOrganization] = useState(memory.organization ?? '')
  const [preparedFor, setPreparedFor] = useState(memory.prepared_for ?? '')
  const [preparedBy, setPreparedBy] = useState(memory.prepared_by ?? '')
  const [scopeText, setScopeText] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [detail, setDetail] = useState<Detail>('high')
  const [exceptions, setExceptions] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const counts: Record<Scope, number> = { selected: selected.length, filtered: filtered.length, all: total }
  // Consolidado de una organización: todos sus repositorios analizados, su cobertura y un solo documento.
  const portfolio = 'account' in target

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy(true); setError('')
    try { localStorage.setItem(MEMORY, JSON.stringify({ framework, organization, prepared_for: preparedFor, prepared_by: preparedBy })) } catch { /* sin almacenamiento */ }
    const fingerprints = portfolio ? undefined : scope === 'selected' ? selected : scope === 'filtered' ? filtered : undefined
    const where = 'runId' in target ? { run_id: target.runId } : 'account' in target ? { account: target.account } : { asset: target.asset, status: target.status }
    const body = { ...where, ...(fingerprints ? { fingerprints } : {}),
      options: { framework, detail, include_exceptions: exceptions, title, organization, prepared_for: preparedFor, prepared_by: preparedBy, scope: scopeText, period_from: from, period_to: to } }
    const file = `${name.replace(/[^a-z0-9-]+/gi, '-').slice(0, 40) || 'hallazgos'}-evidencia-${framework}.pdf`
    try { await api.downloadPost('/api/reports/audit', 'audit-report', body, file); onClose() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  return <Dialog open={open} onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-h-[92vh] max-w-2xl overflow-y-auto">
    <DialogHeader><DialogTitle>{portfolio ? `Informe consolidado · ${name}` : 'Informe de evidencia para auditoría'}</DialogTitle>
      <DialogDescription>Un PDF conciso con alcance, método, hallazgos con su estado, excepciones aprobadas y firmas. Todo es opcional: sin tocar nada se genera con valores por defecto.</DialogDescription></DialogHeader>
    <form className="space-y-5" onSubmit={submit}>
      {/* Ley de Hick: ocho marcos en un selector, con lo que aporta el elegido debajo. */}
      <div className="space-y-2"><label htmlFor="audit-framework" className={label}>Marco</label>
        <Select value={framework} onValueChange={value => setFramework((value ?? 'general') as Framework)}>
          <SelectTrigger id="audit-framework" className="w-full border-app-line bg-inset">{FRAMEWORKS.find(([id]) => id === framework)?.[1]}</SelectTrigger>
          <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{FRAMEWORKS.map(([id, text]) => <SelectItem key={id} value={id}>{text}</SelectItem>)}</SelectContent>
        </Select>
        <p className="text-xs text-app-muted">{FRAMEWORKS.find(([id]) => id === framework)?.[2]}.{framework === 'general' ? '' : ' La relación con cada control es orientativa.'}</p></div>

      {portfolio ? <p className="rounded-lg border border-app-line bg-inset p-3 text-sm text-app-muted">Todos los repositorios analizados de la organización, su cobertura frente a GitHub (cuáles no tienen un análisis completo), los críticos y altos abiertos y las excepciones, en un solo documento.</p>
      : <fieldset className="space-y-2"><legend className={label}>Hallazgos del informe</legend>
        <div className="grid gap-2 sm:grid-cols-3">{([['selected', 'Seleccionados'], ['filtered', 'Los que ves con los filtros'], ['all', 'Todos']] as [Scope, string][]).map(([id, text]) =>
          <label key={id} className={`flex items-center gap-2 rounded-lg border p-3 text-sm ${counts[id] === 0 ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} ${scope === id ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-inset'}`}>
            <input type="radio" name="scope" value={id} checked={scope === id} disabled={counts[id] === 0} onChange={() => setScope(id)} className="size-4 accent-brand" />{text} · {counts[id]}</label>)}</div></fieldset>}

      <div className="grid gap-4 sm:grid-cols-2">
        <div className={field}><label htmlFor="ar-org" className={label}>Organización</label><Input id="ar-org" maxLength={120} value={organization} onChange={event => setOrganization(event.target.value)} placeholder="p. ej. Acme S.A.S. · Equipo AppSec" className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-for" className={label}>Preparado para</label><Input id="ar-for" maxLength={120} value={preparedFor} onChange={event => setPreparedFor(event.target.value)} placeholder="p. ej. Auditoría externa 2026, cliente X" className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-by" className={label}>Preparado por</label><Input id="ar-by" maxLength={80} value={preparedBy} onChange={event => setPreparedBy(event.target.value)} placeholder="Por defecto, tu nombre" className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-scope" className={label}>Sistema o alcance</label><Input id="ar-scope" maxLength={300} value={scopeText} onChange={event => setScopeText(event.target.value)} placeholder={name} className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-from" className={label}>Periodo desde</label><Input id="ar-from" type="date" value={from} onChange={event => setFrom(event.target.value)} className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-to" className={label}>Periodo hasta</label><Input id="ar-to" type="date" value={to} min={from || undefined} onChange={event => setTo(event.target.value)} className="border-app-line bg-app-soft" /></div>
      </div>

      <details className="rounded-lg border border-app-line px-3 py-2 text-sm"><summary className="cursor-pointer text-app-muted">Más opciones</summary>
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          <div className={field}><label htmlFor="ar-title" className={label}>Título</label><Input id="ar-title" maxLength={120} value={title} onChange={event => setTitle(event.target.value)} placeholder="Evidencia de gestión de vulnerabilidades" className="border-app-line bg-app-soft" /></div>
          {!portfolio && <div className={field}><label htmlFor="ar-detail" className={label}>Detalle por hallazgo</label>
            <select id="ar-detail" value={detail} onChange={event => setDetail(event.target.value as Detail)} className="h-9 w-full rounded-lg border border-app-line bg-app-soft px-2 text-sm">
              <option value="high">Solo críticos y altos</option><option value="all">Todos</option><option value="none">Ninguno (solo la tabla)</option></select></div>}
          <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={exceptions} onChange={event => setExceptions(event.target.checked)} className="size-4 accent-brand" />Incluir excepciones y decisiones (riesgos aceptados y falsos positivos con su motivo)</label>
        </div></details>

      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>}
      <p className="text-xs text-app-subtle">Es evidencia técnica para el auditor, no una opinión de auditoría ni una certificación. Revísala y fírmala antes de entregarla.</p>
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>Cancelar</Button>
        <Button type="submit" disabled={busy || (!portfolio && counts[scope] === 0)} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <FileCheck2 />}{busy ? 'Generando…' : portfolio ? 'Generar PDF consolidado' : `Generar PDF · ${counts[scope]} ${counts[scope] === 1 ? 'hallazgo' : 'hallazgos'}`}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}
