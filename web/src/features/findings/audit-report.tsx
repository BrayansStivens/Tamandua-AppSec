import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
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

// [id, name key, hint key]
const FRAMEWORKS: [Framework, string, string][] = [
  ['soc2', 'audit.frameworks.soc2.name', 'audit.frameworks.soc2.hint'],
  ['iso27001', 'audit.frameworks.iso27001.name', 'audit.frameworks.iso27001.hint'],
  ['pci', 'audit.frameworks.pci.name', 'audit.frameworks.pci.hint'],
  ['cra', 'audit.frameworks.cra.name', 'audit.frameworks.cra.hint'],
  ['br-cmn', 'audit.frameworks.br_cmn.name', 'audit.frameworks.br_cmn.hint'],
  ['cl-21663', 'audit.frameworks.cl_21663.name', 'audit.frameworks.cl_21663.hint'],
  ['co-sfc', 'audit.frameworks.co_sfc.name', 'audit.frameworks.co_sfc.hint'],
  ['general', 'audit.frameworks.general.name', 'audit.frameworks.general.hint'],
]
const SCOPES: [Scope, string][] = [['selected', 'audit.scope.selected'], ['filtered', 'audit.scope.filtered'], ['all', 'common:state.all']]
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
  const { t } = useTranslation('findings')
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
    const file = t('audit.file', { name: name.replace(/[^a-z0-9-]+/gi, '-').slice(0, 40) || t('export.file_fallback'), framework })
    try { await api.downloadPost('/api/reports/audit', 'audit-report', body, file); onClose() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  const current = FRAMEWORKS.find(([id]) => id === framework)
  return <Dialog open={open} onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-h-[92vh] max-w-2xl overflow-y-auto">
    <DialogHeader><DialogTitle>{portfolio ? t('audit.title_portfolio', { name }) : t('audit.title')}</DialogTitle>
      <DialogDescription>{t('audit.description')}</DialogDescription></DialogHeader>
    <form className="space-y-5" onSubmit={submit}>
      {/* Ley de Hick: ocho marcos en un selector, con lo que aporta el elegido debajo. */}
      <div className="space-y-2"><label htmlFor="audit-framework" className={label}>{t('audit.framework')}</label>
        <Select value={framework} onValueChange={value => setFramework((value ?? 'general') as Framework)}>
          <SelectTrigger id="audit-framework" className="w-full border-app-line bg-inset">{current && t(current[1])}</SelectTrigger>
          <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{FRAMEWORKS.map(([id, text]) => <SelectItem key={id} value={id}>{t(text)}</SelectItem>)}</SelectContent>
        </Select>
        <p className="text-xs text-app-muted">{current && t(current[2])}.{framework === 'general' ? '' : ` ${t('audit.mapping_note')}`}</p></div>

      {portfolio ? <p className="rounded-lg border border-app-line bg-inset p-3 text-sm text-app-muted">{t('audit.portfolio_scope')}</p>
      : <fieldset className="space-y-2"><legend className={label}>{t('audit.findings_legend')}</legend>
        <div className="grid gap-2 sm:grid-cols-3">{SCOPES.map(([id, text]) =>
          <label key={id} className={`flex items-center gap-2 rounded-lg border p-3 text-sm ${counts[id] === 0 ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'} ${scope === id ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-inset'}`}>
            <input type="radio" name="scope" value={id} checked={scope === id} disabled={counts[id] === 0} onChange={() => setScope(id)} className="size-4 accent-brand" />{t(text)} · {counts[id]}</label>)}</div></fieldset>}

      <div className="grid gap-4 sm:grid-cols-2">
        <div className={field}><label htmlFor="ar-org" className={label}>{t('audit.organization')}</label><Input id="ar-org" maxLength={120} value={organization} onChange={event => setOrganization(event.target.value)} placeholder={t('audit.organization_placeholder')} className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-for" className={label}>{t('audit.prepared_for')}</label><Input id="ar-for" maxLength={120} value={preparedFor} onChange={event => setPreparedFor(event.target.value)} placeholder={t('audit.prepared_for_placeholder')} className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-by" className={label}>{t('audit.prepared_by')}</label><Input id="ar-by" maxLength={80} value={preparedBy} onChange={event => setPreparedBy(event.target.value)} placeholder={t('audit.prepared_by_placeholder')} className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-scope" className={label}>{t('audit.system')}</label><Input id="ar-scope" maxLength={300} value={scopeText} onChange={event => setScopeText(event.target.value)} placeholder={name} className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-from" className={label}>{t('audit.period_from')}</label><Input id="ar-from" type="date" value={from} onChange={event => setFrom(event.target.value)} className="border-app-line bg-app-soft" /></div>
        <div className={field}><label htmlFor="ar-to" className={label}>{t('audit.period_to')}</label><Input id="ar-to" type="date" value={to} min={from || undefined} onChange={event => setTo(event.target.value)} className="border-app-line bg-app-soft" /></div>
      </div>

      <details className="rounded-lg border border-app-line px-3 py-2 text-sm"><summary className="cursor-pointer text-app-muted">{t('audit.more_options')}</summary>
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          <div className={field}><label htmlFor="ar-title" className={label}>{t('audit.report_title')}</label><Input id="ar-title" maxLength={120} value={title} onChange={event => setTitle(event.target.value)} placeholder={t('audit.report_title_placeholder')} className="border-app-line bg-app-soft" /></div>
          {!portfolio && <div className={field}><label htmlFor="ar-detail" className={label}>{t('audit.detail')}</label>
            <select id="ar-detail" value={detail} onChange={event => setDetail(event.target.value as Detail)} className="h-9 w-full rounded-lg border border-app-line bg-app-soft px-2 text-sm">
              <option value="high">{t('audit.detail_high')}</option><option value="all">{t('common:state.all')}</option><option value="none">{t('audit.detail_none')}</option></select></div>}
          <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={exceptions} onChange={event => setExceptions(event.target.checked)} className="size-4 accent-brand" />{t('audit.exceptions')}</label>
        </div></details>

      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>}
      <p className="text-xs text-app-subtle">{t('audit.disclaimer')}</p>
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button>
        <Button type="submit" disabled={busy || (!portfolio && counts[scope] === 0)} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <FileCheck2 />}{busy ? t('audit.generating') : portfolio ? t('audit.generate_portfolio') : t('audit.generate', { count: counts[scope] })}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}
