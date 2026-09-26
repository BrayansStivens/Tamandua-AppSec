import { useRef, useState, type ChangeEvent } from 'react'
import { ArrowDownToLine, ArrowUpFromLine, CheckCircle2, ClipboardCopy, Code2, FileJson2, LoaderCircle, Sparkles } from 'lucide-react'
import { Trans, useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { api } from '@/shared/api/http'
import { formatNumber } from '@/shared/i18n/format'
import { methodName, METHOD_ORDER, type Methodology } from '@/features/threats/threat-guides'
import type { View } from '@/features/threats/threat-model-types'
import stride from '@/examples/threat-models/stride.json'
import linddun from '@/examples/threat-models/linddun.json'
import pasta from '@/examples/threat-models/pasta.json'
import attackTrees from '@/examples/threat-models/attack_trees.json'
import attack from '@/examples/threat-models/attack.json'
import custom from '@/examples/threat-models/custom.json'

const MAX_BYTES = 600_000
const EXAMPLES: Record<Methodology, unknown> = { stride, linddun, pasta, attack_trees: attackTrees, attack, custom }
const EXAMPLE_HINTS: Record<Methodology, string> = {
  stride: 'importer.hints.stride', linddun: 'importer.hints.linddun', pasta: 'importer.hints.pasta',
  attack_trees: 'importer.hints.attack_trees', attack: 'importer.hints.attack', custom: 'importer.hints.custom',
}

type Preview = {
  name: string; methodology: Methodology; components: number; flows: number; boundaries: number
  repository_refs: number; manual_threats: number; attack_trees: number; attack_mappings: number; pasta_stages: number; relayout?: boolean
}

const formatted = (document: unknown) => `${JSON.stringify(document, null, 2)}\n`

export function ThreatJsonImporter({ onClose, onImported }: { onClose: () => void; onImported: (id: string) => void }) {
  const { t } = useTranslation('threats')
  const [selected, setSelected] = useState<Methodology | null>('stride')
  const [text, setText] = useState(() => formatted(EXAMPLES.stride))
  const [preview, setPreview] = useState<Preview | null>(null)
  const [validatedText, setValidatedText] = useState('')
  const [validatedDocument, setValidatedDocument] = useState<unknown>(null)
  const [busy, setBusy] = useState<'validate' | 'import' | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const fileInput = useRef<HTMLInputElement>(null)

  const changeText = (value: string) => {
    setText(value); setPreview(null); setValidatedText(''); setValidatedDocument(null); setError(''); setNotice('')
  }
  const chooseExample = (method: Methodology) => {
    setSelected(method)
    changeText(formatted(EXAMPLES[method]))
  }
  const loadFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (file.size > MAX_BYTES) { setError(t('importer.file_too_large')); return }
    setSelected(null)
    changeText(await file.text())
    setNotice(t('importer.file_loaded', { name: file.name }))
  }
  const parseDocument = () => {
    if (!text.trim()) throw new Error(t('importer.empty'))
    if (new Blob([text]).size > MAX_BYTES) throw new Error(t('importer.json_too_large'))
    try { return JSON.parse(text) as unknown }
    catch { throw new Error(t('importer.invalid_json')) }
  }
  const validate = async () => {
    setError(''); setNotice(''); setPreview(null); setValidatedText('')
    try {
      const document = parseDocument()
      setBusy('validate')
      const result = await api.post<Preview>('/api/threat-models/validate', 'validate-threat-model', document)
      setPreview(result); setValidatedText(text); setValidatedDocument(document)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(null) }
  }
  const importModel = async () => {
    if (!preview || validatedText !== text || validatedDocument === null) return
    setBusy('import'); setError('')
    try {
      const imported = await api.post<View>('/api/threat-models/import', 'import-threat-model', validatedDocument)
      onImported(imported.model.id)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(null) }
  }
  const downloadExample = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url; link.download = t('importer.file_name', { method: selected ?? t('importer.file_edited') })
    document.body.append(link); link.click(); link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
  }
  const copy = async (value: string, message: string) => {
    try { await navigator.clipboard.writeText(value); setNotice(message); setError('') }
    catch { setError(t('importer.copy_failed')) }
  }
  const prompt = t('importer.ai_prompt', { example: text })

  return <Dialog open onOpenChange={next => { if (!next && !busy) onClose() }}>
    <DialogContent className="max-h-[94vh] max-w-6xl gap-4 overflow-y-auto p-4 sm:p-6">
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2"><FileJson2 className="size-5 text-brand" />{t('importer.title')}</DialogTitle>
        <DialogDescription>{t('importer.description')}</DialogDescription>
      </DialogHeader>
      <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
        <section aria-label={t('importer.examples_label')} className="space-y-3">
          <div><h3 className="text-sm font-semibold">{t('importer.step_example')}</h3><p className="mt-1 text-xs leading-5 text-app-muted">{t('importer.step_example_hint')}</p></div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-1">{METHOD_ORDER.map(method => <button key={method} type="button" aria-pressed={selected === method} onClick={() => chooseExample(method)} className={`rounded-xl border px-3 py-2.5 text-left transition focus-visible:outline-2 focus-visible:outline-brand ${selected === method ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-app-soft hover:border-brand/40'}`}>
            <span className="block text-sm font-medium">{methodName(method)}</span><span className="mt-0.5 block text-[11px] leading-4 text-app-muted">{t(EXAMPLE_HINTS[method])}</span>
          </button>)}</div>
          <div className="rounded-xl border border-app-line bg-inset p-3 text-xs leading-5 text-app-muted">
            <p className="font-semibold text-app-fg">{t('importer.how_title')}</p>
            <p><Trans t={t} i18nKey="importer.how_ids" components={{ code: <code /> }} /></p>
            <p className="mt-2">{t('importer.how_refs')}</p>
          </div>
        </section>
        <section aria-label={t('importer.editor_label')} className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2"><div><h3 className="text-sm font-semibold">{t('importer.step_edit')}</h3><p className="text-xs text-app-muted">{t('importer.step_edit_hint')}</p></div>
            <input ref={fileInput} type="file" accept=".json,application/json" className="hidden" aria-label={t('importer.file_label')} onChange={event => void loadFile(event)} />
            <Button size="sm" variant="outline" onClick={() => fileInput.current?.click()}><ArrowUpFromLine />{t('importer.load_file')}</Button>
          </div>
          <textarea aria-label={t('importer.editor')} spellCheck={false} value={text} onChange={event => changeText(event.target.value)} className="h-64 w-full resize-y rounded-xl border border-app-line bg-inset p-3 font-mono text-[11px] leading-[1.55] text-app-fg outline-none focus:border-brand sm:h-80 lg:h-[390px]" />
          <div className="flex flex-wrap items-center gap-2"><Button size="sm" variant="outline" onClick={() => void copy(text, t('importer.json_copied')) }><ClipboardCopy />{t('importer.copy_json')}</Button><Button size="sm" variant="outline" onClick={downloadExample}><ArrowDownToLine />{t('importer.download_json')}</Button><Button size="sm" variant="outline" onClick={() => void copy(prompt, t('importer.prompt_copied'))}><Sparkles />{t('importer.copy_prompt')}</Button><span className="ml-auto text-[11px] text-app-subtle">{t('importer.size', { size: formatNumber(new Blob([text]).size), max: formatNumber(MAX_BYTES) })}</span></div>
          {notice && <p role="status" className="text-xs text-brand">{notice}</p>}
          {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
          {preview && validatedText === text && <div role="status" className="rounded-xl border border-success-line bg-success-soft p-3 text-xs leading-5"><p className="flex items-center gap-2 font-semibold text-success"><CheckCircle2 className="size-4" />{t('importer.valid', { name: preview.name })}</p><p className="mt-1 text-app-muted">{[methodName(preview.methodology), t('count.components', { count: preview.components }), t('count.flows', { count: preview.flows }), t('count.boundaries', { count: preview.boundaries }), t('count.manual_threats', { count: preview.manual_threats }), t('count.trees', { count: preview.attack_trees }), t('count.techniques', { count: preview.attack_mappings }), t('count.pasta_stages', { count: preview.pasta_stages }), ...(preview.repository_refs ? [t('count.pending_refs', { count: preview.repository_refs })] : [])].join(' · ')}</p>{preview.relayout && <p className="mt-1 text-app-muted">{t('importer.relayout')}</p>}</div>}
        </section>
      </div>
      <DialogFooter className="border-t border-app-line pt-4"><Button variant="ghost" disabled={!!busy} onClick={onClose}>{t('common:actions.cancel')}</Button><Button variant="outline" disabled={!!busy} onClick={() => void validate()}>{busy === 'validate' ? <LoaderCircle className="animate-spin" /> : <Code2 />}{t('importer.validate')}</Button><Button disabled={!!busy || !preview || validatedText !== text} onClick={() => void importModel()}>{busy === 'import' ? <LoaderCircle className="animate-spin" /> : <ArrowUpFromLine />}{t('importer.import')}</Button></DialogFooter>
    </DialogContent>
  </Dialog>
}
