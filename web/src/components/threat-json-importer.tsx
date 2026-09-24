import { useRef, useState, type ChangeEvent } from 'react'
import { ArrowDownToLine, ArrowUpFromLine, CheckCircle2, ClipboardCopy, Code2, FileJson2, LoaderCircle, Sparkles } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { api } from '@/lib/api'
import { GUIDES, METHOD_ORDER, type Methodology } from '@/components/threat-guides'
import type { View } from '@/components/threat-model-types'
import stride from '@/examples/threat-models/stride.json'
import linddun from '@/examples/threat-models/linddun.json'
import pasta from '@/examples/threat-models/pasta.json'
import attackTrees from '@/examples/threat-models/attack_trees.json'
import attack from '@/examples/threat-models/attack.json'
import custom from '@/examples/threat-models/custom.json'

const MAX_BYTES = 600_000
const EXAMPLES: Record<Methodology, unknown> = { stride, linddun, pasta, attack_trees: attackTrees, attack, custom }
const EXAMPLE_HINTS: Record<Methodology, string> = {
  stride: 'Diagrama y amenaza de acceso indebido',
  linddun: 'Datos personales y privacidad',
  pasta: 'Etapas de riesgo y ruta de ataque',
  attack_trees: 'Objetivo y alternativas Y/O',
  attack: 'Técnicas mapeadas a componentes',
  custom: 'Todos los módulos combinados',
}

type Preview = {
  name: string; methodology: Methodology; components: number; flows: number; boundaries: number
  repository_refs: number; manual_threats: number; attack_trees: number; attack_mappings: number; pasta_stages: number; relayout?: boolean
}

const formatted = (document: unknown) => `${JSON.stringify(document, null, 2)}\n`

export function ThreatJsonImporter({ onClose, onImported }: { onClose: () => void; onImported: (id: string) => void }) {
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
    if (file.size > MAX_BYTES) { setError('El archivo supera el máximo de 600 KB.'); return }
    setSelected(null)
    changeText(await file.text())
    setNotice(`Archivo cargado: ${file.name}. Valídalo antes de importarlo.`)
  }
  const parseDocument = () => {
    if (!text.trim()) throw new Error('Pega un JSON o elige un ejemplo para empezar.')
    if (new Blob([text]).size > MAX_BYTES) throw new Error('El JSON supera el máximo de 600 KB.')
    try { return JSON.parse(text) as unknown }
    catch { throw new Error('El contenido no es JSON válido. Revisa comas, comillas y llaves.') }
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
    link.href = url; link.download = `modelo-amenazas-${selected ?? 'personalizado'}.json`
    document.body.append(link); link.click(); link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
  }
  const copy = async (value: string, message: string) => {
    try { await navigator.clipboard.writeText(value); setNotice(message); setError('') }
    catch { setError('No se pudo copiar al portapapeles. Selecciona el texto del editor y cópialo manualmente.') }
  }
  const prompt = `Genera únicamente un objeto JSON válido para importar un modelo de amenazas en Tamandua. Usa este ejemplo como contrato y adapta nombres, componentes, flujos, fronteras y contenido al sistema que te describa. Mantén format="appsec-agent-threat-model", version=1 y la metodología indicada. Los id deben ser únicos y usar minúsculas, números y guiones; source y target deben referirse a componentes existentes; cada frontera solo puede contener componentes existentes. No incluyas IDs de la instalación ni evidencia de escaneos. Si mencionas repositorios o dominios, usa repository_refs o asset_ref: quedarán pendientes de vincular. No añadas secciones de otra metodología; para combinarlas usa methodology="custom" y activa sus custom_modules. No incluyas position, size ni box: Tamandua coloca el diagrama solo según las fronteras y los flujos. Kinds disponibles: actor, web_app, api, service, function, database, cache, queue, storage, external, identity; para cualquier otro usa kind="custom" con custom_kind (su nombre) y custom_base (uno de los anteriores, el rol con el que se analiza). Devuelve solo JSON, sin Markdown.\n\nEjemplo:\n${text}`

  return <Dialog open onOpenChange={next => { if (!next && !busy) onClose() }}>
    <DialogContent className="max-h-[94vh] max-w-6xl gap-4 overflow-y-auto p-4 sm:p-6">
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2"><FileJson2 className="size-5 text-brand" />Crear modelo desde JSON</DialogTitle>
        <DialogDescription>Elige un ejemplo, modifícalo aquí o carga un archivo. Valida el contenido antes de crear el modelo.</DialogDescription>
      </DialogHeader>
      <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
        <section aria-label="Ejemplos de metodologías" className="space-y-3">
          <div><h3 className="text-sm font-semibold">1 · Elige un ejemplo</h3><p className="mt-1 text-xs leading-5 text-app-muted">Cada ejemplo es importable y muestra los campos propios de su enfoque.</p></div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-1">{METHOD_ORDER.map(method => <button key={method} type="button" aria-pressed={selected === method} onClick={() => chooseExample(method)} className={`rounded-xl border px-3 py-2.5 text-left transition focus-visible:outline-2 focus-visible:outline-brand ${selected === method ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-app-soft hover:border-brand/40'}`}>
            <span className="block text-sm font-medium">{GUIDES[method].name}</span><span className="mt-0.5 block text-[11px] leading-4 text-app-muted">{EXAMPLE_HINTS[method]}</span>
          </button>)}</div>
          <div className="rounded-xl border border-app-line bg-inset p-3 text-xs leading-5 text-app-muted">
            <p className="font-semibold text-app-fg">Cómo usarlo</p>
            <p>Los componentes usan <code>id</code> únicos; los flujos enlazan <code>source</code> y <code>target</code> con esos ID. En personalizado, <code>custom_modules</code> decide qué secciones puedes incluir.</p>
            <p className="mt-2">Las referencias a repositorios o dominios se importan sin vincularse automáticamente.</p>
          </div>
        </section>
        <section aria-label="Editor e importación de JSON" className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2"><div><h3 className="text-sm font-semibold">2 · Edita o pega tu JSON</h3><p className="text-xs text-app-muted">También puedes pedir a una IA que adapte el ejemplo a tu sistema.</p></div>
            <input ref={fileInput} type="file" accept=".json,application/json" className="hidden" aria-label="Archivo JSON del modelo" onChange={event => void loadFile(event)} />
            <Button size="sm" variant="outline" onClick={() => fileInput.current?.click()}><ArrowUpFromLine />Cargar archivo</Button>
          </div>
          <textarea aria-label="Editor JSON del modelo" spellCheck={false} value={text} onChange={event => changeText(event.target.value)} className="h-64 w-full resize-y rounded-xl border border-app-line bg-inset p-3 font-mono text-[11px] leading-[1.55] text-app-fg outline-none focus:border-brand sm:h-80 lg:h-[390px]" />
          <div className="flex flex-wrap items-center gap-2"><Button size="sm" variant="outline" onClick={() => void copy(text, 'JSON copiado.') }><ClipboardCopy />Copiar JSON</Button><Button size="sm" variant="outline" onClick={downloadExample}><ArrowDownToLine />Descargar JSON</Button><Button size="sm" variant="outline" onClick={() => void copy(prompt, 'Instrucciones para IA copiadas.')}><Sparkles />Copiar prompt para IA</Button><span className="ml-auto text-[11px] text-app-subtle">{new Blob([text]).size.toLocaleString('es-CO')} / 600.000 bytes</span></div>
          {notice && <p role="status" className="text-xs text-brand">{notice}</p>}
          {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
          {preview && validatedText === text && <div role="status" className="rounded-xl border border-success-line bg-success-soft p-3 text-xs leading-5"><p className="flex items-center gap-2 font-semibold text-success"><CheckCircle2 className="size-4" />JSON válido · {preview.name}</p><p className="mt-1 text-app-muted">{GUIDES[preview.methodology].name} · {preview.components} componentes · {preview.flows} flujos · {preview.boundaries} fronteras · {preview.manual_threats} amenazas propias · {preview.attack_trees} árboles · {preview.attack_mappings} técnicas · {preview.pasta_stages} etapas PASTA{preview.repository_refs ? ` · ${preview.repository_refs} referencias pendientes` : ''}</p>{preview.relayout && <p className="mt-1 text-app-muted">Las posiciones del JSON no encajaban con sus fronteras (cajas pequeñas o solapadas): el diagrama se colocará solo al importarlo. Puedes moverlo después.</p>}</div>}
        </section>
      </div>
      <DialogFooter className="border-t border-app-line pt-4"><Button variant="ghost" disabled={!!busy} onClick={onClose}>Cancelar</Button><Button variant="outline" disabled={!!busy} onClick={() => void validate()}>{busy === 'validate' ? <LoaderCircle className="animate-spin" /> : <Code2 />}3 · Validar JSON</Button><Button disabled={!!busy || !preview || validatedText !== text} onClick={() => void importModel()}>{busy === 'import' ? <LoaderCircle className="animate-spin" /> : <ArrowUpFromLine />}4 · Importar modelo</Button></DialogFooter>
    </DialogContent>
  </Dialog>
}
