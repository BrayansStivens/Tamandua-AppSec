import { useId, useState } from 'react'
import { Check, Copy, LoaderCircle, RefreshCw } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { api } from '@/shared/api/http'

// Cómo corregir un hallazgo (appsec_agent/fix_guide.py) y reverificarlo (verifications.py): cierra el ciclo
// encontrar → corregir → verificar sin buscar el hallazgo a mano en un análisis nuevo.
export type FixGuide = { kind: 'dependency' | 'code' | 'secret' | 'config'; steps: string[]; commands: { label: string; code: string }[]
  example: { language: string; before: string; after: string; note?: string } | null }
export type Verification = { run_id: string; by: string; at: string; state: 'running' | 'fixed' | 'present' | 'inconclusive' | 'failed'; finished_at?: string | null }

const when = (value?: string | null) => value ? ` del ${new Date(value).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' })}` : ''

export function CodeBlock({ code, label }: { code: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const copy = (event: React.MouseEvent<HTMLButtonElement>) => {
    const block = event.currentTarget.parentElement?.querySelector('code')
    navigator.clipboard.writeText(code).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500) })
      .catch(() => { if (block) window.getSelection()?.selectAllChildren(block) })  // sin portapapeles: queda seleccionado
  }
  return <div className="flex items-start gap-2">
    <pre className="min-w-0 flex-1 rounded-lg border border-app-line bg-inset p-3 text-xs leading-5 whitespace-pre-wrap wrap-anywhere"><code className="font-mono text-app-secondary">{code}</code></pre>
    <button type="button" onClick={copy} aria-label={`Copiar: ${label}`} title="Copiar"
      className="mt-1.5 grid size-7 shrink-0 place-items-center rounded-md border border-app-line bg-panel text-app-muted hover:text-app-fg">
      {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}</button>
    <span role="status" className="sr-only">{copied ? 'Copiado' : ''}</span>
  </div>
}

export function FixSection({ fix, remediation }: { fix?: FixGuide | null; remediation: string }) {
  const heading = useId()
  if (!fix) return <div className="mt-3 rounded-lg border border-brand/20 bg-brand/[0.06] p-3 text-sm"><span className="font-medium text-brand">Remediación · </span>{remediation}</div>
  const steps = fix.steps.filter(Boolean)
  const example = fix.example && <div className={`grid gap-2 ${fix.example.before ? 'lg:grid-cols-2' : ''}`}>
    {fix.example.before && <div className="min-w-0 space-y-1"><p className="text-xs text-danger">Antes</p><CodeBlock code={fix.example.before} label="ejemplo vulnerable" /></div>}
    <div className="min-w-0 space-y-1"><p className="text-xs text-success">{fix.example.before ? 'Después' : 'Así'}</p><CodeBlock code={fix.example.after} label="ejemplo corregido" /></div>
  </div>
  const commands = fix.commands.map(command => <div key={command.code} className="space-y-1"><p className="text-xs text-app-muted">{command.label}</p><CodeBlock code={command.code} label={command.label} /></div>)
  // En una dependencia, el ejemplo es la edición (override, pom, Dockerfile): va antes del comando que la aplica.
  const editFirst = fix.kind === 'dependency' && !!fix.example && !fix.example.before
  return <section aria-labelledby={heading} className="mt-3 space-y-3 rounded-lg border border-brand/20 bg-brand/[0.04] p-3">
    <h3 id={heading} className="text-sm font-medium text-brand">Cómo corregirlo</h3>
    {steps.length > 0 && <ol className="list-decimal space-y-1 pl-5 text-sm text-app-secondary">{steps.map(step => <li key={step}>{step}</li>)}</ol>}
    {editFirst ? <>{example}{commands}</> : <>{commands}{example}</>}
    {fix.example?.note && <p className="text-xs text-app-muted">{fix.example.note}</p>}
    {fix.kind === 'code' && fix.example && <p className="text-xs text-app-subtle">El ejemplo muestra el patrón y su corrección; adáptalo a tu código.</p>}
  </section>
}

// Estado de la verificación y el botón. El refresco mientras corre lo hace la vista (uno para todos los hallazgos).
export function Reverify({ runId, fingerprint, verification, blocked, canVerify, onChanged }: { runId: string; fingerprint: string; verification?: Verification | null
  blocked?: string | null; canVerify: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const state = verification?.state
  const running = state === 'running'
  const start = async () => {
    if (busy || running) return
    setBusy(true); setError('')
    try { await api.post('/api/findings/reverify', 'reverify-finding', { run_id: runId, fingerprint }); onChanged() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <div className="mt-3 space-y-1 rounded-lg border border-app-line bg-inset p-3">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <p role="status" className="min-w-0 text-xs text-app-muted">
        {blocked ? blocked
          : running ? <span className="inline-flex items-center gap-1.5"><LoaderCircle className="size-3.5 motion-safe:animate-spin" />Verificando: el análisis está en cola o en curso…</span>
          : state === 'fixed' ? <span className="font-medium text-success">Corregido ✓ · ya no aparece en el análisis{when(verification?.finished_at)}</span>
          : state === 'present' ? <span className="font-medium text-attention">Sigue presente en el análisis{when(verification?.finished_at)}</span>
          : state === 'inconclusive' ? 'El análisis quedó incompleto (algún motor no corrió): no demuestra nada. Vuelve a intentarlo.'
          : state === 'failed' ? 'El análisis de verificación falló. Vuelve a intentarlo.'
          : '¿Ya lo corregiste? Reverifica: se vuelve a analizar el repositorio o la imagen y te decimos si sigue ahí.'}
      </p>
      {/* aria-disabled en vez de disabled: el foco de teclado se queda en el botón mientras se verifica. */}
      {!blocked && canVerify && <Button size="sm" variant="outline" aria-disabled={busy || running} onClick={() => void start()} className="border-app-line bg-panel aria-disabled:opacity-60">
        {busy ? <LoaderCircle className="motion-safe:animate-spin" /> : <RefreshCw />}{state && !running ? 'Volver a verificar' : 'Reverificar'}</Button>}
    </div>
    {error && <p role="alert" className="text-xs text-danger">{error}</p>}
  </div>
}
