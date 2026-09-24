import { useEffect, useState, type ComponentProps, type FormEvent } from 'react'
import { ExternalLink, LoaderCircle, PlugZap, Ticket } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/types'

export type JiraStatus = { configured: false } | { configured: true; site: string; email: string; project: string; project_name?: string | null; issue_type: string; last4: string; saved_at?: string; saved_by?: string }
export type TicketLink = { key: string; url: string; by?: string; linked_at?: string }
type ExportResult = { created: (TicketLink & { fingerprint: string })[]; existing: (TicketLink & { fingerprint: string })[]; failed: { fingerprint: string; error: string }[] }

export function useJiraStatus() {
  const [status, setStatus] = useState<JiraStatus | null>(null)
  useEffect(() => { api.get<JiraStatus>('/api/integrations/jira').then(setStatus).catch(() => setStatus({ configured: false })) }, [])
  return [status, setStatus] as const
}

// Tarjeta de Integraciones. Solo un administrador guarda o retira la credencial.
export function JiraCard({ canManage }: { canManage: boolean }) {
  const [status, setStatus] = useJiraStatus()
  const [form, setForm] = useState({ site: '', email: '', token: '', project: '', issue_type: 'Task' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const set = (key: keyof typeof form) => (event: { target: { value: string } }) => setForm(previous => ({ ...previous, [key]: event.target.value }))
  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    try { setStatus(await api.post<JiraStatus>('/api/integrations/jira', 'connect-jira', { action: 'save', ...form })); setForm(previous => ({ ...previous, token: '' })) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const remove = async () => {
    setBusy(true); setError('')
    try { setStatus(await api.post<JiraStatus>('/api/integrations/jira', 'connect-jira', { action: 'remove' })) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <div className="rounded-xl border border-app-line bg-inset p-5">
    <div className="flex items-start justify-between gap-3"><div className="flex items-center gap-3"><div className="rounded-xl bg-brand/10 p-2 text-brand"><Ticket className="size-5" /></div><div><h3 className="font-semibold">Jira Cloud</h3><p className="text-xs text-app-subtle">{status?.configured ? `${status.site} · proyecto ${status.project}${status.project_name ? ` (${status.project_name})` : ''}` : 'Crea incidencias desde los hallazgos'}</p></div></div>
      <Badge variant="outline" className={status?.configured ? 'border-brand/30 text-brand' : 'border-app-line text-app-muted'}>{status?.configured ? 'Conectado' : 'Sin configurar'}</Badge></div>
    {status?.configured ? <div className="mt-5 space-y-3 text-sm text-app-muted">
      <p>Cuenta {status.email} · token ····{status.last4} · tipo «{status.issue_type}»{status.saved_by ? ` · configurado por ${status.saved_by}` : ''}{status.saved_at ? ` el ${formatDate(status.saved_at)}` : ''}</p>
      <p className="text-xs leading-5 text-app-subtle">Cada incidencia lleva la etiqueta <code className="font-mono">appsec-&lt;huella&gt;</code>: volver a exportar el mismo hallazgo enlaza la existente en lugar de duplicarla.</p>
      {canManage && <Button variant="ghost" disabled={busy} onClick={() => void remove()}>Retirar conexión</Button>}
    </div> : canManage ? <form className="mt-5 grid gap-3 sm:grid-cols-2" onSubmit={save}>
      <Field id="jira-site" label="Sitio" placeholder="https://tu-sitio.atlassian.net" value={form.site} onChange={set('site')} />
      <Field id="jira-email" label="Email de la cuenta" type="email" autoComplete="username" value={form.email} onChange={set('email')} />
      <Field id="jira-token" label="API token" type="password" autoComplete="new-password" minLength={16} value={form.token} onChange={set('token')} />
      <div className="grid grid-cols-2 gap-3"><Field id="jira-project" label="Proyecto" placeholder="SEC" maxLength={10} value={form.project} onChange={set('project')} /><Field id="jira-type" label="Tipo" value={form.issue_type} onChange={set('issue_type')} /></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger sm:col-span-2">{error}</div>}
      <div className="flex flex-wrap items-center gap-3 sm:col-span-2"><Button type="submit" disabled={busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <PlugZap />}Guardar y validar</Button>
        <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand hover:underline">Crear un API token <ExternalLink className="size-3" /></a></div>
      <p className="text-xs leading-5 text-app-subtle sm:col-span-2">Se comprueba la cuenta, el proyecto y el tipo de incidencia antes de guardar. El token se queda en el servidor y nunca vuelve al navegador.</p>
    </form> : <p className="mt-5 text-sm text-app-muted">Un administrador puede conectarlo.</p>}
  </div>
}

function Field({ id, label, ...props }: { id: string; label: string } & ComponentProps<typeof Input>) {
  return <div className="space-y-1.5"><label htmlFor={id} className="text-xs text-app-muted">{label}</label><Input id={id} required {...props} className="border-app-line bg-app-soft" /></div>
}

// Resultado de una exportación: qué se creó, qué ya existía y qué falló, con enlace a cada incidencia.
export function JiraExportDialog({ runId, fingerprints, onClose, onDone }: { runId: string; fingerprints: string[] | null; onClose: () => void; onDone: () => void }) {
  const [result, setResult] = useState<ExportResult | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (!fingerprints) return null
  const run = async () => {
    setBusy(true); setError('')
    try { setResult(await api.post<ExportResult>('/api/integrations/jira/issues', 'export-jira', { run_id: runId, fingerprints })); onDone() }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  // Varios hallazgos de un paquete comparten incidencia: se cuenta y se lista cada incidencia una vez.
  const byKey = new Map<string, TicketLink & { state: string; findings: number }>()
  for (const [items, state] of [[result?.created ?? [], 'Creada'], [result?.existing ?? [], 'Ya existía']] as const)
    for (const item of items) { const entry = byKey.get(item.key); if (entry) entry.findings++; else byKey.set(item.key, { ...item, state, findings: 1 }) }
  const links = [...byKey.values()]
  const createdIssues = links.filter(item => item.state === 'Creada').length
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>Crear en Jira · {fingerprints.length} {fingerprints.length === 1 ? 'hallazgo' : 'hallazgos'}</DialogTitle><DialogDescription>{result ? `${createdIssues} ${createdIssues === 1 ? 'incidencia creada' : 'incidencias creadas'}, ${links.length - createdIssues} ya existían${result.failed.length ? `, ${result.failed.length} hallazgos con error` : ''} · ${result.created.length + result.existing.length} hallazgos enlazados.` : 'Una incidencia por trabajo: los avisos de un mismo paquete van juntos con la versión que los cierra todos; el código y los secretos, uno a uno. Lo que ya tenga incidencia se enlaza, no se duplica.'}</DialogDescription></DialogHeader>
    {links.length > 0 && <ul className="max-h-60 space-y-1 overflow-y-auto text-sm">{links.map(item => <li key={item.key} className="flex items-center justify-between gap-2"><a href={item.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-mono text-brand hover:underline">{item.key}<ExternalLink className="size-3" /></a><span className="text-xs text-app-subtle">{item.state}{item.findings > 1 ? ` · ${item.findings} hallazgos` : ''}</span></li>)}</ul>}
    {result?.failed.length ? <ul className="space-y-1 text-xs text-danger">{result.failed.slice(0, 5).map(item => <li key={item.fingerprint}>{item.fingerprint.slice(0, 12)} · {item.error}</li>)}</ul> : null}
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
    <DialogFooter>{result ? <Button onClick={onClose} className="bg-primary text-primary-foreground hover:bg-primary/90">Hecho</Button> : <><Button variant="ghost" onClick={onClose}>Cancelar</Button><Button disabled={busy} onClick={() => void run()} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <Ticket />}Crear incidencias</Button></>}</DialogFooter>
  </DialogContent></Dialog>
}
