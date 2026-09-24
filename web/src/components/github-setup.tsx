import { useRef, useState, type FormEvent } from 'react'
import { Check, CircleCheck, Copy, ExternalLink, FileKey2, LoaderCircle, RefreshCw, ShieldCheck, TriangleAlert, Upload } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api } from '@/lib/api'
import { BRAND } from '@/lib/brand'

export type PermissionReview = { required: Record<string, string>; declared: Record<string, string>; granted: Record<string, string>; excess: string[]; missing: string[]; pending_acceptance: string[] }
export type GitHubStatus = {
  configured: boolean; missing: string[]; connected: boolean; app_id: string; slug: string; owner: string | null; name: string | null; html_url: string | null
  source: 'entorno' | 'almacén cifrado' | null; public_url: string; permissions?: PermissionReview | null; required_permissions: Record<string, string>
  installation: GitHubInstallation | null; installations: GitHubInstallation[]
  available_installations?: { installation_id: number; account: string | null; account_type: string | null; repository_selection: string | null; connected: boolean }[]
}

export type GitHubInstallation = { installation_id: number; account: string | null; account_type: string | null; repository_selection: 'all' | 'selected' | null; permissions: Record<string, string>; connected_by: string | null; connected_at: string; permission_review?: PermissionReview }

const PERMISSION_LABEL: Record<string, string> = { contents: 'Contents', metadata: 'Metadata', pull_requests: 'Pull requests', statuses: 'Commit statuses' }
const LEVEL_LABEL: Record<string, string> = { read: 'Read-only', write: 'Read and write' }

function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return <span className="inline-flex max-w-full items-center gap-1 rounded-md border border-app-line bg-app-soft py-0.5 pr-0.5 pl-2 align-middle">
    <code className="truncate font-mono text-[11px]">{value}</code>
    <button type="button" aria-label={`Copiar ${value}`} onClick={() => { void navigator.clipboard.writeText(value).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1200) }) }}
      className="rounded p-1 text-app-subtle hover:bg-accent hover:text-app-fg">{copied ? <Check className="size-3" /> : <Copy className="size-3" />}</button>
  </span>
}

function Step({ number, title, children }: { number: number; title: string; children: React.ReactNode }) {
  return <li className="relative flex gap-3 pb-5 last:pb-0">
    <span className="grid size-6 shrink-0 place-items-center rounded-full border border-app-line bg-app-soft font-mono text-[11px] text-app-secondary">{number}</span>
    <div className="min-w-0 flex-1 space-y-1.5 pt-0.5"><p className="text-sm font-medium">{title}</p><div className="space-y-1.5 text-xs leading-5 text-app-muted">{children}</div></div>
  </li>
}

// Guía para crear la GitHub App a mano en GitHub y formulario para conectarla aquí.
export function GitHubAppGuide({ status, canManage, onSaved }: { status: GitHubStatus; canManage: boolean; onSaved: (next: GitHubStatus) => void }) {
  const [org, setOrg] = useState('')
  const [appId, setAppId] = useState('')
  const [pem, setPem] = useState('')
  const [pemName, setPemName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const file = useRef<HTMLInputElement>(null)
  const base = status.public_url.replace(/\/$/, '')
  const createUrl = org.trim() ? `https://github.com/organizations/${encodeURIComponent(org.trim())}/settings/apps/new` : 'https://github.com/settings/apps/new'

  const readFile = async (selected: File | undefined) => {
    setError('')
    if (!selected) return
    if (selected.size > 16000) { setError('Ese fichero es demasiado grande para ser una clave .pem'); return }
    const text = await selected.text()
    if (!text.includes('PRIVATE KEY')) { setError('Ese fichero no parece una clave privada (.pem) de GitHub App'); return }
    setPem(text); setPemName(selected.name)
  }
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    try {
      const next = await api.post<GitHubStatus>('/api/integrations/github/app', 'save-github-app', { app_id: appId.trim(), private_key: pem })
      // La clave ya está cifrada en el servidor: aquí no se conserva.
      setPem(''); setPemName(''); if (file.current) file.current.value = ''
      onSaved(next)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  return <div className="mt-4 grid gap-6 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
    <ol className="rounded-xl border border-app-line bg-panel p-4">
      <Step number={1} title="Abre el formulario de nueva GitHub App">
        <p>En tu cuenta personal o en una organización que administres (escribe su nombre):</p>
        <div className="flex flex-wrap items-center gap-2"><Input aria-label="Organización (opcional)" value={org} onChange={event => setOrg(event.target.value.replace(/[^A-Za-z0-9-]/g, ''))} maxLength={39} placeholder="organización (opcional)" className="h-8 w-48 border-app-line bg-app-soft text-xs" />
          <a href={createUrl} target="_blank" rel="noopener noreferrer"><Button type="button" size="sm" variant="outline" className="border-app-line bg-app-soft">Abrir en GitHub <ExternalLink /></Button></a></div>
      </Step>
      <Step number={2} title="Nombre y página de inicio">
        <p><strong className="font-medium text-app-secondary">GitHub App name:</strong> el que quieras, p. ej. <CopyValue value={`${BRAND.name} de mi equipo`} /> (debe ser único en GitHub; añade tu equipo si ya existe).</p>
        <p><strong className="font-medium text-app-secondary">Homepage URL:</strong> cualquier URL tuya, p. ej. <CopyValue value={base.startsWith('https://') ? base : `https://github.com/${org.trim() || 'tu-usuario'}`} /></p>
      </Step>
      <Step number={3} title="Sin OAuth ni webhooks">
        <p>Deja <strong className="font-medium text-app-secondary">Callback URL</strong> vacío y <strong className="font-medium text-app-secondary">sin marcar</strong> «Request user authorization (OAuth) during installation».</p>
        <p><strong className="font-medium text-app-secondary">Setup URL</strong> (opcional, te devuelve aquí al instalar): <CopyValue value={`${base}/oauth/callback`} /> y marca «Redirect on update».</p>
        <p>En <strong className="font-medium text-app-secondary">Webhook</strong>, desmarca «Active»: el panel consulta los PRs por su cuenta, así no necesita estar publicado en internet.</p>
      </Step>
      <Step number={4} title="Permisos: solo estos cuatro">
        <p>En <em>Repository permissions</em>:</p>
        <ul className="space-y-1">{Object.entries(status.required_permissions).map(([name, level]) => <li key={name} className="flex items-center justify-between gap-3 rounded-md border border-app-line px-2.5 py-1"><span className="text-app-secondary">{PERMISSION_LABEL[name] ?? name}</span><span className="font-mono text-[11px]">{LEVEL_LABEL[level] ?? level}</span></li>)}</ul>
        <p>Nada en <em>Organization</em> ni <em>Account permissions</em>, y ningún evento. Cuanto menos permiso, menos daño si la clave se filtrara.</p>
      </Step>
      <Step number={5} title="Cuentas donde se puede instalar">
        <p>En «Where can this GitHub App be installed?» elige <strong className="font-medium text-app-secondary">Any account</strong> si vas a conectar varias organizaciones. Después pulsa <strong className="font-medium text-app-secondary">Create GitHub App</strong>.</p>
      </Step>
      <Step number={6} title="Copia el App ID y genera la clave privada">
        <p>El <strong className="font-medium text-app-secondary">App ID</strong> aparece arriba, en «About». Baja hasta <strong className="font-medium text-app-secondary">Private keys</strong> y pulsa «Generate a private key»: se descarga un fichero <code className="font-mono">.pem</code>.</p>
      </Step>
    </ol>

    <form onSubmit={submit} className="space-y-4 self-start rounded-xl border border-app-line bg-panel p-4">
      <div><p className="text-sm font-medium">7 · Conéctala aquí</p><p className="mt-1 text-xs leading-5 text-app-muted">El panel comprueba con GitHub que la clave es de esa App antes de guardar nada.</p></div>
      {!canManage && <p className="rounded-lg border border-app-line bg-app-soft px-3 py-2 text-xs text-app-muted">Solo un administrador puede conectar la GitHub App.</p>}
      {status.source === 'entorno' && <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-900 dark:text-amber-100">El servidor tiene <code className="font-mono">GITHUB_APP_ID</code> en su entorno, pero le falta: {status.missing.join(', ')}.</p>}
      <div className="space-y-1.5"><label htmlFor="github-app-id" className="text-xs text-app-muted">App ID</label>
        <Input id="github-app-id" required inputMode="numeric" pattern="[1-9][0-9]{0,11}" maxLength={12} disabled={!canManage} value={appId} onChange={event => setAppId(event.target.value.replace(/\D/g, ''))} placeholder="123456" className="border-app-line bg-app-soft font-mono" /></div>
      <div className="space-y-1.5"><span className="text-xs text-app-muted">Clave privada (.pem)</span>
        <input ref={file} type="file" accept=".pem,application/x-pem-file,application/x-x509-ca-cert" className="sr-only" id="github-app-pem" disabled={!canManage} onChange={event => void readFile(event.target.files?.[0])} />
        <label htmlFor="github-app-pem" className={`flex cursor-pointer items-center gap-3 rounded-lg border border-dashed px-3 py-3 text-sm ${pem ? 'border-app-line bg-app-soft' : 'border-app-faint/50 hover:bg-app-soft'}`}>
          {pem ? <FileKey2 className="size-4 shrink-0 text-app-secondary" /> : <Upload className="size-4 shrink-0 text-app-subtle" />}
          <span className="min-w-0 truncate">{pem ? pemName || 'Clave cargada' : 'Elige el fichero .pem descargado'}</span>
        </label>
        <details className="text-xs"><summary className="cursor-pointer text-app-subtle">o pégala como texto</summary>
          <textarea aria-label="Clave privada en texto" rows={4} spellCheck={false} autoComplete="off" disabled={!canManage} value={pemName ? '' : pem} onChange={event => { setPem(event.target.value); setPemName('') }}
            placeholder="-----BEGIN RSA PRIVATE KEY-----" className="mt-2 w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 font-mono text-[11px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50" /></details>
      </div>
      {error && <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-200">{error}</div>}
      <Button type="submit" disabled={!canManage || busy || !appId || !pem} className="w-full bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}Verificar y guardar</Button>
      <p className="flex items-start gap-2 text-[11px] leading-4 text-app-subtle"><ShieldCheck className="mt-0.5 size-3 shrink-0" />La clave se guarda cifrada (AES-256-GCM) en el servidor, nunca vuelve al navegador ni aparece en los logs. Después, borra el .pem de tu carpeta de descargas.</p>
    </form>
  </div>
}

// Paso siguiente: la App existe y hay que instalarla en la cuenta eligiendo repositorios.
export function GitHubInstall({ status, canManage, onChanged }: { status: GitHubStatus; canManage: boolean; onChanged: (next: GitHubStatus) => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [available, setAvailable] = useState<NonNullable<GitHubStatus['available_installations']>>([])
  const detect = async () => {
    setBusy(true); setError('')
    try {
      const next = await api.post<GitHubStatus>('/api/integrations/github', 'connect-github', { action: 'detect' })
      setAvailable(next.available_installations ?? []); onChanged(next)
    }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const connect = async (installationId: number) => {
    setBusy(true); setError('')
    try {
      const next = await api.post<GitHubStatus>('/api/integrations/github', 'connect-github', { action: 'connect', installation_id: installationId })
      setAvailable(current => current.map(item => item.installation_id === installationId ? { ...item, connected: true } : item))
      onChanged(next)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  const review = status.permissions
  return <div className="mt-4 space-y-3">
    <div className="flex items-start gap-2 rounded-lg border border-app-line bg-app-soft px-3 py-2.5 text-sm"><CircleCheck className="mt-0.5 size-4 shrink-0 text-brand" />
      <span>App <strong className="font-medium">{status.name ?? status.slug}</strong>{status.owner ? <> de <strong className="font-medium">{status.owner}</strong></> : null} verificada. {status.connected ? 'Puedes añadir otra organización y elegir sus repositorios.' : 'Instálala en las organizaciones que necesites y elige sus repositorios.'}</span></div>
    {review && (review.excess.length > 0 || review.missing.length > 0) && <PermissionWarning review={review} />}
    <ol className="ml-4 list-decimal space-y-1 text-xs leading-5 text-app-muted">
      <li>Pulsa <strong className="font-medium text-app-secondary">Instalar en GitHub</strong> y elige <strong className="font-medium text-app-secondary">Only select repositories</strong> con los que quieras analizar.</li>
      <li>Vuelve y pulsa <strong className="font-medium text-app-secondary">Buscar instalaciones</strong>; selecciona las organizaciones que quieres usar en este workspace.</li>
    </ol>
    {error && <div role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-900 dark:text-amber-100">{error}</div>}
    <div className="flex flex-wrap gap-2">
      <a href={`https://github.com/apps/${status.slug}/installations/new`} target="_blank" rel="noopener noreferrer"><Button disabled={!canManage} className="bg-primary text-primary-foreground hover:bg-primary/90">Instalar en GitHub <ExternalLink /></Button></a>
      <Button variant="outline" disabled={!canManage || busy} onClick={() => void detect()} className="border-app-line bg-app-soft">{busy ? <LoaderCircle className="animate-spin" /> : <RefreshCw />}Buscar instalaciones</Button>
    </div>
    {available.length > 0 && <div className="space-y-2 rounded-lg border border-app-line bg-app-soft p-3">
      <p className="text-xs font-medium text-app-secondary">Cuentas donde la App está instalada</p>
      {available.map(item => {
        const connected = status.installations.some(current => current.installation_id === item.installation_id)
        return <div key={item.installation_id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-app-line bg-panel px-3 py-2 text-sm">
          <div><p className="font-medium">{item.account ?? `Instalación #${item.installation_id}`}</p>
            <p className="text-xs text-app-muted">{item.account_type === 'Organization' ? 'Organización' : 'Cuenta personal'} · {item.repository_selection === 'selected' ? 'Repositorios seleccionados' : 'Todos los repositorios'}</p></div>
          <Button size="sm" variant={connected ? 'outline' : 'default'} disabled={busy || !canManage || connected} onClick={() => void connect(item.installation_id)}>
            {connected ? 'Conectada' : 'Conectar cuenta'}
          </Button>
        </div>
      })}
    </div>}
  </div>
}

export function PermissionWarning({ review }: { review: PermissionReview }) {
  if (review.excess.length) return <div role="alert" className="flex gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs leading-5 text-rose-800 dark:text-rose-200"><TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
    <div><strong>La App pide {review.excess.length} permisos adicionales.</strong> Revisa los permisos de la GitHub App; los repositorios instalados siguen teniendo el alcance que elegiste.<details className="mt-1"><summary className="cursor-pointer font-medium">Ver permisos</summary><p className="mt-1 break-words">{review.excess.map(name => `${name}: ${review.declared[name]}`).join(' · ')}</p></details></div></div>
  return <div className="flex gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs leading-5 text-amber-900 dark:text-amber-100"><TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
    <span>Faltan permisos: {review.missing.join(', ')}{review.pending_acceptance.length ? ' (hay una actualización de permisos pendiente de aceptar en la instalación)' : ''}. Sin ellos no se revisan pull requests.</span></div>
}
