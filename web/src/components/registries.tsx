import { useEffect, useState, type FormEvent } from 'react'
import { Boxes, KeyRound, LoaderCircle, ShieldCheck, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/types'

type Registry = { registry: string; username: string; last4: string; saved_at: string | null; saved_by: string | null }

const HINTS: [string, string, string][] = [
  ['ghcr.io', 'tu usuario de GitHub', 'token clásico con solo read:packages'],
  ['docker.io', 'tu usuario de Docker Hub', 'access token de solo lectura (Account settings → Personal access tokens)'],
  ['<cuenta>.dkr.ecr.<región>.amazonaws.com', 'AWS', 'salida de aws ecr get-login-password (caduca a las 12 h)'],
  ['<región>-docker.pkg.dev', '_json_key_base64', 'clave de una cuenta de servicio con Artifact Registry Reader'],
]

// Credenciales de solo lectura para analizar imágenes de registros privados. Se guardan cifradas y no vuelven.
export function RegistriesCard({ canManage }: { canManage: boolean }) {
  const [rows, setRows] = useState<Registry[] | null>(null)
  const [allowPrivate, setAllowPrivate] = useState(false)
  const [registry, setRegistry] = useState('')
  const [username, setUsername] = useState('')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  useEffect(() => { api.get<{ registries: Registry[]; allow_private: boolean }>('/api/registries').then(data => { setRows(data.registries); setAllowPrivate(data.allow_private) }).catch(caught => setError(String(caught))) }, [])

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('save'); setError('')
    try {
      const data = await api.post<{ registries: Registry[] }>('/api/registries', 'save-registry', { action: 'save', registry: registry.trim(), username: username.trim(), token })
      setRows(data.registries); setRegistry(''); setUsername(''); setToken('')
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const remove = async (host: string) => {
    setBusy(host); setError('')
    try { setRows((await api.post<{ registries: Registry[] }>('/api/registries', 'save-registry', { action: 'remove', registry: host })).registries) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }

  return <Card className="border-app-line bg-panel">
    <CardHeader><CardTitle className="flex items-center gap-2"><Boxes className="size-5 text-app-muted" />Registros de contenedores</CardTitle>
      <CardDescription>Para analizar imágenes privadas (Nuevo análisis → Imagen de contenedor). Las públicas no necesitan nada. Usa siempre un token de <strong className="font-medium">solo lectura</strong>.</CardDescription></CardHeader>
    <CardContent className="space-y-4">
      {rows && rows.length > 0 && <div className="divide-y divide-app-line rounded-xl border border-app-line">{rows.map(row => <div key={row.registry} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <span className="min-w-0"><span className="block font-mono text-sm">{row.registry}</span><span className="text-xs text-app-subtle">{row.username} · token ····{row.last4}{row.saved_at ? ` · ${formatDate(row.saved_at)}` : ''}{row.saved_by ? ` por ${row.saved_by}` : ''}</span></span>
        {canManage && <Button variant="ghost" size="sm" disabled={!!busy} onClick={() => void remove(row.registry)}>{busy === row.registry ? <LoaderCircle className="animate-spin" /> : <Trash2 />}Quitar</Button>}
      </div>)}</div>}
      {rows && rows.length === 0 && <p className="text-sm text-app-muted">Ningún registro privado configurado.</p>}
      {canManage ? <form onSubmit={save} className="grid gap-3 rounded-xl border border-app-line bg-inset p-4 md:grid-cols-3">
        <div className="space-y-1.5"><label htmlFor="registry-host" className="text-xs text-app-muted">Registro (host)</label><Input id="registry-host" required value={registry} onChange={event => setRegistry(event.target.value)} maxLength={200} placeholder="ghcr.io" className="border-app-line bg-app-soft font-mono" /></div>
        <div className="space-y-1.5"><label htmlFor="registry-user" className="text-xs text-app-muted">Usuario</label><Input id="registry-user" required value={username} onChange={event => setUsername(event.target.value)} maxLength={200} autoComplete="off" className="border-app-line bg-app-soft" /></div>
        <div className="space-y-1.5"><label htmlFor="registry-token" className="text-xs text-app-muted">Token de solo lectura</label><Input id="registry-token" required type="password" autoComplete="new-password" value={token} onChange={event => setToken(event.target.value)} minLength={8} maxLength={4096} className="border-app-line bg-app-soft" /></div>
        <div className="flex flex-wrap items-center gap-3 md:col-span-3"><Button type="submit" disabled={!!busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'save' ? <LoaderCircle className="animate-spin" /> : <KeyRound />}Guardar</Button>
          <span className="flex items-center gap-1.5 text-xs text-app-subtle"><ShieldCheck className="size-3.5" />Cifrado en el servidor; nunca vuelve al navegador ni aparece en los logs. Si ya había uno para ese registro, se reemplaza.</span></div>
      </form> : <p className="text-xs text-app-subtle">Solo un administrador puede guardar credenciales de registros.</p>}
      <details className="text-xs text-app-muted"><summary className="cursor-pointer">Qué poner en cada registro</summary>
        <table className="mt-2 w-full text-left"><tbody>{HINTS.map(([host, user, secret]) => <tr key={host} className="border-t border-app-line"><td className="py-1.5 pr-3 font-mono">{host}</td><td className="py-1.5 pr-3">{user}</td><td className="py-1.5">{secret}</td></tr>)}</tbody></table>
        {!allowPrivate && <p className="mt-2">Los registros de tu red interna (IP privada) están bloqueados para que nadie use el panel para llegar a servicios internos. Para permitirlos, arranca con <span className="font-mono">APPSEC_AGENT_ALLOW_PRIVATE_REGISTRIES=1</span>.</p>}
      </details>
      {error && <div role="alert" className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-200">{error}</div>}
    </CardContent>
  </Card>
}
