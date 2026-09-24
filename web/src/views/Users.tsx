import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Check, Copy, KeyRound, LoaderCircle, ShieldCheck, ShieldOff, UserPlus } from 'lucide-react'
import type { SessionUser } from '@/components/auth/session'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/components/ui/select'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/types'

type Listing = { users: SessionUser[]; totp_policy: 'admins' | 'all' | 'none' }
type LinkResult = { user: SessionUser; link: string; expires_in_hours: number }
const roleLabel = { admin: 'Administrador', member: 'Miembro' }
const policyText = { admins: 'TOTP obligatorio para administradores', all: 'TOTP obligatorio para todos', none: 'TOTP opcional' }

export function Users({ me }: { me: SessionUser }) {
  const [listing, setListing] = useState<Listing | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [inviting, setInviting] = useState(false)
  const [link, setLink] = useState<LinkResult | null>(null)
  const load = useCallback(() => api.get<Listing>('/api/users').then(setListing).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))), [])
  useEffect(() => { void load() }, [load])

  const act = async (user: SessionUser, body: Record<string, string>) => {
    if (busy) return
    setBusy(user.id); setError('')
    try {
      const result = await api.post<LinkResult | { user: SessionUser }>('/api/users', 'manage-users', { ...body, user_id: user.id })
      if ('link' in result) setLink(result)
      await load()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }

  return <div className="space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>Personas con acceso</CardTitle><CardDescription className="mt-1">Invita con un enlace de un solo uso: cada persona elige su contraseña y tú nunca la ves. {listing ? policyText[listing.totp_policy] : ''}.</CardDescription></div>
      <Button onClick={() => setInviting(true)} className="bg-primary text-primary-foreground hover:bg-primary/90"><UserPlus />Invitar</Button></CardHeader>
      <CardContent className="space-y-3">
        {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>}
        {!listing ? <LoaderCircle className="size-5 animate-spin text-app-muted" /> : <div className="overflow-x-auto rounded-xl border border-app-line">
          <table className="w-full min-w-[760px] text-sm"><thead><tr className="border-b border-app-line text-left text-xs text-app-subtle"><th className="px-4 py-2.5 font-normal">Usuario</th><th className="px-4 py-2.5 font-normal">Rol</th><th className="px-4 py-2.5 font-normal">Segundo factor</th><th className="px-4 py-2.5 font-normal">Último acceso</th><th className="px-4 py-2.5 font-normal">Acciones</th></tr></thead>
            <tbody>{listing.users.map(user => { const self = user.id === me.id
              return <tr key={user.id} className={`border-b border-app-line last:border-b-0 ${user.disabled ? 'opacity-60' : ''}`}>
                <td className="px-4 py-3"><div className="font-medium">{user.display_name}{self ? <span className="ml-2 text-xs font-normal text-app-subtle">(tú)</span> : null}</div><div className="text-xs text-app-subtle">@{user.username}{user.disabled ? ' · desactivado' : ''}{user.pending_link === 'invite' ? ' · invitación pendiente' : user.pending_link === 'reset' ? ' · restablecimiento pendiente' : !user.has_password ? ' · sin contraseña' : ''}</div></td>
                <td className="px-4 py-3"><Select value={user.role} disabled={self || !!busy} onValueChange={value => { if (value && value !== user.role) void act(user, { action: 'role', role: value }) }}><SelectTrigger size="sm" aria-label={`Rol de ${user.username}`} className="min-w-36 border-app-line bg-app-soft">{roleLabel[user.role]}</SelectTrigger><SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="member">Miembro</SelectItem><SelectItem value="admin">Administrador</SelectItem></SelectContent></Select></td>
                <td className="px-4 py-3">{user.totp_enabled ? <Badge variant="outline" className="border-brand/30 text-brand"><ShieldCheck className="size-3" />Activo</Badge> : <Badge variant="outline" className="border-app-line text-app-muted"><ShieldOff className="size-3" />Sin activar</Badge>}</td>
                <td className="px-4 py-3 text-xs text-app-muted">{user.last_login_at ? formatDate(user.last_login_at) : 'Nunca'}</td>
                <td className="px-4 py-3"><div className="flex flex-wrap gap-1.5">
                  <Button size="xs" variant="outline" disabled={!!busy || user.disabled} onClick={() => void act(user, { action: 'reset' })} className="border-app-line bg-app-soft"><KeyRound />{user.has_password ? 'Enlace de contraseña' : 'Reenviar invitación'}</Button>
                  {user.totp_enabled && !self && <Button size="xs" variant="outline" disabled={!!busy} onClick={() => void act(user, { action: 'reset_totp' })} className="border-app-line bg-app-soft">Quitar TOTP</Button>}
                  {!self && <Button size="xs" variant="ghost" disabled={!!busy} onClick={() => void act(user, { action: user.disabled ? 'enable' : 'disable' })}>{busy === user.id ? <LoaderCircle className="animate-spin" /> : null}{user.disabled ? 'Reactivar' : 'Desactivar'}</Button>}
                </div></td>
              </tr> })}</tbody></table>
        </div>}
        <p className="text-xs leading-5 text-app-subtle">Desactivar o quitar el TOTP cierra al momento las sesiones abiertas de esa persona. Siempre queda al menos un administrador activo.</p>
      </CardContent></Card>
    <InviteDialog open={inviting} onClose={() => setInviting(false)} onInvited={result => { setInviting(false); setLink(result); void load() }} />
    <LinkDialog result={link} onClose={() => setLink(null)} />
  </div>
}

function InviteDialog({ open, onClose, onInvited }: { open: boolean; onClose: () => void; onInvited: (result: LinkResult) => void }) {
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState<'member' | 'admin'>('member')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    try {
      onInvited(await api.post<LinkResult>('/api/users', 'manage-users', { action: 'invite', username, display_name: displayName, role }))
      setUsername(''); setDisplayName(''); setRole('member')
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Dialog open={open} onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-md">
    <DialogHeader><DialogTitle>Invitar a alguien</DialogTitle><DialogDescription>Se crea la cuenta sin contraseña y un enlace de un solo uso válido 72 horas. Envíaselo por un canal de confianza.</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><label htmlFor="invite-user" className="text-xs text-app-muted">Usuario</label><Input id="invite-user" required autoFocus pattern="[A-Za-z0-9][A-Za-z0-9._\-]{1,38}[A-Za-z0-9]" maxLength={40} value={username} onChange={event => setUsername(event.target.value)} placeholder="ana.lopez" className="border-app-line bg-app-soft" /><p className="text-[11px] text-app-subtle">3-40 caracteres: letras, números, punto, guion o guion bajo.</p></div>
      <div className="space-y-1.5"><label htmlFor="invite-name" className="text-xs text-app-muted">Nombre visible (opcional)</label><Input id="invite-name" maxLength={80} value={displayName} onChange={event => setDisplayName(event.target.value)} placeholder="Ana López" className="border-app-line bg-app-soft" /></div>
      <div className="space-y-1.5"><span className="text-xs text-app-muted">Rol</span><div className="grid grid-cols-2 gap-2">{(['member', 'admin'] as const).map(value => <button key={value} type="button" onClick={() => setRole(value)} className={`rounded-lg border p-3 text-left text-sm ${role === value ? 'border-brand/50 bg-brand/10' : 'border-app-line bg-app-soft'}`}><span className="block font-medium">{roleLabel[value]}</span><span className="text-xs text-app-subtle">{value === 'admin' ? 'Conecta proveedores, gestiona usuarios y acepta riesgos' : 'Lanza análisis, triagea y consulta resultados'}</span></button>)}</div></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>Cancelar</Button><Button type="submit" disabled={busy || username.trim().length < 3} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}Crear invitación</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

function LinkDialog({ result, onClose }: { result: LinkResult | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  if (!result) return null
  const copy = async () => { await navigator.clipboard.writeText(result.link); setCopied(true); window.setTimeout(() => setCopied(false), 1500) }
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>Enlace para @{result.user.username}</DialogTitle><DialogDescription>Sirve una sola vez y caduca en {result.expires_in_hours} horas. No se volverá a mostrar: si se pierde, genera otro (el anterior deja de valer).</DialogDescription></DialogHeader>
    <code className="block rounded-lg bg-inset p-3 font-mono text-xs break-all text-app-secondary">{result.link}</code>
    <DialogFooter><Button variant="outline" onClick={() => void copy()} className="border-app-line bg-app-soft">{copied ? <Check /> : <Copy />}{copied ? 'Copiado' : 'Copiar enlace'}</Button><Button onClick={onClose} className="bg-primary text-primary-foreground hover:bg-primary/90">Hecho</Button></DialogFooter>
  </DialogContent></Dialog>
}
