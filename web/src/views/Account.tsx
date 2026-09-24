import { useMemo, useState, type ComponentProps, type FormEvent } from 'react'
import QRCode from 'qrcode'
import { Check, Copy, KeyRound, LoaderCircle, ShieldCheck, ShieldOff } from 'lucide-react'
import type { SessionUser } from '@/components/auth/session'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { api } from '@/lib/api'
import { formatDate } from '@/lib/types'

// El QR se dibuja con la matriz de módulos: sin imágenes data: (la CSP las bloquea) ni innerHTML.
function QrCode({ value }: { value: string }) {
  const { size, path } = useMemo(() => {
    const modules = QRCode.create(value, { errorCorrectionLevel: 'M' }).modules
    let d = ''
    for (let row = 0; row < modules.size; row++) for (let col = 0; col < modules.size; col++) if (modules.get(row, col)) d += `M${col} ${row}h1v1h-1z`
    return { size: modules.size, path: d }
  }, [value])
  return <svg role="img" aria-label="Código QR para la app de autenticación" viewBox={`-4 -4 ${size + 8} ${size + 8}`} className="size-48 rounded-lg" shapeRendering="crispEdges"><rect x={-4} y={-4} width={size + 8} height={size + 8} fill="#fff" /><path d={path} fill="#000" /></svg>
}

function Field({ id, label, ...props }: { id: string; label: string } & ComponentProps<typeof Input>) {
  return <div className="space-y-1.5"><label htmlFor={id} className="text-xs text-app-muted">{label}</label><Input id={id} {...props} className="border-app-line bg-app-soft" /></div>
}

// `only="totp"` es el enrolamiento obligatorio: sin tarjeta de perfil ni de contraseña.
export function Account({ user, onChanged, only }: { user: SessionUser; onChanged: () => Promise<void>; only?: 'totp' }) {
  const [passwords, setPasswords] = useState({ current: '', next: '', confirm: '' })
  const [enrolment, setEnrolment] = useState<{ secret: string; uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)
  const [disablePassword, setDisablePassword] = useState('')
  const [busy, setBusy] = useState('')
  const [message, setMessage] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const run = async (key: string, action: () => Promise<void>) => {
    if (busy) return
    setBusy(key); setMessage(null)
    try { await action() } catch (caught) { setMessage({ tone: 'error', text: caught instanceof Error ? caught.message : String(caught) }) } finally { setBusy('') }
  }
  const changePassword = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); void run('password', async () => {
    if (passwords.next !== passwords.confirm) throw new Error('La contraseña nueva y su confirmación no coinciden')
    await api.post('/api/auth/password', 'change-password', { current: passwords.current, new: passwords.next })
    setPasswords({ current: '', next: '', confirm: '' })
    setMessage({ tone: 'ok', text: 'Contraseña cambiada. Se cerraron tus otras sesiones.' })
  }) }
  const startTotp = () => run('totp', async () => { setEnrolment(await api.post<{ secret: string; uri: string }>('/api/auth/totp/setup', 'totp-setup', {})); setCode('') })
  const confirmTotp = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); void run('totp', async () => {
    const result = await api.post<{ backup_codes: string[] }>('/api/auth/totp/confirm', 'totp-confirm', { code: code.trim() })
    setBackupCodes(result.backup_codes); setEnrolment(null); setCode('')
  }) }
  const disableTotp = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); void run('disable', async () => {
    await api.post('/api/auth/totp/disable', 'totp-disable', { password: disablePassword })
    setDisablePassword(''); setBackupCodes(null)
    setMessage({ tone: 'ok', text: 'Segundo factor desactivado.' })
    await onChanged()
  }) }
  const copyCodes = async () => { if (!backupCodes) return; await navigator.clipboard.writeText(backupCodes.join('\n')); setCopied(true); window.setTimeout(() => setCopied(false), 1500) }

  return <div className={only ? 'space-y-5' : 'grid gap-5 xl:grid-cols-2'}>
    {!only && <Card className="border-app-line bg-panel xl:col-span-2"><CardContent className="flex flex-wrap items-center justify-between gap-4 pt-6">
      <div><div className="text-lg font-semibold">{user.display_name}</div><div className="text-sm text-app-muted">@{user.username} · {user.role === 'admin' ? 'Administrador' : 'Miembro'}{user.last_login_at ? ` · último acceso ${formatDate(user.last_login_at)}` : ''}</div></div>
      <Badge variant="outline" className={user.totp_enabled ? 'border-brand/30 text-brand' : 'border-warning-line text-warning'}>{user.totp_enabled ? <><ShieldCheck className="size-3" />Segundo factor activo</> : <><ShieldOff className="size-3" />Sin segundo factor</>}</Badge>
    </CardContent></Card>}
    {message && <div role={message.tone === 'error' ? 'alert' : 'status'} className={`xl:col-span-2 rounded-xl border px-4 py-3 text-sm ${message.tone === 'error' ? 'border-danger-line bg-danger-soft text-danger' : 'border-brand/30 bg-brand/10 text-brand'}`}>{message.text}</div>}

    <Card className="border-app-line bg-panel"><CardHeader><CardTitle>Segundo factor (TOTP)</CardTitle><CardDescription>Un código de 6 dígitos de una app como 1Password, Google Authenticator o Authy, además de la contraseña.</CardDescription></CardHeader><CardContent className="space-y-4">
      {backupCodes ? <div className="space-y-3"><p className="text-sm text-app-secondary">Guarda estos códigos de respaldo en tu gestor de contraseñas. Cada uno sirve <strong>una sola vez</strong> si pierdes el dispositivo, y no se volverán a mostrar.</p>
        <div className="grid grid-cols-2 gap-2 rounded-xl border border-app-line bg-inset p-4 font-mono text-sm">{backupCodes.map(item => <span key={item}>{item}</span>)}</div>
        <div className="flex gap-2"><Button variant="outline" className="border-app-line bg-app-soft" onClick={() => void copyCodes()}>{copied ? <Check /> : <Copy />}{copied ? 'Copiados' : 'Copiar'}</Button><span role="status" className="sr-only">{copied ? 'Códigos copiados al portapapeles' : ''}</span><Button onClick={() => { setBackupCodes(null); void onChanged() }} className="bg-primary text-primary-foreground hover:bg-primary/90">Ya los guardé</Button></div></div>
      : user.totp_enabled ? <form className="space-y-3" onSubmit={disableTotp}><p className="text-sm text-app-muted">Para desactivarlo confirma tu contraseña. Si solo cambiaste de teléfono, desactívalo y vuelve a enrolarlo.</p><Field id="totp-disable" label="Contraseña" type="password" required autoComplete="current-password" maxLength={256} value={disablePassword} onChange={event => setDisablePassword(event.target.value)} /><Button type="submit" variant="outline" disabled={!!busy} className="border-app-line bg-app-soft">{busy === 'disable' ? <LoaderCircle className="animate-spin" /> : <ShieldOff />}Desactivar</Button></form>
      : enrolment ? <form className="space-y-4" onSubmit={confirmTotp}><div className="flex flex-col items-start gap-4 sm:flex-row"><QrCode value={enrolment.uri} /><div className="space-y-2 text-sm text-app-muted"><p>1. Escanea el código con tu app.</p><p>2. ¿No puedes escanear? Escribe esta clave:</p><code className="block rounded-lg bg-inset p-2 font-mono text-xs break-all text-app-secondary">{enrolment.secret.match(/.{1,4}/g)?.join(' ')}</code><p>3. Escribe el código que muestra la app.</p></div></div>
        <Field id="totp-code" label="Código de 6 dígitos" required autoComplete="one-time-code" inputMode="numeric" pattern="\d{6}" maxLength={6} value={code} onChange={event => setCode(event.target.value)} />
        <div className="flex gap-2"><Button type="submit" disabled={!!busy || code.trim().length !== 6} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'totp' ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}Activar</Button><Button type="button" variant="ghost" onClick={() => setEnrolment(null)}>Cancelar</Button></div></form>
      : <Button onClick={() => void startTotp()} disabled={!!busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'totp' ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}Configurar TOTP</Button>}
    </CardContent></Card>

    {!only && <Card className="border-app-line bg-panel"><CardHeader><CardTitle>Contraseña</CardTitle><CardDescription>Mínimo 12 caracteres. Una frase larga es mejor que símbolos raros. Al cambiarla se cierran tus demás sesiones.</CardDescription></CardHeader><CardContent><form className="space-y-3" onSubmit={changePassword}>
      <Field id="password-current" label="Contraseña actual" type="password" required autoComplete="current-password" maxLength={256} value={passwords.current} onChange={event => setPasswords(previous => ({ ...previous, current: event.target.value }))} />
      <Field id="password-new" label="Contraseña nueva" type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={passwords.next} onChange={event => setPasswords(previous => ({ ...previous, next: event.target.value }))} />
      <Field id="password-confirm" label="Repite la contraseña nueva" type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={passwords.confirm} onChange={event => setPasswords(previous => ({ ...previous, confirm: event.target.value }))} />
      <Button type="submit" disabled={!!busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'password' ? <LoaderCircle className="animate-spin" /> : <KeyRound />}Cambiar contraseña</Button>
    </form></CardContent></Card>}
  </div>
}
