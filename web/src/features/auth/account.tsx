import { useMemo, useState, type ComponentProps, type FormEvent } from 'react'
import QRCode from 'qrcode'
import { Check, Copy, KeyRound, LoaderCircle, ShieldCheck, ShieldOff } from 'lucide-react'
import { Trans, useTranslation } from 'react-i18next'
import type { SessionUser } from '@/features/auth/session'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import { formatDate } from '@/shared/i18n/format'

// El QR se dibuja con la matriz de módulos: sin imágenes data: (la CSP las bloquea) ni innerHTML.
function QrCode({ value }: { value: string }) {
  const { t } = useTranslation('auth')
  const { size, path } = useMemo(() => {
    const modules = QRCode.create(value, { errorCorrectionLevel: 'M' }).modules
    let d = ''
    for (let row = 0; row < modules.size; row++) for (let col = 0; col < modules.size; col++) if (modules.get(row, col)) d += `M${col} ${row}h1v1h-1z`
    return { size: modules.size, path: d }
  }, [value])
  return <svg role="img" aria-label={t('account.qr_label')} viewBox={`-4 -4 ${size + 8} ${size + 8}`} className="size-48 rounded-lg" shapeRendering="crispEdges"><rect x={-4} y={-4} width={size + 8} height={size + 8} fill="#fff" /><path d={path} fill="#000" /></svg>
}

function Field({ id, label, ...props }: { id: string; label: string } & ComponentProps<typeof Input>) {
  return <div className="space-y-1.5"><label htmlFor={id} className="text-xs text-app-muted">{label}</label><Input id={id} {...props} className="border-app-line bg-app-soft" /></div>
}

// `only="totp"` es el enrolamiento obligatorio: sin tarjeta de perfil ni de contraseña.
export function Account({ user, onChanged, only }: { user: SessionUser; onChanged: () => Promise<void>; only?: 'totp' }) {
  const { t } = useTranslation('auth')
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
    if (passwords.next !== passwords.confirm) throw new Error(t('account.new_password_mismatch'))
    await api.post('/api/auth/password', 'change-password', { current: passwords.current, new: passwords.next })
    setPasswords({ current: '', next: '', confirm: '' })
    setMessage({ tone: 'ok', text: t('account.password_changed') })
  }) }
  const startTotp = () => run('totp', async () => { setEnrolment(await api.post<{ secret: string; uri: string }>('/api/auth/totp/setup', 'totp-setup', {})); setCode('') })
  const confirmTotp = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); void run('totp', async () => {
    const result = await api.post<{ backup_codes: string[] }>('/api/auth/totp/confirm', 'totp-confirm', { code: code.trim() })
    setBackupCodes(result.backup_codes); setEnrolment(null); setCode('')
  }) }
  const disableTotp = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); void run('disable', async () => {
    await api.post('/api/auth/totp/disable', 'totp-disable', { password: disablePassword })
    setDisablePassword(''); setBackupCodes(null)
    setMessage({ tone: 'ok', text: t('account.totp_disabled') })
    await onChanged()
  }) }
  const copyCodes = async () => { if (!backupCodes) return; await navigator.clipboard.writeText(backupCodes.join('\n')); setCopied(true); window.setTimeout(() => setCopied(false), 1500) }

  const role = user.role === 'admin' ? t('role.admin') : t('role.member')
  return <div className={only ? 'space-y-5' : 'grid gap-5 xl:grid-cols-2'}>
    {!only && <Card className="border-app-line bg-panel xl:col-span-2"><CardContent className="flex flex-wrap items-center justify-between gap-4 pt-6">
      <div><div className="text-lg font-semibold">{user.display_name}</div><div className="text-sm text-app-muted">{user.last_login_at
        ? t('account.profile_last_login', { username: user.username, role, date: formatDate(user.last_login_at) })
        : t('account.profile', { username: user.username, role })}</div></div>
      <Badge variant="outline" className={user.totp_enabled ? 'border-brand/30 text-brand' : 'border-warning-line text-warning'}>{user.totp_enabled ? <><ShieldCheck className="size-3" />{t('account.totp_on')}</> : <><ShieldOff className="size-3" />{t('account.totp_off')}</>}</Badge>
    </CardContent></Card>}
    {message && <div role={message.tone === 'error' ? 'alert' : 'status'} className={`xl:col-span-2 rounded-xl border px-4 py-3 text-sm ${message.tone === 'error' ? 'border-danger-line bg-danger-soft text-danger' : 'border-brand/30 bg-brand/10 text-brand'}`}>{message.text}</div>}

    <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('account.totp_title')}</CardTitle><CardDescription>{t('account.totp_description')}</CardDescription></CardHeader><CardContent className="space-y-4">
      {backupCodes ? <div className="space-y-3"><p className="text-sm text-app-secondary"><Trans t={t} i18nKey="account.backup_intro" components={{ strong: <strong /> }} /></p>
        <div className="grid grid-cols-2 gap-2 rounded-xl border border-app-line bg-inset p-4 font-mono text-sm">{backupCodes.map(item => <span key={item}>{item}</span>)}</div>
        <div className="flex gap-2"><Button variant="outline" className="border-app-line bg-app-soft" onClick={() => void copyCodes()}>{copied ? <Check /> : <Copy />}{copied ? t('account.copied') : t('common:actions.copy')}</Button><span role="status" className="sr-only">{copied ? t('account.codes_copied') : ''}</span><Button onClick={() => { setBackupCodes(null); void onChanged() }} className="bg-primary text-primary-foreground hover:bg-primary/90">{t('account.saved_them')}</Button></div></div>
      : user.totp_enabled ? <form className="space-y-3" onSubmit={disableTotp}><p className="text-sm text-app-muted">{t('account.disable_intro')}</p><Field id="totp-disable" label={t('fields.password')} type="password" required autoComplete="current-password" maxLength={256} value={disablePassword} onChange={event => setDisablePassword(event.target.value)} /><Button type="submit" variant="outline" disabled={!!busy} className="border-app-line bg-app-soft">{busy === 'disable' ? <LoaderCircle className="animate-spin" /> : <ShieldOff />}{t('account.disable')}</Button></form>
      : enrolment ? <form className="space-y-4" onSubmit={confirmTotp}><div className="flex flex-col items-start gap-4 sm:flex-row"><QrCode value={enrolment.uri} /><div className="space-y-2 text-sm text-app-muted"><p>{t('account.step_scan')}</p><p>{t('account.step_key')}</p><code className="block rounded-lg bg-inset p-2 font-mono text-xs break-all text-app-secondary">{enrolment.secret.match(/.{1,4}/g)?.join(' ')}</code><p>{t('account.step_code')}</p></div></div>
        <Field id="totp-code" label={t('account.code_6')} required autoComplete="one-time-code" inputMode="numeric" pattern="\d{6}" maxLength={6} value={code} onChange={event => setCode(event.target.value)} />
        <div className="flex gap-2"><Button type="submit" disabled={!!busy || code.trim().length !== 6} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'totp' ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{t('account.enable')}</Button><Button type="button" variant="ghost" onClick={() => setEnrolment(null)}>{t('common:actions.cancel')}</Button></div></form>
      : <Button onClick={() => void startTotp()} disabled={!!busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'totp' ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{t('account.setup_totp')}</Button>}
    </CardContent></Card>

    {!only && <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('account.password_title')}</CardTitle><CardDescription>{t('account.password_description')}</CardDescription></CardHeader><CardContent><form className="space-y-3" onSubmit={changePassword}>
      <Field id="password-current" label={t('account.current_password')} type="password" required autoComplete="current-password" maxLength={256} value={passwords.current} onChange={event => setPasswords(previous => ({ ...previous, current: event.target.value }))} />
      <Field id="password-new" label={t('account.new_password')} type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={passwords.next} onChange={event => setPasswords(previous => ({ ...previous, next: event.target.value }))} />
      <Field id="password-confirm" label={t('account.repeat_new_password')} type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={passwords.confirm} onChange={event => setPasswords(previous => ({ ...previous, confirm: event.target.value }))} />
      <Button type="submit" disabled={!!busy} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy === 'password' ? <LoaderCircle className="animate-spin" /> : <KeyRound />}{t('account.change_password')}</Button>
    </form></CardContent></Card>}
  </div>
}
