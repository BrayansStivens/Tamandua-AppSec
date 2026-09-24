import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { KeyRound, LoaderCircle, LockKeyhole, LogOut, ShieldCheck, TerminalSquare, UserPlus } from 'lucide-react'
import { BrandLockup } from '@/components/brand-mark'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { ApiError, TOTP_REQUIRED_EVENT, UNAUTHORIZED_EVENT, api } from '@/lib/api'
import { Account } from '@/views/Account'
import { SkeletonCard, Splash } from '@/components/loading'

export type SessionUser = { id: string; username: string; display_name: string; role: 'admin' | 'member'; totp_enabled: boolean; last_login_at: string | null; disabled?: boolean; created_at?: string; has_password?: boolean; pending_link?: 'invite' | 'reset' | null }

// El token del enlace viaja en el fragmento (#link=…): el navegador no lo manda al servidor ni en el Referer.
const linkToken = () => new URLSearchParams(window.location.hash.slice(1)).get('link')
type SessionState = { authenticated: true; user: SessionUser; mfa: boolean; totp_required: boolean } | { authenticated: false; setup_required: boolean }
export type SessionActions = { logout: () => Promise<void>; reload: () => Promise<void> }

// La puerta de todo el panel: nada se pinta ni se pide al servidor hasta que hay sesión.
export function SessionGate({ children }: { children: (user: SessionUser, actions: SessionActions) => ReactNode }) {
  const [state, setState] = useState<SessionState | null>(null)
  const [notice, setNotice] = useState('')
  const [link, setLink] = useState<string | null>(linkToken)
  const reload = useCallback(async () => { setState(await api.get<SessionState>('/api/auth/session')) }, [])
  // La marca se ve al menos medio segundo: una pantalla de carga que parpadea parece un fallo.
  useEffect(() => {
    const started = Date.now()
    api.get<SessionState>('/api/auth/session').catch(() => ({ authenticated: false, setup_required: false }) as SessionState)
      .then(next => window.setTimeout(() => setState(next), Math.max(0, 500 - (Date.now() - started))))
  }, [])
  useEffect(() => {
    const expired = () => { setNotice('Tu sesión terminó. Vuelve a iniciar sesión.'); setState(previous => previous?.authenticated ? { authenticated: false, setup_required: false } : previous) }
    const enrol = () => { void reload() }
    const follow = () => { const token = linkToken(); if (token) setLink(token) }
    window.addEventListener('hashchange', follow)
    window.addEventListener(UNAUTHORIZED_EVENT, expired)
    window.addEventListener(TOTP_REQUIRED_EVENT, enrol)
    return () => { window.removeEventListener(UNAUTHORIZED_EVENT, expired); window.removeEventListener(TOTP_REQUIRED_EVENT, enrol); window.removeEventListener('hashchange', follow) }
  }, [reload])
  const logout = useCallback(async () => {
    try { await api.post('/api/auth/logout', 'logout', {}) } finally { setNotice(''); setState({ authenticated: false, setup_required: false }) }
  }, [])
  const leaveLink = () => { window.history.replaceState(null, '', window.location.pathname); setLink(null) }
  if (link) return <LinkView token={link} onDone={() => { leaveLink(); void reload() }} onCancel={leaveLink} />
  if (!state) return <Splash />
  if (state.authenticated && state.totp_required) return <Shell>
    <div className="space-y-2"><h1 className="text-2xl font-semibold">Activa el segundo factor</h1><p className="text-sm leading-6 text-app-muted">Este workspace exige TOTP a {state.user.role === 'admin' ? 'los administradores' : 'todos los usuarios'}. Actívalo para entrar; tardas un minuto.</p></div>
    <Account user={state.user} onChanged={reload} only="totp" />
    <Button variant="ghost" size="sm" onClick={() => void logout()} className="text-app-muted"><LogOut />Cerrar sesión</Button>
  </Shell>
  if (!state.authenticated) return <LoginView setupRequired={state.setup_required} notice={notice} onDone={() => { setNotice(''); void reload() }} />
  return <>{children(state.user, { logout, reload })}</>
}

function Shell({ children, narrow }: { children: ReactNode; narrow?: boolean }) {
  return <div className="grid min-h-screen place-items-center bg-app px-4 py-10 text-app-fg"><div className={`w-full space-y-6 ${narrow ? 'max-w-sm' : 'max-w-xl'}`}>
    <BrandLockup subtitle="Acceso al workspace" />
    {children}
  </div></div>
}

// Invitación o restablecimiento: el enlace de un solo uso que genera un administrador.
function LinkView({ token, onDone, onCancel }: { token: string; onDone: () => void; onCancel: () => void }) {
  const [info, setInfo] = useState<{ username: string; display_name: string; purpose: 'invite' | 'reset' } | null>(null)
  const [error, setError] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [challenge, setChallenge] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { api.post<{ username: string; display_name: string; purpose: 'invite' | 'reset' }>('/api/auth/link/check', 'check-link', { token }).then(setInfo).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [token])
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    if (!challenge && password !== confirm) { setError('Las contraseñas no coinciden'); return }
    setBusy(true); setError('')
    try {
      // Si la cuenta tiene TOTP, el enlace cambia la contraseña pero la sesión sigue pidiendo el segundo factor.
      if (challenge) { await api.post('/api/auth/totp', 'totp', { challenge, code: code.trim() }); onDone(); return }
      const result = await api.post<{ step: 'done' } | { step: 'totp'; challenge: string }>('/api/auth/link', 'accept-link', { token, password })
      if (result.step === 'totp') { setChallenge(result.challenge); setPassword(''); setConfirm(''); return }
      onDone()
    }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Shell narrow><Card className="border-app-line bg-panel"><CardHeader><CardTitle className="flex items-center gap-2"><UserPlus className="size-4" />{info?.purpose === 'reset' ? 'Nueva contraseña' : 'Te damos la bienvenida'}</CardTitle>
    <CardDescription>{info ? <>Cuenta <strong>@{info.username}</strong>. Elige una contraseña de al menos 12 caracteres; una frase larga es lo mejor.</> : error ? 'No se pudo abrir el enlace.' : 'Comprobando el enlace…'}</CardDescription></CardHeader>
    <CardContent>{info && challenge ? <form className="space-y-4" onSubmit={submit}>
      <p className="text-sm text-app-muted">Contraseña guardada. Tu cuenta tiene segundo factor: escribe el código de tu app o un código de respaldo.</p>
      <div className="space-y-1.5"><label htmlFor="link-code" className="text-xs text-app-muted">Código</label><Input id="link-code" autoFocus required autoComplete="one-time-code" inputMode="numeric" maxLength={11} value={code} onChange={event => setCode(event.target.value)} className="border-app-line bg-app-soft font-mono tracking-widest" /></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <Button type="submit" disabled={busy} className="w-full bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}Verificar y entrar</Button>
    </form> : info ? <form className="space-y-4" onSubmit={submit}>
      <input type="text" autoComplete="username" value={info.username} readOnly hidden />
      <div className="space-y-1.5"><label htmlFor="link-password" className="text-xs text-app-muted">Contraseña</label><Input id="link-password" type="password" autoFocus required minLength={12} maxLength={256} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} className="border-app-line bg-app-soft" /></div>
      <div className="space-y-1.5"><label htmlFor="link-confirm" className="text-xs text-app-muted">Repite la contraseña</label><Input id="link-confirm" type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={confirm} onChange={event => setConfirm(event.target.value)} className="border-app-line bg-app-soft" /></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <Button type="submit" disabled={busy} className="w-full bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <KeyRound />}Guardar y entrar</Button>
    </form> : error ? <div className="space-y-3"><div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div><Button variant="outline" className="w-full border-app-line bg-app-soft" onClick={onCancel}>Ir al inicio de sesión</Button></div>
      : <SkeletonCard lines={3} label="Comprobando el enlace" />}</CardContent></Card></Shell>
}

function LoginView({ setupRequired, notice, onDone }: { setupRequired: boolean; notice: string; onDone: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [challenge, setChallenge] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    setBusy(true); setError('')
    try {
      const result = challenge
        ? await api.post<{ step: 'done' }>('/api/auth/totp', 'totp', { challenge, code: code.trim() })
        : await api.post<{ step: 'done' } | { step: 'totp'; challenge: string }>('/api/auth/login', 'login', { username, password })
      if (result.step === 'totp') { setChallenge(result.challenge); setPassword(''); return }
      onDone()
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : String(caught)
      // Si el retén caducó hay que volver a la contraseña; con un código incorrecto se reintenta aquí.
      if (challenge && caught instanceof ApiError && message.includes('caducó')) { setChallenge(null); setCode('') }
      setError(message)
    } finally { setBusy(false) }
  }

  return <div className="grid min-h-screen place-items-center bg-app px-4 py-10 text-app-fg">
    <div className="w-full max-w-sm space-y-6">
      <BrandLockup subtitle="Acceso al workspace" />
      {setupRequired ? <SetupCard onDone={onDone} />
      : <Card className="border-app-line bg-panel"><CardHeader><CardTitle className="flex items-center gap-2">{challenge ? <><ShieldCheck className="size-4" />Segundo factor</> : <><LockKeyhole className="size-4" />Iniciar sesión</>}</CardTitle><CardDescription>{challenge ? 'Escribe el código de 6 dígitos de tu app de autenticación, o uno de tus códigos de respaldo.' : 'Usa las credenciales que te dio el administrador.'}</CardDescription></CardHeader>
        <CardContent><form className="space-y-4" onSubmit={submit}>
          {notice && !error && <div role="status" className="rounded-lg border border-warning-line bg-warning-soft px-3 py-2 text-xs text-warning">{notice}</div>}
          {challenge ? <div className="space-y-1.5"><label htmlFor="login-code" className="text-xs text-app-muted">Código</label><Input id="login-code" autoFocus required autoComplete="one-time-code" inputMode="numeric" maxLength={11} value={code} onChange={event => setCode(event.target.value)} placeholder="123456" className="border-app-line bg-app-soft font-mono tracking-widest" /></div>
          : <><div className="space-y-1.5"><label htmlFor="login-user" className="text-xs text-app-muted">Usuario</label><Input id="login-user" autoFocus required autoComplete="username" maxLength={40} value={username} onChange={event => setUsername(event.target.value)} className="border-app-line bg-app-soft" /></div>
            <div className="space-y-1.5"><label htmlFor="login-password" className="text-xs text-app-muted">Contraseña</label><Input id="login-password" type="password" required autoComplete="current-password" maxLength={256} value={password} onChange={event => setPassword(event.target.value)} className="border-app-line bg-app-soft" /></div></>}
          {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
          <Button type="submit" disabled={busy} className="w-full bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <KeyRound />}{challenge ? 'Verificar' : 'Entrar'}</Button>
          {challenge && <button type="button" onClick={() => { setChallenge(null); setCode(''); setError('') }} className="w-full text-center text-xs text-app-subtle hover:text-app-fg">Volver a la contraseña</button>}
        </form></CardContent></Card>}
      <p className="text-center text-xs text-app-subtle">¿Olvidaste la contraseña o perdiste el dispositivo? Un administrador la restablece desde el servidor.</p>
    </div>
  </div>
}

// Primer arranque: el administrador se crea aquí con el código de un solo uso que imprime el servidor.
function SetupCard({ onDone }: { onDone: () => void }) {
  const [code, setCode] = useState('')
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (busy) return
    if (password !== confirm) { setError('Las contraseñas no coinciden'); return }
    setBusy(true); setError('')
    try {
      await api.post('/api/auth/setup', 'setup-admin', { code: code.trim(), username: username.trim(), password, display_name: displayName.trim() })
      onDone()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }
  return <Card className="border-app-line bg-panel"><CardHeader><CardTitle className="flex items-center gap-2"><TerminalSquare className="size-4" />Configura tu workspace</CardTitle>
    <CardDescription className="leading-6">Crea la cuenta de administrador. Para demostrar que controlas este servidor, escribe el código que aparece en su consola.</CardDescription></CardHeader>
    <CardContent><form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><label htmlFor="setup-code" className="text-xs text-app-muted">Código de configuración</label>
        <Input id="setup-code" autoFocus required autoComplete="off" spellCheck={false} maxLength={20} value={code} onChange={event => setCode(event.target.value.toUpperCase())} placeholder="XXXX-XXXX-XXXX" className="border-app-line bg-app-soft font-mono tracking-widest" />
        <p className="text-[11px] leading-4 text-app-subtle">Con Docker: <code className="font-mono">docker compose logs appsec</code>. Sirve una sola vez.</p></div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1.5"><label htmlFor="setup-user" className="text-xs text-app-muted">Usuario</label><Input id="setup-user" required autoComplete="username" pattern="[A-Za-z0-9][A-Za-z0-9._\-]{1,38}[A-Za-z0-9]" maxLength={40} value={username} onChange={event => setUsername(event.target.value)} className="border-app-line bg-app-soft" /></div>
        <div className="space-y-1.5"><label htmlFor="setup-name" className="text-xs text-app-muted">Nombre (opcional)</label><Input id="setup-name" maxLength={80} value={displayName} onChange={event => setDisplayName(event.target.value)} className="border-app-line bg-app-soft" /></div>
      </div>
      <div className="space-y-1.5"><label htmlFor="setup-password" className="text-xs text-app-muted">Contraseña (mínimo 12 caracteres)</label><Input id="setup-password" type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} className="border-app-line bg-app-soft" /></div>
      <div className="space-y-1.5"><label htmlFor="setup-confirm" className="text-xs text-app-muted">Repite la contraseña</label><Input id="setup-confirm" type="password" required minLength={12} maxLength={256} autoComplete="new-password" value={confirm} onChange={event => setConfirm(event.target.value)} className="border-app-line bg-app-soft" /></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <Button type="submit" disabled={busy} className="w-full bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <KeyRound />}Crear administrador</Button>
      <p className="text-[11px] leading-4 text-app-subtle">Después te pedirá activar el segundo factor (TOTP) con tu app de autenticación.</p>
    </form></CardContent></Card>
}
