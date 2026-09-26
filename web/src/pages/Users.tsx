import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Check, Copy, KeyRound, LoaderCircle, MoreHorizontal, ShieldCheck, ShieldOff, UserPlus } from 'lucide-react'
import type { SessionUser } from '@/features/auth/session'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { api } from '@/shared/api/http'
import { formatDate } from '@/shared/lib/types'
import { SkeletonTable } from '@/shared/ui/loading'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'

type Listing = { users: SessionUser[]; totp_policy: 'admins' | 'all' | 'none' }
type LinkResult = { user: SessionUser; link: string; expires_in_hours: number }
const roleLabel = { admin: 'role.admin', member: 'role.member' } as const
const roleHint = { admin: 'role_hint.admin', member: 'role_hint.member' } as const
const policyText = { admins: 'policy.admins', all: 'policy.all', none: 'policy.none' } as const

export function Users({ me }: { me: SessionUser }) {
  const { t } = useTranslation('users')
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
  const flags = (user: SessionUser) => [
    ...(user.disabled ? [t('flags.disabled')] : []),
    ...(user.pending_link === 'invite' ? [t('flags.invite_pending')] : user.pending_link === 'reset' ? [t('flags.reset_pending')] : !user.has_password ? [t('flags.no_password')] : []),
  ].map(flag => ` · ${flag}`).join('')

  return <div className="space-y-5">
    <Card className="border-app-line bg-panel"><CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3"><div><CardTitle>{t('title')}</CardTitle><CardDescription className="mt-1">{t('description')}{listing ? ` ${t(policyText[listing.totp_policy])}.` : ''}</CardDescription></div>
      <Button onClick={() => setInviting(true)} className="bg-primary text-primary-foreground hover:bg-primary/90"><UserPlus />{t('invite')}</Button></CardHeader>
      <CardContent className="space-y-3">
        {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">{error}</div>}
        {!listing ? <SkeletonTable rows={4} columns={5} label={t('loading')} /> : <div className="overflow-x-auto rounded-xl border border-app-line">
          <table className="w-full min-w-[760px] text-sm"><thead><tr className="border-b border-app-line text-left text-xs text-app-subtle"><th className="px-4 py-2.5 font-normal">{t('columns.user')}</th><th className="px-4 py-2.5 font-normal">{t('columns.role')}</th><th className="px-4 py-2.5 font-normal">{t('columns.second_factor')}</th><th className="px-4 py-2.5 font-normal">{t('columns.last_login')}</th><th className="px-4 py-2.5 font-normal">{t('columns.actions')}</th></tr></thead>
            <tbody>{listing.users.map(user => { const self = user.id === me.id
              return <tr key={user.id} className={`border-b border-app-line last:border-b-0 ${user.disabled ? 'opacity-60' : ''}`}>
                <td className="px-4 py-3"><div className="font-medium">{user.display_name}{self ? <span className="ml-2 text-xs font-normal text-app-subtle">{t('you')}</span> : null}</div><div className="text-xs text-app-subtle">@{user.username}{flags(user)}</div></td>
                <td className="px-4 py-3"><Select value={user.role} disabled={self || !!busy} onValueChange={value => { if (value && value !== user.role) void act(user, { action: 'role', role: value }) }}><SelectTrigger size="sm" aria-label={t('role_of', { username: user.username })} className="min-w-36 border-app-line bg-app-soft">{t(roleLabel[user.role])}</SelectTrigger><SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl"><SelectItem value="member">{t('role.member')}</SelectItem><SelectItem value="admin">{t('role.admin')}</SelectItem></SelectContent></Select></td>
                <td className="px-4 py-3">{user.totp_enabled ? <Badge variant="outline" className="border-brand/30 text-brand"><ShieldCheck className="size-3" />{t('totp_on')}</Badge> : <Badge variant="outline" className="border-app-line text-app-muted"><ShieldOff className="size-3" />{t('totp_off')}</Badge>}</td>
                <td className="px-4 py-3 text-xs text-app-muted">{user.last_login_at ? formatDate(user.last_login_at) : t('never')}</td>
                <td className="px-4 py-3"><Menu><MenuTrigger render={<Button size="icon-sm" variant="ghost" disabled={!!busy} aria-label={t('actions_for', { username: user.username })} />}>{busy === user.id ? <LoaderCircle className="animate-spin" /> : <MoreHorizontal />}</MenuTrigger>
                  <MenuContent>
                    <MenuItem disabled={user.disabled} onClick={() => void act(user, { action: 'reset' })}><KeyRound />{user.has_password ? t('send_reset') : t('resend_invite')}</MenuItem>
                    {user.totp_enabled && !self && <MenuItem onClick={() => void act(user, { action: 'reset_totp' })}><ShieldOff />{t('remove_totp')}</MenuItem>}
                    {!self && <MenuItem onClick={() => void act(user, { action: user.disabled ? 'enable' : 'disable' })}>{user.disabled ? t('enable') : t('disable')}</MenuItem>}
                  </MenuContent></Menu></td>
              </tr> })}</tbody></table>
        </div>}
        <p className="text-xs leading-5 text-app-subtle">{t('footnote')}</p>
      </CardContent></Card>
    <InviteDialog open={inviting} onClose={() => setInviting(false)} onInvited={result => { setInviting(false); setLink(result); void load() }} />
    <LinkDialog result={link} onClose={() => setLink(null)} />
  </div>
}

function InviteDialog({ open, onClose, onInvited }: { open: boolean; onClose: () => void; onInvited: (result: LinkResult) => void }) {
  const { t } = useTranslation('users')
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
    <DialogHeader><DialogTitle>{t('invite_dialog.title')}</DialogTitle><DialogDescription>{t('invite_dialog.description')}</DialogDescription></DialogHeader>
    <form className="space-y-4" onSubmit={submit}>
      <div className="space-y-1.5"><label htmlFor="invite-user" className="text-xs text-app-muted">{t('invite_dialog.username')}</label><Input id="invite-user" required autoFocus pattern="[A-Za-z0-9][A-Za-z0-9._\-]{1,38}[A-Za-z0-9]" maxLength={40} value={username} onChange={event => setUsername(event.target.value)} placeholder={t('invite_dialog.username_placeholder')} className="border-app-line bg-app-soft" /><p className="text-[11px] text-app-subtle">{t('invite_dialog.username_hint')}</p></div>
      <div className="space-y-1.5"><label htmlFor="invite-name" className="text-xs text-app-muted">{t('invite_dialog.display_name')}</label><Input id="invite-name" maxLength={80} value={displayName} onChange={event => setDisplayName(event.target.value)} placeholder={t('invite_dialog.display_name_placeholder')} className="border-app-line bg-app-soft" /></div>
      <div className="space-y-1.5"><span className="text-xs text-app-muted">{t('invite_dialog.role')}</span><div className="grid grid-cols-2 gap-2">{(['member', 'admin'] as const).map(value => <button key={value} type="button" onClick={() => setRole(value)} className={`rounded-lg border p-3 text-left text-sm ${role === value ? 'border-brand/50 bg-brand/10' : 'border-app-line bg-app-soft'}`}><span className="block font-medium">{t(roleLabel[value])}</span><span className="text-xs text-app-subtle">{t(roleHint[value])}</span></button>)}</div></div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{t('common:actions.cancel')}</Button><Button type="submit" disabled={busy || username.trim().length < 3} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy && <LoaderCircle className="animate-spin" />}{t('invite_dialog.submit')}</Button></DialogFooter>
    </form>
  </DialogContent></Dialog>
}

function LinkDialog({ result, onClose }: { result: LinkResult | null; onClose: () => void }) {
  const { t } = useTranslation('users')
  const [copied, setCopied] = useState(false)
  if (!result) return null
  const copy = async () => { await navigator.clipboard.writeText(result.link); setCopied(true); window.setTimeout(() => setCopied(false), 1500) }
  return <Dialog open onOpenChange={next => { if (!next) onClose() }}><DialogContent className="max-w-lg">
    <DialogHeader><DialogTitle>{t('link_dialog.title', { username: result.user.username })}</DialogTitle><DialogDescription>{t('link_dialog.description', { count: result.expires_in_hours })}</DialogDescription></DialogHeader>
    <code className="block rounded-lg bg-inset p-3 font-mono text-xs break-all text-app-secondary">{result.link}</code>
    <DialogFooter><Button variant="outline" onClick={() => void copy()} className="border-app-line bg-app-soft">{copied ? <Check /> : <Copy />}{copied ? t('common:actions.copied') : t('link_dialog.copy')}</Button><span role="status" className="sr-only">{copied ? t('link_dialog.copied_to_clipboard') : ''}</span><Button onClick={onClose} className="bg-primary text-primary-foreground hover:bg-primary/90">{t('link_dialog.done')}</Button></DialogFooter>
  </DialogContent></Dialog>
}
