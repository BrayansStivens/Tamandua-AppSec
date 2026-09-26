import { useRef, useState, type FormEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { Check, CircleCheck, Copy, ExternalLink, FileKey2, LoaderCircle, RefreshCw, ShieldCheck, TriangleAlert, Upload } from 'lucide-react'
import { Button, buttonVariants } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import { BRAND } from '@/shared/lib/brand'

export type PermissionReview = { required: Record<string, string>; declared: Record<string, string>; granted: Record<string, string>; excess: string[]; missing: string[]; pending_acceptance: string[] }
export type GitHubStatus = {
  configured: boolean; missing: string[]; connected: boolean; app_id: string; slug: string; owner: string | null; name: string | null; html_url: string | null
  source: 'environment' | 'vault' | null; public_url: string; permissions?: PermissionReview | null; required_permissions: Record<string, string>
  installation: GitHubInstallation | null; installations: GitHubInstallation[]
  available_installations?: { installation_id: number; account: string | null; account_type: string | null; repository_selection: string | null; connected: boolean }[]
}

export type GitHubInstallation = { installation_id: number; account: string | null; account_type: string | null; repository_selection: 'all' | 'selected' | null; permissions: Record<string, string>; connected_by: string | null; connected_at: string; permission_review?: PermissionReview }

// GitHub's own UI labels, shown as they appear on GitHub.
const PERMISSION_LABEL: Record<string, string> = { contents: 'Contents', metadata: 'Metadata', pull_requests: 'Pull requests', statuses: 'Commit statuses' }
const LEVEL_LABEL: Record<string, string> = { read: 'Read-only', write: 'Read and write' }
const STRONG = <strong className="font-medium text-app-secondary" />

function CopyValue({ value }: { value: string }) {
  const { t } = useTranslation('sources')
  const [copied, setCopied] = useState(false)
  return <span className="inline-flex max-w-full items-center gap-1 rounded-md border border-app-line bg-app-soft py-0.5 pr-0.5 pl-2 align-middle">
    <code className="truncate font-mono text-[11px]">{value}</code>
    <button type="button" aria-label={t('github.copy_value', { value })} onClick={() => { void navigator.clipboard.writeText(value).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1200) }) }}
      className="grid size-6 place-items-center rounded text-app-subtle hover:bg-accent hover:text-app-fg">{copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}</button>
    <span role="status" className="sr-only">{copied ? t('copied_to_clipboard') : ''}</span>
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
  const { t } = useTranslation('sources')
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
    if (selected.size > 16000) { setError(t('github.pem_too_large')); return }
    const text = await selected.text()
    if (!text.includes('PRIVATE KEY')) { setError(t('github.pem_invalid')); return }
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
      <Step number={1} title={t('github.steps.open.title')}>
        <p>{t('github.steps.open.body')}</p>
        <div className="flex flex-wrap items-center gap-2"><Input aria-label={t('github.steps.open.organization')} value={org} onChange={event => setOrg(event.target.value.replace(/[^A-Za-z0-9-]/g, ''))} maxLength={39} placeholder={t('github.steps.open.organization_placeholder')} className="h-8 w-48 border-app-line bg-app-soft text-xs" />
          <a href={createUrl} target="_blank" rel="noopener noreferrer" className={buttonVariants({ size: 'sm', variant: 'outline', className: 'border-app-line bg-app-soft' })}>{t('github.steps.open.open_github')} <ExternalLink /><span className="sr-only">{t('new_tab')}</span></a></div>
      </Step>
      <Step number={2} title={t('github.steps.name.title')}>
        <p><Trans t={t} i18nKey="github.steps.name.app_name" components={{ b: STRONG, copy: <CopyValue value={t('github.steps.name.app_name_example', { brand: BRAND.name })} /> }} /></p>
        <p><Trans t={t} i18nKey="github.steps.name.homepage" components={{ b: STRONG, copy: <CopyValue value={base.startsWith('https://') ? base : `https://github.com/${org.trim() || t('github.steps.name.your_user')}`} /> }} /></p>
      </Step>
      <Step number={3} title={t('github.steps.hooks.title')}>
        <p><Trans t={t} i18nKey="github.steps.hooks.callback" components={{ b: STRONG }} /></p>
        <p><Trans t={t} i18nKey="github.steps.hooks.setup" components={{ b: STRONG, copy: <CopyValue value={`${base}/oauth/callback`} /> }} /></p>
        <p><Trans t={t} i18nKey="github.steps.hooks.webhook" components={{ b: STRONG }} /></p>
      </Step>
      <Step number={4} title={t('github.steps.permissions.title')}>
        <p><Trans t={t} i18nKey="github.steps.permissions.intro" components={{ i: <em /> }} /></p>
        <ul className="space-y-1">{Object.entries(status.required_permissions).map(([name, level]) => <li key={name} className="flex items-center justify-between gap-3 rounded-md border border-app-line px-2.5 py-1"><span className="text-app-secondary">{PERMISSION_LABEL[name] ?? name}</span><span className="font-mono text-[11px]">{LEVEL_LABEL[level] ?? level}</span></li>)}</ul>
        <p><Trans t={t} i18nKey="github.steps.permissions.outro" components={{ i: <em /> }} /></p>
      </Step>
      <Step number={5} title={t('github.steps.install_scope.title')}>
        <p><Trans t={t} i18nKey="github.steps.install_scope.body" components={{ b: STRONG }} /></p>
      </Step>
      <Step number={6} title={t('github.steps.key.title')}>
        <p><Trans t={t} i18nKey="github.steps.key.body" components={{ b: STRONG, code: <code className="font-mono" /> }} /></p>
      </Step>
    </ol>

    <form onSubmit={submit} className="space-y-4 self-start rounded-xl border border-app-line bg-panel p-4">
      <div><p className="text-sm font-medium">{t('github.form.title')}</p><p className="mt-1 text-xs leading-5 text-app-muted">{t('github.form.description')}</p></div>
      {!canManage && <p className="rounded-lg border border-app-line bg-app-soft px-3 py-2 text-xs text-app-muted">{t('github.form.admin_only')}</p>}
      {status.source === 'environment' && <p className="rounded-lg border border-warning-line bg-warning-soft px-3 py-2 text-xs text-warning"><Trans t={t} i18nKey="github.form.env_missing" values={{ missing: status.missing.join(', ') }} components={{ code: <code className="font-mono" /> }} /></p>}
      <div className="space-y-1.5"><label htmlFor="github-app-id" className="text-xs text-app-muted">{t('github.form.app_id')}</label>
        <Input id="github-app-id" required inputMode="numeric" pattern="[1-9][0-9]{0,11}" maxLength={12} disabled={!canManage} value={appId} onChange={event => setAppId(event.target.value.replace(/\D/g, ''))} placeholder="123456" className="border-app-line bg-app-soft font-mono" /></div>
      <div className="space-y-1.5"><span className="text-xs text-app-muted">{t('github.form.private_key')}</span>
        <input ref={file} type="file" accept=".pem,application/x-pem-file,application/x-x509-ca-cert" className="sr-only" id="github-app-pem" disabled={!canManage} onChange={event => void readFile(event.target.files?.[0])} />
        <label htmlFor="github-app-pem" className={`flex cursor-pointer items-center gap-3 rounded-lg border border-dashed px-3 py-3 text-sm ${pem ? 'border-app-line bg-app-soft' : 'border-app-faint/50 hover:bg-app-soft'}`}>
          {pem ? <FileKey2 className="size-4 shrink-0 text-app-secondary" /> : <Upload className="size-4 shrink-0 text-app-subtle" />}
          <span className="min-w-0 truncate">{pem ? pemName || t('github.form.key_loaded') : t('github.form.choose_file')}</span>
        </label>
        <details className="text-xs"><summary className="cursor-pointer text-app-subtle">{t('github.form.paste')}</summary>
          <textarea aria-label={t('github.form.paste_label')} rows={4} spellCheck={false} autoComplete="off" disabled={!canManage} value={pemName ? '' : pem} onChange={event => { setPem(event.target.value); setPemName('') }}
            placeholder="-----BEGIN RSA PRIVATE KEY-----" className="mt-2 w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 font-mono text-[11px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50" /></details>
      </div>
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
      <Button type="submit" disabled={!canManage || busy || !appId || !pem} className="w-full bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{t('github.form.submit')}</Button>
      <p className="flex items-start gap-2 text-[11px] leading-4 text-app-subtle"><ShieldCheck className="mt-0.5 size-3 shrink-0" />{t('github.form.key_note')}</p>
    </form>
  </div>
}

// Paso siguiente: la App existe y hay que instalarla en la cuenta eligiendo repositorios.
export function GitHubInstall({ status, canManage, onChanged }: { status: GitHubStatus; canManage: boolean; onChanged: (next: GitHubStatus) => void }) {
  const { t } = useTranslation('sources')
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
  const bold = { b: <strong className="font-medium" /> }
  return <div className="mt-4 space-y-3">
    <div className="flex items-start gap-2 rounded-lg border border-app-line bg-app-soft px-3 py-2.5 text-sm"><CircleCheck className="mt-0.5 size-4 shrink-0 text-brand" />
      <span>{status.owner
        ? <Trans t={t} i18nKey="github.install.verified_owner" values={{ name: status.name ?? status.slug, owner: status.owner }} components={bold} />
        : <Trans t={t} i18nKey="github.install.verified" values={{ name: status.name ?? status.slug }} components={bold} />} {status.connected ? t('github.install.next_connected') : t('github.install.next_first')}</span></div>
    {review && (review.excess.length > 0 || review.missing.length > 0) && <PermissionWarning review={review} />}
    <ol className="ml-4 list-decimal space-y-1 text-xs leading-5 text-app-muted">
      <li><Trans t={t} i18nKey="github.install.step_install" components={{ b: STRONG }} /></li>
      <li><Trans t={t} i18nKey="github.install.step_detect" components={{ b: STRONG }} /></li>
    </ol>
    {error && <div role="alert" className="rounded-lg border border-warning-line bg-warning-soft px-3 py-2 text-xs text-warning">{error}</div>}
    <div className="flex flex-wrap gap-2">
      {canManage ? <a href={`https://github.com/apps/${status.slug}/installations/new`} target="_blank" rel="noopener noreferrer" className={buttonVariants({ className: 'bg-primary text-primary-foreground hover:bg-primary/90' })}>{t('github.install.install')} <ExternalLink /><span className="sr-only">{t('new_tab')}</span></a>
        : <Button disabled className="bg-primary text-primary-foreground">{t('github.install.install')} <ExternalLink /></Button>}
      <Button variant="outline" disabled={!canManage || busy} onClick={() => void detect()} className="border-app-line bg-app-soft">{busy ? <LoaderCircle className="animate-spin" /> : <RefreshCw />}{t('github.install.detect')}</Button>
    </div>
    {available.length > 0 && <div className="space-y-2 rounded-lg border border-app-line bg-app-soft p-3">
      <p className="text-xs font-medium text-app-secondary">{t('github.install.installed_on')}</p>
      {available.map(item => {
        const connected = status.installations.some(current => current.installation_id === item.installation_id)
        return <div key={item.installation_id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-app-line bg-panel px-3 py-2 text-sm">
          <div><p className="font-medium">{item.account ?? t('github.install.installation', { id: item.installation_id })}</p>
            <p className="text-xs text-app-muted">{item.account_type === 'Organization' ? t('github.install.organization') : t('github.install.personal')} · {item.repository_selection === 'selected' ? t('github.install.selected_repositories') : t('github.install.all_repositories')}</p></div>
          <Button size="sm" variant={connected ? 'outline' : 'default'} disabled={busy || !canManage || connected} onClick={() => void connect(item.installation_id)}>
            {connected ? t('github.install.connected') : t('github.install.connect')}
          </Button>
        </div>
      })}
    </div>}
  </div>
}

export function PermissionWarning({ review }: { review: PermissionReview }) {
  const { t } = useTranslation('sources')
  if (review.excess.length) return <div role="alert" className="flex gap-2 rounded-lg border border-danger-line bg-danger-soft p-3 text-xs leading-5 text-danger"><TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
    <div><strong>{t('github.permission_warning.excess', { count: review.excess.length })}</strong> {t('github.permission_warning.excess_body')}<details className="mt-1"><summary className="cursor-pointer font-medium">{t('github.permission_warning.show')}</summary><p className="mt-1 break-words">{review.excess.map(name => `${name}: ${review.declared[name]}`).join(' · ')}</p></details></div></div>
  const permissions = review.missing.join(', ')
  return <div className="flex gap-2 rounded-lg border border-warning-line bg-warning-soft p-3 text-xs leading-5 text-warning"><TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
    <span>{review.pending_acceptance.length ? t('github.permission_warning.missing_pending', { permissions }) : t('github.permission_warning.missing', { permissions })}</span></div>
}
