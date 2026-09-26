import { useId, useState, type FormEvent, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { Eye, FolderMinus, KeyRound, LoaderCircle, Pencil } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Bone } from '@/shared/ui/loading'
import { api } from '@/shared/api/http'
import { apiPost } from '@/shared/api/client'
import { assetSecretsQuery, exclusionsQuery, keys, type Exclusions } from '@/shared/api/queries'
import { SecretRulesDialog } from '@/features/findings/secret-rules'
import { entryCount, secretCounts, secretSummary } from '@/features/findings/secret-summary'
import { formatDate } from '@/shared/lib/types'

type Saved = Exclusions & { moved: { excluded: number; reopened: number } }
const SHOWN = 2

// A repository's own settings in one strip: excluded paths and its secret detection entries (on top of the defaults).
// Deadlines are global: only a link to the policy.
export function RepositorySettings({ assetKey, name, secrets, canEdit, onChanged, onOpenPolicies }: {
  assetKey: string; name: string; secrets: boolean; canEdit: boolean; onChanged: () => void; onOpenPolicies: () => void
}) {
  const { t } = useTranslation('findings')
  const id = useId()
  const [notice, setNotice] = useState('')
  // Same queries as the entries below (shared cache): only to announce the loading once.
  const pathsPending = useQuery(exclusionsQuery(assetKey)).isPending
  const secretsPending = useQuery({ ...assetSecretsQuery(assetKey), enabled: secrets }).isPending
  const loading = pathsPending || (secrets && secretsPending)
  return <section aria-labelledby={id} className="rounded-xl border border-app-line bg-inset px-4 py-2.5 text-sm">
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
      <h2 id={id} className="text-xs font-medium text-app-subtle">{t('repo_settings.title')}</h2>
      <ExcludedPaths assetKey={assetKey} canEdit={canEdit} onSaved={message => { setNotice(message); onChanged() }} />
      {secrets && <RepositorySecrets assetKey={assetKey} name={name} canEdit={canEdit} onSaved={setNotice} />}
      <Button size="xs" variant="link" className="ml-auto px-0 text-app-muted" onClick={onOpenPolicies}>{t('repo_settings.deadlines')}</Button>
    </div>
    <p role="status" className="mt-1 text-xs text-brand empty:hidden">{notice}</p>
    {loading && <span role="status" className="sr-only">{t('common:state.loading')}</span>}
  </section>
}

// Loading: a bone the size of the summary (the strip announces it once). Error: said, with a retry.
function Status({ query }: { query: { isError: boolean; refetch: () => unknown } }) {
  const { t } = useTranslation('findings')
  if (!query.isError) return <Bone className="h-4 w-24" />
  return <span role="alert" className="flex items-center gap-2 text-danger">{t('repo_settings.load_failed')}
    <Button size="xs" variant="outline" onClick={() => void query.refetch()}>{t('common:actions.retry')}</Button></span>
}

function Setting({ icon: Icon, label, children, action }: { icon: LucideIcon; label: string; children: ReactNode; action: ReactNode }) {
  return <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
    <Icon aria-hidden className="size-4 shrink-0 text-app-subtle" />
    <span className="font-medium text-app-secondary">{label}</span>
    <span className="flex min-w-0 flex-wrap items-center gap-1 text-app-muted">{children}</span>
    {action}
  </div>
}

function ExcludedPaths({ assetKey, canEdit, onSaved }: { assetKey: string; canEdit: boolean; onSaved: (notice: string) => void }) {
  const { t } = useTranslation('findings')
  const id = useId()
  const queryClient = useQueryClient()
  const query = useQuery(exclusionsQuery(assetKey))
  const state = query.data
  const [open, setOpen] = useState(false)
  const [text, setText] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const start = () => { setText((state?.patterns ?? []).join('\n')); setReason(state?.reason ?? ''); setError(''); setOpen(true) }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true); setError('')
    try {
      const patterns = text.split('\n').map(line => line.trim()).filter(Boolean)
      const saved = await api.post<Saved>('/api/assets/exclusions', 'save-exclusions', { key: assetKey, patterns, reason: reason.trim() })
      queryClient.setQueryData(keys.exclusions(assetKey), saved)
      setOpen(false)
      const excluded = saved.moved.excluded ? t('exclusions.moved_excluded', { count: saved.moved.excluded }) : ''
      const reopened = saved.moved.reopened ? t('exclusions.moved_reopened', { count: saved.moved.reopened }) : ''
      onSaved(excluded && reopened ? t('exclusions.moved_both', { excluded, reopened }) : excluded || reopened || t('exclusions.saved'))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  const patterns = state?.patterns ?? []
  const summary = !state ? <Status query={query} />
    : patterns.length ? <>{patterns.slice(0, SHOWN).map(item => <code key={item} className="rounded border border-app-line bg-app px-1.5 py-0.5 font-mono text-xs">{item}</code>)}
      {patterns.length > SHOWN && <span className="text-xs">{t('repo_settings.more', { count: patterns.length - SHOWN })}</span>}</>
    : t('repo_settings.none')
  const action = state && (canEdit ? <Button size="xs" variant="outline" onClick={start}><Pencil />{t('common:actions.edit')}</Button>
    : patterns.length > SHOWN && <Button size="xs" variant="outline" onClick={start}><Eye />{t('repo_settings.view')}</Button>)
  return <>
    <Setting icon={FolderMinus} label={t('repo_settings.paths')} action={action}>{summary}</Setting>
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{t('exclusions.title')}</DialogTitle>
          <DialogDescription>{t('exclusions.dialog_help')}</DialogDescription>
        </DialogHeader>
        {state?.by && <p className="text-xs text-app-subtle">{t('exclusions.last_change', { reason: state.reason ?? '—', by: state.by, date: state.at ? formatDate(state.at) : '—' })}</p>}
        {canEdit ? <form onSubmit={save} className="space-y-3" noValidate>
          <div className="space-y-1">
            <label className="block text-xs text-app-muted" htmlFor={`${id}-patterns`}><Trans t={t} i18nKey="exclusions.patterns_help" components={{ code: <code className="font-mono" /> }} /></label>
            <textarea id={`${id}-patterns`} value={text} onChange={event => setText(event.target.value)} rows={5} spellCheck={false} placeholder="fixtures"
              className="w-full rounded-lg border border-app-line bg-app px-3 py-2 font-mono text-xs text-app-fg" />
          </div>
          <div className="space-y-1">
            <label htmlFor={`${id}-reason`} className="text-xs text-app-muted">{t('exclusions.reason')}</label>
            <Input id={`${id}-reason`} value={reason} onChange={event => setReason(event.target.value)} maxLength={300} placeholder={t('exclusions.reason_placeholder')}
              aria-describedby={error ? `${id}-error` : undefined} className="h-9 border-app-line bg-app" />
          </div>
          {error && <p id={`${id}-error`} role="alert" className="text-xs text-danger">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => setOpen(false)} disabled={busy}>{t('common:actions.cancel')}</Button>
            <Button type="submit" disabled={busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
          </DialogFooter>
        </form> : <p className="flex flex-wrap gap-1.5">{patterns.map(item => <code key={item} className="rounded border border-app-line bg-app px-1.5 py-0.5 font-mono text-xs">{item}</code>)}</p>}
      </DialogContent>
    </Dialog>
  </>
}

function RepositorySecrets({ assetKey, name, canEdit, onSaved }: { assetKey: string; name: string; canEdit: boolean; onSaved: (notice: string) => void }) {
  const { t } = useTranslation('findings')
  const queryClient = useQueryClient()
  const query = useQuery(assetSecretsQuery(assetKey))
  const config = query.data
  const [open, setOpen] = useState(false)
  const own = config ? entryCount(secretCounts(config)) : 0
  const summary = !config ? <Status query={query} />
    : own ? t('repo_settings.secrets_custom', { count: own }) : t('repo_settings.secrets_defaults')
  const action = config && <Button size="xs" variant="outline" onClick={() => setOpen(true)}>
    {canEdit ? <><Pencil />{own ? t('common:actions.edit') : t('repo_settings.customize')}</> : <><Eye />{t('repo_settings.view')}</>}</Button>
  return <>
    <Setting icon={KeyRound} label={t('repo_settings.secrets')} action={action}>{summary}</Setting>
    {config && <SecretRulesDialog open={open} onOpenChange={setOpen} title={t('repo_settings.secrets_title', { name })} description={t('repo_settings.secrets_help')}
      config={config} canEdit={canEdit} save={body => apiPost('/api/assets/secrets', 'save-asset-secret-rules', { ...body, key: assetKey })}
      onSaved={saved => { queryClient.setQueryData(keys.assetSecrets(assetKey), saved); setOpen(false); onSaved(t('secret_rules.saved')) }}>
      <p className="text-xs text-app-subtle">{entryCount(config.defaults) ? t('repo_settings.defaults_line', { summary: secretSummary(t, config.defaults) }) : t('repo_settings.defaults_none')}</p>
    </SecretRulesDialog>}
  </>
}
