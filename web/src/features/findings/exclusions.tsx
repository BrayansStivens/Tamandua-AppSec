import { useEffect, useState, type FormEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { FolderMinus, LoaderCircle, Pencil } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { api, query } from '@/shared/api/http'
import { formatDate } from '@/shared/lib/types'

type Exclusions = { patterns: string[]; reason: string | null; by: string | null; at: string | null }
type Saved = Exclusions & { moved: { excluded: number; reopened: number } }

// Rutas que un administrador decide no mirar (ejemplos vulnerables a propósito, código generado…).
// Viven en el servidor, no en el repositorio: un PR no puede excluirse a sí mismo.
export function ExclusionsCard({ assetKey, canEdit, onChanged }: { assetKey: string; canEdit: boolean; onChanged: () => void }) {
  const { t } = useTranslation('findings')
  const [state, setState] = useState<Exclusions | null>(null)
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  // Un repositorio distinto monta un componente nuevo (key en el padre): aquí solo se carga.
  useEffect(() => {
    api.get<Exclusions>(`/api/assets/exclusions?${query({ key: assetKey })}`).then(setState).catch(() => setState({ patterns: [], reason: null, by: null, at: null }))
  }, [assetKey])

  const start = () => { setText((state?.patterns ?? []).join('\n')); setReason(state?.reason ?? ''); setError(''); setNotice(''); setEditing(true) }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true); setError('')
    try {
      const patterns = text.split('\n').map(line => line.trim()).filter(Boolean)
      const saved = await api.post<Saved>('/api/assets/exclusions', 'save-exclusions', { key: assetKey, patterns, reason: reason.trim() })
      setState(saved); setEditing(false)
      const excluded = saved.moved.excluded ? t('exclusions.moved_excluded', { count: saved.moved.excluded }) : ''
      const reopened = saved.moved.reopened ? t('exclusions.moved_reopened', { count: saved.moved.reopened }) : ''
      setNotice(excluded && reopened ? t('exclusions.moved_both', { excluded, reopened }) : excluded || reopened || t('exclusions.saved'))
      onChanged()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  if (!state) return null
  const active = state.patterns.length > 0
  return <div className="rounded-xl border border-app-line bg-inset px-4 py-3 text-sm">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 items-start gap-2">
        <FolderMinus className="mt-0.5 size-4 shrink-0 text-app-subtle" />
        <div className="min-w-0">
          <p className="font-medium text-app-secondary">{active ? t('exclusions.title') : t('exclusions.title_none')}</p>
          {active && <p className="mt-1 flex flex-wrap gap-1.5">{state.patterns.map(item => <code key={item} className="rounded border border-app-line bg-app px-1.5 py-0.5 font-mono text-xs">{item}</code>)}</p>}
          {active && <p className="mt-1 text-xs leading-5 text-app-subtle">{state.reason}{state.by ? ` · ${state.by}` : ''}{state.at ? `, ${formatDate(state.at)}` : ''}. {t('exclusions.active_help')}</p>}
          {!active && <p className="mt-1 text-xs leading-5 text-app-subtle">{t('exclusions.empty_help')}{canEdit ? '' : ` ${t('exclusions.admin_only')}`}</p>}
        </div>
      </div>
      {canEdit && !editing && <Button size="sm" variant="outline" onClick={start}><Pencil />{active ? t('common:actions.edit') : t('exclusions.exclude')}</Button>}
    </div>
    {notice && <p className="mt-2 text-xs text-brand">{notice}</p>}
    {editing && <form onSubmit={save} className="mt-3 space-y-2">
      <label className="block text-xs text-app-muted" htmlFor="exclusion-patterns"><Trans t={t} i18nKey="exclusions.patterns_help" components={{ code: <code className="font-mono" /> }} /></label>
      <textarea id="exclusion-patterns" value={text} onChange={event => setText(event.target.value)} rows={4} spellCheck={false}
        className="w-full rounded-lg border border-app-line bg-app px-3 py-2 font-mono text-xs outline-none focus-visible:ring-2 focus-visible:ring-brand/40" placeholder="fixtures" />
      <Input value={reason} onChange={event => setReason(event.target.value)} maxLength={300} placeholder={t('exclusions.reason_placeholder')} aria-label={t('exclusions.reason')} />
      {error && <p role="alert" className="text-xs text-danger">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy}>{busy && <LoaderCircle className="animate-spin" />}{t('common:actions.save')}</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => setEditing(false)} disabled={busy}>{t('common:actions.cancel')}</Button>
      </div>
    </form>}
  </div>
}
