import { useQuery, useQueryClient } from '@tanstack/react-query'
import { keys, slaQuery } from '@/shared/api/queries'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Clock3, LoaderCircle, Pencil } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import type { SlaPolicy } from '@/features/findings/sla'
import { formatDate } from '@/shared/lib/types'

const LEVELS = [['critical', 'common:severity.critical'], ['high', 'common:severity.high'], ['medium', 'common:severity.medium'], ['low', 'common:severity.low']] as const
type Level = typeof LEVELS[number][0]

// Plazos de corrección del espacio de trabajo: explican las fechas límite de Hallazgos. Los ve cualquiera;
// los cambia un administrador. Vacío = esa severidad no vence.
export function SlaPolicyCard({ canEdit, onChanged }: { canEdit: boolean; onChanged: () => void }) {
  const { t } = useTranslation('findings')
  const queryClient = useQueryClient()
  const policy: SlaPolicy | null = useQuery(slaQuery()).data ?? null
  const setPolicy = (next: SlaPolicy) => queryClient.setQueryData(keys.sla, next)
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<Record<Level, string>>({ critical: '', high: '', medium: '', low: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const start = () => {
    if (!policy) return
    setDraft(Object.fromEntries(LEVELS.map(([level]) => [level, policy.days[level] ? String(policy.days[level]) : ''])) as Record<Level, string>)
    setError(''); setEditing(true)
  }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    const days = Object.fromEntries(LEVELS.map(([level]) => [level, draft[level].trim() ? Number(draft[level]) : null]))
    if (Object.values(days).some(value => value !== null && (!Number.isInteger(value) || value < 1 || value > 3650))) {
      setError(t('sla_policy.invalid'))
      return
    }
    setBusy(true); setError('')
    try {
      setPolicy(await api.post<SlaPolicy>('/api/sla', 'sla', { days }))
      setEditing(false)
      onChanged()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  if (!policy) return null
  const summary = LEVELS.map(([level, label]) => t('sla_policy.summary_item', { level: t(label).toLowerCase(), value: policy.days[level] ? t('sla_policy.days_short', { days: policy.days[level] }) : t('sla_policy.no_deadline') })).join(' · ')
  return <div className="rounded-xl border border-app-line bg-inset px-4 py-3 text-sm">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 items-start gap-2">
        <Clock3 aria-hidden className="mt-0.5 size-4 shrink-0 text-app-subtle" />
        <div className="min-w-0">
          <p className="font-medium text-app-secondary">{t('sla_policy.title')} <span className="font-normal text-app-muted">{summary}</span></p>
          <p className="mt-1 text-xs leading-5 text-app-subtle">{t('sla_policy.scope')}{' '}
            {policy.updated_by ? policy.updated_at ? t('sla_policy.changed_by_at', { by: policy.updated_by, date: formatDate(policy.updated_at) }) : t('sla_policy.changed_by', { by: policy.updated_by }) : t('sla_policy.defaults')}{canEdit ? '' : ` ${t('sla_policy.admin_only')}`}</p>
        </div>
      </div>
      {canEdit && !editing && <Button size="sm" variant="outline" onClick={start}><Pencil />{t('common:actions.edit')}</Button>}
    </div>
    {editing && <form onSubmit={save} className="mt-3 space-y-2">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">{LEVELS.map(([level, label]) => <label key={level} className="text-xs text-app-muted">{t('sla_policy.days_label', { level: t(label) })}
        <Input type="number" inputMode="numeric" min={1} max={3650} value={draft[level]} onChange={event => setDraft(current => ({ ...current, [level]: event.target.value }))}
          placeholder={t('sla_policy.placeholder')} aria-invalid={!!error || undefined} className="mt-1 h-9 border-app-line bg-app tabular-nums" /></label>)}</div>
      <p className="text-xs text-app-subtle">{t('sla_policy.help')}</p>
      {error && <p role="alert" className="text-xs text-danger">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => setEditing(false)} disabled={busy}>{t('common:actions.cancel')}</Button>
      </div>
    </form>}
  </div>
}
