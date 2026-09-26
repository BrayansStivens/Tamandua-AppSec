import { useId, useState, type FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Clock3, LoaderCircle, Pencil } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { api } from '@/shared/api/http'
import { keys, slaQuery } from '@/shared/api/queries'
import type { SlaPolicy } from '@/features/findings/sla'
import { PolicyRow } from '@/features/policies/policy-row'
import { formatDate } from '@/shared/lib/types'

const LEVELS = [['critical', 'common:severity.critical'], ['high', 'common:severity.high'], ['medium', 'common:severity.medium'], ['low', 'common:severity.low']] as const
type Level = typeof LEVELS[number][0]

// Remediation deadlines: always global, they explain the due dates in Findings. Anyone reads them; an admin changes
// them. Empty = that severity never comes due.
export function SlaPolicyRow({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation('policies')
  const id = useId()
  const queryClient = useQueryClient()
  const query = useQuery(slaQuery())
  const policy: SlaPolicy | undefined = query.data
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState<Record<Level, string>>({ critical: '', high: '', medium: '', low: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const start = () => {
    if (!policy) return
    setDraft(Object.fromEntries(LEVELS.map(([level]) => [level, policy.days[level] ? String(policy.days[level]) : ''])) as Record<Level, string>)
    setError(''); setNotice(''); setOpen(true)
  }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    const days = Object.fromEntries(LEVELS.map(([level]) => [level, draft[level].trim() ? Number(draft[level]) : null]))
    if (Object.values(days).some(value => value !== null && (!Number.isInteger(value) || value < 1 || value > 3650))) {
      setError(t('sla.invalid'))
      return
    }
    setBusy(true); setError('')
    try {
      queryClient.setQueryData(keys.sla, await api.post<SlaPolicy>('/api/sla', 'sla', { days }))
      setOpen(false); setNotice(t('sla.saved'))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  const summary = policy && LEVELS.map(([level, label]) => t('sla.summary_item', { level: t(label), value: policy.days[level] ? t('sla.days_short', { days: policy.days[level] }) : t('sla.no_deadline') })).join(' · ')
  const changed = policy?.updated_by ? policy.updated_at ? t('sla.changed_by_at', { by: policy.updated_by, date: formatDate(policy.updated_at) }) : t('sla.changed_by', { by: policy.updated_by }) : t('sla.defaults')
  return <>
    <PolicyRow icon={Clock3} title={t('sla.title')} summary={summary} notice={notice} state={policy ? 'ready' : query.isError ? 'error' : 'loading'}
      onRetry={() => void query.refetch()} action={canEdit && <Button size="sm" variant="outline" onClick={start}><Pencil />{t('common:actions.edit')}</Button>} />
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{t('sla.title')}</DialogTitle>
          <DialogDescription>{t('sla.dialog_help')}</DialogDescription>
        </DialogHeader>
        <form onSubmit={save} className="space-y-3" noValidate>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">{LEVELS.map(([level, label]) => <div key={level} className="space-y-1">
            <label htmlFor={`${id}-${level}`} className="text-xs text-app-muted">{t('sla.days_label', { level: t(label) })}</label>
            <Input id={`${id}-${level}`} type="number" inputMode="numeric" min={1} max={3650} value={draft[level]} onChange={event => setDraft(current => ({ ...current, [level]: event.target.value }))}
              placeholder={t('sla.placeholder')} aria-invalid={!!error || undefined} aria-describedby={error ? `${id}-error` : undefined} className="h-9 border-app-line bg-app tabular-nums" />
          </div>)}</div>
          <p className="text-xs text-app-subtle">{changed}</p>
          {error && <p id={`${id}-error`} role="alert" className="text-xs text-danger">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => setOpen(false)} disabled={busy}>{t('common:actions.cancel')}</Button>
            <Button type="submit" disabled={busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  </>
}
