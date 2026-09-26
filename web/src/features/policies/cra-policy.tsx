import { useId, useState, type FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Landmark, LoaderCircle, Power } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { apiPost } from '@/shared/api/client'
import { craPolicyQuery, keys } from '@/shared/api/queries'
import { pagedKey } from '@/shared/lib/usePaged'
import { formatDate } from '@/shared/i18n/format'
import { PolicyRow } from '@/features/policies/policy-row'

const REASON_MIN = 5
const HISTORY_SHOWN = 5

// CRA opt-in: only manufacturers that sell products with software in the EU need the reporting kit. Off by default;
// turning it off hides the kit and keeps its data. An admin changes it, with a reason kept in the history.
export function CraPolicyRow({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation('policies')
  const id = useId()
  const queryClient = useQueryClient()
  const query = useQuery(craPolicyQuery())
  const policy = query.data
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const next = !policy?.enabled

  const start = () => { setReason(''); setError(''); setNotice(''); setOpen(true) }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (reason.trim().length < REASON_MIN) { setError(t('cra.reason_short', { min: REASON_MIN })); return }
    setBusy(true); setError('')
    try {
      const saved = await apiPost('/api/policies/cra', 'cra-policy', { enabled: next, reason: reason.trim() })
      queryClient.setQueryData(keys.craPolicy, saved)
      await Promise.all([keys.cra, pagedKey('/api/cra/events'), pagedKey('/api/cra/products')].map(queryKey => queryClient.invalidateQueries({ queryKey })))
      setOpen(false); setNotice(saved.enabled ? t('cra.saved_on') : t('cra.saved_off'))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  const summary = policy && (policy.enabled ? t('cra.on') : t('cra.off')) + (policy.by && policy.at ? ` · ${t('cra.changed', { by: policy.by, date: formatDate(policy.at) })}` : '')
  return <>
    <PolicyRow icon={Landmark} title={t('cra.title')} summary={summary} notice={notice} state={policy ? 'ready' : query.isError ? 'error' : 'loading'}
      onRetry={() => void query.refetch()} action={canEdit && <Button size="sm" variant="outline" onClick={start}><Power />{policy?.enabled ? t('cra.turn_off') : t('cra.turn_on')}</Button>} />
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{next ? t('cra.dialog_on') : t('cra.dialog_off')}</DialogTitle>
          <DialogDescription>{next ? t('cra.help_on') : t('cra.help_off')}</DialogDescription>
        </DialogHeader>
        <form onSubmit={save} className="space-y-3" noValidate>
          <div className="space-y-1">
            <label htmlFor={`${id}-reason`} className="text-xs text-app-muted">{t('cra.reason')}</label>
            <textarea id={`${id}-reason`} required maxLength={500} rows={3} value={reason} onChange={event => setReason(event.target.value)} placeholder={t('cra.reason_placeholder')}
              aria-invalid={!!error || undefined} aria-describedby={error ? `${id}-error` : undefined}
              className="w-full resize-y rounded-lg border border-app-line bg-app px-3 py-2 text-sm text-app-fg" />
          </div>
          {policy && policy.history.length > 0 && <div className="space-y-1">
            <p className="text-xs font-medium text-app-secondary">{t('cra.history')}</p>
            <ul className="space-y-1 text-xs text-app-muted">{policy.history.slice(0, HISTORY_SHOWN).map(entry => <li key={`${entry.at}-${entry.by}`}>
              {entry.enabled ? t('cra.history_on', { by: entry.by ?? '—', date: entry.at ? formatDate(entry.at) : '—' }) : t('cra.history_off', { by: entry.by ?? '—', date: entry.at ? formatDate(entry.at) : '—' })}
              {entry.reason && <span className="block text-app-subtle">{entry.reason}</span>}</li>)}</ul>
          </div>}
          {error && <p id={`${id}-error`} role="alert" className="text-xs text-danger">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => setOpen(false)} disabled={busy}>{t('common:actions.cancel')}</Button>
            <Button type="submit" disabled={busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{next ? t('cra.turn_on') : t('cra.turn_off')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  </>
}
