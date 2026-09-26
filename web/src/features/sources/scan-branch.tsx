import { useId, useState, type FormEvent, type Ref } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { LoaderCircle, Pencil } from 'lucide-react'
import { apiPost } from '@/shared/api/client'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { validBranch, type Source } from '@/features/sources/sources'

// The branch every scan of a repository reads (manual, batch, re-verification). Unset = its default branch.
export function ScanBranchLabel({ source }: { source: Source }) {
  const { t } = useTranslation('sources')
  const fallback = source.default_branch ?? source.branch
  if (source.scan_branch) return <span className="truncate font-mono text-xs text-app-secondary" title={source.scan_branch}>{source.scan_branch}</span>
  return <span className="truncate text-xs text-app-muted">{fallback ? t('repositories.branch.default', { branch: fallback }) : t('repositories.branch.default_unknown')}</span>
}

export function ScanBranchEditor({ source, onClose, onSaved }: { source: Source; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation('sources')
  const id = useId()
  const [draft, setDraft] = useState(source.scan_branch ?? '')
  const [error, setError] = useState('')
  const mutation = useMutation({
    mutationFn: (branch: string | null) => apiPost('/api/repositories/branch', 'set-scan-branch', { uid: source.uid ?? '', branch }),
    onSuccess: () => { onSaved(); onClose() },
    onError: caught => setError(caught instanceof Error ? caught.message : String(caught)),
  })
  const submit = (event: FormEvent) => {
    event.preventDefault()
    const branch = draft.trim()
    if (branch && !validBranch(branch)) { setError(t('repositories.branch.invalid')); return }
    setError('')
    mutation.mutate(branch || null)
  }
  const reset = () => { setError(''); setDraft(''); mutation.mutate(null) }
  const fallback = source.default_branch ?? source.branch
  return <form onSubmit={submit} className="col-span-full space-y-2 rounded-lg border border-app-line bg-inset p-3" aria-busy={mutation.isPending}>
    <label htmlFor={`${id}-branch`} className="block text-xs font-medium text-app-secondary">{t('repositories.branch.input_label', { name: source.name })}</label>
    <div className="flex flex-wrap items-center gap-2">
      <Input id={`${id}-branch`} value={draft} autoFocus maxLength={200} spellCheck={false} autoComplete="off" disabled={mutation.isPending}
        onChange={event => { setDraft(event.target.value); setError('') }} placeholder={fallback ?? t('repositories.branch.placeholder')}
        aria-invalid={!!error || undefined} aria-describedby={`${id}-help${error ? ` ${id}-error` : ''}`} className="h-8 w-60 border-app-line bg-app-soft font-mono text-xs" />
      <Button type="submit" size="sm" disabled={mutation.isPending || draft.trim() === (source.scan_branch ?? '')}>{mutation.isPending && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
      <Button type="button" size="sm" variant="ghost" disabled={mutation.isPending} onClick={onClose}>{t('common:actions.cancel')}</Button>
      {source.scan_branch && <Button type="button" size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={mutation.isPending} onClick={reset}>{t('repositories.branch.reset')}</Button>}
    </div>
    <p id={`${id}-help`} className="text-xs text-app-subtle">{fallback ? t('repositories.branch.help', { branch: fallback }) : t('repositories.branch.help_unknown')}</p>
    {error && <p id={`${id}-error`} role="alert" className="text-xs text-danger">{error}</p>}
    <span role="status" className="sr-only">{mutation.isPending ? t('repositories.branch.saving') : ''}</span>
  </form>
}

export function ScanBranchEdit({ source, expanded, onEdit, ref }: { source: Source; expanded: boolean; onEdit: () => void; ref?: Ref<HTMLButtonElement> }) {
  const { t } = useTranslation('sources')
  return <Button ref={ref} type="button" size="icon-sm" variant="ghost" onClick={onEdit} aria-expanded={expanded} aria-label={t('repositories.branch.edit', { name: source.name })} title={t('repositories.branch.edit', { name: source.name })}><Pencil /></Button>
}
