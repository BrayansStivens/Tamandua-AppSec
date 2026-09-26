import { useId, useRef, useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { GitBranch, LoaderCircle, Plus, X } from 'lucide-react'
import { apiPost } from '@/shared/api/client'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { validBranch } from '@/features/sources/sources'

export const MAX_TARGET_BRANCHES = 10

// Target branches of a watched repository: only PRs into them are reviewed, and each one's latest scan is the
// baseline. Empty = the repository's default branch.
export function TargetBranches({ uid, name, saved, defaultBranch, admin, onSaved }: {
  uid: string; name: string; saved: string[]; defaultBranch: string | null; admin: boolean; onSaved: (branches: string[]) => void
}) {
  const { t } = useTranslation('pulls')
  const id = useId()
  const [draft, setDraft] = useState<string[]>(saved)
  const [input, setInput] = useState('')
  const [error, setError] = useState('')
  const [announce, setAnnounce] = useState('')
  const field = useRef<HTMLInputElement>(null)
  const mutation = useMutation({
    mutationFn: (branches: string[]) => apiPost('/api/pull-requests/branches', 'pr-branches', { uid, branches }),
    onMutate: () => setAnnounce(t('targets.saving')),
    onSuccess: result => { setDraft(result.base_branches); setAnnounce(t('targets.saved')); onSaved(result.base_branches) },
    onError: caught => { setAnnounce(''); setError(caught instanceof Error ? caught.message : String(caught)) },
  })
  const dirty = draft.length !== saved.length || draft.some((branch, index) => branch !== saved[index])
  const busy = mutation.isPending

  const add = (event: FormEvent) => {
    event.preventDefault()
    const branch = input.trim()
    if (!branch) return
    if (!validBranch(branch)) { setError(t('targets.invalid', { branch })); return }
    if (draft.includes(branch)) { setError(t('targets.duplicate', { branch })); return }
    if (draft.length >= MAX_TARGET_BRANCHES) { setError(t('targets.limit', { max: MAX_TARGET_BRANCHES })); return }
    setDraft(current => [...current, branch]); setInput(''); setError('')
  }
  const remove = (branch: string) => { setDraft(current => current.filter(item => item !== branch)); setError(''); field.current?.focus() }
  const discard = () => { setDraft(saved); setInput(''); setError('') }

  return <div className="space-y-2 rounded-xl border border-app-line bg-inset px-4 py-3 text-sm" aria-busy={busy}>
    <div><p id={`${id}-title`} className="font-medium text-app-secondary">{t('targets.title')}</p>
      <p id={`${id}-help`} className="mt-0.5 text-xs leading-5 text-app-subtle">{t('targets.description')}</p></div>
    <ul aria-labelledby={`${id}-title`} className="flex flex-wrap items-center gap-2">
      {draft.length === 0 && <li className="flex items-center gap-1.5 text-xs text-app-muted"><GitBranch className="size-3.5 text-app-subtle" />{defaultBranch ? t('targets.default', { branch: defaultBranch }) : t('targets.default_unknown')}</li>}
      {draft.map(branch => <li key={branch} className="flex min-h-6 items-center gap-1 rounded-full border border-app-line bg-app-soft py-0.5 pr-1 pl-2.5 font-mono text-xs text-app-secondary">
        {branch}
        {admin && <button type="button" onClick={() => remove(branch)} disabled={busy} aria-label={t('targets.remove', { branch })} className="inline-flex size-6 items-center justify-center rounded-full text-app-muted hover:bg-app-line hover:text-app-fg disabled:opacity-50"><X className="size-3.5" /></button>}
      </li>)}
    </ul>
    {admin ? <form onSubmit={add} className="flex flex-wrap items-center gap-2">
      <label htmlFor={`${id}-input`} className="sr-only">{t('targets.input_label', { name })}</label>
      <Input ref={field} id={`${id}-input`} value={input} maxLength={200} spellCheck={false} autoComplete="off" disabled={busy}
        onChange={event => { setInput(event.target.value); setError('') }} placeholder={t('targets.placeholder')}
        aria-invalid={!!error || undefined} aria-describedby={`${id}-help${error ? ` ${id}-error` : ''}`} className="h-8 w-52 border-app-line bg-app-soft font-mono text-xs" />
      <Button type="submit" size="sm" variant="outline" className="border-app-line bg-app-soft" disabled={busy || !input.trim()}><Plus />{t('common:actions.add')}</Button>
      {dirty && <>
        <Button type="button" size="sm" disabled={busy} onClick={() => { setError(''); setAnnounce(''); mutation.mutate(draft) }}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}{t('targets.save')}</Button>
        <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={discard}>{t('targets.discard')}</Button>
      </>}
    </form> : <p className="text-xs text-app-subtle">{t('repo.admin_only')}</p>}
    {error && <p id={`${id}-error`} role="alert" className="text-xs text-danger">{error}</p>}
    <span role="status" className="sr-only">{announce}</span>
  </div>
}
