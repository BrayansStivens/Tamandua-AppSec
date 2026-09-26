import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import type { LucideIcon } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Bone } from '@/shared/ui/loading'

// One policy in one line: what it is, what it says now, and the action. Explanations live in the dialog or the help.
export function PolicyRow({ icon: Icon, title, summary, action, notice, state = 'ready', onRetry }: {
  icon: LucideIcon; title: string; summary?: ReactNode; action?: ReactNode; notice?: string
  state?: 'loading' | 'error' | 'ready'; onRetry?: () => void
}) {
  const { t } = useTranslation('policies')
  return <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-4">
    <Icon aria-hidden className="size-4 shrink-0 text-app-subtle" />
    <div className="min-w-0 flex-1">
      <h2 className="text-sm font-medium text-app-secondary">{title}</h2>
      {state === 'loading' ? <div role="status"><Bone className="mt-1.5 h-3.5 w-2/3" /><span className="sr-only">{t('common:state.loading')}</span></div>
        : state === 'error' ? <p role="alert" className="mt-0.5 flex flex-wrap items-center gap-2 text-sm text-danger">{t('load_failed')}
          {onRetry && <Button size="xs" variant="outline" onClick={onRetry}>{t('common:actions.retry')}</Button>}</p>
        : <p className="mt-0.5 text-sm text-app-muted">{summary}</p>}
      <p role="status" className="mt-0.5 text-xs text-brand empty:hidden">{notice}</p>
    </div>
    {state === 'ready' && action}
  </div>
}
