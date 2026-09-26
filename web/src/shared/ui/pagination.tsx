import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'

export function Pagination({ total, limit, offset, onPrev, onNext, noun }: { total: number; limit: number; offset: number; onPrev: () => void; onNext: () => void; noun?: string }) {
  const { t } = useTranslation('ui')
  const from = total ? offset + 1 : 0
  const to = Math.min(offset + limit, total)
  return <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-xs text-app-subtle">
    <span>{t('pagination.showing', { from, to, total, noun: noun ?? t('pagination.items') })}</span>
    <span className="flex items-center gap-1"><Button variant="ghost" size="icon-sm" aria-label={t('pagination.previous')} disabled={offset === 0} onClick={onPrev}><ChevronLeft /></Button><span className="tabular-nums">{total ? Math.floor(offset / limit) + 1 : 0} / {Math.max(1, Math.ceil(total / limit))}</span><Button variant="ghost" size="icon-sm" aria-label={t('pagination.next')} disabled={offset + limit >= total} onClick={onNext}><ChevronRight /></Button></span>
  </div>
}
