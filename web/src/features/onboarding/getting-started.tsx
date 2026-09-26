import { useEffect, useState } from 'react'
import { ArrowRight, Check, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import { Card, CardContent } from '@/shared/ui/card'
import { api } from '@/shared/api/http'

type State = { mfa: boolean; github: boolean; analyzed: boolean; demo: boolean; watching: boolean; alerts: boolean; admin: boolean }
type Step = { id: string; done: boolean; title: string; hint: string; view?: string; action?: string }
const HIDDEN = 'tamandua-getting-started-hidden'

// Primeros pasos: deducidos del estado real (GET /api/onboarding), una acción por paso. Se ocultan solos al
// completarlos o cuando la persona los descarta (solo en este navegador).
export function GettingStarted({ onNavigate }: { onNavigate: (view: string) => void }) {
  const { t } = useTranslation('onboarding')
  const [state, setState] = useState<State | null>(null)
  const [hidden, setHidden] = useState(() => { try { return localStorage.getItem(HIDDEN) === '1' } catch { return false } })
  useEffect(() => { if (!hidden) api.get<State>('/api/onboarding').then(setState).catch(() => setState(null)) }, [hidden])
  if (hidden || !state) return null
  const admin = state.admin
  const steps: Step[] = [
    { id: 'mfa', done: state.mfa, title: t('steps.mfa.title'), hint: t('steps.mfa.hint'), view: 'account', action: t('steps.mfa.action') },
    { id: 'github', done: state.github, title: t('steps.github.title'), hint: admin ? t('steps.github.hint_admin') : t('steps.github.hint_member'), view: admin ? 'integrations' : undefined, action: t('steps.github.action') },
    { id: 'analyzed', done: state.analyzed, title: t('steps.analyzed.title'), hint: state.demo ? t('steps.analyzed.hint_demo')
      : admin ? t('steps.analyzed.hint_admin') : t('steps.analyzed.hint_member'), view: 'new', action: t('steps.analyzed.action') },
    { id: 'watching', done: state.watching, title: t('steps.watching.title'), hint: admin ? t('steps.watching.hint_admin') : t('steps.watching.hint_member'), view: admin ? 'pulls' : undefined, action: t('steps.watching.action') },
    { id: 'alerts', done: state.alerts, title: t('steps.alerts.title'), hint: admin ? t('steps.alerts.hint_admin') : t('steps.alerts.hint_member'), view: admin ? 'integrations' : undefined, action: t('steps.alerts.action') },
  ]
  const pending = steps.filter(step => !step.done)
  if (!pending.length) return null
  const next = pending.find(step => step.view)  // una sola acción principal: el primer paso que puedes hacer
  const dismiss = () => { try { localStorage.setItem(HIDDEN, '1') } catch { /* sin almacenamiento: se oculta hasta recargar */ } setHidden(true) }
  return <Card className="border-brand/30 bg-panel"><CardContent className="space-y-3 p-5">
    <div className="flex items-start justify-between gap-3">
      <div><h2 className="text-base font-semibold">{t('title')}</h2><p className="text-sm text-app-muted">{t('progress', { done: steps.length - pending.length, total: steps.length })}</p></div>
      <Button variant="ghost" size="icon-sm" aria-label={t('hide')} onClick={dismiss}><X /></Button>
    </div>
    <ol className="divide-y divide-app-line rounded-xl border border-app-line">{steps.map(step => <li key={step.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
      <span className="flex min-w-0 items-start gap-3">
        <span aria-hidden className={`mt-0.5 grid size-5 shrink-0 place-items-center rounded-full border ${step.done ? 'border-success bg-success-soft text-success' : 'border-app-line'}`}>{step.done && <Check className="size-3" />}</span>
        <span className="min-w-0"><span className={`block text-sm font-medium ${step.done ? 'text-app-subtle line-through' : ''}`}>{step.title}<span className="sr-only"> {step.done ? t('done') : t('pending')}</span></span>
          {!step.done && <span className="block text-xs text-app-muted">{step.hint}</span>}</span>
      </span>
      {!step.done && step.view && (step.id === next?.id
        ? <Button size="sm" onClick={() => onNavigate(step.view!)} className="bg-primary text-primary-foreground hover:bg-primary/90">{step.action}<ArrowRight /></Button>
        : <Button size="sm" variant="ghost" onClick={() => onNavigate(step.view!)} className="text-app-muted">{step.action}</Button>)}
    </li>)}</ol>
  </CardContent></Card>
}
