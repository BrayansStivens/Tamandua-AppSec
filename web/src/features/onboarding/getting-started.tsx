import { useEffect, useState } from 'react'
import { ArrowRight, Check, X } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Card, CardContent } from '@/shared/ui/card'
import { api } from '@/shared/api/http'

type State = { mfa: boolean; github: boolean; analyzed: boolean; demo: boolean; watching: boolean; alerts: boolean; admin: boolean }
type Step = { id: string; done: boolean; title: string; hint: string; view?: string; action?: string }
const HIDDEN = 'tamandua-getting-started-hidden'

// Primeros pasos: deducidos del estado real (GET /api/onboarding), una acción por paso. Se ocultan solos al
// completarlos o cuando la persona los descarta (solo en este navegador).
export function GettingStarted({ onNavigate }: { onNavigate: (view: string) => void }) {
  const [state, setState] = useState<State | null>(null)
  const [hidden, setHidden] = useState(() => { try { return localStorage.getItem(HIDDEN) === '1' } catch { return false } })
  useEffect(() => { if (!hidden) api.get<State>('/api/onboarding').then(setState).catch(() => setState(null)) }, [hidden])
  if (hidden || !state) return null
  const admin = state.admin
  const steps: Step[] = [
    { id: 'mfa', done: state.mfa, title: 'Protege tu cuenta con segundo factor', hint: 'Una app de autenticación (TOTP) además de la contraseña.', view: 'account', action: 'Activar' },
    { id: 'github', done: state.github, title: 'Conecta GitHub', hint: admin ? 'Crea la GitHub App de este servidor; el panel te guía paso a paso.' : 'Lo configura un administrador en Integraciones.', view: admin ? 'integrations' : undefined, action: 'Conectar' },
    { id: 'analyzed', done: state.analyzed, title: 'Lanza tu primer análisis', hint: state.demo ? 'Ya tienes los datos de demostración: ahora analiza un repositorio tuyo.'
      : admin ? '¿Aún sin repositorios? Ejecuta «make demo» en el servidor y verás los ejemplos analizados.' : 'Elige un repositorio o una imagen y lánzalo.', view: 'new', action: 'Nuevo análisis' },
    { id: 'watching', done: state.watching, title: 'Vigila tus pull requests y la rama principal', hint: admin ? 'Cada PR se revisa solo y la rama se reanaliza cuando cambia.' : 'Lo activa un administrador en Pull requests.', view: admin ? 'pulls' : undefined, action: 'Vigilar' },
    { id: 'alerts', done: state.alerts, title: 'Recibe avisos en Slack o Teams', hint: admin ? 'Un mensaje cuando aparece algo nuevo que importa, sin abrir el panel.' : 'Lo configura un administrador en Integraciones → Avisos.', view: admin ? 'integrations' : undefined, action: 'Configurar' },
  ]
  const pending = steps.filter(step => !step.done)
  if (!pending.length) return null
  const next = pending.find(step => step.view)  // una sola acción principal: el primer paso que puedes hacer
  const dismiss = () => { try { localStorage.setItem(HIDDEN, '1') } catch { /* sin almacenamiento: se oculta hasta recargar */ } setHidden(true) }
  return <Card className="border-brand/30 bg-panel"><CardContent className="space-y-3 p-5">
    <div className="flex items-start justify-between gap-3">
      <div><h2 className="text-base font-semibold">Primeros pasos</h2><p className="text-sm text-app-muted">{steps.length - pending.length} de {steps.length} hechos. Se tachan solos cuando los completas.</p></div>
      <Button variant="ghost" size="icon-sm" aria-label="Ocultar primeros pasos" onClick={dismiss}><X /></Button>
    </div>
    <ol className="divide-y divide-app-line rounded-xl border border-app-line">{steps.map(step => <li key={step.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
      <span className="flex min-w-0 items-start gap-3">
        <span aria-hidden className={`mt-0.5 grid size-5 shrink-0 place-items-center rounded-full border ${step.done ? 'border-success bg-success-soft text-success' : 'border-app-line'}`}>{step.done && <Check className="size-3" />}</span>
        <span className="min-w-0"><span className={`block text-sm font-medium ${step.done ? 'text-app-subtle line-through' : ''}`}>{step.title}<span className="sr-only">{step.done ? ' (hecho)' : ' (pendiente)'}</span></span>
          {!step.done && <span className="block text-xs text-app-muted">{step.hint}</span>}</span>
      </span>
      {!step.done && step.view && (step.id === next?.id
        ? <Button size="sm" onClick={() => onNavigate(step.view!)} className="bg-primary text-primary-foreground hover:bg-primary/90">{step.action}<ArrowRight /></Button>
        : <Button size="sm" variant="ghost" onClick={() => onNavigate(step.view!)} className="text-app-muted">{step.action}</Button>)}
    </li>)}</ol>
  </CardContent></Card>
}
