import { baseKind } from '@/features/threats/threat-layout'
import type { Component, Model } from '@/features/threats/threat-model-types'

// Colores del diagrama: solo tokens del panel (claro y oscuro con contraste comprobado), los mismos que
// usan el SVG y el PDF (tamandua/modules/threats/diagram.py). Sin color elegido, cada componente toma el de su
// papel y la leyenda lo explica; el equipo puede cambiarlo para marcar lo que quiera (un equipo, un país…).
export const TONES = ['neutral', 'brand', 'info', 'success', 'warning', 'attention', 'danger'] as const
export type Tone = typeof TONES[number]

// Catalog keys (`threats` namespace).
export const TONE_NAMES: Record<Tone, string> = {
  neutral: 'tones.neutral', brand: 'tones.brand', info: 'tones.info', success: 'tones.success', warning: 'tones.warning', attention: 'tones.attention', danger: 'tones.danger',
}

const KIND_TONE: Record<string, Tone> = {
  actor: 'neutral', external: 'neutral', web_app: 'brand', api: 'info', service: 'info', function: 'info',
  database: 'success', cache: 'success', queue: 'success', storage: 'success', identity: 'warning',
}

export const LEGEND: [Tone, string][] = [
  ['brand', 'legend.clients'], ['info', 'legend.services'], ['success', 'legend.data'], ['warning', 'legend.identity'], ['neutral', 'legend.actors'],
]

export const isTone = (value: unknown): value is Tone => TONES.includes(value as Tone)
export const toneOf = (component: Component): Tone => isTone(component.color) ? component.color : KIND_TONE[baseKind(component)] ?? 'neutral'
export const boundaryTone = (color?: string | null): Tone => isTone(color) ? color : 'neutral'
export const kindTone = (component: Component): Tone => KIND_TONE[baseKind(component)] ?? 'neutral'
// A chosen color that differs from the role's color gets its own legend entry, labeled by the team.
export const isManual = (component: Component) => isTone(component.color) && component.color !== kindTone(component)

// Legend tones in use: role colors (LEGEND order) and manual colors (palette order). Same as legend_tones in diagram.py.
export function legendTones(model: Pick<Model, 'components'>): { automatic: Tone[]; manual: Tone[] } {
  const automatic = new Set(model.components.filter(item => !isManual(item)).map(toneOf))
  const manual = new Set(model.components.filter(isManual).map(toneOf))
  return { automatic: LEGEND.map(([tone]) => tone).filter(tone => automatic.has(tone)), manual: TONES.filter(tone => manual.has(tone)) }
}

// Sets or clears (empty text) the team's label for a manual color; it applies to every component with that color.
export function withLegendLabel(model: Model, tone: Tone, label: string): Model {
  const legend = { ...model.legend }
  if (label.trim()) legend[tone] = label
  else delete legend[tone]
  return { ...model, legend }
}

// Clases literales (Tailwind solo genera las que ve escritas completas).
export const NODE_TONE: Record<Tone, string> = {
  neutral: 'border-app-secondary bg-app-soft', brand: 'border-brand bg-brand/10', info: 'border-info bg-info-soft',
  success: 'border-success bg-success-soft', warning: 'border-warning bg-warning-soft', attention: 'border-attention bg-attention-soft',
  danger: 'border-danger bg-danger-soft',
}
// En el lienzo el nodo es opaco (bg-panel: las curvas y la rejilla no se ven a través del nombre) y el tono
// va encima como velo; así coincide con el SVG y el PDF, donde el relleno también es opaco.
export const NODE_WASH: Record<Tone, string> = {
  neutral: 'border-app-secondary before:bg-app-soft', brand: 'border-brand before:bg-brand/10', info: 'border-info before:bg-info-soft',
  success: 'border-success before:bg-success-soft', warning: 'border-warning before:bg-warning-soft',
  attention: 'border-attention before:bg-attention-soft', danger: 'border-danger before:bg-danger-soft',
}
export const NODE_BASE = 'relative isolate bg-panel before:pointer-events-none before:absolute before:inset-0 before:-z-10 before:rounded-[inherit]'

export const TEXT_TONE: Record<Tone, string> = {
  neutral: 'text-app-secondary', brand: 'text-brand', info: 'text-info', success: 'text-success', warning: 'text-warning',
  attention: 'text-attention', danger: 'text-danger',
}
export const BOUNDARY_TONE: Record<Tone, string> = {
  neutral: 'border-app-faint/70 bg-app-soft/40', brand: 'border-brand/60 bg-brand/5', info: 'border-info/60 bg-info-soft/60',
  success: 'border-success/60 bg-success-soft/60', warning: 'border-warning/60 bg-warning-soft/60',
  attention: 'border-attention/60 bg-attention-soft/60', danger: 'border-danger/60 bg-danger-soft/60',
}
