import { slaText, type Sla } from '@/features/findings/sla'

// Solo se marca lo que apremia: fuera de plazo o a una semana de vencer.
export function SlaPill({ sla }: { sla: Sla | null | undefined }) {
  if (!sla || sla.state === 'ok') return null
  return <span className={`mt-1 mr-1 inline-block rounded border px-1.5 text-[11px] ${sla.state === 'overdue' ? 'border-danger-line text-danger' : 'border-warning-line text-warning'}`} title={`Plazo de ${sla.days} ${sla.days === 1 ? 'día' : 'días'} desde la primera detección · vence el ${sla.due}`}>{slaText(sla)}</span>
}
