import type { Response } from '@/shared/api/client'
import i18n from '@/shared/i18n'
// Plazo de corrección (tamandua/modules/findings/sla.py): solo en lo pendiente del registro; null si su severidad no tiene plazo.
export type { Sla } from '@/shared/lib/types'
import type { Sla } from '@/shared/lib/types'
// La política sale del esquema de la API (generado): no se define a mano.
export type SlaPolicy = Response<'/api/sla'>

export const slaText = (sla: Pick<Sla, 'days_left'>) => sla.days_left < 0 ? i18n.t('findings:sla.overdue', { count: -sla.days_left })
  : sla.days_left === 0 ? i18n.t('findings:sla.due_today') : i18n.t('findings:sla.due_in', { count: sla.days_left })
