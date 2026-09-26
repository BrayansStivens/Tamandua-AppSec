import type { Response } from '@/shared/api/client'
// Plazo de corrección (tamandua/modules/findings/sla.py): solo en lo pendiente del registro; null si su severidad no tiene plazo.
export type { Sla } from '@/shared/lib/types'
import type { Sla } from '@/shared/lib/types'
// La política sale del esquema de la API (generado): no se define a mano.
export type SlaPolicy = Response<'/api/sla'>

export const slaText = (sla: Pick<Sla, 'days_left'>) => sla.days_left < 0 ? `Vencido hace ${-sla.days_left} ${sla.days_left === -1 ? 'día' : 'días'}`
  : sla.days_left === 0 ? 'Vence hoy' : `Vence en ${sla.days_left} ${sla.days_left === 1 ? 'día' : 'días'}`
