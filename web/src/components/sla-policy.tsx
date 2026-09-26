import { useEffect, useState, type FormEvent } from 'react'
import { Clock3, LoaderCircle, Pencil } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api } from '@/lib/api'
import type { SlaPolicy } from '@/lib/sla'
import { formatDate } from '@/lib/types'

const LEVELS = [['critical', 'Crítica'], ['high', 'Alta'], ['medium', 'Media'], ['low', 'Baja']] as const
type Level = typeof LEVELS[number][0]

// Plazos de corrección del espacio de trabajo: explican las fechas límite de Hallazgos. Los ve cualquiera;
// los cambia un administrador. Vacío = esa severidad no vence.
export function SlaPolicyCard({ canEdit, onChanged }: { canEdit: boolean; onChanged: () => void }) {
  const [policy, setPolicy] = useState<SlaPolicy | null>(null)
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<Record<Level, string>>({ critical: '', high: '', medium: '', low: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => { api.get<SlaPolicy>('/api/sla').then(setPolicy).catch(() => setPolicy(null)) }, [])

  const start = () => {
    if (!policy) return
    setDraft(Object.fromEntries(LEVELS.map(([level]) => [level, policy.days[level] ? String(policy.days[level]) : ''])) as Record<Level, string>)
    setError(''); setEditing(true)
  }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    const days = Object.fromEntries(LEVELS.map(([level]) => [level, draft[level].trim() ? Number(draft[level]) : null]))
    if (Object.values(days).some(value => value !== null && (!Number.isInteger(value) || value < 1 || value > 3650))) {
      setError('Cada plazo es un número entero de días entre 1 y 3650, o vacío para no fijarlo.')
      return
    }
    setBusy(true); setError('')
    try {
      setPolicy(await api.post<SlaPolicy>('/api/sla', 'sla', { days }))
      setEditing(false)
      onChanged()
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  if (!policy) return null
  const summary = LEVELS.map(([level, label]) => `${label.toLowerCase()} ${policy.days[level] ? `${policy.days[level]} d` : 'sin plazo'}`).join(' · ')
  return <div className="rounded-xl border border-app-line bg-inset px-4 py-3 text-sm">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 items-start gap-2">
        <Clock3 aria-hidden className="mt-0.5 size-4 shrink-0 text-app-subtle" />
        <div className="min-w-0">
          <p className="font-medium text-app-secondary">Plazos de corrección: <span className="font-normal text-app-muted">{summary}</span></p>
          <p className="mt-1 text-xs leading-5 text-app-subtle">Para todos los repositorios, desde la primera detección. Corren para lo abierto o en curso; lo remediado y las excepciones aprobadas no vencen.
            {policy.updated_by ? ` Cambiados por ${policy.updated_by}${policy.updated_at ? `, ${formatDate(policy.updated_at)}` : ''}.` : ' Valores por defecto.'}{canEdit ? '' : ' Solo un administrador puede cambiarlos.'}</p>
        </div>
      </div>
      {canEdit && !editing && <Button size="sm" variant="outline" onClick={start}><Pencil />Editar</Button>}
    </div>
    {editing && <form onSubmit={save} className="mt-3 space-y-2">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">{LEVELS.map(([level, label]) => <label key={level} className="text-xs text-app-muted">{label} (días)
        <Input type="number" inputMode="numeric" min={1} max={3650} value={draft[level]} onChange={event => setDraft(current => ({ ...current, [level]: event.target.value }))}
          placeholder="Sin plazo" aria-invalid={!!error || undefined} className="mt-1 h-9 border-app-line bg-app tabular-nums" /></label>)}</div>
      <p className="text-xs text-app-subtle">Se aplican a todos los repositorios, al Resumen y a los informes. Deja vacío para que esa severidad no venza. Por defecto: 7, 30, 90 y 180 días.</p>
      {error && <p role="alert" className="text-xs text-danger">{error}</p>}
      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={busy}>{busy && <LoaderCircle className="motion-safe:animate-spin" />}Guardar</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => setEditing(false)} disabled={busy}>Cancelar</Button>
      </div>
    </form>}
  </div>
}
