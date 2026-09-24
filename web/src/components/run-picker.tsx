import { useEffect, useState } from 'react'
import { Search } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { api, query } from '@/lib/api'
import { formatDate, statusLabel, type Page, type RunRow } from '@/lib/types'

// Selector de ejecución que escala: busca en el servidor y muestra las diez más recientes que coinciden.
export function RunPicker({ active, type, onSelect }: { active?: string; type?: string; onSelect: (id: string) => void }) {
  const [text, setText] = useState('')
  const [rows, setRows] = useState<RunRow[]>([])
  const [total, setTotal] = useState(0)
  useEffect(() => {
    const timer = window.setTimeout(() => {
      api.get<Page<RunRow>>(`/api/runs/page?${query({ q: text.trim() || undefined, type, limit: 10 })}`).then(page => { setRows(page.items); setTotal(page.total) }).catch(() => setRows([]))
    }, 200)
    return () => window.clearTimeout(timer)
  }, [text, type])
  return <div className="space-y-2">
    <div className="relative max-w-sm"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-app-subtle" /><Input aria-label="Buscar ejecución" placeholder="Repositorio, id…" value={text} onChange={event => setText(event.target.value)} className="border-app-line bg-app-soft pl-9" /></div>
    <div className="flex flex-wrap gap-2">{rows.map(row => <button key={row.id} onClick={() => onSelect(row.id)} className={`rounded-lg border px-3 py-1.5 text-left text-xs transition ${active === row.id ? 'border-brand/40 bg-brand/10 text-brand' : 'border-app-line bg-app-soft text-app-muted hover:border-brand/30'}`}><span className="block font-medium">{row.source?.name ?? `${row.fixture} · ${row.variant ?? ''}`}</span><span className="text-[11px] text-app-subtle">{formatDate(row.created_at)} · {statusLabel(row.status)}</span></button>)}{total > rows.length && <span className="self-center text-xs text-app-subtle">{total - rows.length} más — refina la búsqueda</span>}</div>
  </div>
}
