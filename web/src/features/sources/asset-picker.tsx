import { useCallback, useEffect, useState } from 'react'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { api, query } from '@/shared/api/http'
import { plural, type Page } from '@/shared/lib/types'

export type Asset = { key: string; name: string; provider: string; scans: number; pr_reviews: number; last_activity: string; removed_at: string | null
  latest_scan: { run_id: string; created_at: string } | null; open: { total: number; critical: number; high: number; medium: number; low: number; from_pr?: number; fixed?: number; suppressed?: number } | null }

export const assetOption = (asset: Asset): ComboOption => ({
  id: asset.key, label: asset.name,
  hint: `${asset.open ? `${plural(asset.open.total, 'pendiente', 'pendientes')}${asset.open.critical ? ` · ${plural(asset.open.critical, 'crítico', 'críticos')}` : ''}` : 'sin hallazgos'} · ${plural(asset.scans, 'escaneo', 'escaneos')} · ${plural(asset.pr_reviews, 'PR', 'PR')}`,
  badge: asset.removed_at ? <span className="shrink-0 rounded border border-danger-line px-1.5 text-[11px] text-danger">retirado</span> : undefined,
})

// Selector de repositorio con búsqueda en el servidor; arranca con el de actividad más reciente o el pedido.
export function AssetPicker({ value, onChange, initialKey }: { value: Asset | null; onChange: (asset: Asset | null) => void; initialKey?: string | null }) {
  const [ready, setReady] = useState(false)
  const search = useCallback(async (text: string) => {
    const page = await api.get<Page<Asset>>(`/api/assets?${query({ q: text || undefined, limit: 50 })}`)
    return { options: page.items.map(assetOption), total: page.total, items: page.items }
  }, [])
  useEffect(() => {
    if (value || ready) return
    setReady(true)
    api.get<Page<Asset>>(`/api/assets?${query({ key: initialKey || undefined, limit: 1 })}`)
      .then(page => onChange(page.items[0] ?? null)).catch(() => onChange(null))
  }, [value, ready, initialKey, onChange])
  const pick = (option: ComboOption) => { void search(option.label).then(result => onChange(result.items.find(item => item.key === option.id) ?? null)) }
  return <Combobox label="Repositorio" placeholder="Busca un repositorio…" value={value ? assetOption(value) : null} search={search} onSelect={pick} />
}
