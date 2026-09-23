import { useState, type ReactNode } from 'react'

// Gráficas SVG sin dependencias. Marcas finas, huecos de 2 px entre segmentos, rejilla recesiva,
// leyenda siempre que haya ≥ 2 series, etiquetas directas selectivas y capa de hover con tooltip.
const SEV = ['low', 'medium', 'high', 'critical'] as const
export const sevColor: Record<string, string> = { low: 'var(--sev-low)', medium: 'var(--sev-medium)', high: 'var(--sev-high)', critical: 'var(--sev-critical)' }
export const sevName: Record<string, string> = { low: 'Baja', medium: 'Media', high: 'Alta', critical: 'Crítica' }
const shortDay = (day: string) => day.slice(5).replace('-', '/')

function Tooltip({ x, y, children }: { x: number; y: number; children: ReactNode }) {
  return <div className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-lg border border-app-line bg-panel px-2.5 py-1.5 text-xs text-app-fg shadow-lg" style={{ left: x, top: y - 8 }}>{children}</div>
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-app-muted">{items.map(item => <span key={item.label} className="flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-sm" style={{ background: item.color }} />{item.label}</span>)}</div>
}

/** Barras apiladas por día: hallazgos nuevos por severidad. */
export function StackedSeverityBars({ data, height = 180 }: { data: { day: string; critical: number; high: number; medium: number; low: number }[]; height?: number }) {
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null)
  const width = 640, padLeft = 28, padBottom = 22, padTop = 8
  const max = Math.max(1, ...data.map(item => item.critical + item.high + item.medium + item.low))
  const innerW = width - padLeft - 8, innerH = height - padBottom - padTop
  const slot = innerW / Math.max(1, data.length), bar = Math.max(2, Math.min(18, slot * 0.7))
  const ticks = [0, Math.ceil(max / 2), max]
  const total = data.reduce((sum, item) => sum + item.critical + item.high + item.medium + item.low, 0)
  return <div className="relative">
    <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full" role="img" aria-label={`Hallazgos nuevos por día: ${total} en total`}>
      {ticks.map(tick => { const y = padTop + innerH - (tick / max) * innerH; return <g key={tick}><line x1={padLeft} x2={width - 8} y1={y} y2={y} stroke="var(--grid-line)" strokeWidth={1} /><text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-app-subtle" fontSize={9}>{tick}</text></g> })}
      {data.map((item, index) => { const x = padLeft + index * slot + (slot - bar) / 2; let y = padTop + innerH
        return <g key={item.day} onMouseEnter={event => setHover({ index, x: (event.nativeEvent as MouseEvent).offsetX, y: (event.nativeEvent as MouseEvent).offsetY })} onMouseLeave={() => setHover(null)}>
          <rect x={padLeft + index * slot} y={padTop} width={slot} height={innerH} fill="transparent" />
          {SEV.map(level => { const value = item[level]; if (!value) return null; const h = (value / max) * innerH; y -= h
            return <rect key={level} x={x} y={y + 1} width={bar} height={Math.max(0, h - 2)} rx={level === 'critical' || y + 1 <= padTop + 2 ? 2 : 0} fill={sevColor[level]} /> })}
          {(index % Math.ceil(data.length / 8) === 0 || index === data.length - 1) && <text x={padLeft + index * slot + slot / 2} y={height - 6} textAnchor="middle" className="fill-app-subtle" fontSize={9}>{shortDay(item.day)}</text>}
        </g> })}
      <line x1={padLeft} x2={width - 8} y1={padTop + innerH} y2={padTop + innerH} stroke="var(--axis-line)" strokeWidth={1} />
    </svg>
    {hover && <Tooltip x={hover.x} y={hover.y}><div className="font-medium">{data[hover.index].day}</div>{SEV.slice().reverse().map(level => <div key={level} className="flex justify-between gap-3"><span>{sevName[level]}</span><span className="tabular-nums">{data[hover.index][level]}</span></div>)}</Tooltip>}
    <Legend items={SEV.slice().reverse().map(level => ({ label: sevName[level], color: sevColor[level] }))} />
  </div>
}

/** Parte-todo horizontal: abiertos por severidad, con etiquetas directas. */
export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = SEV.reduce((sum, level) => sum + (counts[level] ?? 0), 0)
  return <div className="space-y-3">
    <div className="flex h-4 w-full overflow-hidden rounded-md bg-app-soft" role="img" aria-label={`Abiertos por severidad, ${total} en total`}>
      {total ? SEV.slice().reverse().map(level => (counts[level] ?? 0) > 0 ? <div key={level} title={`${sevName[level]}: ${counts[level]}`} style={{ width: `${(100 * (counts[level] ?? 0)) / total}%`, background: sevColor[level] }} className="border-r-2 border-panel last:border-r-0" /> : null) : null}
    </div>
    <div className="grid grid-cols-4 gap-2 text-xs">{SEV.slice().reverse().map(level => <div key={level} className="flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-sm" style={{ background: sevColor[level] }} /><span className="text-app-muted">{sevName[level]}</span><span className="ml-auto font-medium tabular-nums text-app-fg">{counts[level] ?? 0}</span></div>)}</div>
  </div>
}

/** Dos líneas: acumulado de hallados y de corregidos. */
export function FoundVsFixed({ data, height = 160 }: { data: { day: string; found: number; fixed: number }[]; height?: number }) {
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null)
  const width = 640, padLeft = 28, padBottom = 22, padTop = 8
  const max = Math.max(1, ...data.map(item => Math.max(item.found, item.fixed)))
  const innerW = width - padLeft - 8, innerH = height - padBottom - padTop
  const x = (index: number) => padLeft + (data.length > 1 ? (index / (data.length - 1)) * innerW : innerW / 2)
  const y = (value: number) => padTop + innerH - (value / max) * innerH
  const path = (key: 'found' | 'fixed') => data.map((item, index) => `${index ? 'L' : 'M'}${x(index).toFixed(1)},${y(item[key]).toFixed(1)}`).join(' ')
  const last = data[data.length - 1]
  return <div className="relative">
    <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full" role="img" aria-label="Hallados frente a corregidos, acumulado">
      {[0, Math.ceil(max / 2), max].map(tick => <g key={tick}><line x1={padLeft} x2={width - 8} y1={y(tick)} y2={y(tick)} stroke="var(--grid-line)" strokeWidth={1} /><text x={padLeft - 6} y={y(tick) + 3} textAnchor="end" className="fill-app-subtle" fontSize={9}>{tick}</text></g>)}
      <path d={path('found')} fill="none" stroke="var(--series-found)" strokeWidth={2} strokeLinejoin="round" />
      <path d={path('fixed')} fill="none" stroke="var(--series-fixed)" strokeWidth={2} strokeLinejoin="round" />
      {last && <><text x={width - 10} y={y(last.found) - 4} textAnchor="end" className="fill-app-secondary" fontSize={10}>{last.found} hallados</text><text x={width - 10} y={y(last.fixed) + (Math.abs(y(last.fixed) - y(last.found)) < 12 ? 12 : -4)} textAnchor="end" className="fill-app-secondary" fontSize={10}>{last.fixed} corregidos</text></>}
      {hover && <><line x1={x(hover.index)} x2={x(hover.index)} y1={padTop} y2={padTop + innerH} stroke="var(--axis-line)" strokeDasharray="3 3" /><circle cx={x(hover.index)} cy={y(data[hover.index].found)} r={4} fill="var(--series-found)" stroke="var(--app-panel)" strokeWidth={2} /><circle cx={x(hover.index)} cy={y(data[hover.index].fixed)} r={4} fill="var(--series-fixed)" stroke="var(--app-panel)" strokeWidth={2} /></>}
      <rect x={padLeft} y={padTop} width={innerW} height={innerH} fill="transparent" onMouseMove={event => { const rect = (event.currentTarget as SVGRectElement).getBoundingClientRect(); const ratio = (event.clientX - rect.left) / rect.width; setHover({ index: Math.round(ratio * (data.length - 1)), x: (event.nativeEvent as MouseEvent).offsetX, y: (event.nativeEvent as MouseEvent).offsetY }) }} onMouseLeave={() => setHover(null)} />
      {data.map((item, index) => (index % Math.ceil(data.length / 6) === 0 || index === data.length - 1) && <text key={item.day} x={x(index)} y={height - 6} textAnchor="middle" className="fill-app-subtle" fontSize={9}>{shortDay(item.day)}</text>)}
      <line x1={padLeft} x2={width - 8} y1={padTop + innerH} y2={padTop + innerH} stroke="var(--axis-line)" strokeWidth={1} />
    </svg>
    {hover && <Tooltip x={hover.x} y={hover.y}><div className="font-medium">{data[hover.index].day}</div><div className="flex justify-between gap-3"><span>Hallados</span><span className="tabular-nums">{data[hover.index].found}</span></div><div className="flex justify-between gap-3"><span>Corregidos</span><span className="tabular-nums">{data[hover.index].fixed}</span></div></Tooltip>}
    <Legend items={[{ label: 'Hallados (acumulado)', color: 'var(--series-found)' }, { label: 'Corregidos (acumulado)', color: 'var(--series-fixed)' }]} />
  </div>
}

/** Barras horizontales de un solo tono con etiqueta directa: magnitud por categoría. */
export function HBars({ rows, colorFor }: { rows: { label: string; value: number; hint?: string; color?: string }[]; colorFor?: (row: { label: string; value: number }) => string }) {
  const max = Math.max(1, ...rows.map(row => row.value))
  if (!rows.length) return null
  return <div className="space-y-2">{rows.map(row => <div key={row.label} className="grid grid-cols-[minmax(0,1fr)_60%_40px] items-center gap-3 text-xs"><span className="truncate text-app-secondary" title={row.hint ?? row.label}>{row.label}</span><div className="h-3 rounded-sm bg-app-soft"><div className="h-full rounded-sm" style={{ width: `${(100 * row.value) / max}%`, background: row.color ?? colorFor?.(row) ?? 'var(--seq-3)' }} /></div><span className="text-right font-medium tabular-nums text-app-fg">{row.value}</span></div>)}</div>
}

/** Mapa de actividad anual: un tono secuencial, más oscuro = más ejecuciones. */
export function ActivityHeatmap({ days }: { days: { day: string; runs: number }[] }) {
  const [hover, setHover] = useState<{ day: string; runs: number; x: number; y: number } | null>(null)
  const max = Math.max(1, ...days.map(item => item.runs))
  const level = (runs: number) => runs === 0 ? 'var(--app-soft)' : `var(--seq-${Math.min(5, 1 + Math.floor((runs / max) * 4.99))})`
  const first = new Date(days[0]?.day ?? Date.now()); const startPad = (first.getUTCDay() + 6) % 7
  const cell = 11, gap = 3, cols = Math.ceil((days.length + startPad) / 7)
  const width = cols * (cell + gap) + 28, height = 7 * (cell + gap) + 18
  const months: { x: number; label: string }[] = []
  days.forEach((item, index) => { if (item.day.endsWith('-01') || index === 0) { const col = Math.floor((index + startPad) / 7); months.push({ x: 28 + col * (cell + gap), label: new Date(item.day).toLocaleDateString('es-CO', { month: 'short', timeZone: 'UTC' }) }) } })
  return <div className="relative overflow-x-auto">
    <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="img" aria-label="Ejecuciones por día en el último año">
      {['L', '', 'X', '', 'V', '', ''].map((label, row) => <text key={row} x={0} y={18 + row * (cell + gap) + 9} className="fill-app-subtle" fontSize={9}>{label}</text>)}
      {months.map(month => <text key={month.x + month.label} x={month.x} y={9} className="fill-app-subtle" fontSize={9}>{month.label}</text>)}
      {days.map((item, index) => { const position = index + startPad; const col = Math.floor(position / 7), row = position % 7
        return <rect key={item.day} x={28 + col * (cell + gap)} y={18 + row * (cell + gap)} width={cell} height={cell} rx={2} fill={level(item.runs)} onMouseEnter={event => setHover({ ...item, x: (event.nativeEvent as MouseEvent).offsetX, y: (event.nativeEvent as MouseEvent).offsetY })} onMouseLeave={() => setHover(null)} /> })}
    </svg>
    {hover && <Tooltip x={hover.x} y={hover.y}><div className="font-medium">{hover.day}</div><div>{hover.runs} {hover.runs === 1 ? 'ejecución' : 'ejecuciones'}</div></Tooltip>}
    <div className="mt-1 flex items-center gap-1 text-[10px] text-app-subtle">Menos {[1, 2, 3, 4, 5].map(step => <span key={step} className="inline-block size-2.5 rounded-sm" style={{ background: `var(--seq-${step})` }} />)} Más</div>
  </div>
}
