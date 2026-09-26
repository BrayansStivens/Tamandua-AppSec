import { useLayoutEffect, useRef, useState, type ReactNode } from 'react'

// Gráficas SVG sin dependencias. Marcas finas, huecos de 2 px entre segmentos, rejilla recesiva,
// leyenda siempre que haya ≥ 2 series, etiquetas directas selectivas y capa de hover con tooltip.
const SEV = ['low', 'medium', 'high', 'critical'] as const
export const sevColor: Record<string, string> = { low: 'var(--sev-low)', medium: 'var(--sev-medium)', high: 'var(--sev-high)', critical: 'var(--sev-critical)' }
export const sevName: Record<string, string> = { low: 'Baja', medium: 'Media', high: 'Alta', critical: 'Crítica' }
const shortDay = (day: string) => day.slice(5).replace('-', '/')

// Ancho real del contenedor: los gráficos se dibujan a su tamaño en píxeles en vez de escalar un viewBox
// fijo, así el texto conserva su tamaño en columnas estrechas y el gráfico ocupa todo el ancho en las anchas.
function useWidth(fallback: number) {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(fallback)
  useLayoutEffect(() => {
    const node = ref.current
    if (!node) return
    const measure = () => { const next = Math.round(node.clientWidth); if (next > 0) setWidth(next) }
    measure()
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(measure)
    observer.observe(node)
    return () => observer.disconnect()
  }, [])
  return [ref, width] as const
}

// Qué días del eje llevan etiqueta: una cada ~64 px, siempre la última y nunca dos pegadas.
function dayTicks(length: number, innerW: number) {
  const step = Math.max(1, Math.ceil(length / Math.max(2, Math.floor(innerW / 64))))
  const ticks = new Set<number>()
  for (let index = 0; index < length; index += step) if (length - 1 - index >= step / 2 || index === length - 1) ticks.add(index)
  if (length) ticks.add(length - 1)
  return ticks
}

function Tooltip({ x, y, children }: { x: number; y: number; children: ReactNode }) {
  return <div className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-lg border border-app-line bg-panel px-2.5 py-1.5 text-xs text-app-fg shadow-lg" style={{ left: x, top: y - 8 }}>{children}</div>
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-app-muted">{items.map(item => <span key={item.label} className="flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-sm" style={{ background: item.color }} />{item.label}</span>)}</div>
}

/** Barras apiladas por día: hallazgos nuevos por severidad. */
export function StackedSeverityBars({ data, height = 180 }: { data: { day: string; critical: number; high: number; medium: number; low: number }[]; height?: number }) {
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null)
  const [ref, width] = useWidth(640)
  const padLeft = 28, padBottom = 22, padTop = 8
  const max = Math.max(1, ...data.map(item => item.critical + item.high + item.medium + item.low))
  const innerW = width - padLeft - 8, innerH = height - padBottom - padTop
  const slot = innerW / Math.max(1, data.length), bar = Math.max(2, Math.min(18, slot * 0.7))
  const ticks = [0, Math.ceil(max / 2), max]
  const total = data.reduce((sum, item) => sum + item.critical + item.high + item.medium + item.low, 0)
  const ticksAt = dayTicks(data.length, innerW)
  return <div ref={ref} className="relative">
    <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} className="block max-w-full" role="img" aria-label={`Hallazgos nuevos por día: ${total} en total`}>
      {ticks.map(tick => { const y = padTop + innerH - (tick / max) * innerH; return <g key={tick}><line x1={padLeft} x2={width - 8} y1={y} y2={y} stroke="var(--grid-line)" strokeWidth={1} /><text x={padLeft - 6} y={y + 3} textAnchor="end" className="fill-app-subtle" fontSize={11}>{tick}</text></g> })}
      {data.map((item, index) => { const x = padLeft + index * slot + (slot - bar) / 2; let y = padTop + innerH
        return <g key={item.day} onMouseEnter={event => setHover({ index, x: (event.nativeEvent as MouseEvent).offsetX, y: (event.nativeEvent as MouseEvent).offsetY })} onMouseLeave={() => setHover(null)}>
          <rect x={padLeft + index * slot} y={padTop} width={slot} height={innerH} fill="transparent" />
          {SEV.map(level => { const value = item[level]; if (!value) return null; const h = (value / max) * innerH; y -= h
            return <rect key={level} x={x} y={y + 1} width={bar} height={Math.max(0, h - 2)} rx={level === 'critical' || y + 1 <= padTop + 2 ? 2 : 0} fill={sevColor[level]} /> })}
          {ticksAt.has(index) && <text x={index === data.length - 1 ? width - 8 : padLeft + index * slot + slot / 2} y={height - 6} textAnchor={index === data.length - 1 ? 'end' : 'middle'} className="fill-app-subtle" fontSize={11}>{shortDay(item.day)}</text>}
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
export function FoundVsFixed({ data, height = 200 }: { data: { day: string; found: number; fixed: number }[]; height?: number }) {
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null)
  const [ref, width] = useWidth(640)
  const padLeft = 28, padBottom = 22, padTop = 14
  const max = Math.max(1, ...data.map(item => Math.max(item.found, item.fixed)))
  const innerW = width - padLeft - 8, innerH = height - padBottom - padTop
  const x = (index: number) => padLeft + (data.length > 1 ? (index / (data.length - 1)) * innerW : innerW / 2)
  const y = (value: number) => padTop + innerH - (value / max) * innerH
  const path = (key: 'found' | 'fixed') => data.map((item, index) => `${index ? 'L' : 'M'}${x(index).toFixed(1)},${y(item[key]).toFixed(1)}`).join(' ')
  const last = data[data.length - 1]
  const ticksAt = dayTicks(data.length, innerW)
  return <div ref={ref} className="relative">
    <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} className="block max-w-full" role="img" aria-label="Hallados frente a corregidos, acumulado">
      {[0, Math.ceil(max / 2), max].map(tick => <g key={tick}><line x1={padLeft} x2={width - 8} y1={y(tick)} y2={y(tick)} stroke="var(--grid-line)" strokeWidth={1} /><text x={padLeft - 6} y={y(tick) + 3} textAnchor="end" className="fill-app-subtle" fontSize={11}>{tick}</text></g>)}
      <path d={path('found')} fill="none" stroke="var(--series-found)" strokeWidth={2} strokeLinejoin="round" />
      <path d={path('fixed')} fill="none" stroke="var(--series-fixed)" strokeWidth={2} strokeLinejoin="round" />
      {last && <><text x={width - 10} y={y(last.found) - 4} textAnchor="end" className="fill-app-secondary" fontSize={11}>{last.found} hallados</text><text x={width - 10} y={y(last.fixed) + (Math.abs(y(last.fixed) - y(last.found)) < 12 ? 12 : -4)} textAnchor="end" className="fill-app-secondary" fontSize={11}>{last.fixed} corregidos</text></>}
      {hover && <><line x1={x(hover.index)} x2={x(hover.index)} y1={padTop} y2={padTop + innerH} stroke="var(--axis-line)" strokeDasharray="3 3" /><circle cx={x(hover.index)} cy={y(data[hover.index].found)} r={4} fill="var(--series-found)" stroke="var(--app-panel)" strokeWidth={2} /><circle cx={x(hover.index)} cy={y(data[hover.index].fixed)} r={4} fill="var(--series-fixed)" stroke="var(--app-panel)" strokeWidth={2} /></>}
      <rect x={padLeft} y={padTop} width={innerW} height={innerH} fill="transparent" onMouseMove={event => { const rect = (event.currentTarget as SVGRectElement).getBoundingClientRect(); const ratio = (event.clientX - rect.left) / rect.width; setHover({ index: Math.round(ratio * (data.length - 1)), x: (event.nativeEvent as MouseEvent).offsetX, y: (event.nativeEvent as MouseEvent).offsetY }) }} onMouseLeave={() => setHover(null)} />
      {data.map((item, index) => ticksAt.has(index) && <text key={item.day} x={x(index)} y={height - 6} textAnchor={index === data.length - 1 ? 'end' : index === 0 ? 'start' : 'middle'} className="fill-app-subtle" fontSize={11}>{shortDay(item.day)}</text>)}
      <line x1={padLeft} x2={width - 8} y1={padTop + innerH} y2={padTop + innerH} stroke="var(--axis-line)" strokeWidth={1} />
    </svg>
    {hover && <Tooltip x={hover.x} y={hover.y}><div className="font-medium">{data[hover.index].day}</div><div className="flex justify-between gap-3"><span>Hallados</span><span className="tabular-nums">{data[hover.index].found}</span></div><div className="flex justify-between gap-3"><span>Corregidos</span><span className="tabular-nums">{data[hover.index].fixed}</span></div></Tooltip>}
    <Legend items={[{ label: 'Hallados (acumulado)', color: 'var(--series-found)' }, { label: 'Corregidos (acumulado)', color: 'var(--series-fixed)' }]} />
  </div>
}

/** Barras horizontales de un solo tono con etiqueta directa: magnitud por categoría.
 *  La etiqueta va encima de la barra, a todo el ancho: en columnas estrechas no se corta. */
export function HBars({ rows, colorFor }: { rows: { label: string; value: number; hint?: string; color?: string }[]; colorFor?: (row: { label: string; value: number }) => string }) {
  const max = Math.max(1, ...rows.map(row => row.value))
  if (!rows.length) return null
  return <ul className="space-y-2.5">{rows.map(row => <li key={row.label} className="text-xs">
    <div className="flex items-baseline justify-between gap-3"><span className="min-w-0 break-words text-app-secondary" title={row.hint ?? row.label}>{row.label}</span><span className="shrink-0 font-medium tabular-nums text-app-fg">{row.value}</span></div>
    <div className="mt-1 h-2 rounded-sm bg-app-soft"><div className="h-full rounded-sm" style={{ width: `${(100 * row.value) / max}%`, background: row.color ?? colorFor?.(row) ?? 'var(--seq-3)' }} /></div>
  </li>)}</ul>
}

/** Actividad diaria en semanas (columnas) × días (filas). Termina siempre en hoy y muestra tantas semanas como
 *  quepan en el ancho disponible: sin scroll horizontal y con el día actual a la vista. */
export function ActivityHeatmap({ days }: { days: { day: string; runs: number }[] }) {
  const [hover, setHover] = useState<{ day: string; runs: number; x: number; y: number } | null>(null)
  const [ref, available] = useWidth(720)
  const gap = 3, left = 22, top = 16
  const weeksWanted = Math.ceil(days.length / 7) + 1
  // Celdas de 10 a 14 px según el ancho: en pantallas anchas cabe el año entero; en estrechas, las últimas semanas.
  const cell = Math.max(10, Math.min(14, Math.floor((available - left) / weeksWanted) - gap))
  const cols = Math.max(4, Math.min(weeksWanted, Math.floor((available - left + gap) / (cell + gap))))
  const lastDay = days[days.length - 1]?.day
  const endRow = lastDay ? (new Date(`${lastDay}T00:00:00Z`).getUTCDay() + 6) % 7 : 6  // 0 = lunes
  const visible = days.slice(Math.max(0, days.length - ((cols - 1) * 7 + endRow + 1)))
  const startRow = visible[0] ? (new Date(`${visible[0].day}T00:00:00Z`).getUTCDay() + 6) % 7 : 0
  const max = Math.max(1, ...visible.map(item => item.runs))
  const level = (runs: number) => runs === 0 ? 'var(--app-soft)' : `var(--seq-${Math.min(5, 1 + Math.floor((runs / max) * 4.99))})`
  const width = left + cols * (cell + gap) - gap, height = top + 7 * (cell + gap) - gap
  const x = (col: number) => left + col * (cell + gap)
  // Un mes se rotula en la columna donde empieza; la primera columna solo si el siguiente rótulo no la pisa.
  const monthOf = (col: number) => visible[Math.max(0, col * 7 - startRow)]?.day.slice(0, 7) ?? ''
  const monthName = (month: string) => new Date(`${month}-01T00:00:00Z`).toLocaleDateString('es-CO', { month: 'short', timeZone: 'UTC' }).replace('.', '')
  const starts = Array.from({ length: cols }, (_, col) => col).filter(col => col > 0 && monthOf(col) && monthOf(col) !== monthOf(col - 1))
  const months = [...(starts[0] === undefined || starts[0] >= 3 ? [0] : []), ...starts].map(col => ({ x: x(col), label: monthName(monthOf(col)) }))
  const total = visible.reduce((sum, item) => sum + item.runs, 0)
  const weeks = Math.ceil((visible.length + startRow) / 7)
  return <div ref={ref} className="relative">
    <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} className="block max-w-full" role="img" aria-label={`Ejecuciones por día en las últimas ${weeks} semanas: ${total} en total`}>
      {['L', '', 'X', '', 'V', '', 'D'].map((label, row) => label && <text key={row} x={0} y={top + row * (cell + gap) + cell - 2} className="fill-app-subtle" fontSize={11}>{label}</text>)}
      {months.map(month => <text key={`${month.x}-${month.label}`} x={month.x} y={10} className="fill-app-subtle" fontSize={11}>{month.label}</text>)}
      {visible.map((item, index) => { const position = index + startRow; const col = Math.floor(position / 7), row = position % 7
        const today = index === visible.length - 1
        return <rect key={item.day} x={x(col)} y={top + row * (cell + gap)} width={cell} height={cell} rx={2} fill={level(item.runs)} stroke={today ? 'var(--app-fg)' : undefined} strokeWidth={today ? 1.5 : undefined}
          onMouseEnter={event => setHover({ ...item, x: (event.nativeEvent as MouseEvent).offsetX, y: (event.nativeEvent as MouseEvent).offsetY })} onMouseLeave={() => setHover(null)} /> })}
    </svg>
    {hover && <Tooltip x={hover.x} y={hover.y}><div className="font-medium">{hover.day === lastDay ? `Hoy · ${hover.day}` : hover.day}</div><div>{hover.runs} {hover.runs === 1 ? 'ejecución' : 'ejecuciones'}</div></Tooltip>}
    <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-app-subtle" style={{ maxWidth: width }}>
      <span>{total} {total === 1 ? 'ejecución' : 'ejecuciones'} en {weeks} semanas · recuadro = hoy</span>
      <span className="flex items-center gap-1">Menos {[1, 2, 3, 4, 5].map(step => <span key={step} className="inline-block size-2.5 rounded-sm" style={{ background: `var(--seq-${step})` }} />)} Más</span>
    </div>
  </div>
}
