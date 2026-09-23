import { useEffect, useRef, useState } from 'react'

export type SkylineCell = { day: string; severity: string; count: number }
const ROWS = ['critical', 'high', 'medium', 'low', 'none'] as const
const ROW_NAME: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', none: 'Sin puntuar' }
const TOKEN: Record<string, string> = { critical: '--sev-critical', high: '--sev-high', medium: '--sev-medium', low: '--sev-low', none: '--axis-line' }
type Face = { points: [number, number][]; cell: SkylineCell }

function shade(hex: string, factor: number) {
  const value = hex.trim().replace('#', '')
  const full = value.length === 3 ? value.split('').map(char => char + char).join('') : value
  const channels = [0, 2, 4].map(index => parseInt(full.slice(index, index + 2), 16) || 0)
  const mix = channels.map(channel => Math.round(factor >= 1 ? channel + (255 - channel) * (factor - 1) : channel * factor))
  return `rgb(${mix[0]},${mix[1]},${mix[2]})`
}

function inside(point: [number, number], polygon: [number, number][]) {
  let hit = false
  for (let index = 0, previous = polygon.length - 1; index < polygon.length; previous = index++) {
    const [xi, yi] = polygon[index], [xj, yj] = polygon[previous]
    if ((yi > point[1]) !== (yj > point[1]) && point[0] < ((xj - xi) * (point[1] - yi)) / (yj - yi) + xi) hit = !hit
  }
  return hit
}

// «Skyline» de severidad: cada columna es un día, cada fila una severidad y la altura, los CVE publicados.
// Es la huella de los últimos 30 días según la copia local de NVD, girando despacio; con movimiento
// reducido queda quieta. Las cifras exactas se leen al pasar el ratón y en el resumen accesible.
export function SeveritySkyline({ cells, days = 30, height = 260 }: { cells: SkylineCell[]; days?: number; height?: number }) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const faces = useRef<Face[]>([])
  const [hover, setHover] = useState<{ x: number; y: number; cell: SkylineCell } | null>(null)
  const hovered = useRef<SkylineCell | null>(null)

  useEffect(() => {
    const element = canvas.current
    const context = element?.getContext('2d')
    if (!element || !context) return
    const today = new Date()
    const labels = Array.from({ length: days }, (_, index) => {
      const date = new Date(today.getTime() - (days - 1 - index) * 86400000)
      return date.toISOString().slice(0, 10)
    })
    const grid = new Map(cells.map(cell => [`${cell.day}|${cell.severity}`, cell.count]))
    const peak = Math.max(1, ...cells.map(cell => cell.count))
    const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const pitch = 0.82
    const GAP = 2.3
    const [width3, depth3, tall3] = [days, ROWS.length * GAP, 4.6]
    const [yawBase, yawSwing] = [-0.36, 0.2]
    let frame = 0
    // Proyección con escala 1; el encuadre se calcula aparte para que la escena no «respire» al girar.
    const raw = (x: number, y: number, z: number, cos: number, sin: number): [number, number] => {
      const [dx, dz] = [x - width3 / 2, z - depth3 / 2]
      return [dx * cos - dz * sin, -y * Math.cos(pitch) + (dx * sin + dz * cos) * Math.sin(pitch)]
    }
    const bounds = (() => {
      let [minX, maxX, minY, maxY] = [Infinity, -Infinity, Infinity, -Infinity]
      for (let step = 0; step <= 8; step++) {
        const yaw = yawBase - yawSwing + (2 * yawSwing * step) / 8
        for (const x of [0, width3]) for (const z of [0, depth3]) for (const y of [0, tall3]) {
          const [px, py] = raw(x, y, z, Math.cos(yaw), Math.sin(yaw))
          minX = Math.min(minX, px); maxX = Math.max(maxX, px); minY = Math.min(minY, py); maxY = Math.max(maxY, py)
        }
      }
      return { minX, maxX, minY, maxY }
    })()

    const draw = (time: number) => {
      const styles = getComputedStyle(element)
      const colors = Object.fromEntries(ROWS.map(row => [row, styles.getPropertyValue(TOKEN[row]).trim() || '#888888']))
      const grid_line = styles.getPropertyValue('--grid-line').trim() || '#444444'
      const ink = styles.getPropertyValue('--muted-foreground').trim() || '#999999'
      const ratio = window.devicePixelRatio || 1
      const width = element.clientWidth, tall = element.clientHeight
      if (element.width !== Math.round(width * ratio) || element.height !== Math.round(tall * ratio)) {
        element.width = Math.round(width * ratio); element.height = Math.round(tall * ratio)
      }
      context.setTransform(ratio, 0, 0, ratio, 0, 0)
      context.clearRect(0, 0, width, tall)
      const yaw = yawBase + (still ? 0 : yawSwing * Math.sin(time / 7000))
      const [cos, sin] = [Math.cos(yaw), Math.sin(yaw)]
      const [padX, padTop, padBottom] = [64, 8, 26]  // hueco para los rótulos de fila y de fecha
      const scale = Math.min((width - padX - 12) / (bounds.maxX - bounds.minX), (tall - padTop - padBottom) / (bounds.maxY - bounds.minY))
      const [offsetX, offsetY] = [padX + (width - padX - 12 - (bounds.maxX - bounds.minX) * scale) / 2 - bounds.minX * scale, padTop - bounds.minY * scale]
      const project = (x: number, y: number, z: number): [number, number] => {
        const [px, py] = raw(x, y, z, cos, sin)
        return [offsetX + px * scale, offsetY + py * scale]
      }
      const depthOf = (x: number, z: number) => (x - width3 / 2) * sin + (z - depth3 / 2) * cos

      // Suelo: filas de severidad y marcas semanales.
      context.lineWidth = 1
      context.strokeStyle = grid_line
      for (let row = 0; row <= ROWS.length; row++) {
        const [a, b] = [project(0, 0, row * GAP), project(width3, 0, row * GAP)]
        context.beginPath(); context.moveTo(a[0], a[1]); context.lineTo(b[0], b[1]); context.stroke()
      }
      for (let column = 0; column <= days; column += 7) {
        const [a, b] = [project(days - column, 0, 0), project(days - column, 0, depth3)]
        context.beginPath(); context.moveTo(a[0], a[1]); context.lineTo(b[0], b[1]); context.stroke()
      }

      const bars: { depth: number; draw: () => void }[] = []
      const drawn: Face[] = []
      labels.forEach((day, column) => ROWS.forEach((row, index) => {
        const count = grid.get(`${day}|${row}`) ?? 0
        if (!count) return
        const [x0, x1] = [column + 0.14, column + 0.86]
        const [z0, z1] = [index * GAP + 0.45, index * GAP + 1.85]
        const h = Math.max(0.08, tall3 * Math.sqrt(count / peak))
        const cell = { day, severity: row, count }
        const base = colors[row]
        const isToday = column === days - 1
        bars.push({ depth: depthOf((x0 + x1) / 2, (z0 + z1) / 2), draw: () => {
          const quads: { pts: [number, number][]; fill: string }[] = []
          // Solo las caras que miran a la cámara: una caja convexa no se tapa a sí misma.
          if (cos > 0) quads.push({ pts: [project(x0, 0, z1), project(x1, 0, z1), project(x1, h, z1), project(x0, h, z1)], fill: shade(base, 0.78) })
          else quads.push({ pts: [project(x0, 0, z0), project(x1, 0, z0), project(x1, h, z0), project(x0, h, z0)], fill: shade(base, 0.78) })
          if (sin > 0) quads.push({ pts: [project(x1, 0, z0), project(x1, 0, z1), project(x1, h, z1), project(x1, h, z0)], fill: shade(base, 0.6) })
          else quads.push({ pts: [project(x0, 0, z0), project(x0, 0, z1), project(x0, h, z1), project(x0, h, z0)], fill: shade(base, 0.6) })
          const glow = isToday && !still ? 1.12 + 0.12 * Math.sin(time / 380) : 1.12
          quads.push({ pts: [project(x0, h, z0), project(x1, h, z0), project(x1, h, z1), project(x0, h, z1)], fill: shade(base, glow) })
          for (const quad of quads) {
            context.beginPath()
            quad.pts.forEach(([px, py], point) => point ? context.lineTo(px, py) : context.moveTo(px, py))
            context.closePath()
            const selected = hovered.current && hovered.current.day === day && hovered.current.severity === row
            context.fillStyle = selected ? shade(base, 1.35) : quad.fill
            context.fill()
            drawn.push({ points: quad.pts, cell })
          }
        } })
      }))
      bars.sort((left, right) => left.depth - right.depth).forEach(bar => bar.draw())
      faces.current = drawn

      // Rótulos de fila al principio del eje y extremos de fecha.
      context.fillStyle = ink
      context.font = '10px Geist Variable, system-ui, sans-serif'
      context.textAlign = 'right'
      ROWS.forEach((row, index) => { const [px, py] = project(-0.5, 0, index * GAP + GAP / 2); context.fillText(ROW_NAME[row], px, py + 3) })
      context.textAlign = 'center'
      const short = (day: string) => `${day.slice(8, 10)}/${day.slice(5, 7)}`
      for (const column of [0, days - 1]) { const [px, py] = project(column + 0.5, 0, depth3 + 0.5); context.fillText(column === days - 1 ? 'hoy' : short(labels[column]), px, py + 12) }
      if (!still) frame = requestAnimationFrame(draw)
    }
    draw(performance.now())
    return () => cancelAnimationFrame(frame)
  }, [cells, days])

  const move = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const box = event.currentTarget.getBoundingClientRect()
    const point: [number, number] = [event.clientX - box.left, event.clientY - box.top]
    // Se recorre de delante hacia atrás: gana la cara que se ve.
    const face = [...faces.current].reverse().find(item => inside(point, item.points))
    hovered.current = face?.cell ?? null
    setHover(face ? { x: point[0], y: point[1], cell: face.cell } : null)
  }
  const total = cells.reduce((sum, cell) => sum + cell.count, 0)
  const bySeverity = ROWS.map(row => `${ROW_NAME[row]} ${cells.filter(cell => cell.severity === row).reduce((sum, cell) => sum + cell.count, 0)}`).join(', ')
  return <div className="relative">
    <canvas ref={canvas} role="img" aria-label={`CVE publicados en los últimos ${days} días por severidad: ${total} en total; ${bySeverity}.`}
      onMouseMove={move} onMouseLeave={() => { hovered.current = null; setHover(null) }} className="block w-full" style={{ height }} />
    {hover && <div className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-md border border-app-line bg-popover px-2.5 py-1.5 text-xs text-popover-foreground shadow-lg" style={{ left: hover.x, top: hover.y - 8 }}>
      <div className="font-medium tabular-nums">{hover.cell.count.toLocaleString('es-CO')} CVE</div>
      <div className="text-app-muted">{ROW_NAME[hover.cell.severity]} · {new Date(`${hover.cell.day}T12:00:00`).toLocaleDateString('es-CO', { day: 'numeric', month: 'short' })}</div>
    </div>}
    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-app-muted">{ROWS.map(row => <span key={row} className="flex items-center gap-1.5"><span className="size-2.5 rounded-sm" style={{ background: `var(${TOKEN[row]})` }} />{ROW_NAME[row]}</span>)}</div>
  </div>
}
