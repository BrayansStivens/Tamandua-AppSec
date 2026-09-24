import type { Box, Component, Model, Point } from '@/components/threat-model-types'

// Colocación automática del diagrama («Ordenar» y lo que llega sin posición, p. ej. un JSON importado).
// Sigue el sentido de los datos: actores → aplicaciones → APIs y servicios → datos → terceros, y
// respeta las fronteras: cada frontera es un bloque que contiene a sus componentes, nunca se solapan.

export const NODE_W = 184
export const NODE_H = 88          // hueco por componente: caben dos líneas de nombre y la tecnología
const GAP_X = 160                 // entre columnas: sitio para la etiqueta del flujo (máx. 132 px)
const GAP_INNER = 150             // entre subcolumnas dentro de una frontera: también llevan etiqueta
const GAP_Y = 44
const PAD = 32
const HEADER = 44                 // nombre de la frontera

const LAYER: Record<string, number> = {
  actor: 0, web_app: 1, identity: 1, api: 2, service: 2, function: 2, cache: 3, queue: 3, database: 3, storage: 3, external: 4,
}

export const baseKind = (component: Component) => component.kind === 'custom' ? component.custom_base ?? 'service' : component.kind
const layer = (component: Component) => LAYER[baseKind(component)] ?? 2
export const sizeOf = (component: Component) => ({ width: component.size?.width ?? NODE_W, height: component.size?.height ?? NODE_H })

// Rango de cada elemento: su capa por tipo, empujada hacia la derecha por los flujos que le llegan.
// Solo cuentan los flujos «hacia delante» (una respuesta de la base de datos a la API no la adelanta),
// así un ciclo no dispara las columnas.
function ranks(ids: string[], edges: [string, string][], seed: (id: string) => number, start: (id: string) => number = seed): Record<string, number> {
  const rank: Record<string, number> = Object.fromEntries(ids.map(id => [id, start(id)]))
  const known = new Set(ids)
  const forward = edges.filter(([a, b]) => a !== b && known.has(a) && known.has(b) && seed(a) <= seed(b))
  for (let pass = 0; pass < ids.length; pass++) {
    let changed = false
    for (const [a, b] of forward) if (rank[b] < rank[a] + 1) { rank[b] = rank[a] + 1; changed = true }
    if (!changed) break
  }
  const levels = [...new Set(Object.values(rank))].sort((a, b) => a - b)
  return Object.fromEntries(ids.map(id => [id, levels.indexOf(rank[id])]))
}

type Group = { id: string; boundary: string | null; members: Component[]; width: number; height: number; place: (x: number, y: number) => void }

export function autoLayout(model: Model): { positions: Record<string, Point>; boxes: Record<string, Box> } {
  const byId = Object.fromEntries(model.components.map(item => [item.id, item]))
  const positions: Record<string, Point> = {}
  const boxes: Record<string, Box> = {}
  const groupOf: Record<string, string> = {}
  const groups: Group[] = []

  const boxed = (boundary: string, members: Component[]): Group => {
    const internal = model.flows.filter(flow => members.some(item => item.id === flow.source) && members.some(item => item.id === flow.target))
    const inner = ranks(members.map(item => item.id), internal.map(flow => [flow.source, flow.target]), id => layer(byId[id]))
    const columns: Component[][] = []
    for (const item of members) (columns[inner[item.id]] ??= []).push(item)
    const solid = columns.filter(Boolean).map(column => column.sort((a, b) => layer(a) - layer(b)))
    const widths = solid.map(column => Math.max(...column.map(item => sizeOf(item).width)))
    const heights = solid.map(column => column.reduce((total, item) => total + sizeOf(item).height, 0) + GAP_Y * (column.length - 1))
    const innerWidth = widths.reduce((total, width) => total + width, 0) + GAP_INNER * (solid.length - 1)
    const innerHeight = Math.max(...heights, NODE_H)
    return { id: `b:${boundary}`, boundary, members, width: innerWidth + PAD * 2, height: HEADER + innerHeight + PAD,
      place: (x, y) => {
        boxes[boundary] = { x, y, width: innerWidth + PAD * 2, height: HEADER + innerHeight + PAD }
        let cx = x + PAD
        solid.forEach((column, index) => {
          let cy = y + HEADER + (innerHeight - heights[index]) / 2
          for (const item of column) {
            positions[item.id] = { x: Math.round(cx + (widths[index] - sizeOf(item).width) / 2), y: Math.round(cy) }
            cy += sizeOf(item).height + GAP_Y
          }
          cx += widths[index] + GAP_INNER
        })
      } }
  }

  const placed = new Set<string>()
  for (const boundary of model.boundaries) {
    const members = boundary.components.map(id => byId[id]).filter(item => item && !placed.has(item.id))
    if (!members.length) continue
    members.forEach(item => { placed.add(item.id); groupOf[item.id] = `b:${boundary.id}` })
    groups.push(boxed(boundary.id, members))
  }
  for (const item of model.components) {
    if (placed.has(item.id)) continue
    groupOf[item.id] = `c:${item.id}`
    const { width, height } = sizeOf(item)
    groups.push({ id: `c:${item.id}`, boundary: null, members: [item], width, height, place: (x, y) => { positions[item.id] = { x: Math.round(x), y: Math.round(y) } } })
  }

  // Columnas de bloques según los flujos entre ellos.
  const seedOf = Object.fromEntries(groups.map(group => [group.id, Math.min(...group.members.map(layer))]))
  const between = model.flows.map(flow => [groupOf[flow.source], groupOf[flow.target]] as [string, string]).filter(([a, b]) => a && b && a !== b)
  // Entre bloques manda el recorrido de los datos: lo que solo recibe flujos (datos, terceros) comparte la
  // última columna en lugar de abrir una por tipo. Los actores empiezan a la izquierda.
  const rank = ranks(groups.map(group => group.id), between, id => seedOf[id], id => seedOf[id] === 0 ? 0 : 1)
  const columns: Group[][] = []
  for (const group of groups) (columns[rank[group.id]] ??= []).push(group)
  const solid = columns.filter(Boolean).map(column => column.sort((a, b) => seedOf[a.id] - seedOf[b.id]))
  const heights = solid.map(column => column.reduce((total, group) => total + group.height, 0) + GAP_Y * 1.5 * (column.length - 1))
  const tallest = Math.max(...heights, 0)
  let x = 40
  solid.forEach((column, index) => {
    let y = 40 + (tallest - heights[index]) / 2
    const width = Math.max(...column.map(group => group.width))
    for (const group of column) {
      group.place(x + (width - group.width) / 2, y)
      y += group.height + GAP_Y * 1.5
    }
    x += width + GAP_X
  })

  // Fronteras vacías: al final, listas para arrastrar componentes dentro.
  let emptyY = 40
  for (const boundary of model.boundaries) {
    if (boxes[boundary.id]) continue
    boxes[boundary.id] = { x, y: emptyY, width: NODE_W + PAD * 2, height: HEADER + NODE_H + PAD }
    emptyY += NODE_H + HEADER + PAD + GAP_Y
  }
  return { positions, boxes }
}

// Una caja siempre contiene a sus componentes: si llega pequeña (p. ej. de un JSON), crece hasta abarcarlos.
export function fitBox(box: Box, members: { position: Point; width: number; height: number }[]): Box {
  if (!members.length) return box
  const left = Math.min(box.x, ...members.map(item => item.position.x - PAD))
  const top = Math.min(box.y, ...members.map(item => item.position.y - HEADER))
  const right = Math.max(box.x + box.width, ...members.map(item => item.position.x + item.width + PAD))
  const bottom = Math.max(box.y + box.height, ...members.map(item => item.position.y + item.height + PAD))
  return { x: left, y: top, width: right - left, height: bottom - top }
}

// Etiquetas de los flujos: el punto medio de la curva cae encima de otro componente cuando el flujo salta
// columnas. Se prueban varios puntos de la curva (del centro hacia los extremos) y gana el primero que no
// pisa componentes ni etiquetas ya colocadas. Mismo trazado que getBezierPath de React Flow.
export type Side = 'top' | 'right' | 'bottom' | 'left'
type Rect = { x: number; y: number; width: number; height: number }
export type LabelEdge = { id: string; source: Rect; target: Rect; sourceSide: Side; targetSide: Side; text: string }

const LABEL_MAX = 132
const LABEL_H = 20
const SPOTS = [0.5, 0.4, 0.6, 0.3, 0.7, 0.78, 0.22, 0.85, 0.15]

const offset = (distance: number) => distance >= 0 ? 0.5 * distance : 0.25 * 25 * Math.sqrt(-distance)
const control = (side: Side, x1: number, y1: number, x2: number, y2: number): [number, number] =>
  side === 'left' ? [x1 - offset(x1 - x2), y1] : side === 'right' ? [x1 + offset(x2 - x1), y1]
    : side === 'top' ? [x1, y1 - offset(y1 - y2)] : [x1, y1 + offset(y2 - y1)]

export function curvePoint(sx: number, sy: number, sourceSide: Side, tx: number, ty: number, targetSide: Side, t: number) {
  const [ax, ay] = control(sourceSide, sx, sy, tx, ty)
  const [bx, by] = control(targetSide, tx, ty, sx, sy)
  const u = 1 - t
  return { x: u ** 3 * sx + 3 * u * u * t * ax + 3 * u * t * t * bx + t ** 3 * tx, y: u ** 3 * sy + 3 * u * u * t * ay + 3 * u * t * t * by + t ** 3 * ty }
}

const anchor = (rect: Rect, side: Side) => side === 'left' ? [rect.x, rect.y + rect.height / 2] : side === 'right' ? [rect.x + rect.width, rect.y + rect.height / 2]
  : side === 'top' ? [rect.x + rect.width / 2, rect.y] : [rect.x + rect.width / 2, rect.y + rect.height]
const overlap = (a: Rect, b: Rect) => Math.max(0, Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x)) * Math.max(0, Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y))

export function labelSpots(edges: LabelEdge[], components: Rect[]): Record<string, number> {
  const placed: Rect[] = []
  const spots: Record<string, number> = {}
  // Primero los flujos cortos: tienen menos sitio donde elegir.
  const length = (edge: LabelEdge) => Math.hypot(edge.target.x - edge.source.x, edge.target.y - edge.source.y)
  for (const edge of [...edges].sort((a, b) => length(a) - length(b))) {
    const [sx, sy] = anchor(edge.source, edge.sourceSide), [tx, ty] = anchor(edge.target, edge.targetSide)
    const width = Math.min(LABEL_MAX, edge.text.length * 6 + 14) + 8
    let best = { t: 0.5, cost: Infinity, rect: null as Rect | null }
    for (const t of SPOTS) {
      const point = curvePoint(sx, sy, edge.sourceSide, tx, ty, edge.targetSide, t)
      const rect = { x: point.x - width / 2, y: point.y - (LABEL_H + 6) / 2, width, height: LABEL_H + 6 }
      // Pisar un componente pesa más que pisar otra etiqueta; alejarse del centro, apenas.
      const cost = components.reduce((total, item) => total + overlap(rect, item) * 4, 0) + placed.reduce((total, item) => total + overlap(rect, item), 0) + Math.abs(t - 0.5)
      if (cost < best.cost) best = { t, cost, rect }
      if (cost < 1) break
    }
    spots[edge.id] = best.t
    if (best.rect) placed.push(best.rect)
  }
  return spots
}
