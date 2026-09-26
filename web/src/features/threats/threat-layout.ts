import type { Box, Component, Model, Point } from '@/features/threats/threat-model-types'

// Colocación automática del diagrama («Ordenar» y lo que llega sin posición, p. ej. un JSON importado).
// Mismo algoritmo que appsec_agent/threat_diagram.py (el SVG y el PDF): si cambia uno, cambia el otro.
// - Columnas según el recorrido de los datos: lo que entra desde Internet a la izquierda, lo que recibe
//   datos a su derecha y los terceros al final. Los flujos de vuelta (respuestas, webhooks) no empujan
//   columnas: cuenta la distancia a los actores.
// - Cada frontera es un bloque que contiene a sus componentes; los bloques nunca se solapan.
// - En cada columna, cada bloque a la altura de aquello con lo que habla (menos cruces).
// - Rejilla de 8 px y pilas de 5 como mucho (más se reparten en columnas).

export const NODE_W = 184
export const NODE_H = 88          // hueco por componente: caben dos líneas de nombre y la tecnología
const GAP_X = 136                 // entre columnas: sitio para la etiqueta corta del flujo («12 · HTTPS»)
const GAP_INNER = 112             // entre subcolumnas de una frontera unidas por flujos
const GAP_GRID = 40               // entre las columnas de una pila repartida (sin flujos entre ellas)
const GAP_Y = 40
const PAD = 32
const HEADER = 44                 // nombre de la frontera
const SNAP = 8
const MAX_STACK = 5

const LAYER: Record<string, number> = {
  actor: 0, web_app: 1, identity: 3, api: 2, service: 2, function: 2, cache: 3, queue: 3, database: 3, storage: 3, external: 4,
}

export const baseKind = (component: Component) => component.kind === 'custom' ? component.custom_base ?? 'service' : component.kind
const layer = (component: Component) => LAYER[baseKind(component)] ?? 2
export const sizeOf = (component: Component) => ({ width: component.size?.width ?? NODE_W, height: component.size?.height ?? NODE_H })
const snap = (value: number) => Math.round(value / SNAP) * SNAP
const mean = (values: number[]) => values.reduce((total, value) => total + value, 0) / values.length

// Columnas dentro de una frontera: el papel de cada componente, empujado por los flujos internos.
function innerRanks(ids: string[], edges: [string, string][], seed: (id: string) => number): Record<string, number> {
  const rank: Record<string, number> = Object.fromEntries(ids.map(id => [id, seed(id)]))
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

const before = (a: number[], b: number[]) => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i]; return false }

// Columna de cada bloque: distancia a los actores, luego papel medio y orden del modelo (un orden estricto:
// dos bloques que se hablan nunca comparten columna). Lo que nada alimenta se acerca a su destino y los
// terceros que solo reciben van al final.
function groupRanks(ids: string[], edges: [string, string][], seed: Record<string, number>, sinks: Set<string>): Record<string, number> {
  const targets: Record<string, string[]> = Object.fromEntries(ids.map(id => [id, []]))
  for (const [a, b] of edges) if (!targets[a].includes(b)) targets[a].push(b)
  const fed = new Set(edges.map(([, b]) => b))
  let starts = ids.filter(id => seed[id] === 0)
  if (!starts.length) starts = ids.filter(id => !fed.has(id))
  if (!starts.length) starts = ids.slice(0, 1)
  const distance: Record<string, number> = Object.fromEntries(starts.map(id => [id, 0]))
  const queue = [...starts]
  while (queue.length) {
    const item = queue.shift()!
    for (const other of targets[item]) if (!(other in distance)) { distance[other] = distance[item] + 1; queue.push(other) }
  }
  for (const id of ids) if (!(id in distance)) distance[id] = -1
  const key: Record<string, number[]> = Object.fromEntries(ids.map((id, index) => [id, [distance[id], seed[id], index]]))
  const forward = ids.flatMap(a => targets[a].filter(b => before(key[a], key[b])).map(b => [a, b] as [string, string]))
  const incoming: Record<string, string[]> = Object.fromEntries(ids.map(id => [id, []]))
  const outgoing: Record<string, string[]> = Object.fromEntries(ids.map(id => [id, []]))
  for (const [a, b] of forward) { incoming[b].push(a); outgoing[a].push(b) }
  const order = [...ids].sort((a, b) => before(key[a], key[b]) ? -1 : before(key[b], key[a]) ? 1 : 0)
  const rank: Record<string, number> = {}
  for (const id of order) rank[id] = Math.max(0, ...incoming[id].map(source => rank[source] + 1))
  for (const id of [...order].reverse()) {
    if (seed[id] > 0 && !incoming[id].length && outgoing[id].length) rank[id] = Math.max(0, Math.min(...outgoing[id].map(other => rank[other])) - 1)
    else if (seed[id] > 0 && !incoming[id].length && !outgoing[id].length) rank[id] = Math.min(1, Math.max(0, ...Object.values(rank)))
  }
  for (const id of ids) {
    if (sinks.has(id) && incoming[id].length && !outgoing[id].length)
      rank[id] = Math.max(rank[id] - 1, ...ids.filter(other => !sinks.has(other)).map(other => rank[other])) + 1
  }
  const levels = [...new Set(Object.values(rank))].sort((a, b) => a - b)
  return Object.fromEntries(ids.map(id => [id, levels.indexOf(rank[id])]))
}

// Una pila de más de MAX_STACK componentes se reparte en columnas parejas (una rejilla).
function stacks(column: Component[]): Component[][] {
  if (column.length <= MAX_STACK) return [column]
  const size = Math.ceil(column.length / Math.ceil(column.length / MAX_STACK))
  const result: Component[][] = []
  for (let start = 0; start < column.length; start += size) result.push(column.slice(start, start + size))
  return result
}

type Group = { id: string; boundary: string | null; members: Component[]; cols: Component[][]; gaps: number[]
  widths: number[]; heights: number[]; innerW: number; innerH: number; width: number; height: number }

function makeGroup(boundary: string | null, members: Component[], flows: Model['flows']): Group {
  let cols: Component[][] = [members], gaps = [0]
  if (boundary !== null) {
    const byId = Object.fromEntries(members.map(item => [item.id, item]))
    const inner = innerRanks(members.map(item => item.id), flows.filter(f => byId[f.source] && byId[f.target]).map(f => [f.source, f.target]), id => layer(byId[id]))
    const columns: Record<number, Component[]> = {}
    for (const item of members) (columns[inner[item.id]] ??= []).push(item)
    cols = []; gaps = []
    for (const index of Object.keys(columns).map(Number).sort((a, b) => a - b)) {
      const parts = stacks([...columns[index]].sort((a, b) => layer(a) - layer(b)))
      cols.push(...parts)
      gaps.push(...parts.slice(1).map(() => GAP_GRID), GAP_INNER)
    }
  }
  const widths = cols.map(column => Math.max(...column.map(item => sizeOf(item).width)))
  const heights = cols.map(column => column.reduce((total, item) => total + sizeOf(item).height, 0) + GAP_Y * (column.length - 1))
  const innerW = widths.reduce((total, width) => total + width, 0) + gaps.slice(0, -1).reduce((total, gap) => total + gap, 0)
  const innerH = Math.max(...heights, NODE_H)
  const own = sizeOf(members[0])
  return { id: boundary === null ? `c:${members[0].id}` : `b:${boundary}`, boundary, members, cols, gaps, widths, heights, innerW, innerH,
    width: boundary === null ? own.width : innerW + PAD * 2, height: boundary === null ? own.height : HEADER + innerH + PAD }
}

function place(columns: Group[][]) {
  const positions: Record<string, Point> = {}
  const boxes: Record<string, Box> = {}
  const heights = columns.map(column => column.reduce((total, group) => total + group.height, 0) + GAP_Y * 1.5 * (column.length - 1))
  const tallest = Math.max(...heights, 0)
  let x = 40
  columns.forEach((column, index) => {
    let y = 40 + (tallest - heights[index]) / 2
    const width = Math.max(...column.map(group => group.width))
    for (const group of column) {
      const gx = x + (width - group.width) / 2
      if (group.boundary === null) positions[group.members[0].id] = { x: snap(gx), y: snap(y) }
      else {
        boxes[group.boundary] = { x: snap(gx), y: snap(y), width: group.width, height: group.height }
        let cx = snap(gx) + PAD
        group.cols.forEach((members, col) => {
          let cy = snap(y) + HEADER + (group.innerH - group.heights[col]) / 2
          for (const item of members) {
            positions[item.id] = { x: snap(cx + (group.widths[col] - sizeOf(item).width) / 2), y: snap(cy) }
            cy += sizeOf(item).height + GAP_Y
          }
          cx += group.widths[col] + group.gaps[col]
        })
      }
      y += group.height + GAP_Y * 1.5
    }
    x += width + GAP_X
  })
  return { positions, boxes }
}

export function autoLayout(model: Model): { positions: Record<string, Point>; boxes: Record<string, Box> } {
  const byId = Object.fromEntries(model.components.map(item => [item.id, item]))
  const flows = model.flows.filter(flow => byId[flow.source] && byId[flow.target])
  const groups: Group[] = []
  const groupOf: Record<string, string> = {}
  const placed = new Set<string>()
  for (const boundary of model.boundaries) {
    const members = boundary.components.map(id => byId[id]).filter(item => item && !placed.has(item.id))
    if (!members.length) continue
    members.forEach(item => placed.add(item.id))
    groups.push(makeGroup(boundary.id, members, flows))
  }
  for (const item of model.components) if (!placed.has(item.id)) groups.push(makeGroup(null, [item], flows))
  for (const group of groups) for (const item of group.members) groupOf[item.id] = group.id
  // Papel del bloque: la media de sus componentes (0 = solo actores).
  const seed = Object.fromEntries(groups.map(group => [group.id, mean(group.members.map(layer))]))
  const sinks = new Set(groups.filter(group => group.members.every(item => baseKind(item) === 'external')).map(group => group.id))
  const between = flows.map(flow => [groupOf[flow.source], groupOf[flow.target]] as [string, string]).filter(([a, b]) => a !== b)
  const ids = groups.map(group => group.id)
  const rank = groupRanks(ids, between, seed, sinks)
  const columns: Group[][] = []
  for (const group of [...groups].sort((a, b) => seed[a.id] - seed[b.id] || ids.indexOf(a.id) - ids.indexOf(b.id))) (columns[rank[group.id]] ??= []).push(group)
  const solid = columns.filter(Boolean)
  const neighbours: Record<string, string[]> = Object.fromEntries(model.components.map(item => [item.id, []]))
  for (const flow of flows) { neighbours[flow.source].push(flow.target); neighbours[flow.target].push(flow.source) }

  // Menos cruces: cada bloque (y cada componente dentro de su bloque) a la altura media de sus vecinos.
  let layout = place(solid)
  for (let pass = 0; pass < 4; pass++) {
    const centre = Object.fromEntries(Object.entries(layout.positions).map(([id, point]) => [id, point.y + sizeOf(byId[id]).height / 2]))
    for (const column of solid) {
      const outside = (group: Group) => {
        const own = new Set(group.members.map(item => item.id))
        const around = group.members.flatMap(item => neighbours[item.id].filter(other => !own.has(other)).map(other => centre[other]))
        return around.length ? mean(around) : mean(group.members.map(item => centre[item.id]))
      }
      const keys = new Map(column.map(group => [group, outside(group)]))
      column.sort((a, b) => keys.get(a)! - keys.get(b)!)
      for (const group of column) {
        if (group.boundary === null) continue
        for (const stack of group.cols) {
          const at = (item: Component) => neighbours[item.id].length ? mean(neighbours[item.id].map(other => centre[other])) : centre[item.id]
          const values = new Map(stack.map(item => [item, at(item)]))
          stack.sort((a, b) => values.get(a)! - values.get(b)!)
        }
      }
    }
    layout = place(solid)
  }
  const { positions, boxes } = layout

  // Fronteras vacías: al final, listas para arrastrar componentes dentro.
  const right = snap(Math.max(0, ...Object.values(boxes).map(box => box.x + box.width), ...Object.values(positions).map(point => point.x + NODE_W)) + GAP_X)
  let emptyY = 40
  for (const boundary of model.boundaries) {
    if (boxes[boundary.id]) continue
    boxes[boundary.id] = { x: right, y: emptyY, width: NODE_W + PAD * 2, height: HEADER + NODE_H + PAD }
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
export type LabelEdge = { id: string; source: Rect; target: Rect; sourceSide: Side; targetSide: Side; text: string; offset?: number }

// Flujos que unen los mismos dos componentes (ida y vuelta, o varios): carriles paralelos, como en threat_diagram.lanes.
export const LANE = 14
export function lanes(flows: { id: string; source: string; target: string }[]): Record<string, number> {
  const groups = new Map<string, string[]>()
  for (const flow of flows) {
    const key = [flow.source, flow.target].sort().join('\u0000')
    groups.set(key, [...(groups.get(key) ?? []), flow.id])
  }
  return Object.fromEntries([...groups.values()].flatMap(members => members.map((id, index) => [id, (index - (members.length - 1) / 2) * LANE])))
}
export const shift = (side: Side, x: number, y: number, offset: number): [number, number] => side === 'left' || side === 'right' ? [x, y + offset] : [x + offset, y]

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
    const [ax, ay] = anchor(edge.source, edge.sourceSide), [bx, by] = anchor(edge.target, edge.targetSide)
    const [sx, sy] = shift(edge.sourceSide, ax, ay, edge.offset ?? 0), [tx, ty] = shift(edge.targetSide, bx, by, edge.offset ?? 0)
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
