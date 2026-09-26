import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import {
  applyNodeChanges, Background, BackgroundVariant, BaseEdge, ConnectionMode, Controls, EdgeLabelRenderer, getBezierPath, Handle,
  MarkerType, NodeResizer, Panel, Position, ReactFlow, ReactFlowProvider, useReactFlow,
  type Connection, type Edge, type EdgeChange, type EdgeProps, type Node, type NodeChange, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Check as CheckIcon, Globe2, LayoutGrid, Lock, Plus, Square, Trash2, Undo2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/shared/ui/select'
import { autoLayout, baseKind, curvePoint, fitBox, labelSpots, lanes, NODE_H, NODE_W, shift, sizeOf, type Side } from '@/features/threats/threat-layout'
import { BOUNDARY_TONE, boundaryTone, LEGEND, NODE_BASE, NODE_TONE, NODE_WASH, TEXT_TONE, toneOf, TONE_NAMES, TONES, type Tone } from '@/features/threats/threat-colors'
import { assetGroups, newId, PROCESSES, STORES, type Catalog, type Component, type Flow, type Kind, type Model, type Point, type Threat } from '@/features/threats/threat-model-types'

// Editor visual del modelo: los componentes se arrastran, los flujos se crean uniendo sus puntos y las
// fronteras son cajas que se mueven y redimensionan. La pertenencia a una frontera sale de dónde está
// cada componente: se dibuja, no se elige en un desplegable. Todo se guarda en el mismo modelo.

const SENSITIVE = ['pii', 'credentials', 'payment']
const select = 'h-8 w-full rounded-lg border border-app-line bg-app-soft px-2 text-xs text-app-fg'

type ComponentData = { component: Component; kindLabel: string; flagged: boolean }
type BoundaryData = { name: string; tone: Tone }
type FlowData = { flow: Flow; number: number; flagged: boolean; labelAt?: number; offset?: number }
type CanvasNode = Node<ComponentData, 'component'> | Node<BoundaryData, 'boundary'>

const componentId = (id: string) => `c:${id}`
const boundaryId = (id: string) => `b:${id}`
const flowId = (id: string) => `f:${id}`
const plain = (id: string) => id.slice(2)

function build(model: Model, threats: Threat[], kinds: Record<Kind, string>, previous: CanvasNode[], select: string | null = null): CanvasNode[] {
  // Lo que no tiene posición (p. ej. un JSON importado) se coloca solo; lo dibujado se respeta.
  const layout = autoLayout(model)
  const before = Object.fromEntries(previous.map(node => [node.id, node]))
  const flagged = new Set(threats.filter(row => row.status === 'evidenced').map(row => row.element))
  const where: Record<string, Point> = Object.fromEntries(model.components.map(item => [item.id, item.position ?? layout.positions[item.id] ?? { x: 60, y: 60 }]))
  const components: CanvasNode[] = model.components.map(item => {
    const old = before[componentId(item.id)]
    return { id: componentId(item.id), type: 'component', position: where[item.id], width: sizeOf(item).width, height: item.size?.height,
             data: { component: item, kindLabel: item.custom_kind || kinds[item.kind] || item.kind, flagged: flagged.has(item.id) }, zIndex: 1,
             selected: select ? componentId(item.id) === select : old?.selected ?? false, measured: item.size ? undefined : old?.measured }
  })
  const boundaries: CanvasNode[] = model.boundaries.map(item => {
    const members = item.components.map(id => model.components.find(entry => entry.id === id)).filter((entry): entry is Component => !!entry)
      .map(entry => ({ position: where[entry.id], width: sizeOf(entry).width, height: entry.size?.height ?? before[componentId(entry.id)]?.measured?.height ?? NODE_H }))
    const box = fitBox(item.box ?? layout.boxes[item.id] ?? { x: 40, y: 40, width: 320, height: 220 }, members)
    const old = before[boundaryId(item.id)]
    return { id: boundaryId(item.id), type: 'boundary', position: { x: box.x, y: box.y }, width: box.width, height: box.height,
             data: { name: item.name, tone: boundaryTone(item.color) }, zIndex: 0, dragHandle: '.tm-drag', selected: select ? false : old?.selected ?? false }
  })
  return [...boundaries, ...components]
}

// Qué lado de cada componente mira al otro (por sus centros): así las flechas no cruzan por dentro de las cajas.
type Rect = Point & { width: number; height: number }
function sides(a: Rect, b: Rect): [string, string] {
  const dx = (b.x + b.width / 2) - (a.x + a.width / 2), dy = (b.y + b.height / 2) - (a.y + a.height / 2)
  if (Math.abs(dx) >= Math.abs(dy)) return dx >= 0 ? ['r', 'l'] : ['l', 'r']
  return dy >= 0 ? ['b', 't'] : ['t', 'b']
}

// Frontera más pequeña que contiene el centro de cada componente.
function membership(nodes: CanvasNode[]): Record<string, string[]> {
  const boxes = nodes.filter(node => node.type === 'boundary').map(node => ({ id: plain(node.id), x: node.position.x, y: node.position.y,
    width: node.width ?? node.measured?.width ?? 0, height: node.height ?? node.measured?.height ?? 0 }))
  const result: Record<string, string[]> = Object.fromEntries(boxes.map(box => [box.id, []]))
  for (const node of nodes) {
    if (node.type !== 'component') continue
    const cx = node.position.x + (node.measured?.width ?? NODE_W) / 2, cy = node.position.y + (node.measured?.height ?? NODE_H) / 2
    const inside = boxes.filter(box => cx >= box.x && cx <= box.x + box.width && cy >= box.y && cy <= box.y + box.height)
      .sort((a, b) => a.width * a.height - b.width * b.height)[0]
    if (inside) result[inside.id].push(plain(node.id))
  }
  return result
}

// Con Shift pulsado, redimensionar conserva la proporción (como en cualquier editor de diseño).
const ShiftContext = createContext(false)
function useShiftKey() {
  const [down, setDown] = useState(false)
  useEffect(() => {
    const update = (event: KeyboardEvent) => setDown(event.shiftKey)
    const reset = () => setDown(false)
    window.addEventListener('keydown', update)
    window.addEventListener('keyup', update)
    window.addEventListener('blur', reset)
    return () => { window.removeEventListener('keydown', update); window.removeEventListener('keyup', update); window.removeEventListener('blur', reset) }
  }, [])
  return down
}

function ComponentNode({ data, selected }: NodeProps<Node<ComponentData, 'component'>>) {
  const { t } = useTranslation('threats')
  const keepRatio = useContext(ShiftContext)
  const { component, kindLabel, flagged } = data
  const base = baseKind(component)
  const tone = toneOf(component)
  // Forma según el papel (como en un diagrama de flujo de datos): proceso redondeado, almacén entre dos
  // líneas, tercero con borde discontinuo; el color, el del papel o el que elija el equipo.
  const shape = PROCESSES.includes(base) ? 'rounded-full px-5' : STORES.includes(base) ? 'rounded-none border-x-0 border-y-2' : base === 'external' ? 'rounded-lg border-dashed' : 'rounded-lg'
  const sensitive = component.data.some(item => SENSITIVE.includes(item))
  return <div title={component.name} className={`tm-node flex h-full min-h-[64px] w-full flex-col items-center justify-center border-[1.5px] px-3 py-2 text-center shadow-sm ${shape}
    ${NODE_BASE} ${NODE_WASH[tone]} ${flagged ? 'ring-2 ring-attention' : ''} ${selected ? 'outline-2 outline-offset-2 outline-brand' : ''}`}>
    <NodeResizer isVisible minWidth={140} minHeight={64} maxWidth={520} maxHeight={320} keepAspectRatio={keepRatio} color="var(--brand)" lineClassName="tm-resize-line" handleClassName="tm-resize-handle" />
    {(['t', 'r', 'b', 'l'] as const).map(side => <Handle key={side} id={side} type="source" position={{ t: Position.Top, r: Position.Right, b: Position.Bottom, l: Position.Left }[side]} className="tm-handle" />)}
    <span className="line-clamp-2 text-[13px] leading-4 font-semibold text-app-fg">{component.name}</span>
    <span className={`mt-0.5 line-clamp-1 text-[11px] ${TEXT_TONE[tone]}`}>{component.technology || kindLabel}</span>
    {(component.internet_facing || sensitive || component.encrypted_at_rest) && <span className="mt-1 flex items-center gap-1.5 text-app-subtle">
      {component.internet_facing && <Globe2 className="size-3" aria-label={t('canvas.internet_facing')} />}
      {component.encrypted_at_rest && <Lock className="size-3" aria-label={t('canvas.encrypted_at_rest')} />}
      {sensitive && <span className="rounded bg-app-soft px-1 text-[11px] font-medium tracking-wide uppercase">{t('canvas.sensitive_data')}</span>}
    </span>}
  </div>
}

function BoundaryNode({ data, selected }: NodeProps<Node<BoundaryData, 'boundary'>>) {
  const keepRatio = useContext(ShiftContext)
  return <div className={`tm-boundary relative h-full w-full rounded-2xl border-2 border-dashed ${BOUNDARY_TONE[data.tone]} ${selected ? 'outline-2 outline-offset-2 outline-brand' : ''}`}>
    <NodeResizer isVisible minWidth={220} minHeight={140} keepAspectRatio={keepRatio} color="var(--brand)" lineClassName="tm-resize-line" handleClassName="tm-resize-handle" />
    <span className={`tm-drag absolute top-2 left-3 cursor-move rounded-md bg-panel px-1.5 py-0.5 text-xs font-semibold ${data.tone === 'neutral' ? 'text-app-muted' : TEXT_TONE[data.tone]}`}>{data.name}</span>
  </div>
}

function FlowEdge({ id, sourceX: rawSourceX, sourceY: rawSourceY, targetX: rawTargetX, targetY: rawTargetY, sourcePosition, targetPosition, data, selected, markerEnd }: EdgeProps<Edge<FlowData, 'flow'>>) {
  const { t } = useTranslation('threats')
  // Carril propio si hay más flujos entre los mismos dos componentes (no se pintan uno encima del otro).
  const [sourceX, sourceY] = shift(sourcePosition as Side, rawSourceX, rawSourceY, data?.offset ?? 0)
  const [targetX, targetY] = shift(targetPosition as Side, rawTargetX, rawTargetY, data?.offset ?? 0)
  const [path, midX, midY] = getBezierPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition })
  const at = data?.labelAt ?? 0.5
  const spot = at === 0.5 ? { x: midX, y: midY } : curvePoint(sourceX, sourceY, sourcePosition as Side, targetX, targetY, targetPosition as Side, at)
  const labelX = Math.round(spot.x), labelY = Math.round(spot.y)
  const flow = data?.flow
  // En el lienzo, corta: número y protocolo (lo mismo que el SVG y el informe). Completa al seleccionarla y en el título.
  const short = flow ? `${data?.number} · ${flow.protocol.toUpperCase()}` : ''
  const label = flow ? `${short}${flow.name ? ` · ${flow.name}` : ''}${flow.encrypted ? '' : ` · ${t('canvas.unencrypted_flow')}`}` : ''
  return <>
    <BaseEdge id={id} path={path} markerEnd={markerEnd} className={`tm-flow ${flow?.encrypted ? '' : 'tm-flow--plain'} ${data?.flagged ? 'tm-flow--flagged' : ''} ${selected ? 'tm-flow--selected' : ''}`} />
    {flow && label && <EdgeLabelRenderer>
      <div className="tm-flow-label nodrag nopan" data-x={labelX} data-y={labelY} ref={element => { if (element) element.style.transform = `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}>
        {/* Acotada al hueco entre columnas para no tapar componentes; completa en el título y al seleccionarla. */}
        <span title={label} className={`inline-block truncate rounded-full border px-1.5 py-0.5 align-middle text-[11px] font-semibold ${selected ? 'max-w-[260px] border-brand/60 text-brand' : flow.encrypted ? 'max-w-[132px] border-app-line text-app-muted' : 'max-w-[132px] border-danger-line text-danger'} bg-panel`}>
          {selected ? label : short}
        </span>
      </div>
    </EdgeLabelRenderer>}
  </>
}

const nodeTypes = { component: ComponentNode, boundary: BoundaryNode }
const edgeTypes = { flow: FlowEdge }

function useDarkMode() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'))
  useEffect(() => {
    const observer = new MutationObserver(() => setDark(document.documentElement.classList.contains('dark')))
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])
  return dark
}

type Props = { model: Model; setModel: (model: Model) => void; threats: Threat[]; catalog: Catalog; compact?: boolean }

export function ThreatCanvas(props: Props) {
  return <ReactFlowProvider><Canvas {...props} /></ReactFlowProvider>
}

// React Flow ships its accessible texts in English only; give it the reader's language (WCAG 3.1.2).
function useAriaLabels() {
  const { t } = useTranslation('threats')
  return useMemo(() => ({
    'node.a11yDescription.default': t('canvas.aria.node'),
    'node.a11yDescription.keyboardDisabled': t('canvas.aria.node_keyboard_disabled'),
    'node.a11yDescription.ariaLiveMessage': ({ direction, x, y }: { direction: string; x: number; y: number }) => {
      const at = { x: Math.round(x), y: Math.round(y) }
      return direction === 'left' ? t('canvas.aria.moved_left', at) : direction === 'right' ? t('canvas.aria.moved_right', at)
        : direction === 'up' ? t('canvas.aria.moved_up', at) : t('canvas.aria.moved_down', at)
    },
    'edge.a11yDescription.default': t('canvas.aria.edge'),
    'controls.ariaLabel': t('canvas.aria.controls'),
    'controls.zoomIn.ariaLabel': t('canvas.aria.zoom_in'),
    'controls.zoomOut.ariaLabel': t('canvas.aria.zoom_out'),
    'controls.fitView.ariaLabel': t('canvas.aria.fit_view'),
    'controls.interactive.ariaLabel': t('canvas.aria.interactive'),
    'minimap.ariaLabel': t('canvas.aria.minimap'),
    'handle.ariaLabel': t('canvas.aria.handle'),
  }), [t])
}

function Canvas({ model, setModel, threats, catalog, compact = false }: Props) {
  const { t } = useTranslation('threats')
  const ariaLabels = useAriaLabels()
  const dark = useDarkMode()
  const shift = useShiftKey()
  const flow = useReactFlow()
  const [nodes, setNodes] = useState<CanvasNode[]>(() => build(model, threats, catalog.kinds, []))
  const [selectedFlow, setSelectedFlow] = useState<string | null>(null)
  const commit = useRef(false)
  // Los manejadores del lienzo leen el modelo más reciente sin volver a crearse en cada cambio.
  const modelRef = useRef(model)
  useLayoutEffect(() => { modelRef.current = model }, [model])
  // El modelo es la fuente de verdad; aquí solo se conserva lo que es del lienzo (medidas y selección).
  // Un componente recién añadido queda seleccionado para editarlo en el panel lateral.
  const pendingSelect = useRef<string | null>(null)
  useEffect(() => { const select = pendingSelect.current; pendingSelect.current = null; setNodes(previous => build(model, threats, catalog.kinds, previous, select)) }, [model, threats, catalog.kinds])

  const onNodesChange = useCallback((changes: NodeChange<CanvasNode>[]) => {
    setNodes(previous => {
      let next = applyNodeChanges(changes, previous)
      // Una frontera arrastra consigo a sus componentes.
      for (const change of changes) {
        if (change.type !== 'position' || !change.position || !change.id.startsWith('b:')) continue
        const old = previous.find(node => node.id === change.id)
        if (!old) continue
        const dx = change.position.x - old.position.x, dy = change.position.y - old.position.y
        const members = new Set((modelRef.current.boundaries.find(item => boundaryId(item.id) === change.id)?.components ?? []).map(componentId))
        next = next.map(node => members.has(node.id) ? { ...node, position: { x: node.position.x + dx, y: node.position.y + dy } } : node)
      }
      return next
    })
    if (changes.some(change => (change.type === 'position' && change.dragging === false) || (change.type === 'dimensions' && change.resizing === false))) commit.current = true
    const picked = changes.find(change => change.type === 'select' && change.selected)
    if (picked) setSelectedFlow(null)
  }, [])

  // Al soltar: posiciones, cajas y pertenencia a fronteras pasan al modelo.
  useEffect(() => {
    if (!commit.current) return
    commit.current = false
    const current = modelRef.current
    const members = membership(nodes)
    const byId = Object.fromEntries(nodes.map(node => [node.id, node]))
    const round = (value: number) => Math.round(value * 10) / 10
    setModel({ ...current,
      components: current.components.map(item => { const node = byId[componentId(item.id)]; if (!node) return item
        // Tamaño propio solo si se redimensionó (el alto lo fija el redimensionado; si no, se ajusta al texto).
        const size = node.height ? { width: round(node.width ?? NODE_W), height: round(node.height) } : item.size ?? null
        return { ...item, position: { x: round(node.position.x), y: round(node.position.y) }, size } }),
      boundaries: current.boundaries.map(item => { const node = byId[boundaryId(item.id)]; if (!node) return item
        return { ...item, components: members[item.id] ?? [], box: { x: round(node.position.x), y: round(node.position.y),
          width: round(node.width ?? node.measured?.width ?? 320), height: round(node.height ?? node.measured?.height ?? 220) } } }) })
  }, [nodes, setModel])

  const hot = useMemo(() => new Set(threats.filter(row => row.status === 'evidenced').map(row => row.element)), [threats])
  const rects = useMemo(() => Object.fromEntries(nodes.filter(node => node.type === 'component').map(node => [plain(node.id),
    { ...node.position, width: node.measured?.width ?? node.width ?? NODE_W, height: node.measured?.height ?? node.height ?? NODE_H }])), [nodes])
  const edges = useMemo<Edge<FlowData, 'flow'>[]>(() => {
    const side: Record<string, Side> = { t: 'top', r: 'right', b: 'bottom', l: 'left' }
    const drawn = model.flows.flatMap((item, index) => {
      const a = rects[item.source], b = rects[item.target]
      if (!a || !b) return []
      return [{ item, number: index + 1, handles: sides(a, b) }]
    })
    const offsets = lanes(model.flows)
    const spots = labelSpots(drawn.map(({ item, number, handles }) => ({ id: item.id, source: rects[item.source], target: rects[item.target],
      sourceSide: side[handles[0]], targetSide: side[handles[1]], text: `${number} · ${item.protocol}`, offset: offsets[item.id] })), Object.values(rects))
    return drawn.map(({ item, number, handles: [sourceHandle, targetHandle] }) => ({ id: flowId(item.id), type: 'flow' as const, source: componentId(item.source), target: componentId(item.target),
      sourceHandle, targetHandle, selected: selectedFlow === item.id, data: { flow: item, number, flagged: hot.has(item.id), labelAt: spots[item.id], offset: offsets[item.id] },
      markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18 } }))
  }, [model.flows, rects, selectedFlow, hot])

  const onEdgesChange = useCallback((changes: EdgeChange[]) => {
    const picked = changes.find(change => change.type === 'select')
    if (picked && picked.type === 'select') setSelectedFlow(picked.selected ? plain(picked.id) : null)
  }, [])

  const onConnect = useCallback((connection: Connection) => {
    const current = modelRef.current
    const source = plain(connection.source), target = plain(connection.target)
    if (!source || !target || source === target || current.flows.some(item => item.source === source && item.target === target)) return
    const id = newId(`${source}-${target}`, current.flows.map(item => item.id))
    setModel({ ...current, flows: [...current.flows, { id, source, target, protocol: 'https', data: [], authenticated: true, encrypted: true }] })
    setSelectedFlow(id)
    setNodes(previous => previous.map(node => node.selected ? { ...node, selected: false } : node))
  }, [setModel])

  const remove = useCallback((nodeIds: string[], flowIds: string[]) => {
    const current = modelRef.current
    const components = new Set(nodeIds.filter(id => id.startsWith('c:')).map(plain))
    const boundaries = new Set(nodeIds.filter(id => id.startsWith('b:')).map(plain))
    const flows = new Set(flowIds.map(plain))
    setModel({ ...current,
      components: current.components.filter(item => !components.has(item.id)),
      flows: current.flows.filter(item => !flows.has(item.id) && !components.has(item.source) && !components.has(item.target)),
      boundaries: current.boundaries.filter(item => !boundaries.has(item.id)).map(item => ({ ...item, components: item.components.filter(member => !components.has(member)) })) })
    setSelectedFlow(null)
  }, [setModel])

  const center = () => {
    const bounds = document.querySelector('.tm-canvas')?.getBoundingClientRect()
    return bounds ? flow.screenToFlowPosition({ x: bounds.left + bounds.width / 2, y: bounds.top + bounds.height / 2 }) : { x: 100, y: 100 }
  }
  const addComponent = (kind: Kind) => {
    const current = modelRef.current
    const at = center()
    const id = newId(kind === 'custom' ? 'componente' : catalog.kinds[kind] ?? 'componente', current.components.map(item => item.id))
    pendingSelect.current = componentId(id)
    setModel({ ...current, components: [...current.components, { id, name: kind === 'custom' ? t('canvas.new_component') : catalog.kinds[kind] ?? t('canvas.component'), kind, custom_kind: kind === 'custom' ? t('canvas.custom_kind_default') : '', custom_base: kind === 'custom' ? 'service' : undefined, data: [], internet_facing: kind === 'actor',
      authenticates: PROCESSES.includes(kind), encrypted_at_rest: false, position: { x: Math.round(at.x - NODE_W / 2), y: Math.round(at.y - NODE_H / 2) }, size: null }] })
  }
  const addBoundary = () => {
    const current = modelRef.current
    const at = center()
    const id = newId('frontera', current.boundaries.map(item => item.id))
    setModel({ ...current, boundaries: [...current.boundaries, { id, name: t('canvas.new_boundary'), components: [], box: { x: Math.round(at.x - 170), y: Math.round(at.y - 120), width: 340, height: 240 } }] })
  }
  // Ordenar: todo se recoloca de una vez (componentes y cajas con la misma geometría) y queda guardable.
  const tidy = () => {
    const current = modelRef.current
    const layout = autoLayout({ ...current, components: current.components.map(item => ({ ...item, position: null })) })
    setModel({ ...current, components: current.components.map(item => ({ ...item, position: layout.positions[item.id] ?? item.position ?? null })),
      boundaries: current.boundaries.map(item => ({ ...item, box: layout.boxes[item.id] ?? item.box ?? null })) })
    setTimeout(() => flow.fitView({ padding: 0.15, duration: 300 }), 60)
  }

  const selectedNode = nodes.find(node => node.selected)
  // Con la guía abierta el panel de edición baja bajo el lienzo: el diagrama necesita el ancho.
  return <div className={`grid gap-4 ${compact ? '' : 'xl:grid-cols-[minmax(0,1fr)_320px]'}`}>
    <ShiftContext.Provider value={shift}><div className="tm-canvas h-[640px] overflow-hidden rounded-2xl border border-app-line bg-inset">
      <ReactFlow<CanvasNode, Edge<FlowData, 'flow'>> ariaLabelConfig={ariaLabels} nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
        onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect}
        onDelete={({ nodes: removed, edges: gone }) => remove(removed.map(node => node.id), gone.map(edge => edge.id))}
        connectionMode={ConnectionMode.Loose} deleteKeyCode={['Backspace', 'Delete']}
        // Shift es para mantener la proporción al redimensionar: como tecla de selección por recuadro el
        // panel capturaría el puntero antes que el tirador. La selección múltiple sigue con Cmd/Ctrl.
        selectionKeyCode={null} colorMode={dark ? 'dark' : 'light'}
        fitView fitViewOptions={{ padding: 0.15 }} minZoom={0.2} maxZoom={2} snapToGrid snapGrid={[8, 8]}>
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} />
        <Controls showInteractive={false} />
        <Panel position="bottom-right"><Legend /></Panel>
        <Panel position="top-left" className="flex flex-wrap gap-1.5">
          <Select value={null} onValueChange={value => { if (value) addComponent(value as Kind) }}><SelectTrigger aria-label={t('canvas.add_component')} className="h-8 border-app-line bg-panel text-xs shadow-sm"><Plus className="size-3.5" /><SelectValue placeholder={t('canvas.component_placeholder')} /></SelectTrigger><SelectContent>{Object.entries(catalog.kinds).filter(([key]) => key !== 'custom').map(([key, label]) => <SelectItem key={key} value={key}>{label}</SelectItem>)}<SelectItem value="custom">{t('canvas.other_kind')}</SelectItem></SelectContent></Select>
          <Button size="sm" variant="outline" className="h-8 border-app-line bg-panel shadow-sm" onClick={addBoundary}><Square />{t('canvas.boundary')}</Button>
          <Button size="sm" variant="outline" className="h-8 border-app-line bg-panel shadow-sm" onClick={tidy} title={t('canvas.tidy_hint')}><LayoutGrid />{t('canvas.tidy')}</Button>
        </Panel>
      </ReactFlow>
    </div></ShiftContext.Provider>
    <Inspector model={model} setModel={setModel} catalog={catalog} node={selectedNode} flowId={selectedFlow}
      onRemove={() => remove(selectedNode ? [selectedNode.id] : [], selectedFlow ? [flowId(selectedFlow)] : [])} />
  </div>
}

function Chips({ value, options, onChange }: { value: string[]; options: Record<string, string>; onChange: (next: string[]) => void }) {
  return <div className="flex flex-wrap gap-1">{Object.entries(options).map(([key, label]) => <button key={key} type="button" aria-pressed={value.includes(key)} onClick={() => onChange(value.includes(key) ? value.filter(item => item !== key) : [...value, key])}
    className={`min-h-6 rounded border px-2 py-0.5 text-[11px] ${value.includes(key) ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line text-app-subtle'}`}>{label}</button>)}</div>
}

function Check({ checked, onChange, children }: { checked: boolean; onChange: (value: boolean) => void; children: string }) {
  return <label className="flex items-center gap-2 text-xs text-app-secondary"><input type="checkbox" className="size-3.5 accent-brand" checked={checked} onChange={event => onChange(event.target.checked)} />{children}</label>
}

function Inspector({ model, setModel, catalog, node, flowId: selected, onRemove }: { model: Model; setModel: (model: Model) => void; catalog: Catalog; node?: CanvasNode; flowId: string | null; onRemove: () => void }) {
  const { t } = useTranslation('threats')
  const field = 'block space-y-1'
  const label = 'text-[11px] font-medium text-app-muted'
  if (selected) {
    const item = model.flows.find(entry => entry.id === selected)
    if (!item) return <Help />
    const names = Object.fromEntries(model.components.map(entry => [entry.id, entry.name]))
    const update = (change: Partial<Flow>) => setModel({ ...model, flows: model.flows.map(entry => entry.id === item.id ? { ...entry, ...change } : entry) })
    return <aside className="space-y-4 rounded-2xl border border-app-line bg-panel p-4">
      <div><p className="text-xs text-app-subtle">{t('inspector.flow')}</p><p className="text-sm font-semibold">{names[item.source]} → {names[item.target]}</p></div>
      <label className={field}><span className={label}>{t('inspector.flow_name')}</span><Input value={item.name ?? ''} maxLength={80} placeholder={t('inspector.flow_name_placeholder')} onChange={event => update({ name: event.target.value })} className="h-8 border-app-line bg-app-soft" /></label>
      <label className={field}><span className={label}>{t('inspector.protocol')}</span><select value={item.protocol} onChange={event => update({ protocol: event.target.value })} className={select}>{catalog.protocols.map(protocol => <option key={protocol} value={protocol}>{protocol.toUpperCase()}</option>)}</select></label>
      <div className={field} role="group" aria-label={t('inspector.data')}><span aria-hidden className={label}>{t('inspector.data')}</span><Chips value={item.data} options={catalog.classifications} onChange={data => update({ data })} /></div>
      <div className="space-y-1.5"><Check checked={item.authenticated} onChange={authenticated => update({ authenticated })}>{t('inspector.authenticated')}</Check><Check checked={item.encrypted} onChange={encrypted => update({ encrypted })}>{t('inspector.encrypted_in_transit')}</Check></div>
      <div className="flex gap-2"><Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => update({ source: item.target, target: item.source })}><Undo2 />{t('inspector.reverse')}</Button>
        <Button size="sm" variant="ghost" onClick={onRemove}><Trash2 />{t('common:actions.remove')}</Button></div>
    </aside>
  }
  if (node?.type === 'boundary') {
    const item = model.boundaries.find(entry => boundaryId(entry.id) === node.id)
    if (!item) return <Help />
    return <aside className="space-y-4 rounded-2xl border border-app-line bg-panel p-4">
      <p className="text-xs text-app-subtle">{t('inspector.boundary_heading', { components: t('count.components', { count: item.components.length }) })}</p>
      <label className={field}><span className={label}>{t('inspector.name')}</span><Input value={item.name} maxLength={80} onChange={event => setModel({ ...model, boundaries: model.boundaries.map(entry => entry.id === item.id ? { ...entry, name: event.target.value } : entry) })} className="h-8 border-app-line bg-app-soft" /></label>
      <ColorPicker label={t('inspector.boundary_color')} value={item.color} automatic={t('inspector.boundary_color_default')} onChange={color => setModel({ ...model, boundaries: model.boundaries.map(entry => entry.id === item.id ? { ...entry, color } : entry) })} />
      <p className="text-xs leading-5 text-app-subtle">{t('inspector.boundary_help')}</p>
      <Button size="sm" variant="ghost" onClick={onRemove}><Trash2 />{t('inspector.remove_boundary')}</Button>
    </aside>
  }
  if (node?.type === 'component') {
    const item = model.components.find(entry => componentId(entry.id) === node.id)
    if (!item) return <Help />
    const update = (change: Partial<Component>) => setModel({ ...model, components: model.components.map(entry => entry.id === item.id ? { ...entry, ...change } : entry) })
    return <aside className="space-y-4 rounded-2xl border border-app-line bg-panel p-4">
      <label className={field}><span className={label}>{t('inspector.name')}</span><Input value={item.name} maxLength={80} onChange={event => update({ name: event.target.value })} className="h-8 border-app-line bg-app-soft" /></label>
      <div className="grid grid-cols-2 gap-2">
        <label className={field}><span className={label}>{t('inspector.kind')}</span><Select value={item.kind} onValueChange={value => { if (value) update({ kind: value as Kind, custom_kind: value === 'custom' ? item.custom_kind || t('canvas.custom_kind_default') : '' }) }}><SelectTrigger aria-label={t('inspector.kind_label')} className="h-8 w-full border-app-line bg-app-soft text-xs"><SelectValue>{catalog.kinds[item.kind]}</SelectValue></SelectTrigger><SelectContent>{Object.entries(catalog.kinds).map(([key, text]) => <SelectItem key={key} value={key}>{text}</SelectItem>)}</SelectContent></Select></label>
        <label className={field}><span className={label}>{t('inspector.technology')}</span><Input value={item.technology ?? ''} maxLength={80} placeholder={t('inspector.technology_placeholder')} onChange={event => update({ technology: event.target.value })} className="h-8 border-app-line bg-app-soft" /></label>
      </div>
      {item.kind === 'custom' && <label className={field}><span className={label}>{t('inspector.custom_kind')}</span><Input value={item.custom_kind ?? ''} maxLength={80} onChange={event => update({ custom_kind: event.target.value })} placeholder={t('inspector.custom_kind_placeholder')} className="h-8 border-app-line bg-app-soft" /></label>}
      {item.kind === 'custom' && <label className={field}><span className={label}>{t('inspector.custom_base')}</span><Select value={item.custom_base || 'service'} onValueChange={value => { if (value) update({ custom_base: value as Exclude<Kind, 'custom'> }) }}><SelectTrigger aria-label={t('inspector.custom_base')} className="h-8 w-full border-app-line bg-app-soft text-xs"><SelectValue>{catalog.kinds[item.custom_base || 'service']}</SelectValue></SelectTrigger><SelectContent>{Object.entries(catalog.kinds).filter(([key]) => key !== 'custom').map(([key, text]) => <SelectItem key={key} value={key}>{text}</SelectItem>)}</SelectContent></Select><p className="mt-1 text-[11px] text-app-subtle">{t('inspector.custom_base_hint')}</p></label>}
      <ColorPicker label={t('inspector.color')} value={item.color} automatic={t('inspector.color_by_kind', { color: t(TONE_NAMES[toneOf({ ...item, color: '' })]).toLowerCase() })} onChange={color => update({ color })} />
      <label className={field}><span className={label}>{t('inspector.description')}</span><textarea value={item.description ?? ''} maxLength={400} rows={2} onChange={event => update({ description: event.target.value })} placeholder={t('inspector.description_placeholder')} className="w-full rounded-lg border border-app-line bg-app-soft px-3 py-2 text-xs text-app-fg" /></label>
      <label className={field}><span className={label}>{t('inspector.code')}</span><select value={item.asset ?? ''} onChange={event => update({ asset: event.target.value || null, asset_ref: event.target.value ? '' : item.asset_ref })} className={select}><option value="">{t('inspector.not_linked')}</option>{assetGroups(catalog, model).map(group => <optgroup key={group.label} label={group.label}>{group.items.map(asset => <option key={asset.id} value={asset.id}>{asset.name}</option>)}</optgroup>)}</select>{item.asset_ref && !item.asset && <p className="mt-1 text-xs text-warning">{t('inspector.imported_ref', { ref: item.asset_ref })}</p>}</label>
      {item.asset && <div className={field}><label htmlFor="tm-component-path" className={label}>{t('inspector.path')}</label><Input id="tm-component-path" aria-describedby="tm-component-path-hint" value={item.path ?? ''} maxLength={200} placeholder={t('inspector.path_placeholder')} onChange={event => update({ path: event.target.value })} className="h-8 border-app-line bg-app-soft font-mono text-xs" />
        <p id="tm-component-path-hint" className="text-[11px] leading-4 text-app-subtle">{t('inspector.path_hint')}</p></div>}
      <div className={field} role="group" aria-label={t('inspector.component_data')}><span aria-hidden className={label}>{t('inspector.component_data')}</span><Chips value={item.data} options={catalog.classifications} onChange={data => update({ data })} /></div>
      <div className="space-y-1.5"><Check checked={item.internet_facing} onChange={internet_facing => update({ internet_facing })}>{t('canvas.internet_facing')}</Check><Check checked={item.authenticates} onChange={authenticates => update({ authenticates })}>{t('inspector.authenticates')}</Check>
        {STORES.includes(item.kind === 'custom' ? item.custom_base ?? 'service' : item.kind) && <Check checked={item.encrypted_at_rest} onChange={encrypted_at_rest => update({ encrypted_at_rest })}>{t('canvas.encrypted_at_rest')}</Check>}</div>
      <Button size="sm" variant="ghost" onClick={onRemove}><Trash2 />{t('inspector.remove_component')}</Button>
    </aside>
  }
  return <Help />
}

function Help() {
  const { t } = useTranslation('threats')
  return <aside className="space-y-3 rounded-2xl border border-dashed border-app-line p-4 text-xs leading-5 text-app-subtle">
    <p className="text-sm font-medium text-app-secondary">{t('help.title')}</p>
    <p><Plus className="mr-1 inline size-3" />{t('help.add')}</p>
    <p>{t('help.flows')}</p>
    <p>{t('help.select')}</p>
    <p>{t('help.colors')}</p>
    <p>{t('help.numbers')}</p>
  </aside>
}

// Paleta de tokens como grupo de opciones (patrón radiogroup de WAI-ARIA): Tab entra en la opción elegida y las
// flechas cambian de color.
function ColorPicker({ label, value, automatic, onChange }: { label: string; value?: string; automatic: string; onChange: (color: string) => void }) {
  const { t } = useTranslation('threats')
  const current = TONES.includes(value as Tone) ? value as Tone : ''
  const options: ('' | Tone)[] = ['', ...TONES]
  const move = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const step = event.key === 'ArrowRight' || event.key === 'ArrowDown' ? 1 : event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 0
    if (!step) return
    event.preventDefault()
    const next = options[(options.indexOf(current) + step + options.length) % options.length]
    onChange(next)
    requestAnimationFrame(() => event.currentTarget.querySelector<HTMLButtonElement>(`[data-tone="${next || 'auto'}"]`)?.focus())
  }
  return <div className="space-y-1">
    <span id={`${label}-label`} className="text-[11px] font-medium text-app-muted">{label}</span>
    <div role="radiogroup" aria-labelledby={`${label}-label`} onKeyDown={move} className="flex flex-wrap items-center gap-1.5">
      <button type="button" role="radio" data-tone="auto" aria-checked={current === ''} tabIndex={current === '' ? 0 : -1} onClick={() => onChange('')}
        className={`min-h-6 rounded border px-2 text-[11px] ${current === '' ? 'border-brand/60 bg-brand/10 text-brand' : 'border-app-line text-app-subtle'}`}>{t('inspector.automatic')}</button>
      {TONES.map(tone => <button key={tone} type="button" role="radio" data-tone={tone} aria-checked={current === tone} tabIndex={current === tone ? 0 : -1}
        aria-label={t(TONE_NAMES[tone])} title={t(TONE_NAMES[tone])} onClick={() => onChange(tone)}
        className={`grid size-6 place-items-center rounded-md border-[1.5px] ${NODE_TONE[tone]} ${current === tone ? 'outline-2 outline-offset-1 outline-brand' : ''}`}>
        {current === tone && <CheckIcon aria-hidden className={`size-3.5 ${TEXT_TONE[tone]}`} />}</button>)}
    </div>
    {current === '' && <p className="text-[11px] text-app-subtle">{automatic}</p>}
  </div>
}

function Legend() {
  const { t } = useTranslation('threats')
  return <div role="group" aria-label={t('canvas.legend')} className="hidden max-w-[420px] flex-wrap md:flex items-center gap-x-3 gap-y-1 rounded-lg border border-app-line bg-panel/95 px-2.5 py-1.5 text-[11px] text-app-muted shadow-sm">
    {LEGEND.map(([tone, text]) => <span key={tone} className="flex items-center gap-1"><span aria-hidden className={`inline-block h-2.5 w-4 rounded-sm border ${NODE_TONE[tone]}`} />{t(text)}</span>)}
    <span className="flex items-center gap-1"><span aria-hidden className="inline-block w-4 border-t-[1.5px] border-dashed border-danger" />{t('canvas.unencrypted')}</span>
  </div>
}
