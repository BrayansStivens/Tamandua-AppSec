import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import {
  applyNodeChanges, Background, BackgroundVariant, BaseEdge, ConnectionMode, Controls, EdgeLabelRenderer, getBezierPath, Handle,
  MarkerType, NodeResizer, Panel, Position, ReactFlow, ReactFlowProvider, useReactFlow,
  type Connection, type Edge, type EdgeChange, type EdgeProps, type Node, type NodeChange, type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Globe2, LayoutGrid, Lock, Plus, Square, Trash2, Undo2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { assetGroups, newId, PROCESSES, STORES, type Box, type Catalog, type Component, type Flow, type Kind, type Model, type Point, type Threat } from '@/components/threat-model-types'

// Editor visual del modelo: los componentes se arrastran, los flujos se crean uniendo sus puntos y las
// fronteras son cajas que se mueven y redimensionan. La pertenencia a una frontera sale de dónde está
// cada componente: se dibuja, no se elige en un desplegable. Todo se guarda en el mismo modelo.

const NODE_W = 184, NODE_H = 72, COLUMN = 300, ROW = 124, PAD = 36
const SENSITIVE = ['pii', 'credentials', 'payment']
const select = 'h-8 w-full rounded-lg border border-app-line bg-app-soft px-2 text-xs text-app-fg'

type ComponentData = { component: Component; kindLabel: string; flagged: boolean }
type BoundaryData = { name: string }
type FlowData = { flow: Flow; flagged: boolean }
type CanvasNode = Node<ComponentData, 'component'> | Node<BoundaryData, 'boundary'>

const componentId = (id: string) => `c:${id}`
const boundaryId = (id: string) => `b:${id}`
const flowId = (id: string) => `f:${id}`
const plain = (id: string) => id.slice(2)

// Columnas por frontera, como en las exportaciones, para lo que aún no se ha colocado a mano.
function defaultLayout(model: Model): { positions: Record<string, Point>; boxes: Record<string, Box> } {
  const columns = model.boundaries.map(item => item.components)
  const placed = new Set(columns.flat())
  const loose = model.components.map(item => item.id).filter(id => !placed.has(id))
  if (loose.length) columns.push(loose)
  const positions: Record<string, Point> = {}
  const boxes: Record<string, Box> = {}
  columns.forEach((column, index) => {
    const x = 60 + index * COLUMN
    column.forEach((member, row) => { positions[member] = { x, y: 90 + row * ROW } })
    const boundary = model.boundaries[index]
    if (boundary) boxes[boundary.id] = { x: x - PAD, y: 40, width: NODE_W + PAD * 2, height: 70 + Math.max(1, column.length) * ROW }
  })
  return { positions, boxes }
}

function build(model: Model, threats: Threat[], kinds: Record<Kind, string>, previous: CanvasNode[]): CanvasNode[] {
  const fallback = defaultLayout(model)
  const before = Object.fromEntries(previous.map(node => [node.id, node]))
  const flagged = new Set(threats.filter(row => row.status === 'evidenced').map(row => row.element))
  const boundaries: CanvasNode[] = model.boundaries.map(item => {
    const box = item.box ?? fallback.boxes[item.id] ?? { x: 40, y: 40, width: 320, height: 220 }
    const old = before[boundaryId(item.id)]
    return { id: boundaryId(item.id), type: 'boundary', position: { x: box.x, y: box.y }, width: box.width, height: box.height,
             data: { name: item.name }, zIndex: 0, dragHandle: '.tm-drag', selected: old?.selected ?? false }
  })
  const components: CanvasNode[] = model.components.map(item => {
    const old = before[componentId(item.id)]
    return { id: componentId(item.id), type: 'component', position: item.position ?? old?.position ?? fallback.positions[item.id] ?? { x: 60, y: 60 },
             data: { component: item, kindLabel: kinds[item.kind] ?? item.kind, flagged: flagged.has(item.id) }, zIndex: 1,
             selected: old?.selected ?? false, measured: old?.measured }
  })
  return [...boundaries, ...components]
}

// Qué lado de cada componente mira al otro: así las flechas no se cruzan por dentro de las cajas.
function sides(a: Point, b: Point): [string, string] {
  const dx = b.x - a.x, dy = b.y - a.y
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

function ComponentNode({ data, selected }: NodeProps<Node<ComponentData, 'component'>>) {
  const { component, kindLabel, flagged } = data
  const shape = PROCESSES.includes(component.kind) ? 'rounded-full px-5' : STORES.includes(component.kind) ? 'rounded-none border-x-0 border-y-2' : 'rounded-lg'
  const sensitive = component.data.some(item => SENSITIVE.includes(item))
  return <div title={component.name} className={`tm-node flex min-h-[72px] w-[184px] flex-col items-center justify-center border bg-panel px-3 py-2 text-center shadow-sm ${shape}
    ${flagged ? 'border-amber-500 ring-2 ring-amber-500/40' : 'border-app-line'} ${selected ? 'outline-2 outline-offset-2 outline-brand' : ''}`}>
    {(['t', 'r', 'b', 'l'] as const).map(side => <Handle key={side} id={side} type="source" position={{ t: Position.Top, r: Position.Right, b: Position.Bottom, l: Position.Left }[side]} className="tm-handle" />)}
    <span className="line-clamp-2 text-[13px] leading-4 font-semibold text-app-fg">{component.name}</span>
    <span className="mt-0.5 line-clamp-1 text-[11px] text-app-subtle">{component.technology || kindLabel}</span>
    {(component.internet_facing || sensitive || component.encrypted_at_rest) && <span className="mt-1 flex items-center gap-1.5 text-app-subtle">
      {component.internet_facing && <Globe2 className="size-3" aria-label="Expuesto a Internet" />}
      {component.encrypted_at_rest && <Lock className="size-3" aria-label="Cifrado en reposo" />}
      {sensitive && <span className="rounded bg-app-soft px-1 text-[9px] font-medium tracking-wide uppercase">datos sensibles</span>}
    </span>}
  </div>
}

function BoundaryNode({ data, selected }: NodeProps<Node<BoundaryData, 'boundary'>>) {
  return <div className={`tm-boundary relative h-full w-full rounded-2xl border-2 border-dashed ${selected ? 'border-brand/70' : 'border-app-faint/70'}`}>
    <NodeResizer isVisible={selected} minWidth={220} minHeight={140} color="var(--brand)" />
    <span className="tm-drag absolute top-2 left-3 cursor-move rounded-md bg-app px-1.5 py-0.5 text-xs font-semibold text-app-muted">{data.name}</span>
  </div>
}

function FlowEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, selected, markerEnd }: EdgeProps<Edge<FlowData, 'flow'>>) {
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition })
  const flow = data?.flow
  return <>
    <BaseEdge id={id} path={path} markerEnd={markerEnd} className={`tm-flow ${flow?.encrypted ? '' : 'tm-flow--plain'} ${data?.flagged ? 'tm-flow--flagged' : ''} ${selected ? 'tm-flow--selected' : ''}`} />
    {flow && <EdgeLabelRenderer>
      <div className="tm-flow-label nodrag nopan" data-x={labelX} data-y={labelY} ref={element => { if (element) element.style.transform = `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}>
        <span className={`rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${selected ? 'border-brand/60 text-brand' : 'border-app-line text-app-muted'} bg-panel`}>
          {flow.protocol.toUpperCase()}{flow.name ? ` · ${flow.name}` : ''}{flow.encrypted ? '' : ' · sin cifrar'}
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

function Canvas({ model, setModel, threats, catalog, compact = false }: Props) {
  const dark = useDarkMode()
  const flow = useReactFlow()
  const [nodes, setNodes] = useState<CanvasNode[]>(() => build(model, threats, catalog.kinds, []))
  const [selectedFlow, setSelectedFlow] = useState<string | null>(null)
  const commit = useRef(false)
  // Los manejadores del lienzo leen el modelo más reciente sin volver a crearse en cada cambio.
  const modelRef = useRef(model)
  useLayoutEffect(() => { modelRef.current = model }, [model])
  // El modelo es la fuente de verdad; aquí solo se conserva lo que es del lienzo (medidas y selección).
  useEffect(() => { setNodes(previous => build(model, threats, catalog.kinds, previous)) }, [model, threats, catalog.kinds])

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
      components: current.components.map(item => { const node = byId[componentId(item.id)]; return node ? { ...item, position: { x: round(node.position.x), y: round(node.position.y) } } : item }),
      boundaries: current.boundaries.map(item => { const node = byId[boundaryId(item.id)]; if (!node) return item
        return { ...item, components: members[item.id] ?? [], box: { x: round(node.position.x), y: round(node.position.y),
          width: round(node.width ?? node.measured?.width ?? 320), height: round(node.height ?? node.measured?.height ?? 220) } } }) })
  }, [nodes, setModel])

  const positions = useMemo(() => Object.fromEntries(nodes.filter(node => node.type === 'component').map(node => [plain(node.id), node.position])), [nodes])
  const hot = useMemo(() => new Set(threats.filter(row => row.status === 'evidenced').map(row => row.element)), [threats])
  const edges = useMemo<Edge<FlowData, 'flow'>[]>(() => model.flows.flatMap(item => {
    const a = positions[item.source], b = positions[item.target]
    if (!a || !b) return []
    const [sourceHandle, targetHandle] = sides(a, b)
    return [{ id: flowId(item.id), type: 'flow', source: componentId(item.source), target: componentId(item.target), sourceHandle, targetHandle,
              selected: selectedFlow === item.id, data: { flow: item, flagged: hot.has(item.id) }, markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18 } }]
  }), [model.flows, positions, selectedFlow, hot])

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
    const id = newId(catalog.kinds[kind] ?? 'componente', current.components.map(item => item.id))
    setModel({ ...current, components: [...current.components, { id, name: catalog.kinds[kind] ?? 'Componente', kind, data: [], internet_facing: kind === 'actor',
      authenticates: PROCESSES.includes(kind), encrypted_at_rest: false, position: { x: Math.round(at.x - NODE_W / 2), y: Math.round(at.y - NODE_H / 2) } }] })
  }
  const addBoundary = () => {
    const current = modelRef.current
    const at = center()
    const id = newId('frontera', current.boundaries.map(item => item.id))
    setModel({ ...current, boundaries: [...current.boundaries, { id, name: 'Nueva frontera', components: [], box: { x: Math.round(at.x - 170), y: Math.round(at.y - 120), width: 340, height: 240 } }] })
  }
  const tidy = () => {
    const current = modelRef.current
    setModel({ ...current, components: current.components.map(item => ({ ...item, position: null })), boundaries: current.boundaries.map(item => ({ ...item, box: null })) })
    setTimeout(() => flow.fitView({ padding: 0.15 }), 50)
  }

  const selectedNode = nodes.find(node => node.selected)
  // Con la guía abierta el panel de edición baja bajo el lienzo: el diagrama necesita el ancho.
  return <div className={`grid gap-4 ${compact ? '' : 'xl:grid-cols-[minmax(0,1fr)_320px]'}`}>
    <div className="tm-canvas h-[640px] overflow-hidden rounded-2xl border border-app-line bg-inset">
      <ReactFlow<CanvasNode, Edge<FlowData, 'flow'>> nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
        onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onConnect={onConnect}
        onDelete={({ nodes: removed, edges: gone }) => remove(removed.map(node => node.id), gone.map(edge => edge.id))}
        connectionMode={ConnectionMode.Loose} deleteKeyCode={['Backspace', 'Delete']} colorMode={dark ? 'dark' : 'light'}
        fitView fitViewOptions={{ padding: 0.15 }} minZoom={0.2} maxZoom={2} snapToGrid snapGrid={[8, 8]}>
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} />
        <Controls showInteractive={false} />
        <Panel position="top-left" className="flex flex-wrap gap-1.5">
          <select aria-label="Añadir componente" value="" onChange={event => { if (event.target.value) addComponent(event.target.value as Kind) }} className="h-8 rounded-lg border border-app-line bg-panel px-2 text-xs text-app-fg shadow-sm">
            <option value="">+ Componente…</option>
            {Object.entries(catalog.kinds).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
          </select>
          <Button size="sm" variant="outline" className="h-8 border-app-line bg-panel shadow-sm" onClick={addBoundary}><Square />Frontera</Button>
          <Button size="sm" variant="outline" className="h-8 border-app-line bg-panel shadow-sm" onClick={tidy} title="Colocar en columnas por frontera"><LayoutGrid />Ordenar</Button>
        </Panel>
      </ReactFlow>
    </div>
    <Inspector model={model} setModel={setModel} catalog={catalog} node={selectedNode} flowId={selectedFlow}
      onRemove={() => remove(selectedNode ? [selectedNode.id] : [], selectedFlow ? [flowId(selectedFlow)] : [])} />
  </div>
}

function Chips({ value, options, onChange }: { value: string[]; options: Record<string, string>; onChange: (next: string[]) => void }) {
  return <div className="flex flex-wrap gap-1">{Object.entries(options).map(([key, label]) => <button key={key} type="button" onClick={() => onChange(value.includes(key) ? value.filter(item => item !== key) : [...value, key])}
    className={`rounded border px-1.5 py-0.5 text-[10px] ${value.includes(key) ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line text-app-subtle'}`}>{label}</button>)}</div>
}

function Check({ checked, onChange, children }: { checked: boolean; onChange: (value: boolean) => void; children: string }) {
  return <label className="flex items-center gap-2 text-xs text-app-secondary"><input type="checkbox" className="size-3.5 accent-brand" checked={checked} onChange={event => onChange(event.target.checked)} />{children}</label>
}

function Inspector({ model, setModel, catalog, node, flowId: selected, onRemove }: { model: Model; setModel: (model: Model) => void; catalog: Catalog; node?: CanvasNode; flowId: string | null; onRemove: () => void }) {
  const field = 'space-y-1'
  const label = 'text-[11px] font-medium text-app-muted'
  if (selected) {
    const item = model.flows.find(entry => entry.id === selected)
    if (!item) return <Help />
    const names = Object.fromEntries(model.components.map(entry => [entry.id, entry.name]))
    const update = (change: Partial<Flow>) => setModel({ ...model, flows: model.flows.map(entry => entry.id === item.id ? { ...entry, ...change } : entry) })
    return <aside className="space-y-4 rounded-2xl border border-app-line bg-panel p-4">
      <div><p className="text-xs text-app-subtle">Flujo de datos</p><p className="text-sm font-semibold">{names[item.source]} → {names[item.target]}</p></div>
      <div className={field}><span className={label}>Qué viaja</span><Input value={item.name ?? ''} maxLength={80} placeholder="p. ej. consultas de pedidos" onChange={event => update({ name: event.target.value })} className="h-8 border-app-line bg-app-soft" /></div>
      <div className={field}><span className={label}>Protocolo</span><select value={item.protocol} onChange={event => update({ protocol: event.target.value })} className={select}>{catalog.protocols.map(protocol => <option key={protocol} value={protocol}>{protocol.toUpperCase()}</option>)}</select></div>
      <div className={field}><span className={label}>Datos</span><Chips value={item.data} options={catalog.classifications} onChange={data => update({ data })} /></div>
      <div className="space-y-1.5"><Check checked={item.authenticated} onChange={authenticated => update({ authenticated })}>Autenticado</Check><Check checked={item.encrypted} onChange={encrypted => update({ encrypted })}>Cifrado en tránsito</Check></div>
      <div className="flex gap-2"><Button size="sm" variant="outline" className="border-app-line bg-app-soft" onClick={() => update({ source: item.target, target: item.source })}><Undo2 />Invertir</Button>
        <Button size="sm" variant="ghost" onClick={onRemove}><Trash2 />Quitar</Button></div>
    </aside>
  }
  if (node?.type === 'boundary') {
    const item = model.boundaries.find(entry => boundaryId(entry.id) === node.id)
    if (!item) return <Help />
    return <aside className="space-y-4 rounded-2xl border border-app-line bg-panel p-4">
      <p className="text-xs text-app-subtle">Frontera de confianza · {item.components.length} componentes</p>
      <div className={field}><span className={label}>Nombre</span><Input value={item.name} maxLength={80} onChange={event => setModel({ ...model, boundaries: model.boundaries.map(entry => entry.id === item.id ? { ...entry, name: event.target.value } : entry) })} className="h-8 border-app-line bg-app-soft" /></div>
      <p className="text-xs leading-5 text-app-subtle">Arrástrala por su nombre (se lleva sus componentes) y ajústala desde las esquinas. Un componente pertenece a la frontera en la que está su centro.</p>
      <Button size="sm" variant="ghost" onClick={onRemove}><Trash2 />Quitar frontera</Button>
    </aside>
  }
  if (node?.type === 'component') {
    const item = model.components.find(entry => componentId(entry.id) === node.id)
    if (!item) return <Help />
    const update = (change: Partial<Component>) => setModel({ ...model, components: model.components.map(entry => entry.id === item.id ? { ...entry, ...change } : entry) })
    return <aside className="space-y-4 rounded-2xl border border-app-line bg-panel p-4">
      <div className={field}><span className={label}>Nombre</span><Input value={item.name} maxLength={80} onChange={event => update({ name: event.target.value })} className="h-8 border-app-line bg-app-soft" /></div>
      <div className="grid grid-cols-2 gap-2">
        <div className={field}><span className={label}>Tipo</span><select value={item.kind} onChange={event => update({ kind: event.target.value as Kind })} className={select}>{Object.entries(catalog.kinds).map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select></div>
        <div className={field}><span className={label}>Tecnología</span><Input value={item.technology ?? ''} maxLength={80} placeholder="p. ej. Django" onChange={event => update({ technology: event.target.value })} className="h-8 border-app-line bg-app-soft" /></div>
      </div>
      <div className={field}><span className={label}>Código (repositorio)</span><select value={item.asset ?? ''} onChange={event => update({ asset: event.target.value || null, path: event.target.value ? item.path : '' })} className={select}><option value="">Sin enlazar</option>{assetGroups(catalog, model).map(group => <optgroup key={group.label} label={group.label}>{group.items.map(asset => <option key={asset.id} value={asset.id}>{asset.name}</option>)}</optgroup>)}</select></div>
      {item.asset && <div className={field}><span className={label}>Carpeta dentro del repositorio</span><Input value={item.path ?? ''} maxLength={200} placeholder="vacío = todo el repositorio · p. ej. frontend/" onChange={event => update({ path: event.target.value })} className="h-8 border-app-line bg-app-soft font-mono text-xs" />
        <p className="text-[11px] leading-4 text-app-subtle">Solo los hallazgos de esa carpeta cuentan como indicios de sus amenazas. En un monorepo evita que el backend «evidencie» amenazas del frontend.</p></div>}
      <div className={field}><span className={label}>Datos que guarda o maneja</span><Chips value={item.data} options={catalog.classifications} onChange={data => update({ data })} /></div>
      <div className="space-y-1.5"><Check checked={item.internet_facing} onChange={internet_facing => update({ internet_facing })}>Expuesto a Internet</Check><Check checked={item.authenticates} onChange={authenticates => update({ authenticates })}>Autentica</Check>
        {STORES.includes(item.kind) && <Check checked={item.encrypted_at_rest} onChange={encrypted_at_rest => update({ encrypted_at_rest })}>Cifrado en reposo</Check>}</div>
      <Button size="sm" variant="ghost" onClick={onRemove}><Trash2 />Quitar componente</Button>
    </aside>
  }
  return <Help />
}

function Help() {
  return <aside className="space-y-3 rounded-2xl border border-dashed border-app-line p-4 text-xs leading-5 text-app-subtle">
    <p className="text-sm font-medium text-app-secondary">Cómo se usa</p>
    <p><Plus className="mr-1 inline size-3" />Añade componentes y fronteras desde la barra del lienzo.</p>
    <p>Para crear un flujo, arrastra desde uno de los puntos de un componente hasta otro. La flecha indica hacia dónde viajan los datos.</p>
    <p>Pulsa un componente, un flujo o el nombre de una frontera para editarlo aquí. Suprimir borra lo seleccionado.</p>
    <p>Borde ámbar: amenazas con indicios en los análisis. Línea discontinua: flujo sin cifrar.</p>
  </aside>
}
