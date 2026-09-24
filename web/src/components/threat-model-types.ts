export type Point = { x: number; y: number }
export type Box = Point & { width: number; height: number }
// Tipos del modelo de amenazas compartidos por la vista y el editor de diagramas.
export type Kind = 'actor' | 'web_app' | 'api' | 'service' | 'function' | 'database' | 'cache' | 'queue' | 'storage' | 'external' | 'identity' | 'custom'
export type Component = { id: string; name: string; kind: Kind; custom_kind?: string; custom_base?: Exclude<Kind, 'custom'>; description?: string; technology?: string; asset?: string | null; asset_ref?: string; path?: string; position?: Point | null; size?: { width: number; height: number } | null; data: string[]; internet_facing: boolean; authenticates: boolean; encrypted_at_rest: boolean; origin?: string }
export type CustomModule = 'stride' | 'linddun' | 'manual' | 'pasta' | 'trees' | 'attack' | 'elements'
export type Flow = { id: string; source: string; target: string; name?: string; protocol: string; data: string[]; authenticated: boolean; encrypted: boolean }
export type Boundary = { id: string; name: string; components: string[]; box?: Box | null }
export type Level = 'low' | 'medium' | 'high'
export type ManualThreat = { id: string; title: string; category?: string; element?: string; severity: 'critical' | 'high' | 'medium' | 'low'; scenario?: string; mitigation?: string; likelihood?: Level | null; impact?: Level | null; owner?: string }
export type TreeNode = { id: string; parent: string | null; text: string; gate: 'and' | 'or'; element?: string; difficulty?: Level | null; mitigated: boolean }
export type AttackTree = { id: string; goal: string; nodes: TreeNode[] }
export type AttackMapping = { technique: string; element?: string; status: 'relevant' | 'mitigated' | 'not_applicable'; note?: string }
export type Model = { id: string; name: string; description?: string; components: Component[]; flows: Flow[]; boundaries: Boundary[]; updated_at?: string; updated_by?: string;
  methodology?: import('./threat-guides').Methodology; custom_modules?: CustomModule[]; repositories?: string[]; repository_refs?: string[]; manual_threats?: ManualThreat[]; attack_trees?: AttackTree[]; attack_mappings?: AttackMapping[]; pasta?: Record<string, string> }
export type MethodsCatalog = { methodologies: Record<string, string>; linddun: Record<string, string>; tactics: Record<string, string>;
  techniques: Record<string, { name: string; name_es: string; tactics: string[] }>; suggestions: Record<string, string[]>; pasta_stages: { key: string; title: string }[] }
export type Evidence = { asset: string; run_id: string; fingerprint: string; title: string; severity: string; location: string }
export type Threat = { id: string; rule: string; stride: string; category: string; title: string; why: string; mitigations: string[]; cwe: number[]; element: string; element_name: string; severity: string; status: 'evidenced' | 'open' | 'mitigated' | 'accepted' | 'not_applicable'; decision?: { status: string; reason: string; by: string; at: string } | null; evidence: Evidence[]; evidence_count: number; framework?: 'stride' | 'linddun' | 'manual'; manual_id?: string; likelihood?: Level | null; impact?: Level | null; owner?: string; evidence_scope?: { asset: string; path: string | null }[] }
export type Summary = { total: number; by_status: Record<string, number>; by_stride: Record<string, number>; by_severity: Record<string, number> }
export type View = { model: Model; threats: Threat[]; summary: Summary }
export type Asset = { id: string; name: string; kind: 'repository' | 'domain'; last_run?: string | null; scanned_at?: string }
export type Catalog = { models: { id: string; name: string; description?: string; updated_at?: string; updated_by?: string; components: number; flows: number; methodology?: string; repositories?: number }[]; assets: Asset[]; kinds: Record<Kind, string>; protocols: string[]; classifications: Record<string, string>; methods: MethodsCatalog }

export const STORES: Kind[] = ['database', 'cache', 'queue', 'storage']
export const PROCESSES: Kind[] = ['web_app', 'api', 'service', 'function']
export const newId = (name: string, used: string[]) => { const base = name.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30) || 'c'; let id = base, n = 2; while (used.includes(id)) id = `${base}-${n++}`; return id }

export function elementsOf(model: Model): { id: string; label: string }[] {
  const names = Object.fromEntries(model.components.map(item => [item.id, item.name]))
  return [...model.components.map(item => ({ id: item.id, label: item.name })),
          ...model.flows.map(item => ({ id: item.id, label: `${names[item.source] ?? '?'} → ${names[item.target] ?? '?'}${item.name ? ` (${item.name})` : ''}` }))]
}

// Repositorios para enlazar un componente: primero los del proyecto, luego el resto.
export function assetGroups(catalog: Catalog, model: Model): { label: string; items: Asset[] }[] {
  const linked = new Set(model.repositories ?? [])
  const project = catalog.assets.filter(item => linked.has(item.id))
  const others = catalog.assets.filter(item => !linked.has(item.id))
  return [{ label: 'Del proyecto', items: project }, { label: project.length ? 'Otros' : 'Repositorios y dominios', items: others }].filter(group => group.items.length)
}
