export type Point = { x: number; y: number }
export type Box = Point & { width: number; height: number }
// Tipos del modelo de amenazas compartidos por la vista y el editor de diagramas.
export type Kind = 'actor' | 'web_app' | 'api' | 'service' | 'function' | 'database' | 'cache' | 'queue' | 'storage' | 'external' | 'identity'
export type Component = { id: string; name: string; kind: Kind; description?: string; technology?: string; asset?: string | null; path?: string; position?: Point | null; data: string[]; internet_facing: boolean; authenticates: boolean; encrypted_at_rest: boolean; origin?: string }
export type Flow = { id: string; source: string; target: string; name?: string; protocol: string; data: string[]; authenticated: boolean; encrypted: boolean }
export type Boundary = { id: string; name: string; components: string[]; box?: Box | null }
export type Model = { id: string; name: string; description?: string; components: Component[]; flows: Flow[]; boundaries: Boundary[]; updated_at?: string; updated_by?: string }
export type Evidence = { asset: string; run_id: string; fingerprint: string; title: string; severity: string; location: string }
export type Threat = { id: string; rule: string; stride: string; category: string; title: string; why: string; mitigations: string[]; cwe: number[]; element: string; element_name: string; severity: string; status: 'evidenced' | 'open' | 'mitigated' | 'accepted' | 'not_applicable'; decision?: { status: string; reason: string; by: string; at: string } | null; evidence: Evidence[]; evidence_count: number; evidence_scope?: { asset: string; path: string | null }[] }
export type Summary = { total: number; by_status: Record<string, number>; by_stride: Record<string, number>; by_severity: Record<string, number> }
export type View = { model: Model; threats: Threat[]; summary: Summary }
export type Asset = { id: string; name: string; kind: 'repository' | 'domain'; last_run?: string | null; scanned_at?: string }
export type Catalog = { models: { id: string; name: string; description?: string; updated_at?: string; updated_by?: string; components: number; flows: number }[]; assets: Asset[]; kinds: Record<Kind, string>; protocols: string[]; classifications: Record<string, string> }

export const STORES: Kind[] = ['database', 'cache', 'queue', 'storage']
export const PROCESSES: Kind[] = ['web_app', 'api', 'service', 'function']
export const newId = (name: string, used: string[]) => { const base = name.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30) || 'c'; let id = base, n = 2; while (used.includes(id)) id = `${base}-${n++}`; return id }
