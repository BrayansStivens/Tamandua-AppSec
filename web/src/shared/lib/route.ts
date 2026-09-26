// Navegación en la URL (#/hallazgos?repo=…&run=…): refrescar deja al usuario donde estaba y Atrás funciona.
// El fragmento #link=… de las invitaciones no empieza por «/» y no se toca aquí.
const SLUGS: Record<string, string> = {
  overview: 'resumen', analyses: 'analisis', new: 'nuevo', findings: 'hallazgos', coverage: 'cobertura', threats: 'amenazas',
  repositories: 'repositorios', pulls: 'pull-requests', domains: 'dominios', integrations: 'integraciones',
  users: 'usuarios', account: 'cuenta', cves: 'cve-tracker', compliance: 'cumplimiento',
}
// Enlaces guardados de antes del cambio de nombre («Pentests» pasó a «Análisis»): siguen funcionando.
const LEGACY: Record<string, string> = { pentests: 'analyses' }
const VIEWS: Record<string, string> = { ...LEGACY, ...Object.fromEntries(Object.entries(SLUGS).map(([view, slug]) => [slug, view])) }
export const ROUTE_EVENT = 'appsec:route'

export function readRoute(): { view: string | null; params: URLSearchParams } {
  const hash = window.location.hash
  if (!hash.startsWith('#/')) return { view: null, params: new URLSearchParams() }
  const [path, search = ''] = hash.slice(2).split('?')
  return { view: VIEWS[path] ?? null, params: new URLSearchParams(search) }
}

export function writeRoute(view: string, params: Record<string, string | null | undefined> = {}, { replace = false } = {}) {
  const search = new URLSearchParams(Object.entries(params).filter(([, value]) => value) as [string, string][]).toString()
  const next = `#/${SLUGS[view] ?? 'resumen'}${search ? `?${search}` : ''}`
  if (next === window.location.hash) return
  if (replace) window.history.replaceState(null, '', next)
  else window.history.pushState(null, '', next)
  window.dispatchEvent(new Event(ROUTE_EVENT))
}

// Cambia un parámetro sin crear una entrada nueva en el historial (p. ej. al elegir un repositorio).
export function setRouteParam(name: string, value: string | null) {
  const { view, params } = readRoute()
  if (!view) return
  const current = Object.fromEntries(params.entries())
  writeRoute(view, { ...current, [name]: value }, { replace: true })
}
