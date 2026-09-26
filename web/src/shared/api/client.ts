// Cliente tipado: los tipos salen del OpenAPI del backend (make openapi → schema.d.ts), así el panel y la API no se
// desincronizan. Por debajo usa el cliente de siempre (lib/api), que mantiene la barra de progreso, el aviso de sesión
// caducada y el de segundo factor pendiente.
import { api, query } from '@/lib/api'
import type { paths } from './schema'

type Get<P extends keyof paths> = paths[P] extends { get: infer Operation } ? Operation : never
type Query<P extends keyof paths> = Get<P> extends { parameters: { query?: infer Params } } ? NonNullable<Params> : never
export type Response<P extends keyof paths> = Get<P> extends { responses: { 200: { content: { 'application/json': infer Body } } } } ? Body : never
type GetPath = { [P in keyof paths]: Get<P> extends never ? never : P }[keyof paths]

export function apiGet<P extends GetPath>(path: P, params?: Query<P>, init?: { signal?: AbortSignal }): Promise<Response<P>> {
  const search = params ? query(params as Record<string, string | number | undefined | null>) : ''
  return api.get<Response<P>>(search ? `${path}?${search}` : path, init)
}
