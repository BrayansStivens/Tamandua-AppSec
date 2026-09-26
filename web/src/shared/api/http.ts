// Cliente único: todas las llamadas pasan por aquí, con la cabecera de acción y errores normalizados.
// La cookie de sesión es HttpOnly y viaja sola en peticiones del mismo origen; si el servidor
// responde 401, se avisa a la puerta de sesión para volver a la pantalla de acceso.
import { currentLocale } from '@/shared/i18n'

export class ApiError extends Error {
  status: number
  retryIn?: number
  code?: string
  // The input a validation error points at (e.g. `rules.2.regex`), when the API says so.
  field?: string
  constructor(message: string, status: number, retryIn?: number, code?: string, field?: string) { super(message); this.status = status; this.retryIn = retryIn; this.code = code; this.field = field }
}

export const UNAUTHORIZED_EVENT = 'tamandua:unauthorized'
export const TOTP_REQUIRED_EVENT = 'tamandua:totp-required'
export const LOADING_EVENT = 'tamandua:loading'

// Peticiones en curso: la barra de progreso superior las escucha para que nada cargue en silencio.
let inflight = 0
const track = <T>(promise: Promise<T>): Promise<T> => {
  inflight += 1
  window.dispatchEvent(new CustomEvent(LOADING_EVENT, { detail: inflight }))
  return promise.finally(() => { inflight = Math.max(0, inflight - 1); window.dispatchEvent(new CustomEvent(LOADING_EVENT, { detail: inflight })) })
}

async function parse<T>(response: Response, path: string): Promise<T> {
  const text = await response.text()
  let body: unknown = null
  try { body = text ? JSON.parse(text) : null } catch { body = null }
  if (!response.ok) {
    const record = body && typeof body === 'object' ? body as { error?: unknown; retry_in?: unknown; code?: unknown; field?: unknown } : {}
    // El login también responde 401 con credenciales malas: eso no es una sesión caducada.
    if (response.status === 401 && !path.startsWith('/api/auth/')) window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))
    if (response.status === 403 && record.code === 'totp_required') window.dispatchEvent(new Event(TOTP_REQUIRED_EVENT))
    throw new ApiError(record.error ? String(record.error) : `Error ${response.status}`, response.status,
      typeof record.retry_in === 'number' ? record.retry_in : undefined, typeof record.code === 'string' ? record.code : undefined,
      typeof record.field === 'string' ? record.field : undefined)
  }
  return body as T
}

// Server text (findings, errors, reports) comes back in the reader's language.
const localeHeaders = () => ({ 'Accept-Language': currentLocale() })

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.append(link)
    link.click()
    link.remove()
  } finally { window.setTimeout(() => URL.revokeObjectURL(url), 60_000) }
}

export const api = {
  get: <T>(path: string, init?: { signal?: AbortSignal }) =>
    track(fetch(path, { credentials: 'same-origin', signal: init?.signal, headers: localeHeaders() }).then(response => parse<T>(response, path))),
  post: <T>(path: string, action: string, body: unknown, init?: { signal?: AbortSignal }) => track(fetch(path, {
    method: 'POST', credentials: 'same-origin', signal: init?.signal,
    headers: { ...localeHeaders(), 'Content-Type': 'application/json', 'X-Tamandua-Action': action }, body: JSON.stringify(body),
  }).then(response => parse<T>(response, path))),
  // Descarga la respuesta de un POST (p. ej. un informe generado con opciones de un formulario).
  downloadPost: (path: string, action: string, body: unknown, filename: string) => track(fetch(path, {
    method: 'POST', credentials: 'same-origin',
    headers: { ...localeHeaders(), 'Content-Type': 'application/json', 'X-Tamandua-Action': action }, body: JSON.stringify(body),
  }).then(async response => {
    if (!response.ok) { await parse(response, path); throw new ApiError(`Error ${response.status}`, response.status) }
    saveBlob(await response.blob(), filename)
  })),
  download: (path: string, filename: string) => track(fetch(path, { credentials: 'same-origin', headers: localeHeaders() }).then(async response => {
    if (!response.ok) { await parse(response, path); throw new ApiError(`Error ${response.status}`, response.status) }
    saveBlob(await response.blob(), filename)
  })),
}

export const query = (params: Record<string, string | number | undefined | null>) =>
  Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`).join('&')
