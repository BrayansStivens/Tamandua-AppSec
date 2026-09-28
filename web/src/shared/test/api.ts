import { vi } from 'vitest'

// What the panel sent: method, path with its query, the X-Tamandua-Action header and the JSON body.
export type Call = { method: string; path: string; action: string | null; body: unknown }
export type Reply = { status?: number; body?: unknown }

// Replaces fetch with `handler`, which answers each call (200 with no body when it returns nothing).
export function mockApi(handler: (call: Call) => Reply | undefined): Call[] {
  const calls: Call[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost')
    const headers = new Headers(init?.headers)
    const call = { method: init?.method ?? 'GET', path: url.pathname + url.search, action: headers.get('X-Tamandua-Action'),
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : null }
    calls.push(call)
    const { status = 200, body = null } = handler(call) ?? {}
    return new Response(body === null ? '' : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  }))
  return calls
}
