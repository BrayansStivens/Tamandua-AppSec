import { describe, expect, it, vi } from 'vitest'
import { useState, type ReactElement } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import i18n from '@/shared/i18n'
import { keys, type JiraQueued } from '@/shared/api/queries'
import { mockApi } from '@/shared/test/api'
import { BatchDetail, JiraBackgroundWork } from '@/features/integrations/jira-background'
import { useJiraSettled } from '@/features/integrations/jira-batches'
import { JiraExportDialog } from '@/features/integrations/jira-export'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`integrations:${key}`, options)
const print = (index: number) => index.toString(16).padStart(64, '0')
const MANY = Array.from({ length: 120 }, (_, index) => ({ fingerprint: print(index), label: `Finding ${index}` }))
const QUEUED: JiraQueued = { batch: 'b1', by: 'ana', started_at: '2026-09-30T10:00:00Z', finished_at: null, queued: 80, findings: 118, linked: 1, created: 0, existing: 0,
  skipped: 0, failed: 0, pending: 80, last_error: null, force: false, rejected: [{ fingerprint: print(5), asset: 'github#1', error: 'No Jira destination for this repository' }] }

function setup(element: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const invalidate = vi.spyOn(client, 'invalidateQueries')
  render(<QueryClientProvider client={client}>{element}</QueryClientProvider>)
  return { client, invalidate }
}
function Settled({ onSettled }: { onSettled: () => void }) { useJiraSettled(onSettled); return null }
// The dialog as the findings view uses it: closing unmounts it.
function Export({ onClose }: { onClose: () => void }) {
  const [open, setOpen] = useState(true)
  return open ? <JiraExportDialog selection={{ asset: 'github#1' }} findings={MANY} onClose={() => { onClose(); setOpen(false) }} onDone={() => {}} /> : null
}

describe('large selections run in the background', () => {
  it('closes the dialog on queueing and follows the batch from the shell until nothing is pending', async () => {
    const polls = [{ items: [] as JiraQueued[] }, { items: [{ ...QUEUED, created: 40, existing: 2, pending: 38, rejected: undefined }] },
      { items: [{ ...QUEUED, created: 76, existing: 2, failed: 2, pending: 0, finished_at: '2026-09-30T10:03:00Z', last_error: 'Jira responded 400', rejected: undefined }] }]
    const calls = mockApi(call => call.path === '/api/integrations/jira/issues/queue' ? { status: 202, body: QUEUED }
      : call.path === '/api/integrations/jira/issues/batches' ? { body: polls.length > 1 ? polls.shift() : polls[0] } : undefined)
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const notice = vi.fn(), close = vi.fn(), settled = vi.fn()
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
      const { invalidate } = setup(<><JiraBackgroundWork onNotice={notice} /><Settled onSettled={settled} />
        <Export onClose={close} /></>)
      await vi.waitFor(() => expect(calls.some(call => call.path === '/api/integrations/jira/issues/batches')).toBe(true))
      expect(screen.queryByRole('button', { name: /Jira/ })).toBeNull()
      await user.click(screen.getByRole('button', { name: tr('jira.export.submit', { count: 120 }) }))

      expect(close).toHaveBeenCalledOnce()
      expect(calls.filter(call => call.path.endsWith('/queue'))).toEqual([{ method: 'POST', path: '/api/integrations/jira/issues/queue', action: 'export-jira',
        body: { selections: [{ asset: 'github#1', fingerprints: MANY.map(item => item.fingerprint) }] } }])
      expect(await screen.findByRole('button', { name: tr('jira.background.label', { done: 0, total: 80 }) })).toBeTruthy()
      expect(notice).toHaveBeenCalledWith('ok', tr('jira.background.started', { count: 80 }))

      await vi.advanceTimersByTimeAsync(3100)
      expect(await screen.findByRole('button', { name: tr('jira.background.label', { done: 42, total: 80 }) })).toBeTruthy()
      await vi.advanceTimersByTimeAsync(3100)
      await vi.waitFor(() => expect(notice).toHaveBeenCalledWith('error', tr('jira.background.finished_failed', { count: 76, failed: 2 })))
      expect(settled).toHaveBeenCalledOnce()
      expect(invalidate).toHaveBeenCalledWith({ queryKey: keys.runs })
      // Finished: no more polling.
      const count = calls.filter(call => call.path === '/api/integrations/jira/issues/batches').length
      await vi.advanceTimersByTimeAsync(10_000)
      expect(calls.filter(call => call.path === '/api/integrations/jira/issues/batches')).toHaveLength(count)
      expect(screen.getByRole('button', { name: tr('jira.background.label_done') })).toBeTruthy()
    } finally { vi.useRealTimers() }
  })

  it('"create anyway" asks first and sends force with only the linked findings, by asset', async () => {
    const calls = mockApi(call => call.path.endsWith('/queue') ? { status: 202, body: { ...QUEUED, batch: 'b2', force: true } } : { body: { items: [] } })
    const user = userEvent.setup()
    const linked = [{ fingerprint: print(1), asset: 'github#1', key: 'PAY-1', url: 'https://acme.atlassian.net/browse/PAY-1' },
      { fingerprint: print(2), asset: 'github#2', key: 'WEB-9', url: 'https://acme.atlassian.net/browse/WEB-9' }, { fingerprint: print(3), asset: 'github#1', key: 'PAY-1', url: 'https://acme.atlassian.net/browse/PAY-1' }]
    setup(<BatchDetail batch={{ ...QUEUED, pending: 0, finished_at: '2026-09-30T10:03:00Z', linked: 3, linked_items: linked }} />)
    expect(screen.getByText(new RegExp(tr('jira.queue.linked', { count: 3 })))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('jira.background.review') }))
    expect(screen.getByRole('link', { name: 'WEB-9' }).getAttribute('href')).toBe('https://acme.atlassian.net/browse/WEB-9')
    await user.click(screen.getByRole('button', { name: tr('jira.force.action', { count: 3 }) }))
    expect(calls.some(call => call.path.endsWith('/queue'))).toBe(false)
    expect(screen.getByText(tr('jira.force.explain', { count: 3 }))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('jira.force.confirm', { count: 3 }) }))

    await vi.waitFor(() => expect(calls.filter(call => call.path.endsWith('/queue'))).toEqual([{ method: 'POST', path: '/api/integrations/jira/issues/queue', action: 'export-jira',
      body: { selections: [{ asset: 'github#1', fingerprints: [print(1), print(3)] }, { asset: 'github#2', fingerprints: [print(2)] }], force: true } }]))
    expect(await screen.findByText(tr('jira.background.force_queued', { count: 3 }))).toBeTruthy()
  })

  it('in the synchronous result, "create anyway" sends force with only the findings that already had an issue', async () => {
    const existing = { fingerprint: print(1), asset: 'github#1', key: 'PAY-1', url: 'https://acme.atlassian.net/browse/PAY-1', project: 'PAY' }
    const replies = [{ created: [{ ...existing, fingerprint: print(0), key: 'PAY-2' }], existing: [existing], failed: [] }, { created: [{ ...existing, key: 'PAY-3' }], existing: [], failed: [] }]
    const calls = mockApi(() => ({ body: replies.shift() }))
    const user = userEvent.setup()
    setup(<JiraExportDialog selection={{ runId: 'run-1' }} findings={MANY.slice(0, 2)} onClose={() => {}} onDone={() => {}} />)
    await user.click(screen.getByRole('button', { name: tr('jira.export.submit', { count: 2 }) }))
    await user.click(await screen.findByRole('button', { name: tr('jira.force.action', { count: 1 }) }))
    await user.click(screen.getByRole('button', { name: tr('jira.force.confirm', { count: 1 }) }))

    expect(await screen.findByRole('link', { name: 'PAY-3' })).toBeTruthy()
    expect(calls.map(call => call.body)).toEqual([{ run_id: 'run-1', fingerprints: [print(0), print(1)] }, { run_id: 'run-1', fingerprints: [print(1)], force: true }])
  })
})
