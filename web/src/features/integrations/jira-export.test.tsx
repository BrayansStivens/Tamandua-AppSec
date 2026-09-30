import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Reply } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { JiraExportDialog, JiraFindingAction } from '@/features/integrations/jira-export'
import { useJiraAvailability } from '@/features/integrations/jira-availability'
import { RepositoryResult, type RepositoryFinding, type RepositoryRun } from '@/features/findings/repository-result'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`integrations:${key}`, options)
const CONNECTED = { configured: true, site: 'https://acme.atlassian.net', email: 'sec@acme.test', last4: 'abcd', destinations: 1, rules: 2, automatic: false }
const ROUTING = {
  destinations: [{ id: 'd1', name: 'Payments', project: { key: 'PAY' }, issue_type: { name: 'Bug' }, mapping: {} }],
  rules: [{ id: 'a1', name: 'Payments', assets: [], patterns: ['org/payments-*'], destination: 'd1', mode: 'manual', min_severity: 'high', backfill: false, enabled: true },
    { id: 'default', name: 'Every other repository', default: true, assets: [], patterns: [], destination: null, mode: 'manual', min_severity: 'high', backfill: false, enabled: false }],
  history: [], limits: {},
}

function Action({ canManage, name, ticket, pending = true, onCreate = () => {} }: { canManage: boolean; name: string; ticket?: { key: string; url: string }; pending?: boolean; onCreate?: () => void }) {
  const availability = useJiraAvailability(canManage, { key: 'github#1', name })
  return <JiraFindingAction ticket={ticket} pending={pending} availability={availability} name="eval on user input" onCreate={onCreate} />
}
function api(status: unknown, routing: unknown = ROUTING) {
  return mockApi(call => call.path === '/api/integrations/jira' ? { body: status } : call.path === '/api/integrations/jira/routing' ? { body: routing } : undefined)
}
const createButton = () => screen.findByRole('button', { name: tr('jira.finding.create_label', { name: 'eval on user input' }) })

describe('creating one finding in Jira', () => {
  it('shows the linked issue instead of the action', async () => {
    api(CONNECTED)
    renderWithQueries(<Action canManage name="org/payments-api" ticket={{ key: 'PAY-12', url: 'https://acme.atlassian.net/browse/PAY-12' }} />)
    const link = screen.getByRole('link', { name: tr('jira.finding.open_issue', { key: 'PAY-12' }) })
    expect(link.getAttribute('href')).toBe('https://acme.atlassian.net/browse/PAY-12')
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('is disabled, saying why, when Jira is not connected or no rule routes the repository', async () => {
    api({ configured: false })
    const { unmount } = renderWithQueries(<Action canManage name="org/payments-api" />)
    const disconnected = await createButton()
    expect(disconnected.hasAttribute('disabled')).toBe(true)
    expect(document.getElementById(disconnected.getAttribute('aria-describedby') ?? '')?.textContent).toBe(tr('jira.finding.not_configured'))
    unmount()

    api(CONNECTED)
    renderWithQueries(<Action canManage name="org/identity" />)
    expect(await screen.findByText(tr('jira.finding.no_rule'))).toBeTruthy()
    expect((await createButton()).hasAttribute('disabled')).toBe(true)
  })

  it('is enabled when a rule routes the repository, or for a member when the server decides', async () => {
    const calls = api(CONNECTED)
    const create = vi.fn()
    const { unmount } = renderWithQueries(<Action canManage name="org/payments-api" onCreate={create} />)
    await vi.waitFor(() => expect(calls.some(call => call.path === '/api/integrations/jira/routing')).toBe(true))
    const user = userEvent.setup()
    await vi.waitFor(async () => expect((await createButton()).hasAttribute('disabled')).toBe(false))
    await user.click(await createButton())
    expect(create).toHaveBeenCalledOnce()
    unmount()

    const member = api(CONNECTED)
    renderWithQueries(<Action canManage={false} name="org/identity" />)
    await vi.waitFor(async () => expect((await createButton()).hasAttribute('disabled')).toBe(false))
    expect(member.some(call => call.path === '/api/integrations/jira/routing')).toBe(false)
  })

  it('is not offered for a dismissed finding', () => {
    api(CONNECTED)
    renderWithQueries(<Action canManage name="org/payments-api" pending={false} />)
    expect(screen.queryByRole('button')).toBeNull()
  })
})

describe('the export result', () => {
  const FINDINGS = [{ fingerprint: 'a'.repeat(64), label: 'lodash 4.17.20' }, { fingerprint: 'b'.repeat(64), label: 'lodash prototype pollution' }, { fingerprint: 'c'.repeat(64), label: 'eval on user input' }]
  const RESULT: Reply = { body: {
    created: [{ fingerprint: 'a'.repeat(64), asset: 'github#1', key: 'PAY-7', url: 'https://acme.atlassian.net/browse/PAY-7', project: 'PAY', destination: 'd1' },
      { fingerprint: 'b'.repeat(64), asset: 'github#1', key: 'PAY-7', url: 'https://acme.atlassian.net/browse/PAY-7', project: 'PAY', destination: 'd1' }],
    existing: [],
    failed: [{ fingerprint: 'c'.repeat(64), asset: 'github#1', error: 'No Jira destination for this repository' }],
  } }

  it('sends the asset view and says per finding which issue it got or why it failed', async () => {
    const calls = mockApi(() => RESULT)
    const done = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<JiraExportDialog selection={{ asset: 'github#1' }} findings={FINDINGS} target="PAY · Bug" onClose={() => {}} onDone={done} />)
    expect(screen.getByText(tr('jira.export.intro_target', { target: 'PAY · Bug' }))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('jira.export.submit', { count: 3 }) }))

    expect(calls).toEqual([{ method: 'POST', path: '/api/integrations/jira/issues', action: 'export-jira', body: { asset: 'github#1', fingerprints: FINDINGS.map(item => item.fingerprint) } }])
    const issues = await screen.findByRole('list', { name: tr('jira.export.issues') })
    const [issue] = within(issues).getAllByRole('listitem')
    expect(within(issue).getByRole('link', { name: 'PAY-7' }).getAttribute('href')).toBe('https://acme.atlassian.net/browse/PAY-7')
    expect(issue.textContent).toContain(tr('jira.export.state.created_in', { project: 'PAY' }))
    expect(issue.textContent).toContain(tr('jira.export.covers', { count: 1, first: 'lodash 4.17.20' }))
    expect(screen.getByRole('alert').textContent).toContain('eval on user input · No Jira destination for this repository')
    expect(done).toHaveBeenCalledOnce()
  })

  it('sends the run view for a single run', async () => {
    const calls = mockApi(() => ({ body: { created: [], existing: [], failed: [] } }))
    const user = userEvent.setup()
    renderWithQueries(<JiraExportDialog selection={{ runId: 'run-1' }} findings={FINDINGS.slice(0, 1)} onClose={() => {}} onDone={() => {}} />)
    await user.click(screen.getByRole('button', { name: tr('jira.export.submit', { count: 1 }) }))
    expect(calls[0].body).toEqual({ run_id: 'run-1', fingerprints: ['a'.repeat(64)] })
  })
})

describe('a large selection', () => {
  const MANY = Array.from({ length: 120 }, (_, index) => ({ fingerprint: index.toString(16).padStart(64, '0'), label: `Finding ${index}` }))
  const QUEUED = { batch: 'b1', by: 'ana', started_at: '2026-09-30T10:00:00Z', finished_at: null, queued: 80, findings: 118, linked: 1, created: 0, existing: 0, skipped: 0, failed: 0, pending: 80, last_error: null,
    rejected: [{ fingerprint: MANY[5].fingerprint, asset: 'github#1', error: 'No Jira destination for this repository' }] }

  it('goes through the queue and follows it only while issues are pending', async () => {
    const progress = [{ ...QUEUED, created: 40, existing: 2, pending: 38, rejected: undefined },
      { ...QUEUED, created: 76, existing: 2, failed: 2, pending: 0, finished_at: '2026-09-30T10:03:00Z', last_error: 'Jira responded 400', rejected: undefined }]
    const calls = mockApi(call => call.path === '/api/integrations/jira/issues/queue' ? { status: 202, body: QUEUED }
      : call.path === '/api/integrations/jira/issues/batches/b1' ? { body: progress.shift() ?? progress[0] } : undefined)
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const done = vi.fn()
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
      renderWithQueries(<JiraExportDialog selection={{ asset: 'github#1' }} findings={MANY} onClose={() => {}} onDone={done} />)
      expect(screen.getByText(new RegExp(tr('jira.queue.intro', { max: 50 }).slice(0, 30)))).toBeTruthy()
      await user.click(screen.getByRole('button', { name: tr('jira.export.submit', { count: 120 }) }))

      expect(calls.filter(call => call.path.endsWith('/queue'))).toEqual([{ method: 'POST', path: '/api/integrations/jira/issues/queue', action: 'export-jira',
        body: { selections: [{ asset: 'github#1', fingerprints: MANY.map(item => item.fingerprint) }] } }])
      expect(calls.some(call => call.path === '/api/integrations/jira/issues')).toBe(false)
      expect(await screen.findByText(tr('jira.queue.background'))).toBeTruthy()
      expect(screen.getByText(/Finding 5/).parentElement?.textContent).toContain('No Jira destination for this repository')
      expect(await screen.findByText(tr('jira.queue.progress', { done: 42, total: 80, pending: 38, count: 38 }))).toBeTruthy()
      expect(done).not.toHaveBeenCalled()

      await vi.advanceTimersByTimeAsync(3100)
      expect(await screen.findByText(tr('jira.queue.finished', { count: 80 }))).toBeTruthy()
      expect(screen.getByRole('alert').textContent).toContain(tr('jira.queue.last_error', { error: 'Jira responded 400' }))
      expect(screen.getByText(new RegExp(tr('jira.queue.linked', { count: 1 })))).toBeTruthy()
      expect(done).toHaveBeenCalledOnce()
      const polls = calls.filter(call => call.path.endsWith('/batches/b1')).length
      await vi.advanceTimersByTimeAsync(10_000)
      expect(calls.filter(call => call.path.endsWith('/batches/b1'))).toHaveLength(polls)
    } finally { vi.useRealTimers() }
  })

  it('50 or fewer still use the synchronous endpoint', async () => {
    const calls = mockApi(() => ({ body: { created: [], existing: [], failed: [] } }))
    const user = userEvent.setup()
    renderWithQueries(<JiraExportDialog selection={{ asset: 'github#1' }} findings={MANY.slice(0, 50)} onClose={() => {}} onDone={() => {}} />)
    await user.click(screen.getByRole('button', { name: tr('jira.export.submit', { count: 50 }) }))
    await vi.waitFor(() => expect(calls.map(call => call.path)).toEqual(['/api/integrations/jira/issues']))
  })
})

describe('a finding linked from a Jira issue', () => {
  const finding = (fingerprint: string, title: string): RepositoryFinding => ({ finding_id: fingerprint.slice(0, 8), fingerprint, scanner: 'sast', rule_id: 'r', title, path: 'app.py', line: 1,
    severity: 'high', confidence: 8, verdict: 'candidate', cwe: [], cve: [], ghsa: [], owasp: [], reason: '', remediation: '', lifecycle: { status: 'open' } })
  const RUN = { id: 'asset:github#1', type: 'asset_state', status: 'completed', created_at: '2026-09-01T00:00:00Z', source: { id: 'github#1', name: 'org/payments-api', provider: 'github' },
    summary: {}, findings: [finding('a'.repeat(64), 'First finding'), finding('d'.repeat(64), 'Linked finding')] } as RepositoryRun

  it('opens with its detail expanded and its Jira action ready', async () => {
    api(CONNECTED)
    renderWithQueries(<RepositoryResult run={RUN} onNew={() => {}} onChanged={() => {}} canAccept canManage focus={'d'.repeat(64)} />)
    const row = (name: RegExp) => screen.getAllByRole('button', { name }).find(item => item.hasAttribute('aria-expanded'))
    expect(row(/Linked finding/)?.getAttribute('aria-expanded')).toBe('true')
    expect(row(/First finding/)?.getAttribute('aria-expanded')).toBe('false')
    expect(document.activeElement?.id).toBe(`finding-${'d'.repeat(64)}`)
    await vi.waitFor(async () => expect((await screen.findByRole('button', { name: tr('jira.finding.create_label', { name: 'Linked finding' }) })).hasAttribute('disabled')).toBe(false))
  })
})
