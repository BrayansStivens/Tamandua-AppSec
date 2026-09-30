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
