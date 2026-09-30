import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { RepositoryResult, type RepositoryFinding, type RepositoryRun } from '@/features/findings/repository-result'

const FINDING: RepositoryFinding = { finding_id: 'f1', fingerprint: 'a'.repeat(64), scanner: 'sast', tool: 'Semgrep', rule_id: 'python.lang.eval', title: 'eval on user input',
  path: 'app/views.py', line: 12, severity: 'high', confidence: 6, verdict: 'candidate', cwe: [95], cve: [], ghsa: [], owasp: [], reason: 'Semgrep reported it', remediation: 'Avoid eval',
  lifecycle: { status: 'open', origin: { kind: 'import', tool: 'Semgrep' }, first_seen: '2026-09-01T00:00:00Z' } }
const RUN: RepositoryRun = { id: 'run-imp', type: 'sarif_import', status: 'completed', created_at: '2026-09-01T00:00:00Z',
  trigger: { kind: 'import', tool: 'Semgrep', scope: 'partial', commit: 'abcdef1234', branch: 'main' },
  source: { name: 'org/api', provider: 'github' }, summary: { candidates: 1, severities: { high: 1 } }, findings: [FINDING] }

describe('imported findings', () => {
  it('say which tool they came from and never offer a reverification that would fail', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    renderWithQueries(<RepositoryResult run={RUN} onNew={() => {}} onChanged={() => {}} canAccept />)

    expect(screen.getByText(i18n.t('findings:import.eyebrow', { tool: 'Semgrep' }))).toBeTruthy()
    expect(screen.getByText(i18n.t('findings:import.help_partial', { tool: 'Semgrep' }))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: /eval on user input/ }))
    expect(screen.getByText(new RegExp(i18n.t('findings:lifecycle.from_import', { tool: 'Semgrep' })))).toBeTruthy()
    expect(screen.getByText(i18n.t('findings:verify.imported', { tool: 'Semgrep' }))).toBeTruthy()
    expect(screen.queryByRole('button', { name: new RegExp(`^(${i18n.t('findings:verify.start')}|${i18n.t('findings:verify.again')})$`) })).toBeNull()
  })
})
