import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { AnalysisWizard } from '@/features/analyses/analysis-wizard'

const SOURCE = { id: 'github#7', name: 'org/api', provider: 'github', branch: 'main', installation_id: 1 }
const PLAN = { languages: [{ name: 'Python', files: 12, rules: 40 }], runs: ['Opengrep'], skips: [], osv_needed: true, files: 12,
  manifests: ['setup.py'], iac: [] }

function wizard(onComplete: (id: string) => Promise<void>) {
  const calls = mockApi(call => {
    if (call.path.startsWith('/api/sources')) return { body: { sources: [SOURCE], total: 1 } }
    if (call.path.startsWith('/api/repositories/plan')) return { body: PLAN }
    if (call.path === '/api/repositories/batches') return { body: { active: null, recent: [] } }
    if (call.path === '/api/repositories/scans') return { body: { run: { id: 'run-9' } } }
  })
  renderWithQueries(<AnalysisWizard onComplete={onComplete} onBatchStarted={() => {}} onManageConnections={() => {}} onCancel={() => {}}
    initialSourceId={SOURCE.id} isAdmin={false} />)
  return calls
}

async function toReview(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText(SOURCE.name)
  await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) }))
  await user.type(screen.getByLabelText(new RegExp(i18n.t('analyses:context.question'))), 'Public API behind the gateway')
  await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) }))
  await screen.findByRole('checkbox')
}

describe('launching an analysis', () => {
  it('sends nothing to OSV unless the person agrees', async () => {
    const done = vi.fn(async () => {})
    const user = userEvent.setup()
    const calls = wizard(done)
    await toReview(user)
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:launch.code')) }))

    await vi.waitFor(() => expect(done).toHaveBeenCalledWith('run-9'))
    expect(calls.find(call => call.path === '/api/repositories/scans')).toEqual({ method: 'POST', path: '/api/repositories/scans',
      action: 'scan-repository', body: { source_id: SOURCE.id, allow_osv_upload: false, context: 'Public API behind the gateway' } })
  })

  it('asks OSV only with the consent ticked', async () => {
    const user = userEvent.setup()
    const calls = wizard(async () => {})
    await toReview(user)
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:launch.code')) }))
    await vi.waitFor(() => expect(calls.some(call => call.path === '/api/repositories/scans')).toBe(true))
    const scan = calls.find(call => call.path === '/api/repositories/scans')
    expect(scan?.body).toMatchObject({ allow_osv_upload: true })
  })
})
