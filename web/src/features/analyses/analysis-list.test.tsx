import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { AnalysisList } from '@/features/analyses/analysis-list'

describe('scan list', () => {
  it('the scan list names the run type and the tool', async () => {
    mockApi(call => {
      if (call.path.startsWith('/api/runs/page')) return { body: { items: [{ id: 'run-imp', type: 'sarif_import', status: 'completed', created_at: '2026-09-01T00:00:00Z',
        target: 'org/api', source: { name: 'org/api' }, trigger: { kind: 'import', tool: 'Semgrep', scope: 'full' }, summary: { candidates: 1 } }], total: 1, limit: 25, offset: 0 } }
      if (call.path.includes('batches')) return { body: { active: null, recent: [] } }
    })
    renderWithQueries(<AnalysisList refreshKey={0} onOpen={() => {}} onNew={() => {}} viewer={{ username: 'ana', admin: false }} />)

    expect(await screen.findByText(i18n.t('analyses:run_type.sarif_import'))).toBeTruthy()
    expect(screen.getByText(i18n.t('analyses:list.trigger_import', { tool: 'Semgrep' }))).toBeTruthy()
    expect(screen.queryByText('sarif_import')).toBeNull()
  })
})
