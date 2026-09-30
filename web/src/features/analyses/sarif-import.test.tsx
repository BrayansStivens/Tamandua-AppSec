import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Call, type Reply } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { SarifImport } from '@/features/analyses/sarif-import'

const ASSET = { key: 'github#7', name: 'org/api', provider: 'github', scans: 3, pr_reviews: 0, last_activity: '2026-09-01T00:00:00Z', removed_at: null,
  latest_scan: null, open: null }
const SARIF = { version: '2.1.0', runs: [{ tool: { driver: { name: 'Semgrep', version: '1.90.0' } }, results: [{ ruleId: 'r1' }, { ruleId: 'r2' }] }] }
const RESULT = { asset: ASSET.key, name: ASSET.name, runs: [{ id: 'run-imp', tool: 'Semgrep', version: '1.90.0', scope: 'full', status: 'completed',
  findings: 2, excluded: 0, skipped: 1, opened: 2, fixed: 3 }] }

function setup(importReply: Reply = { body: RESULT }) {
  const calls = mockApi(call => {
    if (call.path.startsWith('/api/assets')) return { body: { items: [ASSET], total: 1, limit: 1, offset: 0 } }
    if (call.path === '/api/imports/sarif') return importReply
    if (call.path === '/api/runs') return { body: [] }
  })
  const open = vi.fn()
  renderWithQueries(<SarifImport onOpenRun={open} onBack={() => {}} />)
  return { calls, open, user: userEvent.setup() }
}

const sarifFile = (content: string, name = 'scan.sarif') => new File([content], name, { type: 'application/json' })
const fileInput = () => screen.getByLabelText(new RegExp(i18n.t('analyses:import.file.label')))
const submit = () => screen.getByRole('button', { name: new RegExp(i18n.t('analyses:import.submit')) })
const imports = (calls: Call[]) => calls.filter(call => call.path === '/api/imports/sarif')

describe('importing SARIF', () => {
  it('rejects a file over 10 MB before reading or sending it', async () => {
    const { calls, user } = setup()
    await screen.findByText(ASSET.name)
    const big = sarifFile('{}', 'big.sarif')
    Object.defineProperty(big, 'size', { value: 10_000_001 })
    await user.upload(fileInput(), big)

    expect((await screen.findByRole('alert')).textContent).toContain('big.sarif')
    expect(submit().hasAttribute('disabled')).toBe(true)
    expect(imports(calls)).toEqual([])
  })

  it('rejects a file that is not JSON, or JSON without runs', async () => {
    const { user } = setup()
    await screen.findByText(ASSET.name)
    await user.upload(fileInput(), sarifFile('{"version": "2.1.0", "runs": ['))
    await vi.waitFor(() => expect(screen.getByRole('alert').textContent).toBe(i18n.t('analyses:import.file.invalid_json', { name: 'scan.sarif' })))

    await user.upload(fileInput(), sarifFile('{"version": "2.1.0"}', 'other.json'))
    await vi.waitFor(() => expect(screen.getByRole('alert').textContent).toBe(i18n.t('analyses:import.file.not_sarif', { name: 'other.json' })))
    expect(submit().hasAttribute('disabled')).toBe(true)
  })

  it('sends the asset, the scope and the parsed document, then links to each run', async () => {
    const { calls, open, user } = setup()
    await screen.findByText(ASSET.name)
    await user.upload(fileInput(), sarifFile(JSON.stringify(SARIF)))
    expect((await screen.findByText(/Semgrep · 2/)).textContent).toContain('scan.sarif')
    await user.click(submit())

    const title = await screen.findByRole('heading', { name: i18n.t('analyses:import.result.title', { name: ASSET.name }) })
    expect(document.activeElement).toBe(title)
    expect(imports(calls)).toEqual([{ method: 'POST', path: '/api/imports/sarif', action: 'import-sarif', body: { asset: ASSET.key, scope: 'full', sarif: SARIF } }])
    const counts = screen.getByText(new RegExp(i18n.t('analyses:import.result.opened', { count: 2 }))).textContent
    expect(counts).toContain(i18n.t('analyses:import.result.fixed', { count: 3 }))
    expect(counts).toContain(i18n.t('analyses:import.result.skipped', { count: 1 }))
    await user.click(screen.getByRole('button', { name: i18n.t('analyses:import.result.open_label', { tool: 'Semgrep' }) }))
    expect(open).toHaveBeenCalledWith('run-imp')
  })

  it('a partial import carries the tool, commit and branch given under more options', async () => {
    const { calls, user } = setup({ body: { ...RESULT, runs: [{ ...RESULT.runs[0], scope: 'partial', fixed: 0 }] } })
    await screen.findByText(ASSET.name)
    await user.upload(fileInput(), sarifFile(JSON.stringify(SARIF)))
    await user.click(screen.getByRole('radio', { name: new RegExp(i18n.t('analyses:import.scope.partial')) }))
    await user.click(screen.getByRole('button', { name: i18n.t('analyses:import.more') }))
    await user.type(screen.getByLabelText(new RegExp(i18n.t('analyses:import.tool'))), 'semgrep-ci')
    await user.type(screen.getByLabelText(new RegExp(i18n.t('analyses:import.commit'))), 'xyz')
    expect(submit().hasAttribute('disabled')).toBe(true)
    await user.clear(screen.getByLabelText(new RegExp(i18n.t('analyses:import.commit'))))
    await user.type(screen.getByLabelText(new RegExp(i18n.t('analyses:import.commit'))), 'ABCDEF1')
    await user.type(screen.getByLabelText(new RegExp(i18n.t('analyses:import.branch'))), 'main')
    await user.click(submit())

    await screen.findByText(i18n.t('analyses:import.result.description_partial'))
    expect(imports(calls)[0].body).toEqual({ asset: ASSET.key, scope: 'partial', sarif: SARIF, tool: 'semgrep-ci', commit: 'ABCDEF1', branch: 'main' })
    expect(screen.queryByText(new RegExp(i18n.t('analyses:import.result.fixed', { count: 0 })))).toBeNull()
  })

  it('shows the server refusal and keeps the form', async () => {
    const { user } = setup({ status: 404, body: { error: 'There is no asset named org/api: scan it or connect its repository first' } })
    await screen.findByText(ASSET.name)
    await user.upload(fileInput(), sarifFile(JSON.stringify(SARIF)))
    await user.click(submit())

    expect((await screen.findByRole('alert')).textContent).toBe('There is no asset named org/api: scan it or connect its repository first')
    expect(submit().hasAttribute('disabled')).toBe(false)
  })

  it('explains a 413 cut off before reaching the server', async () => {
    const { user } = setup({ status: 413 })
    await screen.findByText(ASSET.name)
    await user.upload(fileInput(), sarifFile(JSON.stringify(SARIF)))
    await user.click(submit())
    expect((await screen.findByRole('alert')).textContent).toBe(i18n.t('analyses:import.too_large', { max: 10 }))
  })

  it('tells an empty workspace from assets that failed to load', async () => {
    mockApi(() => ({ status: 500, body: { error: 'boom' } }))
    renderWithQueries(<SarifImport onOpenRun={() => {}} onBack={() => {}} />)
    expect((await screen.findByRole('alert')).textContent).toBe(i18n.t('analyses:import.asset_error'))
    expect(screen.queryByText(i18n.t('analyses:import.no_asset'))).toBeNull()
  })
})
