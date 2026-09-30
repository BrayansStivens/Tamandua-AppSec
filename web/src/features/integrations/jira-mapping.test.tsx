import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Call } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { DestinationEditor } from '@/features/integrations/jira-destinations'
import { MappingTable, ValueSearch } from '@/features/integrations/jira-mapping'
import { initialDraft, type Entry, type JiraField, type JiraVariables } from '@/features/integrations/jira-mapping-model'
import type { JiraDestination } from '@/features/integrations/jira-routing'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`integrations:${key}`, options)
const field = (id: string, name: string, type: JiraField['type'], extra: Partial<JiraField> = {}): JiraField => ({
  id, name, type, required: false, has_default: false, schema: { type }, allowed: [], allowed_truncated: false, fillable: !['unsupported', 'managed'].includes(type), ...extra,
})
const VARIABLES: JiraVariables = {
  variables: [
    { key: 'summary', type: 'text', label: 'Issue title' }, { key: 'description', type: 'rich_text', label: 'Full description' },
    { key: 'line', type: 'number', label: 'Line' }, { key: 'due_date', type: 'date', label: 'Due date' }, { key: 'labels', type: 'labels', label: 'Labels' },
  ],
  sources: ['tamandua', 'fixed', 'template'],
  fits: { text: ['date', 'labels', 'number', 'text'], rich_text: ['labels', 'number', 'rich_text', 'text'], number: ['number'], date: ['date'], option: [], priority: [] },
  by_name: { option: ['severity', 'jira_priority'], priority: ['severity', 'jira_priority'] },
  limits: { fields: 50, template: 2000, fixed_values: 20, backfill: 5000 },
}
const FIELDS: JiraField[] = [
  field('summary', 'Summary', 'text', { required: true }),
  field('customfield_1', 'Team', 'option', { required: true, allowed: [{ id: '10', name: 'Payments' }, { id: '11', name: 'Identity' }] }),
  field('customfield_2', 'Story points', 'number'),
  field('assignee', 'Assignee', 'unsupported'),
  field('project', 'Project', 'managed', { required: true }),
]
const DESTINATION = { id: 'd1', name: 'Payments', project: { id: '100', key: 'PAY', name: 'Payments' }, issue_type: { id: '3', name: 'Bug' },
  mapping: { summary: { source: 'tamandua', key: 'summary' } }, fields: {} } as JiraDestination

function editor(save: (call: Call) => { status?: number; body?: unknown } | undefined = () => undefined) {
  const calls = mockApi(call => {
    if (call.path.endsWith('/issue-types')) return { body: { items: [{ id: '3', name: 'Bug', subtask: false }, { id: '9', name: 'Sub-task', subtask: true }], truncated: false } }
    if (call.path.endsWith('/fields')) return { body: { fields: FIELDS, truncated: false, suggested: {} } }
    if (call.path === '/api/integrations/jira/variables') return { body: VARIABLES }
    if (call.path === '/api/integrations/jira/destinations') return save(call)
  })
  const saved = vi.fn()
  renderWithQueries(<DestinationEditor destination={DESTINATION} onClose={() => {}} onSaved={saved} />)
  return { calls, saved, user: userEvent.setup() }
}
const posts = (calls: Call[]) => calls.filter(call => call.path === '/api/integrations/jira/destinations')
const optionsOf = (select: HTMLElement) => within(select).getAllByRole('option').map(option => option.textContent)

describe('destination field mapping', () => {
  it('offers only the Tamandua variables that fit each field type', async () => {
    const draft = initialDraft(FIELDS, {})
    const change = vi.fn()
    const { rerender } = renderWithQueries(<MappingTable fields={FIELDS} variables={VARIABLES} draft={draft} errors={{}} onChange={change} searchValues={vi.fn()} />)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: tr('jira.mapping.more', { count: 1 }) }))
    // An option field takes no variable (fits is empty): the source list has no "Tamandua data".
    expect(optionsOf(screen.getByLabelText(tr('jira.mapping.source_label', { field: 'Team' })))).not.toContain(tr('jira.mapping.source.tamandua'))
    // A required field can't be left empty.
    expect(optionsOf(screen.getByLabelText(tr('jira.mapping.source_label', { field: 'Summary' })))).not.toContain(tr('jira.mapping.source.none'))

    const points: Entry = { source: 'tamandua', key: '', value: '', values: [], text: '', names: {} }
    rerender(<MappingTable fields={FIELDS} variables={VARIABLES} draft={{ ...draft, customfield_2: points }} errors={{}} onChange={change} searchValues={vi.fn()} />)
    expect(optionsOf(screen.getByLabelText(tr('jira.mapping.value_label', { field: 'Story points' }))).slice(1)).toEqual(['Line'])
    // Fields Tamandua can't fill are listed, never offered.
    expect(screen.queryByLabelText(tr('jira.mapping.source_label', { field: 'Assignee' }))).toBeNull()
    expect(screen.getByText(tr('jira.mapping.unsupported_summary', { count: 1 }))).toBeTruthy()
  })

  it('enforces required fields before sending, then sends every field (empty ones as null)', async () => {
    const { calls, saved, user } = editor(() => ({ body: { destination: { ...DESTINATION }, warnings: [{ field: 'labels', error: 'No labels field' }], routing: { destinations: [], rules: [], history: [], limits: {} } } }))
    const team = await screen.findByLabelText(tr('jira.mapping.source_label', { field: 'Team' }))
    await user.click(screen.getByRole('button', { name: tr('jira.destinations.save') }))

    expect(posts(calls)).toEqual([])
    expect(screen.getByText(tr('jira.mapping.required'))).toBeTruthy()
    expect(team.closest('tr')?.textContent).toContain(tr('jira.mapping.required'))

    await user.selectOptions(team, 'fixed')
    await user.selectOptions(screen.getByLabelText(tr('jira.mapping.value_label', { field: 'Team' })), '10')
    await user.click(screen.getByRole('button', { name: tr('jira.destinations.save') }))

    await vi.waitFor(() => expect(saved).toHaveBeenCalledOnce())
    expect(posts(calls)[0]).toMatchObject({ action: 'jira-routing', body: { id: 'd1', name: 'Payments', project: 'PAY', issue_type: '3',
      mapping: { summary: { source: 'tamandua', key: 'summary' }, customfield_1: { source: 'fixed', value: '10' }, customfield_2: null } } })
    expect(saved.mock.calls[0][0].warnings).toEqual([{ field: 'labels', error: 'No labels field' }])
  })

  it('shows each server error next to its field', async () => {
    const { user } = editor(() => ({ status: 400, body: { error: 'Check the highlighted fields', errors: [
      { field: 'mapping.customfield_2', error: 'Story points needs a number' }, { field: 'name', error: 'That name is already in use' }] } }))
    await user.selectOptions(await screen.findByLabelText(tr('jira.mapping.source_label', { field: 'Team' })), 'fixed')
    await user.selectOptions(screen.getByLabelText(tr('jira.mapping.value_label', { field: 'Team' })), '11')
    await user.click(screen.getByRole('button', { name: tr('jira.destinations.save') }))

    const name = screen.getByLabelText(tr('jira.destinations.name'))
    expect(await screen.findByText('That name is already in use')).toBeTruthy()
    expect(name.getAttribute('aria-invalid')).toBe('true')
    expect(document.getElementById(name.getAttribute('aria-describedby') ?? '')?.textContent).toBe('That name is already in use')
    // The optional field with the error comes out of "More fields" to show it.
    expect(screen.getByText('Story points needs a number').closest('tr')?.textContent).toContain('Story points')
    expect(screen.getAllByRole('alert').some(item => item.textContent === 'Check the highlighted fields')).toBe(true)
  })
})

describe('searching a long list of allowed values', () => {
  const COMPONENTS = field('components', 'Components', 'options', { allowed: [{ id: '1', name: 'API' }], allowed_truncated: true })
  const TEAM = field('customfield_9', 'Team', 'option', { allowed: [{ id: '1', name: 'API' }], allowed_truncated: true })

  it('waits for the typing to stop, asks the server with the text and picks the value', async () => {
    const search = vi.fn(async (_field: string, q: string) => ({ items: [{ id: '812', name: `Payments ${q}` }], total: 40, truncated: true }))
    const change = vi.fn()
    const entry: Entry = { source: 'fixed', key: '', value: '', values: [], text: '', names: {} }
    renderWithQueries(<ValueSearch field={TEAM} entry={entry} label="Team" invalid={false} search={search} onChange={change} />)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: `Team: ${tr('jira.mapping.search_value')}` }))
    expect(await screen.findByText(i18n.t('ui:combobox.min_chars', { count: 1 }))).toBeTruthy()
    await user.type(screen.getByRole('combobox', { name: 'Team' }), 'pay')

    const option = await screen.findByRole('option', { name: 'Payments pay' })
    expect(search.mock.calls).toEqual([['customfield_9', 'pay']])
    expect(screen.getByText(i18n.t('ui:combobox.more', { remaining: 39 }))).toBeTruthy()
    await user.click(option)
    expect(change).toHaveBeenCalledWith({ ...entry, value: '812', names: { 812: 'Payments pay' } })
  })

  it('shows the stored name of a saved value outside the first page, and adds several for a multi-value field', async () => {
    const saved = initialDraft([TEAM, COMPONENTS], { customfield_9: { source: 'fixed', value: '812' }, components: { source: 'fixed', value: ['1', '977'] } },
      { customfield_9: { allowed: [{ id: '812', name: 'Payments' }] }, components: { allowed: [{ id: '1', name: 'API' }, { id: '977', name: 'Billing' }] } })
    renderWithQueries(<ValueSearch field={TEAM} entry={saved.customfield_9} label="Team" invalid={false} search={vi.fn()} onChange={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Team: Payments' })).toBeTruthy()

    const change = vi.fn()
    const search = vi.fn(async () => ({ items: [{ id: '5', name: 'Web' }], total: 1, truncated: false }))
    renderWithQueries(<ValueSearch field={COMPONENTS} entry={saved.components} label="Components" invalid={false} search={search} onChange={change} />)
    expect(within(screen.getByRole('list', { name: tr('jira.mapping.chosen', { field: 'Components' }) })).getAllByRole('listitem').map(item => item.textContent)).toEqual(['API', 'Billing'])
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: `Components: ${tr('jira.mapping.search_values')}` }))
    await user.type(screen.getByRole('combobox', { name: 'Components' }), 'w')
    await user.click(await screen.findByRole('option', { name: 'Web' }))
    expect(change).toHaveBeenCalledWith(expect.objectContaining({ values: ['1', '977', '5'] }))
  })
})
