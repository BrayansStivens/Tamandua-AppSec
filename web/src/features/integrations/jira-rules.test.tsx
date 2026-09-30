import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import type { JiraRouting } from '@/shared/api/queries'
import { RuleEditor, RulesSection } from '@/features/integrations/jira-rules'
import { globMatch, resolveRule, type JiraRule } from '@/features/integrations/jira-routing'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`integrations:${key}`, options)
const rule = (id: string, name: string, extra: Partial<JiraRule> = {}): JiraRule => ({
  id, name, assets: [], patterns: [], destination: 'd1', mode: 'manual', min_severity: 'high', backfill: false, enabled: true, ...extra,
})
const ROUTING: JiraRouting = {
  destinations: [{ id: 'd1', name: 'Payments', project: { key: 'PAY', name: 'Payments' }, issue_type: { name: 'Bug' }, mapping: {} }],
  rules: [rule('a1', 'Payments', { patterns: ['org/payments-*'] }), rule('b2', 'Identity', { assets: ['github#7'] }), rule('default', 'Every other repository', { default: true, enabled: false, destination: null })],
  history: [], limits: { destinations: 20, rules: 50, assets: 200, patterns: 20 },
}

describe('routing rules', () => {
  it('match like the server: first enabled rule with a destination wins, patterns ignore case', () => {
    expect(globMatch('org/payments-*', 'org/payments-api')).toBe(true)
    expect(globMatch('org/pay?ents-[!x]*', 'org/payments-api')).toBe(true)
    expect(globMatch('org/payments-*', 'org/identity')).toBe(false)
    expect(resolveRule(ROUTING, 'github#9', 'Org/Payments-Web')?.id).toBe('a1')
    expect(resolveRule(ROUTING, 'github#7', 'org/identity')?.id).toBe('b2')
    expect(resolveRule(ROUTING, 'github#8', 'org/other')).toBeNull()
  })

  it('move with buttons, and the default rule stays last without them', async () => {
    const reordered = { ...ROUTING, rules: [ROUTING.rules[1], ROUTING.rules[0], ROUTING.rules[2]] }
    const calls = mockApi(call => call.path === '/api/integrations/jira/rules/order' ? { body: reordered } : { body: { items: [], total: 0, limit: 1, offset: 0 } })
    const user = userEvent.setup()
    renderWithQueries(<RulesSection routing={ROUTING} backfills={[]} onRemove={() => {}} />)

    expect(screen.getByRole('button', { name: tr('jira.rules.move_up', { name: 'Payments' }) }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByRole('button', { name: tr('jira.rules.move_down', { name: 'Identity' }) }).hasAttribute('disabled')).toBe(true)
    expect(screen.queryByRole('button', { name: tr('jira.rules.move_up', { name: 'Every other repository' }) })).toBeNull()
    await user.click(screen.getByRole('button', { name: tr('jira.rules.move_up', { name: 'Identity' }) }))

    expect(calls.filter(call => call.path === '/api/integrations/jira/rules/order')).toEqual([
      { method: 'POST', path: '/api/integrations/jira/rules/order', action: 'jira-routing', body: { ids: ['b2', 'a1'] } }])
    expect(await screen.findByText(tr('jira.rules.moved', { name: 'Identity', position: 1 }))).toBeTruthy()
  })

  it('show how a backfill is going', () => {
    mockApi(() => ({ body: { items: [], total: 0, limit: 1, offset: 0 } }))
    renderWithQueries(<RulesSection routing={ROUTING} onRemove={() => {}} backfills={[{ rule: 'a1', queued: 10, findings: 14, created: 6, existing: 1, skipped: 0, failed: 1, pending: 2, truncated: false, last_error: 'Jira responded 400' }]} />)
    const status = screen.getAllByRole('status').find(item => item.textContent?.includes(tr('jira.backfill.running', { count: 10 })))!
    expect(status.textContent).toContain(tr('jira.backfill.running', { count: 10 }))
    expect(status.textContent).toContain(tr('jira.backfill.pending', { count: 2 }))
    expect(status.textContent).toContain(tr('jira.backfill.last_error', { error: 'Jira responded 400' }))
  })

  it('preview what a backfill would create before saving an automatic rule', async () => {
    const preview = { assets: 2, findings: 9, issues: 5, linked: 3, truncated: false }
    const calls = mockApi(call => {
      if (call.path === '/api/integrations/jira/rules/preview') return { body: preview }
      if (call.path === '/api/integrations/jira/rules') return { body: { rule: rule('c3', 'Web', { mode: 'auto', backfill: true }), backfill: { rule: 'c3', queued: 5 }, routing: ROUTING } }
    })
    const saved = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<RuleEditor rule={null} routing={ROUTING} onClose={() => {}} onSaved={saved} />)
    await user.type(screen.getByLabelText(tr('jira.rules.name')), 'Web')
    await user.type(screen.getByLabelText(tr('jira.rules.patterns')), 'org/web-*')
    await user.click(screen.getByRole('radio', { name: new RegExp(tr('jira.rules.mode_auto_help').slice(0, 20)) }))
    await user.selectOptions(screen.getByLabelText(tr('jira.rules.min_severity')), 'critical')
    await user.click(screen.getByLabelText(new RegExp(tr('jira.rules.backfill'))))
    expect(screen.getByText(tr('jira.preview.needed'))).toBeTruthy()

    // Saving first checks what it would create; nothing is saved yet.
    await user.click(screen.getByRole('button', { name: tr('jira.preview.run') }))
    const body = { name: 'Web', assets: [], patterns: ['org/web-*'], destination: 'd1', mode: 'auto', min_severity: 'critical', backfill: true, enabled: true }
    expect(await screen.findByText(tr('jira.preview.result', { count: 5, issues: '5', findings: '9', assets: '2', linked: '3' }))).toBeTruthy()
    expect(calls.map(call => call.path)).toEqual(['/api/integrations/jira/rules/preview'])
    expect(calls[0]).toMatchObject({ action: 'jira-preview', body })

    await user.click(screen.getByRole('button', { name: tr('jira.rules.save_backfill', { count: 5 }) }))
    await vi.waitFor(() => expect(saved).toHaveBeenCalledOnce())
    expect(calls[1]).toMatchObject({ path: '/api/integrations/jira/rules', action: 'jira-routing', body })
  })

  it('asks for a new preview when the rule changes after it', async () => {
    mockApi(call => call.path === '/api/integrations/jira/rules/preview' ? { body: { assets: 1, findings: 0, issues: 0, linked: 4, truncated: false } } : undefined)
    const user = userEvent.setup()
    renderWithQueries(<RuleEditor rule={rule('a1', 'Payments', { patterns: ['org/payments-*'], mode: 'auto', backfill: true })} routing={ROUTING} onClose={() => {}} onSaved={() => {}} />)
    await user.click(screen.getAllByRole('button', { name: tr('jira.preview.run') })[0])
    expect(await screen.findByText(tr('jira.preview.nothing', { linked: '4' }))).toBeTruthy()
    await user.selectOptions(screen.getByLabelText(tr('jira.rules.min_severity')), 'low')
    expect(screen.getByText(tr('jira.preview.outdated'))).toBeTruthy()
  })
})
