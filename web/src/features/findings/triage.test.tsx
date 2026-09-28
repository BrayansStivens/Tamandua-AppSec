import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { TriageActions, TriageDialog } from '@/features/findings/triage'

const PRINTS = ['a'.repeat(64), 'b'.repeat(64)]

describe('triage', () => {
  it('needs a reason to dismiss findings and sends the decision for all of them', async () => {
    const calls = mockApi(() => ({ body: {} }))
    const done = vi.fn()
    const user = userEvent.setup()
    render(<TriageDialog runId="run-1" status="false_positive" fingerprints={PRINTS} onClose={() => {}} onDone={done} />)
    const save = screen.getByRole('button', { name: i18n.t('common:actions.save') })
    await user.type(screen.getByLabelText(i18n.t('findings:triage.reason')), 'too short')
    expect(save.hasAttribute('disabled')).toBe(true)
    await user.type(screen.getByLabelText(i18n.t('findings:triage.reason')), ' but now long enough  ')
    await user.click(save)

    expect(done).toHaveBeenCalledOnce()
    expect(calls).toEqual([{ method: 'POST', path: '/api/findings/triage', action: 'triage', body: {
      run_id: 'run-1', fingerprints: PRINTS, status: 'false_positive', reason: 'too short but now long enough' } }])
  })

  it('an accepted risk carries its expiry date', async () => {
    const calls = mockApi(() => ({ body: {} }))
    const user = userEvent.setup()
    render(<TriageDialog runId="run-1" status="accepted" fingerprints={PRINTS.slice(0, 1)} onClose={() => {}} onDone={() => {}} />)
    await user.type(screen.getByLabelText(i18n.t('findings:triage.reason')), 'Compensated by the WAF until the upgrade')
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.save') }))
    await vi.waitFor(() => expect(calls).toHaveLength(1))
    expect((calls[0].body as { expires_at: string }).expires_at).toMatch(/^\d{4}-\d{2}-\d{2}$/)
  })

  it('keeps the dialog open with the server error', async () => {
    mockApi(() => ({ status: 400, body: { error: 'Some fingerprints are not in this run.' } }))
    const done = vi.fn()
    const user = userEvent.setup()
    render(<TriageDialog runId="run-1" status="in_progress" fingerprints={PRINTS} onClose={() => {}} onDone={done} />)
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.save') }))
    expect((await screen.findByRole('alert')).textContent).toBe('Some fingerprints are not in this run.')
    expect(done).not.toHaveBeenCalled()
  })

  it('only an administrator can accept a risk', async () => {
    const user = userEvent.setup()
    const { unmount } = render(<TriageActions canAccept={false} onPick={() => {}} />)
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('findings:triage.more_states')) }))
    expect(screen.queryByRole('menuitem', { name: i18n.t('findings:triage.verb.accepted') })).toBeNull()
    await user.keyboard('{Escape}')
    unmount()

    const picked = vi.fn()
    render(<TriageActions canAccept onPick={picked} />)
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('findings:triage.more_states')) }))
    await user.click(await screen.findByRole('menuitem', { name: i18n.t('findings:triage.verb.accepted') }))
    expect(picked).toHaveBeenCalledWith('accepted')
  })
})
