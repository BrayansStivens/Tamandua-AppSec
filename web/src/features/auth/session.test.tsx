import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { act } from 'react'
import i18n from '@/shared/i18n'
import { UNAUTHORIZED_EVENT } from '@/shared/api/http'
import { mockApi } from '@/shared/test/api'
import { SessionGate } from '@/features/auth/session'

const USER = { id: 'u1', username: 'ana', display_name: 'Ana', role: 'member', totp_enabled: true, last_login_at: null }
const signedIn = { authenticated: true, user: USER, mfa: true, totp_required: false }
const signedOut = { authenticated: false, setup_required: false }
const app = () => <SessionGate>{user => <p>inside as {user.username}</p>}</SessionGate>

describe('sign-in', () => {
  it('asks for the second factor and lets the person in', async () => {
    let session: unknown = signedOut
    const calls = mockApi(call => {
      if (call.path === '/api/auth/session') return { body: session }
      if (call.path === '/api/auth/login') return { body: { step: 'totp', challenge: 'challenge-1' } }
      if (call.path === '/api/auth/totp') { session = signedIn; return { body: { step: 'done' } } }
    })
    const user = userEvent.setup()
    render(app())
    await user.type(await screen.findByLabelText(i18n.t('auth:fields.username')), 'ana')
    await user.type(screen.getByLabelText(i18n.t('auth:fields.password')), 'a long passphrase')
    await user.click(screen.getByRole('button', { name: i18n.t('auth:login.enter') }))
    await user.type(await screen.findByLabelText(i18n.t('auth:fields.code')), ' 123456 ')
    await user.click(screen.getByRole('button', { name: i18n.t('auth:login.verify') }))

    expect(await screen.findByText('inside as ana')).toBeTruthy()
    const login = calls.find(call => call.path === '/api/auth/login')
    expect(login).toEqual({ method: 'POST', path: '/api/auth/login', action: 'login', body: { username: 'ana', password: 'a long passphrase' } })
    // The code goes trimmed, with the challenge the server handed out; the password never goes twice.
    expect(calls.find(call => call.path === '/api/auth/totp')?.body).toEqual({ challenge: 'challenge-1', code: '123456' })
  })

  it('shows why a sign-in failed and stays on the form', async () => {
    mockApi(call => {
      if (call.path === '/api/auth/session') return { body: signedOut }
      if (call.path === '/api/auth/login') return { status: 401, body: { error: 'Wrong username or password.' } }
    })
    const user = userEvent.setup()
    render(app())
    await user.type(await screen.findByLabelText(i18n.t('auth:fields.username')), 'ana')
    await user.type(screen.getByLabelText(i18n.t('auth:fields.password')), 'not the passphrase')
    await user.click(screen.getByRole('button', { name: i18n.t('auth:login.enter') }))

    expect((await screen.findByRole('alert')).textContent).toBe('Wrong username or password.')
    // A failed sign-in is not an expired session.
    expect(screen.queryByText(i18n.t('auth:session_expired'))).toBeNull()
  })

  it('sends the person back to sign in when the session expires', async () => {
    mockApi(call => call.path === '/api/auth/session' ? { body: signedIn } : undefined)
    render(app())
    expect(await screen.findByText('inside as ana')).toBeTruthy()
    act(() => { window.dispatchEvent(new Event(UNAUTHORIZED_EVENT)) })
    expect(await screen.findByText(i18n.t('auth:session_expired'))).toBeTruthy()
    expect(screen.queryByText('inside as ana')).toBeNull()
  })
})
