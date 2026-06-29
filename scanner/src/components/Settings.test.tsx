import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Settings } from './Settings'
import type { AuthState } from '../hooks/useAuth'
import type { AccountTier, MeResponse } from '../api/types'
import * as client from '../api/client'

function user(tier: AccountTier): MeResponse {
  return {
    email: 'ada@securesg.test',
    tier,
    createdAt: '2026-06-01T00:00:00.000Z',
    apiKeyPrefix: 'sk_live_ab',
    firstName: 'Ada',
    lastName: 'Lovelace',
    role: 'member',
    isAdmin: false,
    isOwner: false,
  }
}

function authState(): AuthState {
  return { status: 'authenticated', user: user('free'), isAdmin: false, isOwner: false, refresh: vi.fn() }
}

/**
 * Capture `window.location.assign` calls. jsdom's `location.assign` is a
 * non-configurable navigation method (and not spyable), so swap in a minimal
 * location stub whose `assign` records the target. Restored in `afterEach`.
 */
function stubAssign(): { calls: string[] } {
  const calls: string[] = []
  const original = window.location
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { ...original, assign: (url: string | URL) => calls.push(String(url)) },
  })
  restoreLocation = () =>
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: original,
    })
  return { calls }
}

let restoreLocation: (() => void) | null = null

afterEach(() => {
  restoreLocation?.()
  restoreLocation = null
  vi.restoreAllMocks()
})

describe('Settings billing', () => {
  it('opens the Stripe billing portal for a paid (pro) account', async () => {
    const { calls } = stubAssign()
    const portal = vi
      .spyOn(client, 'openPortal')
      .mockResolvedValue({ url: 'https://billing.stripe.test/portal' })
    const checkout = vi.spyOn(client, 'startCheckout')

    render(<Settings user={user('pro')} auth={authState()} />)

    fireEvent.click(screen.getByRole('button', { name: /Manage plan/ }))

    await waitFor(() => expect(portal).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(calls).toContain('https://billing.stripe.test/portal'))
    expect(checkout).not.toHaveBeenCalled()
  })

  it('opens the billing portal for a personal account too', async () => {
    const { calls } = stubAssign()
    const portal = vi
      .spyOn(client, 'openPortal')
      .mockResolvedValue({ url: 'https://billing.stripe.test/portal2' })

    render(<Settings user={user('personal')} auth={authState()} />)

    expect(screen.getByRole('button', { name: /Manage plan/ })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Manage plan/ }))

    await waitFor(() => expect(portal).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(calls).toContain('https://billing.stripe.test/portal2'))
  })

  it('starts a Personal checkout for a free account', async () => {
    const { calls } = stubAssign()
    const checkout = vi
      .spyOn(client, 'startCheckout')
      .mockResolvedValue({ url: 'https://checkout.stripe.test/session' })
    const portal = vi.spyOn(client, 'openPortal')

    render(<Settings user={user('free')} auth={authState()} />)

    fireEvent.click(screen.getByRole('button', { name: /Start Personal/ }))

    await waitFor(() => expect(checkout).toHaveBeenCalledWith('personal'))
    await waitFor(() => expect(calls).toContain('https://checkout.stripe.test/session'))
    expect(portal).not.toHaveBeenCalled()
  })

  it('surfaces an inline error when the portal cannot be opened', async () => {
    stubAssign()
    vi.spyOn(client, 'openPortal').mockRejectedValue(new client.ApiError(422, 'no customer'))

    render(<Settings user={user('pro')} auth={authState()} />)

    fireEvent.click(screen.getByRole('button', { name: /Manage plan/ }))

    await waitFor(() =>
      expect(screen.getByText('Could not open billing.')).toBeInTheDocument(),
    )
  })
})
