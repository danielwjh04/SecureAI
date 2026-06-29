import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Navbar } from './Navbar'
import type { AuthState } from '../hooks/useAuth'
import type { MeResponse } from '../api/types'

function user(isAdmin: boolean): MeResponse {
  return {
    email: 'a@b.com',
    tier: 'free',
    createdAt: '2026-06-01T00:00:00.000Z',
    apiKeyPrefix: 'sk_live_ab',
    firstName: null,
    lastName: null,
    role: isAdmin ? 'owner' : 'member',
    isAdmin,
    isOwner: isAdmin,
  }
}

function authState(overrides: Partial<AuthState> = {}): AuthState {
  return {
    status: 'anonymous',
    user: null,
    isAdmin: false,
    isOwner: false,
    refresh: vi.fn(),
    ...overrides,
  }
}

describe('Navbar admin link', () => {
  it('shows the Admin link for an authenticated admin', () => {
    render(
      <Navbar
        auth={authState({ status: 'authenticated', user: user(true), isAdmin: true })}
      />,
    )
    const admin = screen.getByRole('link', { name: /Admin/ })
    expect(admin).toBeInTheDocument()
    expect(admin).toHaveAttribute('href', '#admin')
    expect(screen.getByRole('link', { name: /Dashboard/ })).toBeInTheDocument()
  })

  it('hides the Admin link for an authenticated non-admin', () => {
    render(
      <Navbar
        auth={authState({ status: 'authenticated', user: user(false), isAdmin: false })}
      />,
    )
    expect(screen.queryByRole('link', { name: /Admin/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Dashboard/ })).toBeInTheDocument()
  })

  it('hides the Admin link for an anonymous visitor', () => {
    render(<Navbar auth={authState()} />)
    expect(screen.queryByRole('link', { name: /Admin/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Log in/ })).toBeInTheDocument()
  })
})

describe('Navbar app navigation', () => {
  it('renders the six Personal app links for an authenticated user', () => {
    render(
      <Navbar
        auth={authState({ status: 'authenticated', user: user(false), isAdmin: false })}
      />,
    )
    for (const label of ['How it works', 'Dashboard', 'Protection', 'Activity', 'Integrations', 'Settings']) {
      expect(screen.getByRole('link', { name: label })).toBeInTheDocument()
    }
    // The redundant "Scan" item (it duplicated the logo) is gone.
    expect(screen.queryByRole('link', { name: 'Scan' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Enterprise' })).toBeNull()
  })

  it('orders How it works first among the authenticated app links', () => {
    render(
      <Navbar
        auth={authState({ status: 'authenticated', user: user(false), isAdmin: false })}
      />,
    )
    const how = screen.getByRole('link', { name: 'How it works' })
    const dashboard = screen.getByRole('link', { name: 'Dashboard' })
    // How it works precedes Dashboard in the DOM (it leads the cluster).
    expect(
      how.compareDocumentPosition(dashboard) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
  })
})

describe('Navbar log out', () => {
  it('renders a Log out button at the right, after the Admin pill, for an admin', () => {
    render(
      <Navbar
        auth={authState({ status: 'authenticated', user: user(true), isAdmin: true })}
      />,
    )
    const logout = screen.getByRole('button', { name: 'Log out' })
    const admin = screen.getByRole('link', { name: /Admin/ })
    expect(logout).toBeInTheDocument()
    // Admin sits to the LEFT of Log out: Admin appears earlier in the DOM.
    expect(
      admin.compareDocumentPosition(logout) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
  })

  it('renders Log out for an authenticated non-admin (no Admin pill)', () => {
    render(
      <Navbar
        auth={authState({ status: 'authenticated', user: user(false), isAdmin: false })}
      />,
    )
    expect(screen.getByRole('button', { name: 'Log out' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Admin/ })).toBeNull()
  })

  it('shows no Log out button for an anonymous visitor', () => {
    render(<Navbar auth={authState()} />)
    expect(screen.queryByRole('button', { name: 'Log out' })).toBeNull()
  })
})

describe('Navbar anonymous auth link', () => {
  it('labels the anonymous link "Log in / Sign up" and routes to #login', () => {
    render(<Navbar auth={authState()} />)
    const link = screen.getByRole('link', { name: 'Log in / Sign up' })
    expect(link).toBeInTheDocument()
    expect(link).toHaveAttribute('href', '#login')
  })

  it('keeps the same label on the same anchor on the register route (hash drives mode)', () => {
    // The anchor always points at #login; the bare "Log in" label is gone.
    render(<Navbar auth={authState()} />)
    expect(screen.queryByRole('link', { name: 'Log in' })).toBeNull()
    expect(
      screen.getByRole('link', { name: 'Log in / Sign up' }),
    ).toHaveAttribute('href', '#login')
  })
})

describe('Navbar guard link removal', () => {
  it('does not render a Guard nav link in the desktop links', () => {
    render(<Navbar auth={authState()} />)
    expect(screen.queryByRole('link', { name: 'Guard' })).toBeNull()
    // No #guard anchor remains anywhere in the bar.
    expect(
      document.querySelector('a[href="#guard"]'),
    ).toBeNull()
    // The neighbouring links it sat between still render.
    expect(screen.getByRole('link', { name: 'How it works' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Pricing' })).toBeInTheDocument()
  })

  it('does not render a Guard link in the mobile dropdown', () => {
    render(<Navbar auth={authState()} />)
    fireEvent.click(screen.getByRole('button', { name: /Open menu/ }))
    // The dropdown is open (a second How it works link appears) but carries no Guard.
    expect(screen.getAllByRole('link', { name: 'How it works' })).toHaveLength(2)
    expect(screen.queryByRole('link', { name: 'Guard' })).toBeNull()
    expect(document.querySelector('a[href="#guard"]')).toBeNull()
  })
})

describe('Navbar GitHub link removal', () => {
  it('does not render a GitHub link in the desktop nav', () => {
    render(<Navbar auth={authState()} />)
    expect(screen.queryByRole('link', { name: 'GitHub' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Enterprise' })).toBeNull()
  })

  it('does not render a GitHub link in the mobile dropdown', () => {
    render(<Navbar auth={authState()} />)
    fireEvent.click(screen.getByRole('button', { name: /Open menu/ }))
    expect(screen.queryByRole('link', { name: 'GitHub' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Enterprise' })).toBeNull()
  })
})

describe('Navbar mobile menu', () => {
  it('keeps the inline links hidden below md and a hamburger toggle visible', () => {
    render(<Navbar auth={authState()} />)
    // The inline link cluster is hidden on mobile (md:flex), proving the desktop
    // links collapse on a phone rather than overflowing the bar.
    const inlineHow = screen.getByRole('link', { name: 'How it works' })
    expect(inlineHow.parentElement?.className).toContain('hidden')
    expect(inlineHow.parentElement?.className).toContain('md:flex')
    // The hamburger toggle is present for phones (md:hidden).
    const toggle = screen.getByRole('button', { name: /Open menu/ })
    expect(toggle.className).toContain('md:hidden')
  })

  it('toggles the dropdown with the primary links on click', () => {
    render(<Navbar auth={authState()} />)
    // Closed: only the single inline (hidden) Pricing link exists.
    expect(screen.getAllByRole('link', { name: 'Pricing' })).toHaveLength(1)

    fireEvent.click(screen.getByRole('button', { name: /Open menu/ }))

    // Open: the dropdown adds a second Pricing link.
    expect(screen.getAllByRole('link', { name: 'Pricing' })).toHaveLength(2)
    // The toggle now offers to close.
    expect(screen.getByRole('button', { name: /Close menu/ })).toBeInTheDocument()
  })
})
