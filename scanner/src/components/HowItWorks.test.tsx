import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { HowItWorks } from './HowItWorks'

describe('HowItWorks', () => {
  it('renders the real six-layer pipeline heading and sub', () => {
    render(<HowItWorks />)
    expect(
      screen.getByText('Six checks. Cheapest first. AI last. One proof.'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/the model runs last, rarely/i),
    ).toBeInTheDocument()
  })

  it('clears the floating navbar with its own top padding on the #how anchor', () => {
    const { container } = render(<HowItWorks />)
    const section = container.querySelector('#how')
    expect(section).not.toBeNull()
    // The anchor lands flush at the viewport top (no `:target` scroll-margin); its
    // own top padding clears the floating navbar so the heading is not hidden
    // behind it, while the lower rhythm (pb-20) stays asymmetric, not py-20.
    expect(section?.className).toContain('pt-[8.5rem]')
    expect(section?.className).not.toContain('py-20')
  })

  it('renders all six pipeline steps in order', () => {
    render(<HowItWorks />)
    const titles = ['Parse', 'Trace', 'Rules', 'Indicators', 'Check', 'Seal']
    for (const title of titles) {
      expect(screen.getByText(title)).toBeInTheDocument()
    }
    // The numbered badges run 01..06.
    for (const n of ['01', '02', '03', '04', '05', '06']) {
      expect(screen.getByText(n)).toBeInTheDocument()
    }
  })

  it('describes indicators as a known-bad denylist, not live-web reputation', () => {
    render(<HowItWorks />)
    expect(
      screen.getByText(/matched against a known-bad denylist/i),
    ).toBeInTheDocument()
    expect(screen.queryByText(/live web/i)).toBeNull()
    expect(screen.queryByText(/reputation/i)).toBeNull()
  })

  it('renders the SSRF guard and tighten-only framing in the cards', () => {
    render(<HowItWorks />)
    expect(screen.getByText(/behind an SSRF guard/i)).toBeInTheDocument()
    expect(screen.getByText(/never overturn a block/i)).toBeInTheDocument()
  })

  it('renders the two invariants callout (fail-closed and tighten-only)', () => {
    render(<HowItWorks />)
    expect(screen.getByText('Fail-closed')).toBeInTheDocument()
    expect(screen.getByText('Tighten-only')).toBeInTheDocument()
    expect(
      screen.getByText(/blocked, never waved through/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/it never overturns a deterministic block/i),
    ).toBeInTheDocument()
  })
})
