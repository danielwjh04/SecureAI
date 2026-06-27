import { render } from '@testing-library/react'
import type { LinkChain, RedirectHop } from '../api/types'
import { RedirectChain } from './RedirectChain'

/**
 * Build a redirect hop with sane defaults so each test only states the fields
 * it cares about.
 */
function hop(overrides: Partial<RedirectHop> = {}): RedirectHop {
  return {
    from: 'https://a.example/from',
    to: 'https://b.example/to',
    status: 301,
    dangerous: false,
    reason: null,
    ...overrides,
  }
}

/** Build a LinkChain from a hop list and an optional dangerous hop index. */
function chain(hops: RedirectHop[], dangerousHopIndex: number | null): LinkChain {
  return {
    origin: 'https://origin.example/start',
    hops,
    finalUrl: hops.length > 0 ? hops[hops.length - 1].to : 'https://origin.example/start',
    dangerousHopIndex,
    depthExceeded: false,
    loopDetected: false,
  }
}

describe('RedirectChain', () => {
  it('marks exactly the hop at dangerousHopIndex with chain-vis__hop--danger', () => {
    const hops = [
      hop({ to: 'https://one.example/a', status: 302 }),
      hop({ to: 'https://two.example/b', status: 301 }),
      hop({ to: 'https://three.example/c', status: 307, dangerous: true, reason: 'TLD mismatch' }),
      hop({ to: 'https://four.example/d', status: 200 }),
    ]
    const { container } = render(<RedirectChain chain={chain(hops, 2)} index={0} />)

    const danger = container.querySelectorAll('.chain-vis__hop--danger')
    expect(danger).toHaveLength(1)

    // The danger node is hop index 2: its host text and reason prove position.
    expect(danger[0].textContent).toContain('three.example')
    expect(danger[0].textContent).toContain('TLD mismatch')
  })

  it('marks no hop dangerous when dangerousHopIndex is null', () => {
    const hops = [
      hop({ to: 'https://one.example/a' }),
      hop({ to: 'https://two.example/b' }),
      hop({ to: 'https://three.example/c' }),
    ]
    const { container } = render(<RedirectChain chain={chain(hops, null)} index={0} />)

    expect(container.querySelectorAll('.chain-vis__hop--danger')).toHaveLength(0)
  })

  it('renders the origin, then every hop host, then the final, in order', () => {
    const hops = [
      hop({ to: 'https://first.example/a', status: 301 }),
      hop({ to: 'https://second.example/b', status: 302 }),
      hop({ to: 'https://third.example/c', status: 200 }),
    ]
    const { container } = render(<RedirectChain chain={chain(hops, null)} index={0} />)

    const hosts = Array.from(container.querySelectorAll('.chain-vis__host')).map(
      (node) => node.textContent,
    )
    // Origin first, then each hop's destination host, in cascade order; the last
    // host is the final node rendered from chain.finalUrl (= the last hop's `to`).
    expect(hosts).toEqual([
      'origin.example',
      'first.example',
      'second.example',
      'third.example',
    ])
  })
})
