// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { traceRedirects } from './redirect'
import type { RedirectTraceConfig } from './redirect'
import { RedirectResolutionError } from '../errors'

// These tests drive `traceRedirects` with a MOCK fetch so cascades are
// deterministic and no real network is touched. The SSRF case exercises the
// real `assertSafeUrl` (a loopback literal must be rejected), that is the one
// integration point we deliberately keep live.

/** A small, fixed config so cap behavior is exercised at low hop counts. */
const CONFIG: RedirectTraceConfig = {
  maxRedirectHops: 3,
  redirectTimeoutMs: 1000,
  allowedSchemes: new Set(['https']),
}

/**
 * Build a mock `fetch` from a routing table of `url -> {status, location}`.
 * A `location` makes the URL a 302 redirect; its absence makes it a final 200.
 * An unrouted URL throws, surfacing accidental over-fetching.
 */
function mockFetch(
  routes: Record<string, { status: number; location?: string }>,
): typeof fetch {
  const impl = async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    const route = routes[url]
    if (route === undefined) {
      throw new Error(`unexpected fetch for ${url}`)
    }
    const headers = new Headers()
    if (route.location !== undefined) {
      headers.set('Location', route.location)
    }
    return new Response(null, { status: route.status, headers })
  }
  return impl as unknown as typeof fetch
}

describe('traceRedirects', () => {
  it('follows N hops to a final 200 and reports the final URL', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'https://b.example/' },
      'https://b.example/': { status: 301, location: 'https://c.example/' },
      'https://c.example/': { status: 200 },
    })

    const chain = await traceRedirects('https://a.example/', CONFIG, fetchImpl)

    expect(chain.origin).toBe('https://a.example/')
    expect(chain.finalUrl).toBe('https://c.example/')
    expect(chain.hops.map((h) => [h.from, h.to])).toEqual([
      ['https://a.example/', 'https://b.example/'],
      ['https://b.example/', 'https://c.example/'],
    ])
    expect(chain.hops.every((h) => !h.dangerous)).toBe(true)
    expect(chain.dangerousHopIndex).toBeNull()
    expect(chain.depthExceeded).toBe(false)
    expect(chain.loopDetected).toBe(false)
  })

  it('resolves a relative Location against the current URL', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/start': { status: 302, location: '/next' },
      'https://a.example/next': { status: 200 },
    })

    const chain = await traceRedirects(
      'https://a.example/start',
      CONFIG,
      fetchImpl,
    )

    expect(chain.hops[0]?.to).toBe('https://a.example/next')
    expect(chain.finalUrl).toBe('https://a.example/next')
    expect(chain.loopDetected).toBe(false)
  })

  it('stops at maxRedirectHops and flags depthExceeded on an endless cascade', async () => {
    // Every URL redirects to the next: the cascade never terminates on its own.
    const endless: typeof fetch = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      const n = Number(new URL(url).searchParams.get('n') ?? '0')
      const headers = new Headers()
      headers.set('Location', `https://hop.example/?n=${n + 1}`)
      return Promise.resolve(new Response(null, { status: 302, headers }))
    }) as unknown as typeof fetch

    const chain = await traceRedirects(
      'https://hop.example/?n=0',
      CONFIG,
      endless,
    )

    expect(chain.depthExceeded).toBe(true)
    expect(chain.loopDetected).toBe(false)
    // Exactly `maxRedirectHops` redirects were followed before the cap fired.
    expect(chain.hops).toHaveLength(CONFIG.maxRedirectHops)
    expect(chain.dangerousHopIndex).toBeNull()
  })

  it('detects an A->B->A loop and flags loopDetected', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'https://b.example/' },
      'https://b.example/': { status: 302, location: 'https://a.example/' },
    })

    const chain = await traceRedirects('https://a.example/', CONFIG, fetchImpl)

    expect(chain.loopDetected).toBe(true)
    expect(chain.depthExceeded).toBe(false)
    expect(chain.dangerousHopIndex).toBeNull()
    // A->B and B->A were recorded; the second return to A tripped the guard.
    expect(chain.hops.map((h) => [h.from, h.to])).toEqual([
      ['https://a.example/', 'https://b.example/'],
      ['https://b.example/', 'https://a.example/'],
    ])
  })

  it('applies the SSRF guard: a hop to 127.0.0.1 is marked dangerous and stops', async () => {
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'http://127.0.0.1/' },
      // The loopback URL must NEVER be fetched; routing it would over-fetch.
    })

    const chain = await traceRedirects('https://a.example/', CONFIG, fetchImpl)

    expect(chain.dangerousHopIndex).toBe(1)
    const dangerous = chain.hops[1]
    expect(dangerous?.dangerous).toBe(true)
    expect(dangerous?.from).toBe('http://127.0.0.1/')
    expect(dangerous?.reason).not.toBeNull()
    // Tracing halted at the dangerous hop; no further hops were recorded.
    expect(chain.hops).toHaveLength(2)
    expect(chain.depthExceeded).toBe(false)
    expect(chain.loopDetected).toBe(false)
  })

  it('rejects a malformed Location by treating the next hop as dangerous', async () => {
    // `new URL('::::', base)` throws -> the resolved hop is recorded but the
    // SSRF guard re-parsing the same bad string flags it. Here we instead feed
    // a Location that resolves but to a scheme the SSRF guard rejects, to keep
    // the failure inside the guard rather than URL parsing.
    const fetchImpl = mockFetch({
      'https://a.example/': { status: 302, location: 'ftp://a.example/file' },
    })

    const chain = await traceRedirects('https://a.example/', CONFIG, fetchImpl)

    expect(chain.dangerousHopIndex).toBe(1)
    expect(chain.hops[1]?.dangerous).toBe(true)
  })

  it('fails closed by raising RedirectResolutionError on a transport failure', async () => {
    const failing: typeof fetch = (() =>
      Promise.reject(new TypeError('network down'))) as unknown as typeof fetch

    await expect(
      traceRedirects('https://a.example/', CONFIG, failing),
    ).rejects.toBeInstanceOf(RedirectResolutionError)
  })
})
