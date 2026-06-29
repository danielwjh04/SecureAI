import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanResult } from '../schemas/contract'
import { loadConfig } from '../config/env'
import { MemoryD1, MemoryStore } from '../db/memory.test'
import { d1Database } from '../db/database'
import { replaceFeed } from '../db/feed'
import { handleScan } from './scan'

function post(body: unknown): Request {
  return new Request('https://secureai.test/api/scan', { method: 'POST', body: JSON.stringify(body) })
}

/** A DB seeded with one feed-listed host on the live version. */
async function dbWithFeedHost(host: string): Promise<D1Database> {
  const d1 = new MemoryD1(new MemoryStore()) as unknown as D1Database
  await replaceFeed(d1Database(d1), 1, '2026-06-29T00:00:00.000Z', [
    { kind: 'host', value: host, source: 'urlhaus' },
  ])
  return d1
}

describe('handleScan, threat feed wiring', () => {
  // Stub fetch so the redirect tracer is terminal/network-free.
  beforeEach(() => {
    vi.stubGlobal('fetch', (async () => new Response('ok', { status: 200 })) as unknown as typeof fetch)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('escalates to REVIEW when a scanned link resolves to a feed-listed host', async () => {
    const db = await dbWithFeedHost('evil.test')
    const config = loadConfig({ SCANNER_FEED_ENABLED: 'true' })
    const res = await handleScan(post({ content: 'Visit https://evil.test/landing now' }), { DB: db }, config)
    expect(res.status).toBe(200)
    const result = (await res.json()) as ScanResult
    expect(result.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
    expect(result.reputation.some((r) => r.flagged && r.status === 'denylisted')).toBe(true)
  })

  it('leaves a clean link as ALLOW when the feed is enabled but does not list it', async () => {
    const db = await dbWithFeedHost('evil.test')
    const config = loadConfig({ SCANNER_FEED_ENABLED: 'true' })
    const res = await handleScan(post({ content: 'Visit https://example.com/ok now' }), { DB: db }, config)
    const result = (await res.json()) as ScanResult
    expect(result.verdict).toBe('ALLOW')
  })

  it('does NOT consult the feed when it is disabled (feed-listed host stays ALLOW)', async () => {
    const db = await dbWithFeedHost('evil.test')
    const config = loadConfig({}) // feed disabled by default
    const res = await handleScan(post({ content: 'Visit https://evil.test/landing now' }), { DB: db }, config)
    const result = (await res.json()) as ScanResult
    expect(result.verdict).toBe('ALLOW')
  })
})
