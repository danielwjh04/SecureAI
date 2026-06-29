import { describe, expect, it, vi } from 'vitest'
import { MemoryD1, MemoryStore } from './db/memory.test'
import worker from './index'

const controller = { scheduledTime: 1700, cron: '0 * * * *', noRetry: () => {} }

function call(env: Record<string, unknown>): Promise<void> {
  return worker.scheduled!(controller as unknown as ScheduledController, env)
}

describe('worker.scheduled (threat-feed cron)', () => {
  it('no-ops when the feed is disabled', async () => {
    const store = new MemoryStore()
    await call({ DB: new MemoryD1(store) as unknown as D1Database })
    expect(store.feedMetaVersion).toBeNull()
  })

  it('no-ops without throwing when DB is unbound', async () => {
    await expect(call({ SCANNER_FEED_ENABLED: 'true' })).resolves.toBeUndefined()
  })

  it('loads a feed version stamped with the scheduledTime when enabled', async () => {
    const store = new MemoryStore()
    const bodies: Record<string, string> = {
      'https://f.test/u': '',
      'https://f.test/h': 'evilhost.test\n',
      'https://f.test/t': '',
    }
    vi.stubGlobal('fetch', (async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString()
      return new Response(bodies[url] ?? '', { status: url in bodies ? 200 : 404 })
    }) as unknown as typeof fetch)
    await call({
      DB: new MemoryD1(store) as unknown as D1Database,
      SCANNER_FEED_ENABLED: 'true',
      URLHAUS_AUTH_KEY: 'k',
      SCANNER_FEED_URLHAUS_URLS: 'https://f.test/u',
      SCANNER_FEED_URLHAUS_HOSTS: 'https://f.test/h',
      SCANNER_FEED_THREATFOX: 'https://f.test/t',
    })
    vi.unstubAllGlobals()
    expect(store.feedMetaVersion).toBe(1700)
  })
})
