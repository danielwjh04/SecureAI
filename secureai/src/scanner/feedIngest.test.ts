// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { d1FeedStore } from '../db/feed'
import { memoryDatabase } from '../db/memory.test'
import { ingestFeeds, type FeedIngestDeps } from './feedIngest'

const URLS = 'https://feeds.test/urlhaus-urls'
const HOSTS = 'https://feeds.test/urlhaus-hosts'
const TFX = 'https://feeds.test/threatfox-csv'

interface Route {
  readonly body?: string
  readonly status?: number
  readonly fail?: boolean
}

/** A routing fetch fake; an unrouted URL or `fail: true` rejects (source error). */
function feedFetch(routes: Record<string, Route>): typeof fetch {
  return (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    const route = routes[url]
    if (route === undefined || route.fail === true) {
      throw new Error(`feed source unavailable: ${url}`)
    }
    return new Response(route.body ?? '', { status: route.status ?? 200 })
  }) as unknown as typeof fetch
}

function deps(fetchImpl: typeof fetch, overrides: Partial<FeedIngestDeps> = {}): FeedIngestDeps {
  const { db } = memoryDatabase()
  return {
    db,
    fetchImpl,
    authKey: 'k',
    version: 1700,
    updatedAt: '2026-06-29T00:00:00.000Z',
    sources: { urlhausUrlList: URLS, urlhausHostfile: HOSTS, threatfoxCsv: TFX },
    maxRows: 10000,
    fetchTimeoutMs: 5000,
    ...overrides,
  }
}

describe('ingestFeeds', () => {
  it('fetches every source, loads the merged feed, and flips the live version', async () => {
    const fetchImpl = feedFetch({
      [URLS]: { body: '# c\nhttp://evil.test/mal\n' },
      [HOSTS]: { body: '# c\n0.0.0.0 badhost.test\n' },
      [TFX]: { body: '# h\n"t","1","tfx.test","domain","cc","M"\n' },
    })
    const d = deps(fetchImpl)
    const summary = await ingestFeeds(d)

    expect(summary.total).toBe(3)
    expect(summary.flipped).toBe(true)
    const feed = d1FeedStore(d.db)
    expect(await feed.match(['badhost.test'], null)).toBe('urlhaus')
    expect(await feed.match(['tfx.test'], null)).toBe('threatfox')
    expect(await feed.match([], 'evil.test/mal')).toBe('urlhaus')
  })

  it('skips a failing source and still loads the others (degraded but live)', async () => {
    const fetchImpl = feedFetch({
      [URLS]: { body: '# c\nhttp://evil.test/mal\n' },
      [HOSTS]: { body: '# c\nbadhost.test\n' },
      [TFX]: { fail: true },
    })
    const d = deps(fetchImpl)
    const summary = await ingestFeeds(d)

    expect(summary.flipped).toBe(true)
    expect(summary.sources.find((s) => s.label === 'threatfox')?.ok).toBe(false)
    expect(await d1FeedStore(d.db).match(['badhost.test'], null)).toBe('urlhaus')
  })

  it('never flips to an empty version when every source fails (keeps last good)', async () => {
    const { db, store } = memoryDatabase()
    const fetchImpl = feedFetch({}) // every URL unrouted → throws
    const summary = await ingestFeeds(deps(fetchImpl, { db }))

    expect(summary.total).toBe(0)
    expect(summary.flipped).toBe(false)
    expect(store.feedMetaVersion).toBeNull()
  })

  it('treats a non-OK HTTP status as a source failure', async () => {
    const fetchImpl = feedFetch({
      [URLS]: { status: 429 },
      [HOSTS]: { body: 'badhost.test\n' },
      [TFX]: { status: 500 },
    })
    const summary = await ingestFeeds(deps(fetchImpl))
    expect(summary.sources.find((s) => s.label === 'urlhaus-urls')?.ok).toBe(false)
    expect(summary.total).toBe(1)
  })
})
