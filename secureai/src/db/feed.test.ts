import { describe, expect, it } from 'vitest'
import type { FeedIndicator } from '../pipeline/feedParse'
import type { Database } from './database'
import { memoryDatabase } from './memory.test'
import { d1FeedStore, replaceFeed } from './feed'

describe('d1FeedStore.match', () => {
  it('returns null before any feed version is loaded', async () => {
    const { db } = memoryDatabase()
    expect(await d1FeedStore(db).match(['evil.com'], 'evil.com/')).toBeNull()
  })

  it('matches a host via its parent-domain suffixes, and an exact URL', async () => {
    const { db } = memoryDatabase()
    const indicators: FeedIndicator[] = [
      { kind: 'host', value: 'evil.com', source: 'urlhaus' },
      { kind: 'url', value: 'host.test/mal', source: 'threatfox' },
    ]
    await replaceFeed(db, 1000, '2026-06-29T00:00:00.000Z', indicators)
    const feed = d1FeedStore(db)
    // subdomain matches via the suffix walk the caller supplies
    expect(await feed.match(['x.evil.com', 'evil.com'], 'clean.test/')).toBe('urlhaus')
    expect(await feed.match(['clean.test'], 'host.test/mal')).toBe('threatfox')
    expect(await feed.match(['clean.test'], 'clean.test/')).toBeNull()
  })
})

describe('replaceFeed', () => {
  it('atomic version swap: the previous version stops matching after a refresh', async () => {
    const { db, store } = memoryDatabase()
    await replaceFeed(db, 1, 't1', [{ kind: 'host', value: 'a.com', source: 'urlhaus' }])
    await replaceFeed(db, 2, 't2', [{ kind: 'host', value: 'b.com', source: 'urlhaus' }])
    const feed = d1FeedStore(db)
    expect(await feed.match(['a.com'], null)).toBeNull()
    expect(await feed.match(['b.com'], null)).toBe('urlhaus')
    // old-version rows were deleted, leaving only the current version
    expect(store.feedIndicators.every((r) => r.version === 2)).toBe(true)
  })

  it('does not flip to an empty version (keeps the last good feed)', async () => {
    const { db, store } = memoryDatabase()
    await replaceFeed(db, 1, 't1', [{ kind: 'host', value: 'a.com', source: 'urlhaus' }])
    await replaceFeed(db, 2, 't2', [])
    expect(store.feedMetaVersion).toBe(1)
    expect(await d1FeedStore(db).match(['a.com'], null)).toBe('urlhaus')
  })

  it('loads large replacements through bounded batch calls', async () => {
    const { db, store } = memoryDatabase()
    await replaceFeed(db, 1, 't1', [{ kind: 'host', value: 'old.test', source: 'urlhaus' }])

    const batchSizes: number[] = []
    const countedDb: Database = {
      queryOne: db.queryOne,
      queryAll: db.queryAll,
      execute: db.execute,
      async batch(statements) {
        batchSizes.push(statements.length)
        return db.batch(statements)
      },
    }
    const indicators: FeedIndicator[] = Array.from({ length: 450 }, (_, index) => ({
      kind: 'host',
      value: `bad-${index}.test`,
      source: 'urlhaus',
    }))

    await replaceFeed(countedDb, 2, 't2', indicators)

    expect(batchSizes).toEqual([5])
    expect(store.feedMetaVersion).toBe(2)
    expect(store.feedIndicators).toHaveLength(450)
    expect(store.feedIndicators.every((record) => record.version === 2)).toBe(true)
    expect(store.feedIndicators.map((record) => record.value).sort()).toEqual(
      indicators.map((indicator) => indicator.value).sort(),
    )
  })
})
