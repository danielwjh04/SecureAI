/**
 * Threat-feed ingestion: fetch each configured abuse.ch source, parse it, merge
 * + de-dup + cap, and atomically replace the live feed version. Every capability
 * (fetch, db, the version/clock) is injected via {@link FeedIngestDeps}, so this
 * is Node-runnable and unit-tested with a fake fetch + the in-memory DB.
 *
 * Fail-SAFE for availability: a source that fails to fetch/parse is skipped
 * (logged + metered) and the others still load. If EVERY source fails (zero
 * indicators gathered) the live version is NOT flipped, the last good feed
 * stays, so a transient abuse.ch outage never empties the denylist.
 */

import type { Database } from '../db/database'
import { replaceFeed } from '../db/feed'
import {
  dedupeAndCap,
  parseThreatfoxCsv,
  parseUrlhausHostfile,
  parseUrlhausUrlList,
  type FeedIndicator,
} from '../pipeline/feedParse'
import { errorClassOf, log } from '../observability/logger'
import { metrics } from '../observability/metrics'

/** The source URLs each feed is fetched from (from config; defaults in wrangler). */
export interface FeedSourceUrls {
  readonly urlhausUrlList: string
  readonly urlhausHostfile: string
  readonly threatfoxCsv: string
}

/** Injected dependencies for {@link ingestFeeds}. */
export interface FeedIngestDeps {
  readonly db: Database
  readonly fetchImpl: typeof fetch
  /** abuse.ch Auth-Key (secret), or `undefined` to fetch without the header. */
  readonly authKey: string | undefined
  /** Monotonic version for this refresh (the cron's scheduledTime, ms). */
  readonly version: number
  /** ISO timestamp recorded on `feed_meta` for operability. */
  readonly updatedAt: string
  readonly sources: FeedSourceUrls
  readonly maxRows: number
  readonly fetchTimeoutMs: number
}

/** Per-source outcome, for the summary and logs. */
export interface FeedSourceResult {
  readonly label: string
  readonly ok: boolean
  readonly rows: number
}

/** The outcome of one ingestion run. */
export interface FeedIngestSummary {
  readonly total: number
  readonly dropped: number
  readonly flipped: boolean
  readonly sources: readonly FeedSourceResult[]
}

/** Internal: one source's display label, fetch URL, and body parser. */
interface FeedSourceSpec {
  readonly label: string
  readonly url: string
  readonly parse: (body: string) => FeedIndicator[]
}

/**
 * Fetch and parse ONE source, isolating its failure: a transport fault, a non-OK
 * status, or a parse error is logged + metered and yields an empty result with
 * `ok: false`, never a throw, so one bad source cannot abort the whole refresh.
 *
 * Time complexity: O(b) in the body length. Space complexity: O(b).
 */
async function fetchSource(
  spec: FeedSourceSpec,
  deps: FeedIngestDeps,
): Promise<{ result: FeedSourceResult; indicators: FeedIndicator[] }> {
  try {
    const headers = deps.authKey !== undefined ? { 'Auth-Key': deps.authKey } : undefined
    const response = await deps.fetchImpl(spec.url, {
      headers,
      signal: AbortSignal.timeout(deps.fetchTimeoutMs),
    })
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }
    const indicators = spec.parse(await response.text())
    metrics.count('feed.refresh', { labels: [spec.label, 'ok'] })
    log.info('feedIngest', 'source loaded', { source: spec.label, rows: indicators.length })
    return { result: { label: spec.label, ok: true, rows: indicators.length }, indicators }
  } catch (error: unknown) {
    metrics.count('feed.refresh', { labels: [spec.label, 'fail'] })
    log.warn('feedIngest', 'source failed; skipped', {
      source: spec.label,
      errorClass: errorClassOf(error),
    })
    return { result: { label: spec.label, ok: false, rows: 0 }, indicators: [] }
  }
}

/**
 * Refresh the live threat feed from every configured source.
 *
 * Time complexity: O(n) in the total indicator count. Space complexity: O(n).
 *
 * @param deps - Injected fetch, db, version/clock, source URLs, and bounds.
 * @returns A {@link FeedIngestSummary}: per-source outcomes + whether it flipped.
 */
export async function ingestFeeds(deps: FeedIngestDeps): Promise<FeedIngestSummary> {
  const specs: readonly FeedSourceSpec[] = [
    { label: 'urlhaus-urls', url: deps.sources.urlhausUrlList, parse: parseUrlhausUrlList },
    { label: 'urlhaus-hosts', url: deps.sources.urlhausHostfile, parse: parseUrlhausHostfile },
    { label: 'threatfox', url: deps.sources.threatfoxCsv, parse: parseThreatfoxCsv },
  ]
  const fetched = await Promise.all(specs.map((spec) => fetchSource(spec, deps)))
  const merged = fetched.flatMap((entry) => entry.indicators)
  const { indicators, dropped } = dedupeAndCap(merged, deps.maxRows)

  if (dropped > 0) {
    log.warn('feedIngest', 'indicator cap reached; surplus dropped', { dropped, cap: deps.maxRows })
  }
  // Never flip to an empty version: a run where every source failed keeps the
  // last good feed live (replaceFeed is itself a no-op on empty too).
  const flipped = indicators.length > 0
  if (flipped) {
    await replaceFeed(deps.db, deps.version, deps.updatedAt, indicators)
  }
  log.info('feedIngest', 'refresh complete', { total: indicators.length, dropped, flipped })
  return {
    total: indicators.length,
    dropped,
    flipped,
    sources: fetched.map((entry) => entry.result),
  }
}
