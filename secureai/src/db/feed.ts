/**
 * The bulk threat-feed indicator store, over the narrow {@link Database} seam.
 *
 * Feed rows live in a VERSIONED table: every refresh writes a fresh `version`,
 * then atomically flips the `feed_meta.current_version` pointer and deletes the
 * superseded rows. Reads JOIN through the pointer, so a scan only ever sees a
 * COMPLETE version, a refresh (or a crashed refresh) never exposes a partial or
 * empty denylist. Matched `value` namespaces are disjoint (a host value has no
 * `/`; a URL value always does, see `pipeline/normalizeUrl`), so one equality
 * test over `value` covers both kinds.
 */

import type { FeedIndicator } from '../pipeline/feedParse'
import type { FeedIndicatorStore } from '../pipeline/indicators'
import type { BatchStatement, Database } from './database'

/**
 * Read the active feed version from `feed_meta`, or `null` when the table has
 * no row yet (feed never loaded) or the value is missing.
 *
 * Time complexity: O(1) indexed lookup. Space complexity: O(1).
 *
 * @param db - The persistence seam.
 * @returns The `current_version` as a string, or `null` when absent.
 */
export async function currentFeedVersion(db: Database): Promise<string | null> {
  const row = await db.queryOne('SELECT current_version FROM feed_meta WHERE id = 1', [])
  if (row === null) {
    return null
  }
  const version = row['current_version']
  if (version === null || version === undefined) {
    return null
  }
  return String(version)
}

/**
 * Rows per multi-row INSERT. Four bound params per row, kept well under SQLite's
 * ~999 bound-variable limit so each chunk is one prepared statement.
 */
const FEED_INSERT_ROWS = 100

/** Number of INSERT statements sent in one database batch call. */
const FEED_BATCH_STATEMENTS = 20

/**
 * A {@link FeedIndicatorStore} backed by the `feed_indicators` table. `match`
 * runs ONE indexed query: the host's parent-domain suffixes plus the normalized
 * URL are tested against the current version's `value` column.
 *
 * Time complexity: O(s) bound params (s = suffix count ≤ host label count) for a
 *   single indexed lookup. Space complexity: O(s).
 *
 * @param db - The persistence seam.
 * @returns A store whose `match` resolves a hit's source label, or `null`.
 */
export function d1FeedStore(db: Database): FeedIndicatorStore {
  return {
    async match(
      hostSuffixes: readonly string[],
      normalizedUrl: string | null,
    ): Promise<string | null> {
      const values = normalizedUrl !== null ? [...hostSuffixes, normalizedUrl] : [...hostSuffixes]
      if (values.length === 0) {
        return null
      }
      const placeholders = values.map(() => '?').join(', ')
      const row = await db.queryOne(
        'SELECT fi.source AS source FROM feed_indicators fi ' +
          'JOIN feed_meta fm ON fm.id = 1 AND fi.version = fm.current_version ' +
          `WHERE fi.value IN (${placeholders}) LIMIT 1`,
        values,
      )
      if (row === null) {
        return null
      }
      const source = row['source']
      return typeof source === 'string' ? source : null
    },
  }
}

/**
 * Replace the live feed with `indicators` under a new `version`, atomically.
 *
 * Order is load-bearing for the atomic swap: insert every new-version row
 * (chunked multi-row INSERTs) FIRST, invisible to readers because the pointer
 * still names the old version, then flip `current_version` in one statement,
 * then delete all non-current rows. A crash before the flip leaves the prior
 * version live; a crash after it leaves only stale rows the NEXT refresh reclaims.
 *
 * An EMPTY `indicators` is a no-op (no flip): a refresh that gathered nothing
 * (every source failed) never empties the denylist, the last good version stays.
 *
 * Time complexity: O(n) inserts in chunks of {@link FEED_INSERT_ROWS}. Space: O(n).
 *
 * @param db - The persistence seam.
 * @param version - The new monotonic version (the cron's scheduledTime, ms).
 * @param updatedAt - ISO timestamp recorded on `feed_meta` for operability.
 * @param indicators - The de-duplicated, capped indicators to make live.
 */
export async function replaceFeed(
  db: Database,
  version: number,
  updatedAt: string,
  indicators: readonly FeedIndicator[],
): Promise<void> {
  if (indicators.length === 0) {
    return
  }
  const inserts: BatchStatement[] = []
  for (let offset = 0; offset < indicators.length; offset += FEED_INSERT_ROWS) {
    const chunk = indicators.slice(offset, offset + FEED_INSERT_ROWS)
    const placeholders = chunk.map(() => '(?, ?, ?, ?)').join(', ')
    const params: unknown[] = []
    for (const indicator of chunk) {
      params.push(version, indicator.kind, indicator.value, indicator.source)
    }
    inserts.push({
      sql: `INSERT INTO feed_indicators (version, kind, value, source) VALUES ${placeholders}`,
      params,
    })
  }
  for (let index = 0; index < inserts.length; index += FEED_BATCH_STATEMENTS) {
    await db.batch(inserts.slice(index, index + FEED_BATCH_STATEMENTS))
  }
  await db.execute('UPDATE feed_meta SET current_version = ?, updated_at = ? WHERE id = 1', [
    version,
    updatedAt,
  ])
  await db.execute('DELETE FROM feed_indicators WHERE version <> ?', [version])
}
