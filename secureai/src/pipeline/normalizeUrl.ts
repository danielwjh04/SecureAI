/**
 * Canonical match key for a URL indicator, shared by feed ingestion and
 * scan-time lookup. Both sides MUST derive the key with this one function so a
 * feed URL and a scanned destination URL compare byte-identically, the same
 * discipline the proof chain uses for its canonical bytes.
 *
 * The key is `host + pathname + search` of the parsed URL:
 *   - host is lowercased and has its scheme's default port stripped (both by the
 *     URL parser), so the match is SCHEME-INSENSITIVE, a malicious resource is
 *     equally bad over http or https. A non-default explicit port is kept.
 *   - pathname is exact (case-sensitive; a trailing slash is significant), and
 *     the query string is kept, so distinct malicious URLs on one host stay
 *     distinct. The fragment and any userinfo are dropped.
 * A URL value therefore always contains a `/` (the pathname is at least `/`),
 * while a host indicator value never does, the two namespaces cannot collide,
 * so a single equality test over the value column is sufficient at lookup.
 */

/**
 * Normalize a URL string to its canonical indicator match key, or `null` when
 * the input is unparseable or has no host (a hostless scheme like `mailto:`).
 *
 * Time complexity: O(n) in the URL length. Space complexity: O(n).
 *
 * @param raw - A candidate URL string (a feed entry or a scanned destination).
 * @returns The `host + pathname + search` key, or `null` if not a hosted URL.
 */
export function normalizeIndicatorUrl(raw: string): string | null {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.host.length === 0) {
    return null
  }
  return `${url.host}${url.pathname}${url.search}`
}
