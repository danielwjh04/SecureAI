/**
 * Manual redirect-cascade tracer.
 *
 * A skill's links are followed hop-by-hop with `redirect: 'manual'` so the
 * scanner sees every intermediate destination — the exact surface a redirect
 * laundering attack hides behind. Every hop URL is run through the SSRF guard
 * *before* it is fetched, the cascade is bounded by a configured depth cap, and
 * a normalized-URL set catches loops. Nothing here trusts the network to
 * terminate on its own.
 *
 * Fail-closed posture: a hop that the SSRF guard rejects is recorded as a
 * dangerous hop and the cascade stops (we never fetch it). A genuine transport
 * failure (network error / timeout) cannot be resolved into a verdict here, so
 * it is raised as `RedirectResolutionError` for the orchestrator to escalate —
 * it is never swallowed into a "clean" chain.
 *
 * Cloudflare note: Workers cannot inspect the resolved IP of a hostname, so the
 * SSRF guard is hostname/scheme based (see `./ssrf`); Exa-as-fetcher is the
 * compensating control for actual page content.
 */

import type { LinkChain, RedirectHop } from '../../shared/contract'
import { assertSafeUrl } from './ssrf'
import { RedirectResolutionError } from '../errors'

/**
 * The slice of runtime config this tracer needs. Declared structurally so the
 * module stays decoupled from the full `ScannerConfig` and is trivially
 * testable; the real config object satisfies this shape.
 */
export interface RedirectTraceConfig {
  /** Maximum number of redirect hops to follow before declaring depth exceeded. */
  maxRedirectHops: number
  /** Per-hop fetch timeout in milliseconds (drives `AbortSignal.timeout`). */
  redirectTimeoutMs: number
  /**
   * Allowlisted URL schemes for the per-hop SSRF guard (e.g. `new Set(["https"])`).
   * Structurally satisfies {@link SsrfConfig} so it can be passed straight to
   * `assertSafeUrl`.
   */
  allowedSchemes: ReadonlySet<string>
}

/** HTTP status codes that carry a `Location` redirect. */
const REDIRECT_STATUS_MIN = 300
const REDIRECT_STATUS_MAX = 399

/**
 * Normalize a URL for loop detection.
 *
 * Uses the WHATWG URL serialization (`href`), which canonicalizes scheme/host
 * casing, default ports, and path so that two textually different spellings of
 * the same location collide in the visited set.
 *
 * Time complexity: O(m) in URL length. Space complexity: O(m).
 *
 * @param url - An absolute URL string.
 * @returns The canonical serialized form.
 */
function normalizeUrl(url: string): string {
  return new URL(url).href
}

/** Outcome of resolving a 3xx response's `Location` header. */
type LocationResolution =
  | { kind: 'none' }
  | { kind: 'resolved'; url: string }
  | { kind: 'malformed'; raw: string }

/**
 * Read the `Location` header of a 3xx response and resolve it against the URL
 * that produced the response (relative redirects are legal and common).
 *
 * A malformed `Location` is reported as `malformed` (never thrown) so the
 * caller can record it as a dangerous, terminal hop — fail-closed, not a raw
 * `TypeError` escaping the tracer.
 *
 * Time complexity: O(m) in the resolved URL length. Space complexity: O(m).
 *
 * @param response - The hop response (already known to be a 3xx).
 * @param currentUrl - The absolute URL the response was fetched from.
 * @returns A {@link LocationResolution} discriminated on whether a `Location`
 *   was present and parseable.
 */
function resolveLocation(
  response: Response,
  currentUrl: string,
): LocationResolution {
  const location = response.headers.get('Location')
  if (location === null || location.length === 0) {
    return { kind: 'none' }
  }
  // Resolve relative Locations against the current URL; absolute ones pass
  // through unchanged.
  try {
    return { kind: 'resolved', url: new URL(location, currentUrl).href }
  } catch {
    return { kind: 'malformed', raw: location }
  }
}

/**
 * Trace a URL's redirect cascade hop-by-hop, with SSRF guards, a depth cap,
 * and loop detection.
 *
 * Algorithm (single forward walk, no rescans):
 *   1. Run `assertSafeUrl` on the current URL. If it throws, record a dangerous
 *      hop carrying the guard's reason and stop (the URL is never fetched).
 *   2. If the current URL was already visited, set `loopDetected` and stop.
 *   3. Fetch with `redirect: 'manual'` and a per-hop abort timeout. A transport
 *      failure raises `RedirectResolutionError` (fail-closed — never resolves to
 *      a clean chain).
 *   4. If the status is not a 3xx with a usable `Location`, the current URL is
 *      final — stop.
 *   5. Otherwise record the hop, advance to the resolved Location, and repeat.
 *      Exceeding `maxRedirectHops` sets `depthExceeded` and stops.
 *
 * Time complexity: O(h) where h = number of hops (≤ `maxRedirectHops`); one
 *   fetch per hop, one set lookup per hop. Space complexity: O(h) for the hop
 *   list and the visited set.
 *
 * @param startUrl - The origin URL extracted from the skill.
 * @param config - Depth cap and per-hop timeout.
 * @param fetchImpl - Injected fetch (defaults to global `fetch`); tests pass a
 *   mock to drive deterministic cascades.
 * @returns The traced {@link LinkChain}: origin, hops, final URL, first
 *   dangerous hop index (or null), and the depth/loop flags.
 * @throws {RedirectResolutionError} On a transport failure or timeout while
 *   fetching a hop.
 */
export async function traceRedirects(
  startUrl: string,
  config: RedirectTraceConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<LinkChain> {
  const hops: RedirectHop[] = []
  const visited = new Set<string>()
  let dangerousHopIndex: number | null = null
  let depthExceeded = false
  let loopDetected = false

  let currentUrl = startUrl

  // The loop is bounded by `maxRedirectHops`: each iteration either terminates
  // the cascade (final/dangerous/loop) or consumes one hop budget. The extra
  // `<=` lets us detect the *overflow* iteration so `depthExceeded` is set
  // exactly when a further redirect would push past the cap.
  for (let hopCount = 0; ; hopCount += 1) {
    // 1. SSRF guard BEFORE any network access. A rejection is terminal and
    //    dangerous; we record it and never fetch the URL.
    try {
      assertSafeUrl(new URL(currentUrl), config)
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : String(error)
      dangerousHopIndex = hops.length
      hops.push({
        from: currentUrl,
        to: currentUrl,
        status: 0,
        dangerous: true,
        reason,
      })
      break
    }

    // 2. Loop detection on the normalized form (before fetching again).
    const normalized = normalizeUrl(currentUrl)
    if (visited.has(normalized)) {
      loopDetected = true
      break
    }
    visited.add(normalized)

    // 3. Depth cap: if we have already followed `maxRedirectHops` redirects and
    //    are about to follow another, stop and flag depth exceeded.
    if (hopCount >= config.maxRedirectHops) {
      depthExceeded = true
      break
    }

    // 4. Fetch the current URL without auto-following redirects. A transport
    //    failure is fail-closed: it cannot yield a clean chain.
    let response: Response
    try {
      response = await fetchImpl(currentUrl, {
        redirect: 'manual',
        signal: AbortSignal.timeout(config.redirectTimeoutMs),
      })
    } catch (error: unknown) {
      const cause = error instanceof Error ? error.constructor.name : 'unknown'
      throw new RedirectResolutionError(
        `fetch failed while tracing redirect hop ${hops.length} ` +
          `(${currentUrl}): ${cause}`,
        { cause: error },
      )
    }

    // 5. Non-redirect status (or a 3xx with no Location) means the current URL
    //    is the final destination — terminate.
    const isRedirect =
      response.status >= REDIRECT_STATUS_MIN &&
      response.status <= REDIRECT_STATUS_MAX
    if (!isRedirect) {
      break
    }
    const resolution = resolveLocation(response, currentUrl)
    if (resolution.kind === 'none') {
      break
    }
    if (resolution.kind === 'malformed') {
      // A redirect we cannot parse cannot be followed safely — record it as a
      // dangerous, terminal hop (fail-closed) rather than guessing.
      dangerousHopIndex = hops.length
      hops.push({
        from: currentUrl,
        to: resolution.raw,
        status: response.status,
        dangerous: true,
        reason: `malformed Location header: ${resolution.raw}`,
      })
      break
    }

    // 6. Record the hop and advance.
    hops.push({
      from: currentUrl,
      to: resolution.url,
      status: response.status,
      dangerous: false,
      reason: null,
    })
    currentUrl = resolution.url
  }

  return {
    origin: startUrl,
    hops,
    finalUrl: currentUrl,
    dangerousHopIndex,
    depthExceeded,
    loopDetected,
  }
}
