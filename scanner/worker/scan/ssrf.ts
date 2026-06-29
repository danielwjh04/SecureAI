/**
 * SSRF (server-side request forgery) host and scheme guards for the redirect
 * tracer.
 *
 * The Worker follows redirect cascades by issuing real subrequests. Without a
 * guard, an attacker-controlled redirect could point the Worker at an internal
 * address (cloud metadata, RFC1918 ranges, loopback) to exfiltrate data or pivot
 * inside the network. Cloudflare Workers cannot inspect the *resolved* IP of a
 * fetch, so enforcement is hostname- and scheme-based:
 *
 *   - scheme must be in `config.allowedSchemes` (https-only by default);
 *   - the host must not be a raw IPv4/IPv6 literal (bypasses name-based policy);
 *   - the host must not be a private (RFC1918), loopback, link-local, or
 *     internal-only name (`localhost`, `*.internal`, `*.local`).
 *
 * RESIDUAL LIMITATION, DNS rebinding: a *public* hostname can still resolve to
 * a private IP at fetch time, and the Worker has no visibility into that
 * resolution, so these literal/name checks cannot catch it. This is inherent to
 * the Workers runtime. The compensating control is that the scanner never pulls
 * attacker page *content* itself, Exa (a sandboxed external fetcher) does, so
 * the blast radius of a rebind is limited to a redirect HEAD/GET against an
 * internal address with no response body surfaced to the client. Document, do
 * not pretend to fully solve.
 *
 * Config is read from the caller (`ScannerConfig`, see `worker/config.ts`); the
 * allowed-scheme set is never hardcoded here. Until `config.ts` lands this module
 * is typed against the structural {@link SsrfConfig} slice it needs, which the
 * full `ScannerConfig` satisfies.
 */

import { RedirectResolutionError } from '../errors'

/**
 * The slice of `ScannerConfig` the SSRF guard depends on. The full config object
 * (`worker/config.ts`) structurally satisfies this interface.
 */
export interface SsrfConfig {
  /**
   * Allowed URL schemes (lowercase, no trailing colon), e.g. `["https"]`.
   * A `ReadonlySet` so membership is O(1) and the set cannot be mutated through
   * this reference.
   */
  readonly allowedSchemes: ReadonlySet<string>
}

/** RFC1918 private ranges, expressed as first-octet (and second-octet) tests. */
const PRIVATE_10_OCTET = 10
const PRIVATE_172_OCTET = 172
const PRIVATE_172_SECOND_MIN = 16
const PRIVATE_172_SECOND_MAX = 31
const PRIVATE_192_FIRST_OCTET = 192
const PRIVATE_192_SECOND_OCTET = 168
const LOOPBACK_OCTET = 127
const LINK_LOCAL_FIRST_OCTET = 169
const LINK_LOCAL_SECOND_OCTET = 254
const IPV4_OCTET_COUNT = 4
const OCTET_MIN = 0
const OCTET_MAX = 255

/**
 * Hostnames that always resolve to the local or an internal-only namespace and
 * must never be fetched, regardless of resolution. Lowercase. A `Set` for O(1)
 * membership.
 */
const INTERNAL_EXACT_HOSTS: ReadonlySet<string> = new Set(['localhost'])

/**
 * Internal-only TLD suffixes. Any host ending in one of these is internal by
 * convention (`*.internal` for cloud VPCs, `*.local` for mDNS). Includes the
 * leading dot so a host equal to the bare suffix is not matched as a subdomain.
 */
const INTERNAL_SUFFIXES: readonly string[] = ['.internal', '.local']

/** A bare IPv4 dotted-quad, e.g. `192.168.0.1`. Anchored to the whole host. */
const IPV4_LITERAL = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/**
 * Assert that a URL is safe for the Worker to fetch. Throws on any violation;
 * returns nothing on success (the guard's value is the absence of an exception).
 *
 * Order of checks (cheapest, most categorical first):
 *   1. scheme allowlist (rejects http, ftp, file, gopher, data, …);
 *   2. raw IP literal rejection (an IP host bypasses name-based policy entirely);
 *   3. private / loopback / link-local / internal-name rejection.
 *
 * Time complexity: O(1), a fixed number of set lookups, a bounded regex on the
 *   host, and constant suffix comparisons. No scan over the URL length.
 * Space complexity: O(1).
 *
 * @param url - The fully-parsed candidate URL (origin or a redirect target).
 * @param config - The {@link SsrfConfig} slice (allowed schemes).
 * @throws {RedirectResolutionError} If the scheme is disallowed, the host is a
 *   raw IP literal, or the host is private/loopback/link-local/internal.
 */
export function assertSafeUrl(url: URL, config: SsrfConfig): void {
  // `URL.protocol` includes the trailing colon ("https:"); normalize to "https".
  const scheme = url.protocol.replace(/:$/, '').toLowerCase()
  if (!config.allowedSchemes.has(scheme)) {
    throw new RedirectResolutionError(
      `disallowed URL scheme '${scheme}' for ${url.href}`,
    )
  }

  // `URL.hostname` already strips the port and lowercases; for IPv6 it is the
  // bracketed-content form without brackets (e.g. "::1").
  const host = url.hostname.toLowerCase()

  if (isRawIpLiteral(host)) {
    throw new RedirectResolutionError(
      `raw IP literal host is not allowed: ${host}`,
    )
  }

  if (isPrivateOrLoopbackHost(host)) {
    throw new RedirectResolutionError(
      `private/loopback/link-local/internal host is not allowed: ${host}`,
    )
  }
}

/**
 * Report whether `host` is a raw IPv4 or IPv6 literal (as opposed to a DNS
 * name). Raw IP hosts are rejected outright because they sidestep every
 * name-based policy below.
 *
 * IPv4: a valid dotted-quad with each octet in 0..255.
 * IPv6: any host containing a colon. `URL.hostname` only yields a colon for an
 *   IPv6 address (it has already removed the surrounding brackets and the port),
 *   so a single colon test is sufficient and unambiguous for parsed URLs.
 *
 * Time complexity: O(1), bounded regex + constant comparisons. Space: O(1).
 *
 * @param host - Lowercase hostname from a parsed URL.
 * @returns `true` if the host is a raw IP literal.
 */
export function isRawIpLiteral(host: string): boolean {
  if (host.includes(':')) {
    // IPv6 literal (e.g. "::1", "fe80::1", "2001:db8::1"). For a parsed URL the
    // only source of a colon in hostname is an IPv6 address.
    return true
  }
  return parseIpv4Octets(host) !== null
}

/**
 * Report whether `host` is private (RFC1918), loopback, link-local, or an
 * internal-only name. Covers both IPv4 literals (by octet ranges) and DNS names
 * (`localhost`, `*.internal`, `*.local`) and the canonical IPv6 loopback/
 * link-local forms.
 *
 * IPv4 ranges rejected:
 *   - 10.0.0.0/8        (RFC1918)
 *   - 172.16.0.0/12     (RFC1918, second octet 16..31)
 *   - 192.168.0.0/16    (RFC1918)
 *   - 127.0.0.0/8       (loopback)
 *   - 169.254.0.0/16    (link-local)
 * IPv6 forms rejected: `::1` (loopback), `fe80::/10` link-local prefixes.
 * Names rejected: `localhost`, and any host ending in `.internal` / `.local`.
 *
 * Time complexity: O(1), constant octet/prefix/suffix comparisons. Space: O(1).
 *
 * @param host - Lowercase hostname from a parsed URL.
 * @returns `true` if the host is private/loopback/link-local/internal.
 */
export function isPrivateOrLoopbackHost(host: string): boolean {
  if (INTERNAL_EXACT_HOSTS.has(host)) {
    return true
  }
  for (const suffix of INTERNAL_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return true
    }
  }

  if (host.includes(':')) {
    return isPrivateIpv6(host)
  }

  const octets = parseIpv4Octets(host)
  if (octets !== null) {
    return isPrivateIpv4(octets)
  }

  return false
}

/**
 * Parse a host into four validated IPv4 octets, or `null` if it is not a
 * well-formed dotted-quad. Each octet must be 0..255 with no leading-zero
 * ambiguity beyond what `Number` tolerates; out-of-range values yield `null`.
 *
 * Time complexity: O(1), fixed-size match and four bounded conversions.
 * Space complexity: O(1) (a 4-element tuple).
 */
function parseIpv4Octets(
  host: string,
): readonly [number, number, number, number] | null {
  const match = IPV4_LITERAL.exec(host)
  if (match === null) {
    return null
  }
  const octets: number[] = []
  for (let i = 1; i <= IPV4_OCTET_COUNT; i += 1) {
    const part = match[i]
    if (part === undefined) {
      return null
    }
    const value = Number(part)
    if (
      !Number.isInteger(value) ||
      value < OCTET_MIN ||
      value > OCTET_MAX
    ) {
      return null
    }
    octets.push(value)
  }
  return [octets[0]!, octets[1]!, octets[2]!, octets[3]!]
}

/**
 * Decide whether a validated IPv4 octet tuple falls in a private/loopback/
 * link-local range.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function isPrivateIpv4(
  octets: readonly [number, number, number, number],
): boolean {
  const [first, second] = octets
  if (first === PRIVATE_10_OCTET) {
    return true
  }
  if (
    first === PRIVATE_172_OCTET &&
    second >= PRIVATE_172_SECOND_MIN &&
    second <= PRIVATE_172_SECOND_MAX
  ) {
    return true
  }
  if (first === PRIVATE_192_FIRST_OCTET && second === PRIVATE_192_SECOND_OCTET) {
    return true
  }
  if (first === LOOPBACK_OCTET) {
    return true
  }
  if (first === LINK_LOCAL_FIRST_OCTET && second === LINK_LOCAL_SECOND_OCTET) {
    return true
  }
  return false
}

/**
 * Decide whether an IPv6 literal host is loopback or link-local. Operates on
 * the bracket-free, lowercased form produced by `URL.hostname`.
 *
 * Recognizes:
 *   - `::1` loopback (and its uncompressed form `0:0:0:0:0:0:0:1`);
 *   - `fe80::/10` link-local, i.e. any address whose first hextet is in
 *     `fe80`..`febf`. We test the documented `fe8`/`fe9`/`fea`/`feb` prefixes,
 *     which exactly cover that /10 for the leading hextet.
 *
 * Time complexity: O(1), constant prefix/equality checks. Space: O(1).
 */
function isPrivateIpv6(host: string): boolean {
  if (host === '::1' || host === '0:0:0:0:0:0:0:1') {
    return true
  }
  return (
    host.startsWith('fe8') ||
    host.startsWith('fe9') ||
    host.startsWith('fea') ||
    host.startsWith('feb')
  )
}
