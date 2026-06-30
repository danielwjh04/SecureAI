/**
 * Safe remote source fetching for scanner inputs. This is the single helper for
 * turning an untrusted `sourceUrl` into bounded text: parse, apply the SSRF
 * guard, resolve supported GitHub web URLs to raw content, re-check the resolved
 * URL, fetch with a timeout, and stream under the configured byte cap.
 */

import type { ScannerConfig } from '../config/env'
import type { ScanResult } from '../schemas/contract'
import { ParseError, SourceResolutionError } from '../errors'
import { assertSafeUrl } from '../pipeline/redirects'
import { parseGithubWebUrl, resolveGithubSkillUrl } from './github'

const REDIRECT_STATUS_MIN = 300
const REDIRECT_STATUS_MAX = 399

export interface RemoteSourceFetchOptions {
  readonly config: ScannerConfig
  readonly fetchImpl: typeof fetch
  readonly githubToken?: string
}

/**
 * Resolve and fetch a remote source URL safely.
 *
 * Time complexity: O(n) in the fetched body length plus bounded GitHub discovery
 * calls. Space complexity: O(n) up to the configured skill byte cap.
 *
 * @throws {ParseError} If the URL is malformed or the body exceeds the byte cap.
 * @throws {RedirectResolutionError} If a URL trips the SSRF guard.
 * @throws {SourceResolutionError} If the source cannot be resolved or fetched.
 */
export async function fetchRemoteSourceText(
  sourceUrl: string,
  options: RemoteSourceFetchOptions,
): Promise<{ text: string; source: ScanResult['source'] }> {
  const trimmed = sourceUrl.trim()
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch (error: unknown) {
    throw new ParseError(`sourceUrl is not a valid URL: ${trimmed}`, { cause: error })
  }

  const schemes = new Set(options.config.allowedSchemes)
  assertSafeUrl(parsed, { allowedSchemes: schemes })

  const githubTarget = parseGithubWebUrl(parsed)
  let fetchUrl = parsed
  if (githubTarget !== null) {
    const rawUrl = await resolveGithubSkillUrl(
      githubTarget,
      options.fetchImpl,
      options.config.redirectTimeoutMs,
      options.githubToken,
    )
    fetchUrl = new URL(rawUrl)
    assertSafeUrl(fetchUrl, { allowedSchemes: schemes })
  }

  const { response, finalUrl } = await fetchSourceResponse(fetchUrl, options, schemes)
  if (!response.ok) {
    throw new SourceResolutionError(
      `source URL returned HTTP ${response.status}: ${finalUrl.href}`,
    )
  }

  return {
    text: await readResponseTextCapped(response, options.config.skillMaxBytes),
    source: { kind: 'url', ref: finalUrl.href },
  }
}

async function fetchSourceResponse(
  startUrl: URL,
  options: RemoteSourceFetchOptions,
  schemes: ReadonlySet<string>,
): Promise<{ response: Response; finalUrl: URL }> {
  let currentUrl = new URL(startUrl.href)
  const seen = new Set<string>()

  for (let hop = 0; ; hop += 1) {
    assertSafeUrl(currentUrl, { allowedSchemes: schemes })
    if (seen.has(currentUrl.href)) {
      throw new SourceResolutionError(`source URL redirect loop detected: ${currentUrl.href}`)
    }
    seen.add(currentUrl.href)

    let response: Response
    try {
      response = await options.fetchImpl(currentUrl.href, {
        redirect: 'manual',
        signal: AbortSignal.timeout(options.config.redirectTimeoutMs),
      })
    } catch (error: unknown) {
      throw new SourceResolutionError(`source URL fetch failed: ${currentUrl.href}`, {
        cause: error,
      })
    }

    if (!isRedirectStatus(response.status)) {
      return { response, finalUrl: currentUrl }
    }

    if (hop >= options.config.maxRedirectHops) {
      throw new SourceResolutionError(
        `source URL exceeded redirect limit ${options.config.maxRedirectHops}: ${startUrl.href}`,
      )
    }

    const location = response.headers.get('location')
    if (location === null || location.trim().length === 0) {
      throw new SourceResolutionError(`source URL redirect missing Location: ${currentUrl.href}`)
    }
    currentUrl = new URL(location, currentUrl.href)
  }
}

function isRedirectStatus(status: number): boolean {
  return status >= REDIRECT_STATUS_MIN && status <= REDIRECT_STATUS_MAX
}

/**
 * Read a fetched source body with a hard byte cap.
 *
 * Time complexity: O(n) up to `maxBytes + 1`. Space complexity: O(n) up to
 * `maxBytes`.
 *
 * @throws {ParseError} If the response body exceeds the configured byte cap.
 */
export async function readResponseTextCapped(response: Response, maxBytes: number): Promise<string> {
  if (response.body === null) {
    return ''
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let bytesRead = 0
  let text = ''

  try {
    for (;;) {
      const chunk = await reader.read()
      if (chunk.done) {
        break
      }
      const value = chunk.value
      if (value === undefined) {
        continue
      }
      bytesRead += value.byteLength
      if (bytesRead > maxBytes) {
        await reader.cancel()
        throw new ParseError(`source body exceeds limit ${maxBytes}`)
      }
      text += decoder.decode(value, { stream: true })
    }
  } finally {
    reader.releaseLock()
  }

  text += decoder.decode()
  return text
}
