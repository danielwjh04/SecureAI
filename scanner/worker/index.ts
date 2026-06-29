/**
 * Cloudflare Worker entry point for the Skill Safety Scanner.
 *
 * One Worker serves the whole product (Static Assets unified model): `/api/scan`
 * and `/api/verify` are handled here; every other path is delegated to the
 * `ASSETS` binding, which serves the built SPA (with single-page-application
 * fallback for client routes). `run_worker_first: ["/api/*"]` in `wrangler.jsonc`
 * guarantees the API paths reach this handler rather than the asset server.
 *
 * Fail-closed at the boundary: `loadConfig` runs once per request and any
 * `ConfigError` (or other load fault) is returned as a 500, the Worker never
 * proceeds into a request path with an invalid configuration.
 */

import type { Env, ScannerConfig } from './config'
import { loadConfig } from './config'
import { handleScan } from './handlers/scan'
import { handleVerify } from './handlers/verify'

/** API route paths. Named, never inlined at the dispatch site. */
const ROUTE_SCAN = '/api/scan'
const ROUTE_VERIFY = '/api/verify'
const API_PREFIX = '/api/'

const METHOD_POST = 'POST'

const STATUS_NOT_FOUND = 404
const STATUS_METHOD_NOT_ALLOWED = 405
const STATUS_SERVER_ERROR = 500

/**
 * Route an API request to its handler. Both endpoints are POST-only; a wrong
 * method on a known route is a 405, an unknown `/api/*` path is a 404 (never
 * falls through to the SPA, which would mask a typo'd endpoint as a 200).
 *
 * Time complexity: O(1), constant path/method comparisons.
 * Space complexity: O(1).
 *
 * @returns The handler's response, or a JSON 404/405 for unmatched API paths.
 */
async function routeApi(
  pathname: string,
  request: Request,
  env: Env,
): Promise<Response> {
  // Config is loaded inside the API branch and wrapped fail-closed: a bad config
  // must never serve an API result, but it must not block static assets either.
  let config: ScannerConfig
  try {
    config = loadConfig(env)
  } catch (error: unknown) {
    const className =
      error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    console.warn(`[index] config load failed (${className}): ${message}`)
    return Response.json(
      { error: className, message },
      { status: STATUS_SERVER_ERROR },
    )
  }

  if (pathname === ROUTE_SCAN) {
    if (request.method !== METHOD_POST) {
      return methodNotAllowed()
    }
    return handleScan(request, env, config)
  }

  if (pathname === ROUTE_VERIFY) {
    if (request.method !== METHOD_POST) {
      return methodNotAllowed()
    }
    return handleVerify(request, env, config)
  }

  return Response.json({ error: 'NotFound' }, { status: STATUS_NOT_FOUND })
}

/** A 405 JSON response for a wrong method on a known route. */
function methodNotAllowed(): Response {
  return Response.json(
    { error: 'MethodNotAllowed' },
    { status: STATUS_METHOD_NOT_ALLOWED, headers: { Allow: METHOD_POST } },
  )
}

/**
 * The Worker fetch handler.
 *
 * `/api/*` paths are routed to {@link routeApi}; everything else is served by
 * the SPA asset binding. The asset server is reached only for non-API paths, so
 * a malformed API call can never be silently answered with `index.html`.
 *
 * Time complexity: O(1) routing plus the chosen handler's cost.
 * Space complexity: O(response size).
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    if (url.pathname.startsWith(API_PREFIX)) {
      return routeApi(url.pathname, request, env)
    }
    return env.ASSETS.fetch(request)
  },
} satisfies ExportedHandler<Env>
