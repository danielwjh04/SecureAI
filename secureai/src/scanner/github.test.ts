// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { SourceResolutionError } from '../errors'
import {
  parseGithubWebUrl,
  resolveGithubSkillUrl,
  type GithubTarget,
} from './github'

// These tests drive the GitHub source resolver with a MOCK fetch, so no real
// network or GitHub API is touched. They assert the two responsibilities the
// resolver owns: (1) parsing a GitHub *web* URL into a structured target (or
// `null` for shapes we must not rewrite), and (2) turning that target into the
// raw SKILL.md URL — via a deterministic blob rewrite (no API), a raw-first HEAD
// probe that resolves a root SKILL.md with zero API calls, or the repo/tree
// discovery API (only when the probe misses) with a reproducible shallowest-path choice.

const TIMEOUT_MS = 5000

/** A GitHub tree entry as the recursive trees API returns it (subset we read). */
interface TreeEntry {
  path: string
  type: 'blob' | 'tree'
}

/**
 * Build a mock `fetch` from a routing table of `url -> json | status`. A routed
 * entry returns its JSON with status 200 unless an explicit status is given; an
 * unrouted URL throws, surfacing accidental or unexpected requests (e.g. a blob
 * rewrite that wrongly hit the API).
 *
 * NOTE: this mock keys ONLY on the URL and discards `init`, so it cannot assert
 * the probe's method/redirect/headers — the dedicated security test below uses a
 * hand-rolled impl for that.
 */
function mockFetch(
  routes: Record<string, { json?: unknown; status?: number }>,
): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = []
  const impl = async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    calls.push(url)
    const route = routes[url]
    if (route === undefined) {
      throw new Error(`unexpected fetch for ${url}`)
    }
    const status = route.status ?? 200
    const body = route.json === undefined ? '' : JSON.stringify(route.json)
    return new Response(body, {
      status,
      headers: { 'content-type': 'application/json' },
    })
  }
  return { fetch: impl as unknown as typeof fetch, calls }
}

/** A fetch that fails the test if it is ever called (for the no-API blob path). */
const NEVER_FETCH: typeof fetch = (() => {
  throw new Error('resolver must not fetch for a blob URL')
}) as unknown as typeof fetch

const API = 'https://api.github.com/repos/netresearch/context7-skill'
const TREE_MAIN = `${API}/git/trees/main?recursive=1`
const RAW = 'https://raw.githubusercontent.com/netresearch/context7-skill'
// The raw-first HEAD probe URLs the resolver hits BEFORE any api.github.com call.
// A repo probes its root SKILL.md at the literal `HEAD` ref; a tree probes
// `<subdir>/SKILL.md` at the tree's ref. Routing these to 404 makes the resolver
// fall through to the API path the discovery tests below exercise.
const RAW_ROOT_PROBE = `${RAW}/HEAD/SKILL.md`
const RAW_SUBDIR_PROBE = `${RAW}/main/skills/SKILL.md`

describe('parseGithubWebUrl', () => {
  it('parses a bare repository root', () => {
    const target = parseGithubWebUrl(
      new URL('https://github.com/netresearch/context7-skill'),
    )
    expect(target).toEqual<GithubTarget>({
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    })
  })

  it('normalizes www. and strips a trailing .git', () => {
    const target = parseGithubWebUrl(
      new URL('https://www.github.com/netresearch/context7-skill.git'),
    )
    expect(target).toEqual<GithubTarget>({
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    })
  })

  it('parses a blob URL into a ref + path', () => {
    const target = parseGithubWebUrl(
      new URL(
        'https://github.com/netresearch/context7-skill/blob/main/skills/context7/SKILL.md',
      ),
    )
    expect(target).toEqual<GithubTarget>({
      kind: 'blob',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      path: 'skills/context7/SKILL.md',
    })
  })

  it('parses a tree URL into a ref + subdir', () => {
    const target = parseGithubWebUrl(
      new URL(
        'https://github.com/netresearch/context7-skill/tree/main/skills',
      ),
    )
    expect(target).toEqual<GithubTarget>({
      kind: 'tree',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      subdir: 'skills',
    })
  })

  it('returns null for a non-GitHub host', () => {
    expect(
      parseGithubWebUrl(new URL('https://gitlab.com/owner/repo')),
    ).toBeNull()
  })

  it('returns null for a non-skill GitHub path (issues)', () => {
    expect(
      parseGithubWebUrl(
        new URL('https://github.com/netresearch/context7-skill/issues/1'),
      ),
    ).toBeNull()
  })

  it('returns null for an owner-only URL', () => {
    expect(parseGithubWebUrl(new URL('https://github.com/netresearch'))).toBeNull()
  })
})

describe('resolveGithubSkillUrl — blob (no API call)', () => {
  // The blob branch returns before the raw-first probe runs (it is already a raw
  // URL), so NEVER_FETCH must stay: zero fetches, no probe.
  it('rewrites a blob URL straight to the raw host', async () => {
    const target: GithubTarget = {
      kind: 'blob',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      path: 'skills/context7/SKILL.md',
    }
    const url = await resolveGithubSkillUrl(target, NEVER_FETCH, TIMEOUT_MS)
    expect(url).toBe(`${RAW}/main/skills/context7/SKILL.md`)
  })
})

describe('resolveGithubSkillUrl — raw-first fast path (zero API)', () => {
  it('resolves a repo-root SKILL.md from the raw CDN with no api.github.com call', async () => {
    // Only the raw HEAD probe is routed; any api.github.com call would throw
    // (unrouted), proving the fast path never touches the rate-limited API.
    const { fetch, calls } = mockFetch({ [RAW_ROOT_PROBE]: { status: 200 } })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const url = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS)

    expect(url).toBe(`${RAW}/HEAD/SKILL.md`)
    expect(calls).toEqual([RAW_ROOT_PROBE])
  })

  it('resolves a tree subdir SKILL.md from the raw CDN with no api.github.com call', async () => {
    const { fetch, calls } = mockFetch({ [RAW_SUBDIR_PROBE]: { status: 200 } })
    const target: GithubTarget = {
      kind: 'tree',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      subdir: 'skills',
    }

    const url = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS)

    expect(url).toBe(`${RAW}/main/skills/SKILL.md`)
    expect(calls).toEqual([RAW_SUBDIR_PROBE])
  })

  it('probes with method HEAD, redirect:manual, and NO Authorization header', async () => {
    // mockFetch discards init, so a hand-rolled impl captures the probe's init to
    // LOCK the security contract: HEAD (no body), redirect:'manual' (a 3xx is a
    // miss, never followed off the pinned host), and header-free (a token is never
    // exposed to the unauthenticated raw CDN). Without this, a silent regression
    // to GET, to following redirects, or to leaking the token would pass.
    let probeMethod: string | undefined
    let probeRedirect: string | undefined
    let probeAuth: string | null = null
    const impl = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === RAW_ROOT_PROBE) {
        probeMethod = init?.method
        probeRedirect = init?.redirect
        probeAuth = new Headers(init?.headers).get('Authorization')
        return new Response(null, { status: 200 })
      }
      throw new Error(`unexpected fetch for ${url}`)
    }
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    // A token is supplied to prove it is NOT forwarded to the raw probe.
    await resolveGithubSkillUrl(
      target,
      impl as unknown as typeof fetch,
      TIMEOUT_MS,
      'ghp_secret',
    )

    expect(probeMethod).toBe('HEAD')
    expect(probeRedirect).toBe('manual')
    expect(probeAuth).toBeNull()
  })

  it('fails closed onto the API path when the raw probe throws', async () => {
    // A probe transport error/timeout must fall back to the API tree search — not
    // crash, not silently allow.
    const seen: string[] = []
    const impl = async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString()
      seen.push(url)
      if (url === RAW_ROOT_PROBE) {
        throw new Error('network down')
      }
      if (url === API) {
        return new Response(JSON.stringify({ default_branch: 'main' }), { status: 200 })
      }
      if (url === TREE_MAIN) {
        return new Response(
          JSON.stringify({ tree: [{ path: 'skills/context7/SKILL.md', type: 'blob' }] }),
          { status: 200 },
        )
      }
      throw new Error(`unexpected fetch for ${url}`)
    }
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const url = await resolveGithubSkillUrl(target, impl as unknown as typeof fetch, TIMEOUT_MS)

    expect(url).toBe(`${RAW}/main/skills/context7/SKILL.md`)
    expect(seen).toEqual([RAW_ROOT_PROBE, API, TREE_MAIN])
  })
})

describe('resolveGithubSkillUrl — repo root (default branch + tree)', () => {
  it('finds the SKILL.md via the default branch and tree API', async () => {
    const { fetch, calls } = mockFetch({
      [RAW_ROOT_PROBE]: { status: 404 },
      [API]: { json: { default_branch: 'main' } },
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'README.md', type: 'blob' },
            { path: 'skills/context7/SKILL.md', type: 'blob' },
            { path: 'skills', type: 'tree' },
          ] satisfies TreeEntry[],
          truncated: false,
        },
      },
    })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const url = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS)

    expect(url).toBe(`${RAW}/main/skills/context7/SKILL.md`)
    // Raw probe misses (404), then two discovery calls: repo meta, then the tree.
    expect(calls).toEqual([RAW_ROOT_PROBE, API, TREE_MAIN])
  })

  it('passes an optional token as a Bearer Authorization header', async () => {
    let seenAuth: string | null = null
    const impl = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === 'string' ? input : input.toString()
      const headers = new Headers(init?.headers)
      // Probe miss FIRST — before the catch-all tree branch below, which returns
      // 200 for any non-API URL and would otherwise read the probe as a hit and
      // skip the Bearer assertion entirely.
      if (url === RAW_ROOT_PROBE) {
        return new Response(null, { status: 404 })
      }
      if (url === API) {
        seenAuth = headers.get('Authorization')
        return new Response(JSON.stringify({ default_branch: 'main' }), {
          status: 200,
        })
      }
      return new Response(
        JSON.stringify({ tree: [{ path: 'SKILL.md', type: 'blob' }] }),
        { status: 200 },
      )
    }
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const url = await resolveGithubSkillUrl(
      target,
      impl as unknown as typeof fetch,
      TIMEOUT_MS,
      'ghp_secret',
    )

    expect(url).toBe(`${RAW}/main/SKILL.md`)
    expect(seenAuth).toBe('Bearer ghp_secret')
  })

  it('chooses the shallowest SKILL.md, breaking ties lexicographically', async () => {
    const { fetch } = mockFetch({
      [RAW_ROOT_PROBE]: { status: 404 },
      [API]: { json: { default_branch: 'main' } },
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'deep/nested/SKILL.md', type: 'blob' },
            { path: 'zeta/SKILL.md', type: 'blob' },
            { path: 'alpha/SKILL.md', type: 'blob' },
          ] satisfies TreeEntry[],
        },
      },
    })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const url = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS)

    // 'alpha/SKILL.md' and 'zeta/SKILL.md' are both depth 2; 'alpha' < 'zeta'.
    expect(url).toBe(`${RAW}/main/alpha/SKILL.md`)
  })

  it('throws an actionable "not a skill" SourceResolutionError when the repo has no SKILL.md', async () => {
    const { fetch } = mockFetch({
      [RAW_ROOT_PROBE]: { status: 404 },
      [API]: { json: { default_branch: 'main' } },
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'README.md', type: 'blob' },
            { path: 'src/index.ts', type: 'blob' },
          ] satisfies TreeEntry[],
        },
      },
    })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    const error = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS).then(
      () => null,
      (caught: unknown) => caught,
    )
    expect(error).toBeInstanceOf(SourceResolutionError)
    // Lock the user-facing 422 copy: it must explain SecureAI scans skill
    // manifests and what to do, so a non-skill repo (e.g. a plain project) gets a
    // clear message rather than a confusing one.
    expect((error as Error).message).toMatch(/SecureAI scans Agent Skill manifests/i)
    expect((error as Error).message).toMatch(/SKILL\.md/)
  })

  it('throws SourceResolutionError on a GitHub API error status', async () => {
    const { fetch } = mockFetch({ [RAW_ROOT_PROBE]: { status: 404 }, [API]: { status: 404 } })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    await expect(
      resolveGithubSkillUrl(target, fetch, TIMEOUT_MS),
    ).rejects.toBeInstanceOf(SourceResolutionError)
  })

  it('throws SourceResolutionError on a 403 rate-limit response', async () => {
    const { fetch } = mockFetch({ [RAW_ROOT_PROBE]: { status: 404 }, [API]: { status: 403 } })
    const target: GithubTarget = {
      kind: 'repo',
      owner: 'netresearch',
      repo: 'context7-skill',
    }

    await expect(
      resolveGithubSkillUrl(target, fetch, TIMEOUT_MS),
    ).rejects.toThrow(/rate limit/i)
  })
})

describe('resolveGithubSkillUrl — tree (scoped to a subdir)', () => {
  it('only considers SKILL.md under the requested subdir', async () => {
    const { fetch, calls } = mockFetch({
      [RAW_SUBDIR_PROBE]: { status: 404 },
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'other/SKILL.md', type: 'blob' },
            { path: 'skills/context7/SKILL.md', type: 'blob' },
          ] satisfies TreeEntry[],
        },
      },
    })
    const target: GithubTarget = {
      kind: 'tree',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      subdir: 'skills',
    }

    const url = await resolveGithubSkillUrl(target, fetch, TIMEOUT_MS)

    // Raw subdir probe misses, then the tree API (a tree URL carries its ref, so
    // no repo-meta call).
    expect(url).toBe(`${RAW}/main/skills/context7/SKILL.md`)
    expect(calls).toEqual([RAW_SUBDIR_PROBE, TREE_MAIN])
  })

  it('throws when no SKILL.md exists under the subdir', async () => {
    const { fetch } = mockFetch({
      [RAW_SUBDIR_PROBE]: { status: 404 },
      [TREE_MAIN]: {
        json: {
          tree: [
            { path: 'other/SKILL.md', type: 'blob' },
          ] satisfies TreeEntry[],
        },
      },
    })
    const target: GithubTarget = {
      kind: 'tree',
      owner: 'netresearch',
      repo: 'context7-skill',
      ref: 'main',
      subdir: 'skills',
    }

    await expect(
      resolveGithubSkillUrl(target, fetch, TIMEOUT_MS),
    ).rejects.toBeInstanceOf(SourceResolutionError)
  })
})
