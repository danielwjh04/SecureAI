import { describe, expect, it } from 'vitest'
import { loadConfig } from '../config/env'
import { RedirectResolutionError, SourceResolutionError } from '../errors'
import { fetchRemoteSourceText } from './sourceFetch'

function fetchFrom(responses: Map<string, Response>, calls: string[] = []): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input)
    calls.push(url)
    const response = responses.get(url)
    if (response === undefined) {
      return new Response('missing fixture', { status: 404 })
    }
    return response
  }) as typeof fetch
}

describe('fetchRemoteSourceText', () => {
  it('follows source redirects manually and returns the final URL as provenance', async () => {
    const calls: string[] = []
    const responses = new Map<string, Response>([
      [
        'https://example.com/start',
        new Response(null, { status: 302, headers: { location: '/SKILL.md' } }),
      ],
      ['https://example.com/SKILL.md', new Response('safe skill text', { status: 200 })],
    ])

    const result = await fetchRemoteSourceText('https://example.com/start', {
      config: loadConfig({ SCANNER_MAX_REDIRECT_HOPS: '2' }),
      fetchImpl: fetchFrom(responses, calls),
    })

    expect(calls).toEqual(['https://example.com/start', 'https://example.com/SKILL.md'])
    expect(result).toEqual({
      text: 'safe skill text',
      source: { kind: 'url', ref: 'https://example.com/SKILL.md' },
    })
  })

  it('rejects a source redirect to a raw private or metadata address before fetch', async () => {
    const calls: string[] = []
    const responses = new Map<string, Response>([
      [
        'https://example.com/start',
        new Response(null, {
          status: 302,
          headers: { location: 'https://169.254.169.254/latest/meta-data' },
        }),
      ],
    ])

    await expect(
      fetchRemoteSourceText('https://example.com/start', {
        config: loadConfig({}),
        fetchImpl: fetchFrom(responses, calls),
      }),
    ).rejects.toBeInstanceOf(RedirectResolutionError)
    expect(calls).toEqual(['https://example.com/start'])
  })

  it('fails closed when a source redirect chain exceeds the configured hop cap', async () => {
    const responses = new Map<string, Response>([
      [
        'https://example.com/start',
        new Response(null, { status: 302, headers: { location: '/one' } }),
      ],
      [
        'https://example.com/one',
        new Response(null, { status: 302, headers: { location: '/two' } }),
      ],
    ])

    await expect(
      fetchRemoteSourceText('https://example.com/start', {
        config: loadConfig({ SCANNER_MAX_REDIRECT_HOPS: '1' }),
        fetchImpl: fetchFrom(responses),
      }),
    ).rejects.toBeInstanceOf(SourceResolutionError)
  })
})
