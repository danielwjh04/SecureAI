import { describe, expect, it, vi } from 'vitest'
import { parseScanResult, scanContent, scanUrl } from '../src/scanClient'
import { scanResult } from './helpers'

const OPTIONS = {
  apiBase: 'https://secureai.software',
  apiKey: 'test_key',
  timeoutMs: 100,
}

function response(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'content-type': 'application/json' },
  })
}

describe('scan client', () => {
  it('parses ALLOW responses', async () => {
    const fetchImpl = vi.fn(async () => response(scanResult()))
    const outcome = await scanUrl('https://example.com', { ...OPTIONS, fetchImpl })
    expect(outcome.ok).toBe(true)
    if (outcome.ok) expect(outcome.result.verdict).toBe('ALLOW')
  })

  it('normalizes REVIEW responses to the repo verdict', () => {
    const parsed = parseScanResult(scanResult({ verdict: 'REVIEW' as never }))
    expect(parsed?.verdict).toBe('HUMAN_APPROVAL_REQUIRED')
  })

  it('parses BLOCK responses', async () => {
    const fetchImpl = vi.fn(async () => response(scanResult({ verdict: 'BLOCK' })))
    const outcome = await scanContent('danger', { ...OPTIONS, fetchImpl })
    expect(outcome.ok).toBe(true)
    if (outcome.ok) expect(outcome.result.verdict).toBe('BLOCK')
  })

  it('fails closed when the API key is missing', async () => {
    const outcome = await scanContent('hello', { ...OPTIONS, apiKey: '' })
    expect(outcome).toMatchObject({ ok: false, reason: 'missing-key', failClosed: true })
  })

  it('fails closed on timeout', async () => {
    const fetchImpl = vi.fn(
      () =>
        new Promise<Response>((_resolve, reject) => {
          const error = new DOMException('aborted', 'AbortError')
          reject(error)
        }),
    )
    const outcome = await scanUrl('https://example.com', { ...OPTIONS, fetchImpl })
    expect(outcome).toMatchObject({ ok: false, reason: 'timeout', failClosed: true })
  })

  it('fails closed on non-2xx responses', async () => {
    const fetchImpl = vi.fn(async () => response({ message: 'nope' }, { status: 500 }))
    const outcome = await scanContent('hello', { ...OPTIONS, fetchImpl })
    expect(outcome).toMatchObject({ ok: false, reason: 'http', failClosed: true })
  })

  it('fails closed on malformed JSON shapes', async () => {
    const fetchImpl = vi.fn(async () => response({ verdict: 'ALLOW' }))
    const outcome = await scanContent('hello', { ...OPTIONS, fetchImpl })
    expect(outcome).toMatchObject({ ok: false, reason: 'parse', failClosed: true })
  })

  it('rejects unknown verdicts', () => {
    expect(parseScanResult(scanResult({ verdict: 'MAYBE' as never }))).toBeNull()
  })
})
