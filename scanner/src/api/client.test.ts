// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, scanSkill, verifyProof } from './client'
import { API } from '../config'
import type { Proof, ScanRequest, ScanResult, VerifyResult } from './types'

function mockFetch(response: Partial<Response> & { ok: boolean }): void {
  vi.stubGlobal('fetch', vi.fn(async () => response as Response))
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('scanSkill', () => {
  it('returns the parsed JSON body on an ok response', async () => {
    const body = { verdict: 'BLOCK' } as unknown as ScanResult
    mockFetch({ ok: true, status: 200, json: async () => body })
    await expect(scanSkill({ content: 'x' })).resolves.toBe(body)
  })

  it('POSTs the request body to API.scan', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({}) as ScanResult,
    }) as Response)
    vi.stubGlobal('fetch', fetchMock)

    const req: ScanRequest = { sourceUrl: 'https://example.com/SKILL.md' }
    await scanSkill(req)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [path, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ]
    expect(path).toBe(API.scan)
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual(req)
  })

  it('throws ApiError with the status on a non-ok response', async () => {
    mockFetch({ ok: false, status: 422, json: async () => ({}) })
    await expect(scanSkill({ content: 'x' })).rejects.toMatchObject({
      name: 'ApiError',
      status: 422,
    })
  })

  it('throws ApiError(0) when the backend is unreachable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network down')
      }),
    )
    const caught = await scanSkill({ content: 'x' }).catch((e: unknown) => e)
    expect(caught).toBeInstanceOf(ApiError)
    expect((caught as ApiError).status).toBe(0)
  })
})

describe('verifyProof', () => {
  it('POSTs the proof envelope to API.verify and returns the result', async () => {
    const proof = { genesisHash: 'g', steps: [], headHash: 'g' } as unknown as Proof
    const result: VerifyResult = { status: 'CHAIN_OK', firstInvalidIndex: null }
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => result,
    }) as Response)
    vi.stubGlobal('fetch', fetchMock)

    await expect(verifyProof(proof)).resolves.toEqual(result)
    const [path, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ]
    expect(path).toBe(API.verify)
    expect(JSON.parse(init.body as string)).toEqual({ proof })
  })
})
