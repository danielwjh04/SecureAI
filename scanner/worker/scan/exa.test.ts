// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import { ExaReputationClient } from './exa'
import { ReputationError } from '../errors'

// The reputation config slice the client needs; the full ScannerConfig
// structurally satisfies this, but the unit only needs these three fields.
const config = {
  exaMaxCharacters: 2000,
  exaMaxAgeHours: 0,
  exaLivecrawlTimeoutMs: 12000,
} as const

/** A factory returning a fake Exa SDK whose getContents resolves `response`. */
function factoryReturning(response: unknown) {
  return () => ({ getContents: vi.fn().mockResolvedValue(response) })
}

describe('ExaReputationClient', () => {
  it('rejects an empty API key at construction (fail loud)', () => {
    expect(() => new ExaReputationClient('', config)).toThrow(ReputationError)
  })

  it('returns [] for empty input without calling the SDK', async () => {
    const getContents = vi.fn()
    const client = new ExaReputationClient('k', config, () => ({ getContents }))
    expect(await client.assessFinalUrls([])).toEqual([])
    expect(getContents).not.toHaveBeenCalled()
  })

  it('maps a successful crawl to a clean, unflagged report (judge is the backstop)', async () => {
    const client = new ExaReputationClient(
      'k',
      config,
      factoryReturning({
        results: [
          {
            url: 'https://a.test',
            title: 'A',
            summary: 'no evidence of phishing or malware here',
            text: '',
          },
        ],
        statuses: [{ id: 'https://a.test', status: 'success' }],
      }),
    )
    const [r] = await client.assessFinalUrls(['https://a.test'])
    // The summary mentions "phishing"/"malware" (to say there are none); the old
    // lexical heuristic would have wrongly flagged this. It must be clean now.
    expect(r?.flagged).toBe(false)
    expect(r?.score).toBe('1.00')
    expect(r?.status).toBe('OK')
    expect(r?.summary).toContain('no evidence of phishing')
  })

  it('flags a crawl failure with the error tag (fail-closed signal)', async () => {
    const client = new ExaReputationClient(
      'k',
      config,
      factoryReturning({
        results: [],
        statuses: [
          { id: 'https://bad.test', status: 'error', error: { tag: 'CRAWL_TIMEOUT' } },
        ],
      }),
    )
    const [r] = await client.assessFinalUrls(['https://bad.test'])
    expect(r?.flagged).toBe(true)
    expect(r?.status).toBe('CRAWL_TIMEOUT')
    expect(r?.score).toBe('0.00')
  })

  it('flags a URL whose status is missing (no evidence of success)', async () => {
    const client = new ExaReputationClient(
      'k',
      config,
      factoryReturning({ results: [], statuses: [] }),
    )
    const [r] = await client.assessFinalUrls(['https://x.test'])
    expect(r?.flagged).toBe(true)
    expect(r?.status).toBe('CRAWL_FAILED')
  })

  it('aligns reports 1:1 with the input order regardless of result order', async () => {
    const client = new ExaReputationClient(
      'k',
      config,
      factoryReturning({
        results: [
          { url: 'https://b.test', summary: 's', title: 't' },
          { url: 'https://a.test', summary: 's', title: 't' },
        ],
        statuses: [
          { id: 'https://a.test', status: 'success' },
          { id: 'https://b.test', status: 'success' },
        ],
      }),
    )
    const reports = await client.assessFinalUrls(['https://a.test', 'https://b.test'])
    expect(reports.map((r) => r.url)).toEqual(['https://a.test', 'https://b.test'])
  })

  it('wraps an SDK throw in ReputationError (never a silent clean result)', async () => {
    const client = new ExaReputationClient('k', config, () => ({
      getContents: vi.fn().mockRejectedValue(new Error('network down')),
    }))
    await expect(
      client.assessFinalUrls(['https://a.test']),
    ).rejects.toBeInstanceOf(ReputationError)
  })
})
