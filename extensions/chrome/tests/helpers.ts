import type { ScanResult } from '../src/types'

export function scanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    verdict: 'ALLOW',
    findings: [],
    chains: [],
    reputation: [],
    injections: [],
    proof: { genesisHash: 'genesis', headHash: 'head', steps: [] },
    scannedAt: '2026-06-29T00:00:00.000Z',
    source: { kind: 'url', ref: 'https://example.com' },
    ...overrides,
  }
}
