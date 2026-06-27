// @vitest-environment node
import { describe, expect, it } from 'vitest'
import type { Proof, ProofStep } from './contract'
import { deriveGenesisHash } from './hash'
import { ProofBuilder, verifyChain } from './proof'

// Fixed seed and golden hashes. These hex values were computed independently
// (Python reference: sha256, sort_keys + compact separators) and pin the exact
// byte scheme: changing canonicalization, the concat order, or the hash
// algorithm breaks these. The Worker and the browser import the SAME proof
// module, so matching this once guarantees cross-runtime byte-parity.
const GOLDEN_SEED = 'securesg-scanner-genesis-v1'
const GOLDEN_GENESIS =
  'f0b050311cf99986fc1660fabca38a5c902a77a35bd0d98997fc88fe144e95af'
const GOLDEN_HEAD =
  'f60bf9f87c7e23495bc0175af56cdb5be069f52103d83554d11fa25630199c60'

/** Builds the canonical 3-step golden chain used across the tamper tests. */
async function buildGoldenProof(): Promise<Proof> {
  const genesis = await deriveGenesisHash(GOLDEN_SEED)
  const builder = new ProofBuilder(genesis)
  await builder.append('SKILL_INPUT', { length: 128, source: 'paste' })
  await builder.append('URL_EXTRACTED', {
    url: 'https://example.com/',
    ordinal: 1,
  })
  await builder.append('VERDICT', { verdict: 'ALLOW', ruleCount: 0 })
  return builder.toProof()
}

/** Deep-clones a proof so a tamper test never mutates a shared fixture. */
function cloneProof(proof: Proof): Proof {
  return {
    genesisHash: proof.genesisHash,
    headHash: proof.headHash,
    steps: proof.steps.map((step): ProofStep => ({
      ...step,
      payload: { ...step.payload },
    })),
  }
}

describe('deriveGenesisHash golden vector', () => {
  it('pins sha256(utf8(seed)) for the fixed seed', async () => {
    await expect(deriveGenesisHash(GOLDEN_SEED)).resolves.toBe(GOLDEN_GENESIS)
  })

  it('changes the genesis when the seed changes', async () => {
    await expect(deriveGenesisHash(`${GOLDEN_SEED}!`)).resolves.not.toBe(
      GOLDEN_GENESIS,
    )
  })
})

describe('ProofBuilder', () => {
  it('links the first step to the genesis hash', async () => {
    const genesis = await deriveGenesisHash(GOLDEN_SEED)
    const builder = new ProofBuilder(genesis)
    await builder.append('SKILL_INPUT', { length: 1 })
    expect(builder.steps[0]?.prevHash).toBe(genesis)
    expect(builder.steps[0]?.index).toBe(0)
  })

  it('chains each step to its predecessor and tracks the head in O(1)', async () => {
    const proof = await buildGoldenProof()
    expect(proof.steps).toHaveLength(3)
    expect(proof.steps[1]?.prevHash).toBe(proof.steps[0]?.currHash)
    expect(proof.steps[2]?.prevHash).toBe(proof.steps[1]?.currHash)
    expect(proof.headHash).toBe(proof.steps[2]?.currHash)
  })

  it('produces the committed golden head hash (byte-parity lock)', async () => {
    const proof = await buildGoldenProof()
    expect(proof.genesisHash).toBe(GOLDEN_GENESIS)
    expect(proof.headHash).toBe(GOLDEN_HEAD)
  })

  it('is deterministic: identical appends produce identical chains', async () => {
    const first = await buildGoldenProof()
    const second = await buildGoldenProof()
    expect(second.headHash).toBe(first.headHash)
    expect(second.steps.map((s) => s.currHash)).toEqual(
      first.steps.map((s) => s.currHash),
    )
  })

  it('refuses to snapshot an empty proof (fail loud)', async () => {
    const genesis = await deriveGenesisHash(GOLDEN_SEED)
    const builder = new ProofBuilder(genesis)
    expect(() => builder.toProof()).toThrow()
  })
})

describe('verifyChain', () => {
  it('accepts an intact chain', async () => {
    const proof = await buildGoldenProof()
    await expect(verifyChain(proof)).resolves.toEqual({
      ok: true,
      firstBrokenIndex: null,
    })
  })

  it('detects a tampered MIDDLE step payload at that index', async () => {
    const proof = cloneProof(await buildGoldenProof())
    proof.steps[1]!.payload.url = 'https://evil.example/'
    await expect(verifyChain(proof)).resolves.toEqual({
      ok: false,
      firstBrokenIndex: 1,
    })
  })

  it('detects a tampered FIRST step at index 0', async () => {
    const proof = cloneProof(await buildGoldenProof())
    proof.steps[0]!.payload.length = 999
    await expect(verifyChain(proof)).resolves.toEqual({
      ok: false,
      firstBrokenIndex: 0,
    })
  })

  it('detects a tampered LAST step at the last index', async () => {
    const proof = cloneProof(await buildGoldenProof())
    proof.steps[2]!.payload.verdict = 'BLOCK'
    await expect(verifyChain(proof)).resolves.toEqual({
      ok: false,
      firstBrokenIndex: 2,
    })
  })

  it('detects a directly tampered currHash at that index', async () => {
    const proof = cloneProof(await buildGoldenProof())
    proof.steps[1]!.currHash = '0'.repeat(64)
    await expect(verifyChain(proof)).resolves.toEqual({
      ok: false,
      firstBrokenIndex: 1,
    })
  })

  it('detects tampered prevHash linkage at that index', async () => {
    const proof = cloneProof(await buildGoldenProof())
    proof.steps[2]!.prevHash = '0'.repeat(64)
    await expect(verifyChain(proof)).resolves.toEqual({
      ok: false,
      firstBrokenIndex: 2,
    })
  })

  it('detects a tampered genesis hash at index 0', async () => {
    const proof = cloneProof(await buildGoldenProof())
    proof.genesisHash = '0'.repeat(64)
    await expect(verifyChain(proof)).resolves.toEqual({
      ok: false,
      firstBrokenIndex: 0,
    })
  })
})
