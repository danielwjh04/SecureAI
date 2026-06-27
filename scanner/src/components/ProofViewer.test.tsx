import { fireEvent, render, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, vi } from 'vitest'
import type { Proof } from '../../shared/contract'
import { ProofBuilder } from '../../shared/proof'
import { deriveGenesisHash } from '../../shared/hash'
import { ProofViewer } from './ProofViewer'

/**
 * Build a small, genuinely valid proof using the exact same builder the Worker
 * uses, so its hashes are real and re-verifiable by the in-browser `verifyChain`
 * (no recorded fixtures, no hand-written hashes).
 */
async function buildProof(): Promise<Proof> {
  const genesis = await deriveGenesisHash('proof-viewer-test-seed')
  const builder = new ProofBuilder(genesis)
  await builder.append('SKILL_INPUT', { source: 'paste', length: 42 })
  await builder.append('URL_EXTRACTED', { url: 'https://example.test/a', count: 1 })
  await builder.append('VERDICT', { verdict: 'ALLOW', flagged: false })
  return builder.toProof()
}

/** Count rows currently marked broken via the AlertCard chain idiom. */
function brokenCount(container: HTMLElement): number {
  return container.querySelectorAll('.proof__mark--broken').length
}

/** The textarea for a given step index (its aria-label is stable). */
function editorFor(container: HTMLElement, index: number): HTMLTextAreaElement {
  const node = container.querySelector<HTMLTextAreaElement>(
    `textarea[aria-label="payload for step ${index}"]`,
  )
  if (node === null) {
    throw new Error(`no editor for step ${index}`)
  }
  return node
}

describe('ProofViewer', () => {
  let fetchSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    // Spy on fetch so the test can prove the re-verification is purely
    // in-browser: editing must NOT trigger any network round-trip. The spy is
    // asserted never-called, so its return value is irrelevant.
    fetchSpy = vi.fn(() => Promise.resolve(new Response()))
    vi.stubGlobal('fetch', fetchSpy)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('starts with every row intact and never calls fetch', async () => {
    const proof = await buildProof()
    const { container } = render(<ProofViewer proof={proof} />)

    // The pristine chain re-verifies clean: no row is marked broken.
    await waitFor(() => {
      expect(brokenCount(container)).toBe(0)
    })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('flips the edited row and every later row to broken — with no fetch', async () => {
    const proof = await buildProof()
    const { container } = render(<ProofViewer proof={proof} />)

    await waitFor(() => {
      expect(brokenCount(container)).toBe(0)
    })

    // Tamper step 1's payload. Re-hashing it changes its currHash, which breaks
    // step 1 and — because each link feeds the next — every downstream step.
    fireEvent.change(editorFor(container, 1), {
      target: { value: JSON.stringify({ url: 'https://evil.test/x', count: 99 }) },
    })

    // Steps 1 and 2 (the edited row and onward) go broken; step 0 stays intact.
    await waitFor(() => {
      expect(brokenCount(container)).toBe(2)
    })
    const marks = Array.from(
      container.querySelectorAll<HTMLElement>('.proof__mark'),
    )
    expect(marks[0].className).toContain('proof__mark--ok')
    expect(marks[1].className).toContain('proof__mark--broken')
    expect(marks[2].className).toContain('proof__mark--broken')

    // The whole interaction was client-side: the chain was re-hashed via Web
    // Crypto in the browser, with zero server round-trips.
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('restores every row to intact when "Reset proof" is clicked', async () => {
    const proof = await buildProof()
    const { container, getByRole } = render(<ProofViewer proof={proof} />)

    fireEvent.change(editorFor(container, 0), {
      target: { value: JSON.stringify({ source: 'url', length: 7 }) },
    })
    await waitFor(() => {
      expect(brokenCount(container)).toBeGreaterThan(0)
    })

    fireEvent.click(getByRole('button', { name: 'Reset proof' }))

    // Reset reloads the pristine proof, so the chain re-verifies clean again.
    await waitFor(() => {
      expect(brokenCount(container)).toBe(0)
    })
    // The editor is re-seeded with the original payload, not the tampered text.
    expect(editorFor(container, 0).value).toContain('paste')

    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
