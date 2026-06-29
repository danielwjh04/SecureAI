/**
 * `POST /api/verify` handler.
 *
 * Re-verifies a submitted proof chain server-side. This is a *pure recompute*:
 * it issues zero subrequests and reaches no sponsor API. The same `verifyChain`
 * runs in the browser, so this endpoint exists to let any third party confirm a
 * proof against the server without trusting the client's own re-verification.
 *
 * `verifyChain` walks from `proof.genesisHash` (carried in the proof) per
 * `shared/proof.ts`. We additionally derive the genesis hash from the
 * configured seed and reject any proof whose embedded genesis does not match it,
 * so a proof minted under a different (or forged) seed cannot pass as ours
 * fail-closed against a swapped genesis.
 */

import type { Proof, VerifyResult } from '../../shared/contract'
import type { Env, ScannerConfig } from '../config'
import { deriveGenesisHash } from '../../shared/hash'
import { verifyChain } from '../../shared/proof'
import { ParseError } from '../errors'

const STATUS_OK = 200
const STATUS_BAD_REQUEST = 400
const STATUS_UNPROCESSABLE = 422

/**
 * Shape-check the request body into a {@link Proof}. Only structural validation
 * is done here; the cryptographic check is `verifyChain`. A body that is not a
 * JSON object carrying a `proof` with the three chain fields is a `ParseError`.
 *
 * Time complexity: O(b) in the body byte length. Space complexity: O(b).
 *
 * @throws {ParseError} If the body is not JSON or lacks a well-shaped proof.
 */
async function parseVerifyBody(request: Request): Promise<Proof> {
  let raw: unknown
  try {
    raw = await request.json()
  } catch (error: unknown) {
    throw new ParseError('request body is not valid JSON', { cause: error })
  }
  if (typeof raw !== 'object' || raw === null) {
    throw new ParseError('request body must be a JSON object')
  }
  const proof = (raw as Record<string, unknown>).proof
  if (typeof proof !== 'object' || proof === null) {
    throw new ParseError('request body must include a "proof" object')
  }
  const candidate = proof as Record<string, unknown>
  if (
    typeof candidate.genesisHash !== 'string' ||
    typeof candidate.headHash !== 'string' ||
    !Array.isArray(candidate.steps)
  ) {
    throw new ParseError(
      'proof must have string genesisHash, string headHash, and a steps array',
    )
  }
  return proof as Proof
}

/**
 * Handle `POST /api/verify`.
 *
 * Returns `{ status, firstInvalidIndex }`: `CHAIN_OK` with `null` when intact,
 * `CHAIN_BROKEN` with the first invalid step index otherwise. A proof whose
 * embedded genesis does not match the configured seed's genesis is reported as
 * `CHAIN_BROKEN` at index 0 (the earliest possible break) rather than silently
 * verifying under an attacker-chosen genesis.
 *
 * Time complexity: O(n) in the step count (one digest per step, no rescans).
 * Space complexity: O(1) beyond the proof.
 *
 * @param request - The inbound HTTP request.
 * @param _env - The Worker environment (unused; verify needs no bindings).
 * @param config - The validated scanner configuration (supplies the seed).
 * @returns The JSON {@link VerifyResult}, or a JSON error with a mapped status.
 */
export async function handleVerify(
  request: Request,
  _env: Env,
  config: ScannerConfig,
): Promise<Response> {
  try {
    const proof = await parseVerifyBody(request)

    const expectedGenesis = await deriveGenesisHash(config.genesisSeed)
    if (proof.genesisHash !== expectedGenesis) {
      const result: VerifyResult = {
        status: 'CHAIN_BROKEN',
        firstInvalidIndex: 0,
      }
      return Response.json(result, { status: STATUS_OK })
    }

    const verification = await verifyChain(proof)
    const result: VerifyResult = {
      status: verification.ok ? 'CHAIN_OK' : 'CHAIN_BROKEN',
      firstInvalidIndex: verification.firstBrokenIndex,
    }
    return Response.json(result, { status: STATUS_OK })
  } catch (error: unknown) {
    const className =
      error instanceof Error ? error.constructor.name : typeof error
    const message = error instanceof Error ? error.message : String(error)
    console.warn(`[handleVerify] ${className}: ${message}`)
    const status =
      error instanceof ParseError ? STATUS_UNPROCESSABLE : STATUS_BAD_REQUEST
    return Response.json({ error: className, message }, { status })
  }
}
