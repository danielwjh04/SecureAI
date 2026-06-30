/**
 * Short-lived signed Guard decision tickets. A ticket authorizes one exact
 * repeated action under a policy revision and trust revision. It is not a
 * replacement for authentication: the route still authenticates and meters the
 * caller before accepting a ticket.
 */

import type { GuardPermissionDecision } from '../schemas/contract'
import type { PreToolUsePayload } from '../schemas/validate'
import { canonicalJson } from '../audit/chain'

const HMAC_ALGORITHM = 'HMAC'
const ECDSA_ALGORITHM = 'ECDSA'
const HASH_ALGORITHM = 'SHA-256'
const ECDSA_NAMED_CURVE = 'P-256'
const textEncoder = new TextEncoder()

export type GuardTicketAlgorithm = 'HS256' | 'ES256'

export interface GuardDecisionTicket {
  readonly alg: GuardTicketAlgorithm
  readonly kid: string
  readonly action_hash: string
  readonly scope: string
  readonly decision: GuardPermissionDecision
  readonly policy_version: string
  readonly trust_revision: string
  readonly expires_at: string
  readonly signature: string
  device_id?: string
  integration_version?: string
}

export type GuardTicketSigner =
  | {
      readonly alg: 'HS256'
      readonly kid: string
      readonly secret: string
    }
  | {
      readonly alg: 'ES256'
      readonly kid: string
      readonly privateJwk: JsonWebKey
    }

export type GuardTicketVerifier =
  | {
      readonly alg: 'HS256'
      readonly kid: string
      readonly secret: string
    }
  | {
      readonly alg: 'ES256'
      readonly kid: string
      readonly publicJwk: JsonWebKey
    }

export interface GuardTicketContext {
  readonly signer: GuardTicketSigner
  readonly verifiers: readonly GuardTicketVerifier[]
  readonly policyVersion: string
  readonly trustRevision: string
  readonly ttlSeconds: number
  readonly now: Date
}

export interface GuardTicketVerification {
  readonly ok: boolean
  readonly reason: string
}

/**
 * Parse an unknown value into a structurally valid ticket, or `null`.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function parseGuardDecisionTicket(value: unknown): GuardDecisionTicket | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null
  }
  const record = value as Record<string, unknown>
  if (
    !(record.alg === 'HS256' || record.alg === 'ES256') ||
    typeof record.kid !== 'string' ||
    record.kid.length === 0 ||
    typeof record.action_hash !== 'string' ||
    typeof record.scope !== 'string' ||
    !(record.decision === 'allow' || record.decision === 'ask' || record.decision === 'deny') ||
    typeof record.policy_version !== 'string' ||
    typeof record.trust_revision !== 'string' ||
    typeof record.expires_at !== 'string' ||
    typeof record.signature !== 'string'
  ) {
    return null
  }
  const ticket: GuardDecisionTicket = {
    alg: record.alg,
    kid: record.kid,
    action_hash: record.action_hash,
    scope: record.scope,
    decision: record.decision,
    policy_version: record.policy_version,
    trust_revision: record.trust_revision,
    expires_at: record.expires_at,
    signature: record.signature,
  }
  if (typeof record.device_id === 'string' && record.device_id.length > 0) {
    ticket.device_id = record.device_id
  }
  if (typeof record.integration_version === 'string' && record.integration_version.length > 0) {
    ticket.integration_version = record.integration_version
  }
  return ticket
}

/**
 * Build the exact action hash a ticket is bound to.
 *
 * Time complexity: O(n) in the canonical payload length. Space complexity: O(n).
 */
export async function guardActionHash(payload: PreToolUsePayload): Promise<string> {
  const record = payload as unknown as Record<string, unknown>
  return sha256Hex(canonicalJson({
    tool_name: payload.tool_name,
    tool_input: payload.tool_input,
    cwd: stringOrNull(payload.cwd),
    device_id: stringOrNull(record.device_id),
    integration_version: stringOrNull(record.integration_version),
    content_hash: stringOrNull(record.content_hash),
  }))
}

/**
 * Sign one ticket for a computed Guard decision.
 *
 * Time complexity: O(n) in canonical ticket size. Space complexity: O(n).
 */
export async function signGuardDecisionTicket(
  payload: PreToolUsePayload,
  decision: GuardPermissionDecision,
  context: GuardTicketContext,
): Promise<GuardDecisionTicket | null> {
  if (context.ttlSeconds <= 0 || context.signer.kid.length === 0) {
    return null
  }
  if (context.signer.alg === 'HS256' && context.signer.secret.length === 0) {
    return null
  }
  const scope = stringOrNull(payload.cwd)
  if (scope === null) {
    return null
  }
  const expiresAt = new Date(context.now.getTime() + context.ttlSeconds * 1000).toISOString()
  const ticket = unsignedTicket(
    payload,
    decision,
    context,
    expiresAt,
    await guardActionHash(payload),
    context.signer.alg,
    context.signer.kid,
    scope,
  )
  return { ...ticket, signature: await signatureFor(ticket, context.signer) }
}

/**
 * Verify a presented Guard ticket against the current payload and revisions.
 *
 * Time complexity: O(n) in canonical ticket size. Space complexity: O(n).
 */
export async function verifyGuardDecisionTicket(
  payload: PreToolUsePayload,
  ticket: GuardDecisionTicket,
  context: GuardTicketContext,
): Promise<GuardTicketVerification> {
  const scope = stringOrNull(payload.cwd)
  if (scope === null) {
    return { ok: false, reason: 'missing project scope' }
  }
  const expiresMs = Date.parse(ticket.expires_at)
  if (!Number.isFinite(expiresMs) || expiresMs <= context.now.getTime()) {
    return { ok: false, reason: 'ticket expired' }
  }
  if (ticket.policy_version !== context.policyVersion) {
    return { ok: false, reason: 'policy version mismatch' }
  }
  if (ticket.trust_revision !== context.trustRevision) {
    return { ok: false, reason: 'trust revision mismatch' }
  }
  const verifier = context.verifiers.find(
    (candidate) => candidate.alg === ticket.alg && candidate.kid === ticket.kid,
  )
  if (verifier === undefined) {
    return { ok: false, reason: 'ticket key mismatch' }
  }
  if (verifier.alg === 'HS256' && verifier.secret.length === 0) {
    return { ok: false, reason: 'missing ticket secret' }
  }
  const expectedHash = await guardActionHash(payload)
  if (ticket.action_hash !== expectedHash) {
    return { ok: false, reason: 'action hash mismatch' }
  }
  const expected = unsignedTicket(
    payload,
    ticket.decision,
    context,
    ticket.expires_at,
    expectedHash,
    ticket.alg,
    ticket.kid,
    scope,
  )
  if (!(await verifySignature(expected, ticket.signature, verifier))) {
    return { ok: false, reason: 'signature mismatch' }
  }
  return { ok: true, reason: 'ticket valid' }
}

function unsignedTicket(
  payload: PreToolUsePayload,
  decision: GuardPermissionDecision,
  context: GuardTicketContext,
  expiresAt: string,
  actionHash: string,
  alg: GuardTicketAlgorithm,
  kid: string,
  scope: string,
): Omit<GuardDecisionTicket, 'signature'> {
  const record = payload as unknown as Record<string, unknown>
  const ticket: Omit<GuardDecisionTicket, 'signature'> = {
    alg,
    kid,
    action_hash: actionHash,
    scope,
    decision,
    policy_version: context.policyVersion,
    trust_revision: context.trustRevision,
    expires_at: expiresAt,
  }
  const deviceId = stringOrNull(record.device_id)
  if (deviceId !== null) {
    ticket.device_id = deviceId
  }
  const integrationVersion = stringOrNull(record.integration_version)
  if (integrationVersion !== null) {
    ticket.integration_version = integrationVersion
  }
  return ticket
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

async function signatureFor(
  ticket: Omit<GuardDecisionTicket, 'signature'>,
  signer: GuardTicketSigner,
): Promise<string> {
  const bytes = textEncoder.encode(canonicalJson(ticket))
  if (signer.alg === 'HS256') {
    const key = await crypto.subtle.importKey(
      'raw',
      textEncoder.encode(signer.secret),
      { name: HMAC_ALGORITHM, hash: HASH_ALGORITHM },
      false,
      ['sign'],
    )
    const signature = await crypto.subtle.sign(HMAC_ALGORITHM, key, bytes)
    return hexEncode(new Uint8Array(signature))
  }

  const key = await crypto.subtle.importKey(
    'jwk',
    signer.privateJwk,
    { name: ECDSA_ALGORITHM, namedCurve: ECDSA_NAMED_CURVE },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign(
    { name: ECDSA_ALGORITHM, hash: HASH_ALGORITHM },
    key,
    bytes,
  )
  return hexEncode(new Uint8Array(signature))
}

async function verifySignature(
  ticket: Omit<GuardDecisionTicket, 'signature'>,
  signatureHex: string,
  verifier: GuardTicketVerifier,
): Promise<boolean> {
  const bytes = textEncoder.encode(canonicalJson(ticket))
  if (verifier.alg === 'HS256') {
    const signature = await signatureFor(ticket, verifier)
    return constantTimeEqual(signatureHex, signature)
  }

  const signature = hexDecode(signatureHex)
  if (signature === null) {
    return false
  }
  const key = await crypto.subtle.importKey(
    'jwk',
    verifier.publicJwk,
    { name: ECDSA_ALGORITHM, namedCurve: ECDSA_NAMED_CURVE },
    false,
    ['verify'],
  )
  return crypto.subtle.verify(
    { name: ECDSA_ALGORITHM, hash: HASH_ALGORITHM },
    key,
    signature,
    bytes,
  )
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(HASH_ALGORITHM, textEncoder.encode(value))
  return hexEncode(new Uint8Array(digest))
}

function hexEncode(bytes: Uint8Array): string {
  let hex = ''
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

function hexDecode(value: string): Uint8Array | null {
  if (value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
    return null
  }
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < value.length; index += 2) {
    bytes[index / 2] = Number.parseInt(value.slice(index, index + 2), 16)
  }
  return bytes
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) {
    return false
  }
  let diff = 0
  for (let index = 0; index < left.length; index += 1) {
    diff |= left.charCodeAt(index) ^ right.charCodeAt(index)
  }
  return diff === 0
}
