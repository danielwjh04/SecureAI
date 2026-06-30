/**
 * Short-lived signed Guard decision tickets. A ticket authorizes one exact
 * repeated action under a policy revision and trust revision. It is not a
 * replacement for authentication: the route still authenticates and meters the
 * caller before accepting a ticket.
 */

import type { GuardDecisionTicket, GuardPermissionDecision } from '../schemas/contract'
import type { PreToolUsePayload } from '../schemas/validate'
import { canonicalJson } from '../audit/chain'

const SIGNATURE_ALGORITHM = 'HMAC'
const HASH_ALGORITHM = 'SHA-256'
const textEncoder = new TextEncoder()

export interface GuardTicketContext {
  readonly secret: string
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
  if (context.ttlSeconds <= 0 || context.secret.length === 0) {
    return null
  }
  const expiresAt = new Date(context.now.getTime() + context.ttlSeconds * 1000).toISOString()
  const ticket = unsignedTicket(payload, decision, context, expiresAt, await guardActionHash(payload))
  return { ...ticket, signature: await signatureFor(ticket, context.secret) }
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
  if (context.secret.length === 0) {
    return { ok: false, reason: 'missing ticket secret' }
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
  const expectedHash = await guardActionHash(payload)
  if (ticket.action_hash !== expectedHash) {
    return { ok: false, reason: 'action hash mismatch' }
  }
  const expected = unsignedTicket(payload, ticket.decision, context, ticket.expires_at, expectedHash)
  const signature = await signatureFor(expected, context.secret)
  if (!constantTimeEqual(ticket.signature, signature)) {
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
): Omit<GuardDecisionTicket, 'signature'> {
  const record = payload as unknown as Record<string, unknown>
  const ticket: Omit<GuardDecisionTicket, 'signature'> = {
    action_hash: actionHash,
    scope: stringOrNull(payload.cwd) ?? 'project:unknown',
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
  secret: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: SIGNATURE_ALGORITHM, hash: HASH_ALGORITHM },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign(
    SIGNATURE_ALGORITHM,
    key,
    textEncoder.encode(canonicalJson(ticket)),
  )
  return hexEncode(new Uint8Array(signature))
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
