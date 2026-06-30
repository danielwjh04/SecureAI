import { describe, expect, it } from 'vitest'
import type { PreToolUsePayload } from '../schemas/validate'
import type { GuardDecisionTicket } from '../schemas/contract'
import {
  guardActionHash,
  signGuardDecisionTicket,
  verifyGuardDecisionTicket,
} from './decisionTicket'

const now = new Date('2026-06-30T00:00:00.000Z')
const context = {
  signer: { alg: 'HS256', kid: 'guard-ticket-test', secret: 'test-ticket-secret' } as const,
  verifiers: [{ alg: 'HS256', kid: 'guard-ticket-test', secret: 'test-ticket-secret' } as const],
  policyVersion: 'policy-1',
  trustRevision: 'trust-1',
  ttlSeconds: 300,
  now,
}

const payload = {
  hook_event_name: 'PreToolUse',
  tool_name: 'Read',
  tool_input: { file_path: 'README.md' },
  cwd: '/workspace/project',
  device_id: 'dev_test',
  integration_version: '1.0.0',
} as PreToolUsePayload

function requireTicket(ticket: GuardDecisionTicket | null): GuardDecisionTicket {
  expect(ticket).not.toBeNull()
  return ticket as GuardDecisionTicket
}

describe('Guard decision tickets', () => {
  it('signs and verifies an exact repeated allow action', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))

    expect(ticket.alg).toBe('HS256')
    expect(ticket.kid).toBe('guard-ticket-test')
    expect(ticket.action_hash).toBe(await guardActionHash(payload))
    expect(ticket.policy_version).toBe('policy-1')
    expect(ticket.trust_revision).toBe('trust-1')
    expect(ticket.device_id).toBe('dev_test')

    await expect(verifyGuardDecisionTicket(payload, ticket, context)).resolves.toEqual({
      ok: true,
      reason: 'ticket valid',
    })
  })

  it('rejects a ticket when the action changes', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))
    const changed = { ...payload, tool_input: { file_path: '.env' } } as PreToolUsePayload

    await expect(verifyGuardDecisionTicket(changed, ticket, context)).resolves.toEqual({
      ok: false,
      reason: 'action hash mismatch',
    })
  })

  it('rejects expired and revision-mismatched tickets', async () => {
    const ticket = requireTicket(await signGuardDecisionTicket(payload, 'allow', context))

    await expect(
      verifyGuardDecisionTicket(payload, ticket, { ...context, now: new Date('2026-06-30T00:06:00.000Z') }),
    ).resolves.toEqual({ ok: false, reason: 'ticket expired' })

    await expect(
      verifyGuardDecisionTicket(payload, ticket, { ...context, policyVersion: 'policy-2' }),
    ).resolves.toEqual({ ok: false, reason: 'policy version mismatch' })
  })
})
