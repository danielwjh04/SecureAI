import { describe, expect, it } from 'vitest'
import { buildDnrPlan, candidatesFromScan, ruleIdForDestination } from '../src/dnr'
import type { DnrRuleMetadata } from '../src/types'
import { scanResult } from './helpers'

describe('DNR rule builder', () => {
  it('creates an exact URL block rule for a flagged destination', () => {
    const result = scanResult({
      verdict: 'BLOCK',
      reputation: [
        {
          url: 'https://evil.example/payload.js#frag',
          score: '1.0',
          summary: 'known bad',
          title: 'Known bad',
          flagged: true,
          status: 'listed',
        },
      ],
    })
    const plan = buildDnrPlan(result, [], 10, 10)
    expect(plan.addRules).toHaveLength(1)
    expect(plan.addRules[0]?.condition.urlFilter).toBe('|https://evil.example/payload.js|')
  })

  it('creates a host-level block rule for a malicious host finding', () => {
    const result = scanResult({
      verdict: 'BLOCK',
      findings: [
        {
          ruleId: 'destination.host_malicious',
          severity: 'BLOCK',
          detail: 'known-bad host: evil.example',
        },
      ],
    })
    const plan = buildDnrPlan(result, [], 10, 10)
    expect(plan.addRules[0]?.condition.urlFilter).toBe('||evil.example^')
  })

  it('can create a rule for REVIEW destination risk', () => {
    const result = scanResult({
      verdict: 'HUMAN_APPROVAL_REQUIRED',
      findings: [
        {
          ruleId: 'destination.review',
          severity: 'HUMAN_APPROVAL_REQUIRED',
          detail: 'destination risk at https://review.example/install.sh',
        },
      ],
    })
    expect(buildDnrPlan(result, [], 10, 10).addRules).toHaveLength(1)
  })

  it('does not create a DNR rule for prompt-injection-only findings', () => {
    const result = scanResult({
      verdict: 'BLOCK',
      injections: [
        {
          excerpt: 'ignore previous instructions',
          category: 'prompt-injection',
          severity: 'BLOCK',
          rationale: 'subverts the user',
        },
      ],
    })
    expect(candidatesFromScan(result)).toHaveLength(0)
  })

  it('does not create rules for ALLOW results', () => {
    const result = scanResult({
      verdict: 'ALLOW',
      reputation: [
        {
          url: 'https://example.com',
          score: '0',
          summary: 'clean',
          title: 'Clean',
          flagged: true,
          status: 'listed',
        },
      ],
    })
    expect(buildDnrPlan(result, [], 10, 10).addRules).toHaveLength(0)
  })

  it('uses deterministic rule ids', () => {
    expect(ruleIdForDestination('host', 'evil.example')).toBe(ruleIdForDestination('host', 'evil.example'))
  })

  it('keeps existing rules idempotent', () => {
    const id = ruleIdForDestination('host', 'evil.example')
    const existing: DnrRuleMetadata[] = [
      {
        id,
        destination: 'evil.example',
        filter: '||evil.example^',
        kind: 'host',
        createdAt: 1,
        lastSeenAt: 1,
      },
    ]
    const result = scanResult({
      verdict: 'BLOCK',
      findings: [{ ruleId: 'destination.host', severity: 'BLOCK', detail: 'host: evil.example' }],
    })
    const plan = buildDnrPlan(result, existing, 20, 10)
    expect(plan.addRules).toHaveLength(0)
    expect(plan.metadata[0]?.createdAt).toBe(1)
    expect(plan.metadata[0]?.lastSeenAt).toBe(20)
  })

  it('evicts least-recent rules before adding new ones', () => {
    const oldId = ruleIdForDestination('host', 'old.example')
    const newerId = ruleIdForDestination('host', 'newer.example')
    const existing: DnrRuleMetadata[] = [
      { id: oldId, destination: 'old.example', filter: '||old.example^', kind: 'host', createdAt: 1, lastSeenAt: 1 },
      {
        id: newerId,
        destination: 'newer.example',
        filter: '||newer.example^',
        kind: 'host',
        createdAt: 2,
        lastSeenAt: 2,
      },
    ]
    const result = scanResult({
      verdict: 'BLOCK',
      findings: [{ ruleId: 'destination.host', severity: 'BLOCK', detail: 'host: fresh.example' }],
    })
    const plan = buildDnrPlan(result, existing, 30, 2)
    expect(plan.removeRuleIds).toEqual([oldId])
    expect(plan.metadata).toHaveLength(2)
  })
})
