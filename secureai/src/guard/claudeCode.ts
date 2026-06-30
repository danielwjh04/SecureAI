/**
 * Claude Code PreToolUse guard, the inline interceptor that routes an agent's
 * tool calls through SecureAI before they run.
 *
 * The guard first normalizes the native hook payload into a capability-aware
 * action, then scans content indicators when URLs or download-execute patterns
 * are present. A missing URL is not treated as proof of safety.
 */

import type { ScanDeps } from '../scanner/runScan'
import type { GuardDecision, GuardPermissionDecision, Verdict } from '../schemas/contract'
import type { PreToolUsePayload } from '../schemas/validate'
import { parseSkill } from '../pipeline/parse'
import { runScan } from '../scanner/runScan'
import { log } from '../observability/logger'
import { escalate } from '../verdict'
import { evaluateGuardActionPolicy, normalizeGuardAction } from './actionPolicy'

// GuardPermissionDecision and GuardDecision are defined once in @secureai/contract
// so the server and SDK response shapes cannot drift.
export type { GuardDecision, GuardPermissionDecision } from '../schemas/contract'

/**
 * Map a scanner verdict to the corresponding hook permission decision.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function verdictToDecision(verdict: Verdict): GuardPermissionDecision {
  switch (verdict) {
    case 'ALLOW':
      return 'allow'
    case 'HUMAN_APPROVAL_REQUIRED':
      return 'ask'
    case 'BLOCK':
      return 'deny'
  }
}

/** Maximum number of finding details folded into a guard reason. */
const MAX_REASON_FINDINGS = 3

/**
 * Build a concise reason from deterministic findings and injection findings.
 *
 * Time complexity: O(f) in finding count. Space complexity: O(f).
 */
function buildReason(
  verdict: Verdict,
  findings: readonly { detail: string }[],
  injections: readonly { rationale: string; category: string }[],
): string {
  const details: string[] = []
  for (const finding of findings) {
    if (finding.detail.length > 0) {
      details.push(finding.detail)
    }
  }
  for (const injection of injections) {
    if (injection.rationale.length > 0) {
      details.push(`${injection.category}: ${injection.rationale}`)
    }
  }

  if (details.length === 0) {
    return verdict === 'ALLOW'
      ? 'no risk indicators in tool call'
      : `scanner verdict ${verdict} with no itemized findings`
  }
  return details.slice(0, MAX_REASON_FINDINGS).join('; ')
}

/**
 * Serialize a PreToolUse tool call into the text consumed by the scanner.
 *
 * Time complexity: O(n) in serialized size. Space complexity: O(n).
 */
function buildScannableContent(payload: PreToolUsePayload): string {
  return `${payload.tool_name}\n${JSON.stringify(payload.tool_input)}`
}

/**
 * Return true when the serialized tool call carries scanner content indicators.
 * Empty parse results are handled by capability policy, while parser faults
 * propagate so the caller can fail closed.
 *
 * Time complexity: O(n) in content length. Space complexity: O(u + e).
 */
function hasScannableIndicators(content: string, deps: ScanDeps): boolean {
  const result = parseSkill(content, deps.config)
  return result.urls.length > 0 || result.execPatterns.length > 0
}

/** The fail-closed decision returned on unexpected guard faults. */
const FAIL_CLOSED_DECISION: GuardDecision = {
  decision: 'deny',
  reason: 'SecureAI guard could not verify this tool call; blocked fail-closed',
  verdict: null,
}

/**
 * Evaluate a validated PreToolUse payload and return a hook permission decision.
 *
 * Pipeline:
 * 1. Serialize the tool call to scannable content.
 * 2. Normalize it into a capability-aware action.
 * 3. Evaluate deterministic guard policy.
 * 4. If no content indicators exist, let policy decide the result.
 * 5. Otherwise run the scanner and tighten its verdict with the policy verdict.
 * 6. Map every unexpected fault to a fail-closed deny.
 *
 * Time complexity: dominated by runScan when scanner content exists. Space
 * complexity: O(result size).
 */
export async function guardDecision(
  payload: PreToolUsePayload,
  deps: ScanDeps,
): Promise<GuardDecision> {
  const content = buildScannableContent(payload)

  try {
    const action = normalizeGuardAction(payload, deps.config)
    const actionPolicy = evaluateGuardActionPolicy(action, deps.config)

    if (!hasScannableIndicators(content, deps)) {
      if (actionPolicy.verdict === 'ALLOW') {
        return { decision: 'allow', reason: 'no scannable indicators', verdict: null }
      }
      return {
        decision: verdictToDecision(actionPolicy.verdict),
        reason: buildReason(actionPolicy.verdict, actionPolicy.findings, []),
        verdict: actionPolicy.verdict,
      }
    }

    const { result } = await runScan({ content }, deps)
    const verdict = escalate(actionPolicy.verdict, result.verdict)
    const decision = verdictToDecision(verdict)
    const reason = buildReason(
      verdict,
      [...actionPolicy.findings, ...result.findings],
      result.injections,
    )
    const proof = verdict === result.verdict ? result.proof : undefined

    return { decision, reason, verdict, proof }
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.error('guardDecision', 'failing closed', { errorClass: className })
    return FAIL_CLOSED_DECISION
  }
}
