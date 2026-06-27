/**
 * Verdict severity ordering and the two safety-critical verdict operations:
 * `escalate` (tighten-only) and `mapProbabilityToVerdict` (threshold bands).
 *
 * Port of `secureSG/guard/screening.py` (`_SEVERITY`, `escalate`,
 * `map_probability_to_verdict`). The core safety invariant — the SP3 design —
 * is that a model or any later stage may only ever *raise* severity, never lower
 * it. Every place that folds a candidate verdict into a running baseline does so
 * through `escalate`, so the chain of decisions is monotonic toward caution.
 *
 * `Verdict` is re-exported from the shared contract so worker modules import the
 * type and these operations from a single place.
 */

import type { Verdict } from '../../shared/contract'

export type { Verdict }

/**
 * Severity ranking of the three verdicts: ALLOW < HUMAN_APPROVAL_REQUIRED <
 * BLOCK. Mirrors `_SEVERITY` in `screening.py`. The map is the only place the
 * ordinal is defined; comparisons elsewhere read through it.
 */
const SEVERITY: Record<Verdict, number> = {
  ALLOW: 0,
  HUMAN_APPROVAL_REQUIRED: 1,
  BLOCK: 2,
}

/**
 * Return the more severe of two verdicts; ties keep `baseline`.
 *
 * This is the tighten-only gate (port of `escalate` in `screening.py`): a
 * `candidate` verdict — from a deterministic rule, Exa reputation, or the OpenAI
 * judge — may raise the running `baseline` but can never weaken it. An
 * equal-severity candidate keeps the baseline so a precise earlier finding is
 * not displaced by a coincident one.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @param baseline - The verdict computed so far (the floor that holds on ties).
 * @param candidate - The verdict a later stage proposes.
 * @returns `candidate` when strictly more severe than `baseline`, else `baseline`.
 */
export function escalate(baseline: Verdict, candidate: Verdict): Verdict {
  return SEVERITY[candidate] > SEVERITY[baseline] ? candidate : baseline
}

/**
 * Map an injection probability to a verdict by threshold band.
 *
 * Mirrors `map_probability_to_verdict` in `screening.py`: at or above `block`
 * the content is blocked; at or above `review` it needs human approval;
 * otherwise it is allowed. The thresholds are passed in (they live in
 * `worker/config.ts`, never inline) so this function carries no policy of its
 * own. The caller is responsible for `0 < review <= block <= 1`.
 *
 * Time complexity: O(1). Space complexity: O(1).
 *
 * @param p - Injection probability in [0, 1].
 * @param review - Threshold at/above which the verdict is HUMAN_APPROVAL_REQUIRED.
 * @param block - Threshold at/above which the verdict is BLOCK.
 * @returns The banded verdict.
 */
export function mapProbabilityToVerdict(
  p: number,
  review: number,
  block: number,
): Verdict {
  if (p >= block) {
    return 'BLOCK'
  }
  if (p >= review) {
    return 'HUMAN_APPROVAL_REQUIRED'
  }
  return 'ALLOW'
}
