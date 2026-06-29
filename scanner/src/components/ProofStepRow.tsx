import type { ReactNode } from 'react'
import type { ProofStep } from '../../shared/contract'
import { truncateHash } from '../lib/format'

/** Live integrity state of a single proof row during re-verification. */
type ProofStepStatus = 'ok' | 'broken'

interface ProofStepRowProps {
  step: ProofStep
  status: ProofStepStatus
  /** Raw textarea contents for this step's editable canonical-JSON payload. */
  editedText: string
  onEdit: (text: string) => void
}

/**
 * One row of the proof inspector: the step's index, kind, an editable mono
 * `<textarea>` holding the canonical JSON of the step's payload, the truncated
 * current hash, and an integrity mark (`● INTACT` / `● BROKEN`).
 *
 * Pure presentation. Editing the textarea is the tamper input, its raw text
 * bubbles up via `onEdit`; this row owns no verification logic. The parent
 * {@link ProofViewer} re-hashes the candidate chain client-side and feeds the
 * resulting `status` back down. Layout matches the `.proof__step` grid (index,
 * kind, editor, mark) in `scanner.css`.
 *
 * Time complexity: O(1) in this row's fields. Space complexity: O(1).
 */
export function ProofStepRow({
  step,
  status,
  editedText,
  onEdit,
}: ProofStepRowProps): ReactNode {
  const markClass =
    status === 'broken'
      ? 'proof__mark proof__mark--broken'
      : 'proof__mark proof__mark--ok'
  const markLabel = status === 'broken' ? '● BROKEN' : '● INTACT'
  return (
    <div className="proof__step" role="listitem">
      <span className="proof__index">{step.index}</span>
      <span className="proof__kind">{step.kind}</span>
      <textarea
        className="proof__editor"
        spellCheck={false}
        aria-label={`payload for step ${step.index}`}
        value={editedText}
        onChange={(event) => onEdit(event.target.value)}
      />
      <span style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
        <span className={markClass}>{markLabel}</span>
        <span className="proof__hash" title={step.currHash}>
          {truncateHash(step.currHash)}
        </span>
      </span>
    </div>
  )
}

export type { ProofStepStatus }
