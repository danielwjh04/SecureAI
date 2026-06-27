/**
 * The animated multi-step scan indicator. Renders the scan pipeline `labels` as
 * a horizontal stepper driven by a single `stepIndex`:
 *   - steps before the active index are done (static check mark),
 *   - the active step animates its label through the copied {@link Typewriter}
 *     beside a pulsing status dot (the `.statusbar`/pulse idiom),
 *   - steps after the active index are pending (idle dot).
 *
 * Purely presentational: it owns no scan state and never advances itself; the
 * parent (the scan machine) passes the live `labels` and maps real scan progress
 * onto `stepIndex`. When `stepIndex` reaches the label count, every step reads as
 * done.
 */

import { Typewriter } from './Typewriter'

interface ScanProgressProps {
  /** Index of the in-flight step. Steps below it are done, above it pending. */
  stepIndex: number
  /** Ordered pipeline labels to render, supplied by the scan machine. */
  labels: readonly string[]
}

export function ScanProgress({ stepIndex, labels }: ScanProgressProps) {
  return (
    <div className="scan-progress" role="list" aria-label="Scan progress">
      {labels.map((label, index) => {
        const done = index < stepIndex
        const active = index === stepIndex
        const stateClass = done
          ? 'scan-progress__step--done'
          : active
            ? 'scan-progress__step--active'
            : ''
        return (
          <div
            key={label}
            className={`scan-progress__step ${stateClass}`.trimEnd()}
            role="listitem"
            aria-current={active ? 'step' : undefined}
          >
            <span className="scan-progress__dot" aria-hidden="true" />
            {active ? (
              <Typewriter text={label} />
            ) : (
              <span>
                {done && '✓ '}
                {label}
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}
