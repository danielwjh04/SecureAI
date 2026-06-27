import type { ReactNode } from 'react'
import { ScannerHeader } from './components/ScannerHeader'
import { SkillInput } from './components/SkillInput'
import { ScanProgress } from './components/ScanProgress'
import { Gallery } from './components/Gallery'
import { ResultView } from './components/ResultView'
import { useScan } from './scan/useScan'
import type { ScanState } from './scan/scanMachine'

/**
 * The landing surface: the skill input plus the example-scan gallery. Shown
 * while idle and while a scan is in flight (the input goes inert via `busy`),
 * with the live stepper appearing under the input once `scanning` begins.
 */
function ScanLanding({
  state,
  controller,
}: {
  state: Extract<ScanState, { phase: 'idle' | 'scanning' }>
  controller: ReturnType<typeof useScan>
}): ReactNode {
  const scanning = state.phase === 'scanning'
  return (
    <div className="scan-shell">
      <section className="scan-hero">
        <h2>Scan a skill before your agent learns it</h2>
        <p>
          Paste a SKILL.md or point us at a source URL. We trace every redirect,
          check destination reputation with Exa, judge the text for prompt
          injection, and seal the evidence into a proof you can re-verify yourself.
        </p>
      </section>
      <SkillInput onScan={controller.scan} busy={scanning} />
      {scanning && (
        <ScanProgress stepIndex={state.stepIndex} labels={state.labels} />
      )}
      <Gallery onPick={controller.loadResult} />
    </div>
  )
}

/** The error surface: a tasteful panel naming the failure with a retry action. */
function ScanError({
  message,
  onRetry,
}: {
  message: string
  onRetry: () => void
}): ReactNode {
  return (
    <div className="scan-shell">
      <section className="panel">
        <div className="panel__head">
          <h2>Scan Failed</h2>
        </div>
        <div className="panel__body">
          <div className="panel__state panel__state--error">{message}</div>
          <div className="scan-input__actions">
            <button type="button" className="btn" onClick={onRetry}>
              Try another scan
            </button>
          </div>
        </div>
      </section>
    </div>
  )
}

/** The finished surface: the full report with a reset to scan again. */
function ScanDone({
  state,
  onReset,
}: {
  state: Extract<ScanState, { phase: 'done' }>
  onReset: () => void
}): ReactNode {
  return (
    <div className="scan-shell">
      <div className="scan-input__actions">
        <button type="button" className="btn btn--ghost" onClick={onReset}>
          ← Scan another
        </button>
      </div>
      <ResultView result={state.result} />
    </div>
  )
}

/**
 * The Skill Safety Scanner SPA shell: a fixed header over a single state-driven
 * scan surface. `useScan` owns the lifecycle; this component only routes the
 * current phase to the matching surface. Live scans and gallery replays share
 * one render path — both land in `done` with a {@link ResultView}.
 */
function App(): ReactNode {
  const controller = useScan()
  const { state } = controller

  let body: ReactNode
  switch (state.phase) {
    case 'idle':
    case 'scanning':
      body = <ScanLanding state={state} controller={controller} />
      break
    case 'done':
      body = <ScanDone state={state} onReset={controller.reset} />
      break
    case 'error':
      body = <ScanError message={state.message} onRetry={controller.reset} />
      break
  }

  return (
    <div className="app">
      <ScannerHeader />
      <main className="app__main">{body}</main>
    </div>
  )
}

export default App
