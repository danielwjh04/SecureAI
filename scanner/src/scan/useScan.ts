/**
 * The scan controller hook. Wraps the pure {@link scanReducer} with the two side
 * effects a live scan needs: the network call to the scan client and a paced
 * stepper that advances the progress animation on a fixed interval, decoupled
 * from request latency (a fast scan still shows the full pipeline; a slow one
 * holds on the last step).
 */

import { useCallback, useEffect, useReducer, useRef } from 'react'
import { ApiError, defaultScanClient } from '../api/client'
import type { ScanClient } from '../api/client'
import { SCAN_STEP_PACING_MS } from '../config'
import type { ScanRequest, ScanResult } from '../api/types'
import { initialScanState, scanReducer } from './scanMachine'
import type { ScanState } from './scanMachine'

/** The controller surface returned to the SPA. */
export interface ScanController {
  state: ScanState
  scan: (req: ScanRequest) => void
  loadResult: (result: ScanResult) => void
  reset: () => void
}

/**
 * Drive a scan against an injected {@link ScanClient} (the live API by default).
 *
 * `scan` starts the machine, kicks off the request, and starts the stepper
 * interval; whichever settles first, the interval is always cleared on settle
 * and on unmount. `loadResult` jumps straight to a finished result (used by the
 * gallery to replay a recorded scan without a network call). The latest run is
 * tracked by a monotonic id so a stale resolution from a superseded scan is
 * dropped rather than overwriting a newer run.
 *
 * Time complexity: O(1) per dispatch. Space complexity: O(1).
 */
export function useScan(client: ScanClient = defaultScanClient): ScanController {
  const [state, dispatch] = useReducer(scanReducer, initialScanState)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const runIdRef = useRef(0)

  const clearStepper = useCallback((): void => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }
  }, [])

  const scan = useCallback(
    (req: ScanRequest): void => {
      const runId = runIdRef.current + 1
      runIdRef.current = runId
      clearStepper()
      dispatch({ type: 'start' })
      intervalRef.current = setInterval(() => {
        dispatch({ type: 'advance' })
      }, SCAN_STEP_PACING_MS)

      client
        .scanSkill(req)
        .then((result) => {
          if (runIdRef.current !== runId) return
          clearStepper()
          dispatch({ type: 'resolve', result })
        })
        .catch((caught: unknown) => {
          if (runIdRef.current !== runId) return
          clearStepper()
          const message =
            caught instanceof ApiError ? caught.message : 'unexpected scan error'
          dispatch({ type: 'fail', message })
        })
    },
    [client, clearStepper],
  )

  const loadResult = useCallback(
    (result: ScanResult): void => {
      runIdRef.current += 1
      clearStepper()
      dispatch({ type: 'start' })
      dispatch({ type: 'resolve', result })
    },
    [clearStepper],
  )

  const reset = useCallback((): void => {
    runIdRef.current += 1
    clearStepper()
    dispatch({ type: 'reset' })
  }, [clearStepper])

  useEffect(() => clearStepper, [clearStepper])

  return { state, scan, loadResult, reset }
}
