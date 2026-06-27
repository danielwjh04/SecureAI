import { useEffect } from 'react'

/**
 * Scroll the window back to the top whenever `key` changes (and on first mount).
 *
 * The result surface uses this so each freshly shown scan report opens at the
 * top — the verdict and the scan dashboard — instead of inheriting the caller's
 * scroll position. Picking an example from the gallery at the bottom of the
 * landing page does not change the route, so the App-level scroll effect (keyed
 * on route/target) never fires for it; without this reset the report would open
 * scrolled to the bottom, dropping the reader onto the trailing proof-chain
 * panel.
 *
 * `key` should be stable within one displayed result and unique across results
 * (the proof head hash), so the reset fires once per report and again only when
 * a different report replaces it.
 *
 * Time complexity: O(1) per change. Space complexity: O(1).
 */
export function useScrollToTopOnChange(key: string): void {
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' })
  }, [key])
}
