import type { ReactNode } from 'react'
import type { LinkChain } from '../api/types'
import { hostname } from '../lib/format'

interface RedirectChainProps {
  chain: LinkChain
  index: number
}

/** One node's label: the URL's hostname plus an optional HTTP status. */
function nodeLabel(url: string, status: number | null): ReactNode {
  return (
    <>
      <span className="chain-vis__host">{hostname(url)}</span>
      {status !== null && <span className="chain-vis__status">{status}</span>}
    </>
  )
}

/**
 * Render a single traced redirect cascade as a horizontal visual chain:
 * origin → hop → hop → finalUrl. The destination renders as a `.chain-vis__final`
 * node; intermediate hops as `.chain-vis__hop` nodes joined by `.chain-vis__arrow`.
 *
 * Pure mapping from {@link LinkChain} to DOM. The hop whose index equals
 * `chain.dangerousHopIndex` gets `.chain-vis__hop--danger` and surfaces its
 * `reason`; when `dangerousHopIndex` is null no hop is marked dangerous.
 * `depthExceeded` and `loopDetected` render as trailing badges when set.
 *
 * Node layout: the origin node (status null), then one node per intermediate hop
 * (all hops except the last), then the final hop as the destination node showing
 * `finalUrl`. With h hops there are h+1 nodes, matching origin → h hops.
 *
 * Time complexity: O(h) where h = chain.hops.length. Space complexity: O(h).
 *
 * @param index - This chain's position in the result's chain list. Used only to
 *   label the cascade for assistive tech; never enters any hashed payload.
 */
export function RedirectChain({ chain, index }: RedirectChainProps): ReactNode {
  const lastHopIndex = chain.hops.length - 1
  return (
    <div
      className="chain-vis"
      role="list"
      aria-label={`Redirect cascade ${index + 1} for ${chain.origin}`}
    >
      <span className="chain-vis__hop" role="listitem">
        {nodeLabel(chain.origin, null)}
      </span>
      {chain.hops.map((hop, hopIndex) => {
        const dangerous = hopIndex === chain.dangerousHopIndex
        const isFinal = hopIndex === lastHopIndex
        const baseClass = isFinal ? 'chain-vis__final' : 'chain-vis__hop'
        const hopClass = dangerous ? `${baseClass} chain-vis__hop--danger` : baseClass
        return (
          <span key={hopIndex} className="chain-vis__group" role="listitem">
            <span className="chain-vis__arrow" aria-hidden="true">
              →
            </span>
            <span className={hopClass}>
              {nodeLabel(isFinal ? chain.finalUrl : hop.to, hop.status)}
              {dangerous && hop.reason !== null && (
                <span className="chain-vis__reason">{hop.reason}</span>
              )}
            </span>
          </span>
        )
      })}
      {chain.depthExceeded && <span className="chain-vis__badge">depth exceeded</span>}
      {chain.loopDetected && <span className="chain-vis__badge">loop detected</span>}
    </div>
  )
}
