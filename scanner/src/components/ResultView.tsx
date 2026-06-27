import type { ReactNode } from 'react'
import type { LinkChain, ScanResult } from '../api/types'
import type { ApiResource } from '../hooks/useApiResource'
import { VerdictBanner } from './VerdictBanner'
import { RedirectChain } from './RedirectChain'
import { ExaReputation } from './ExaReputation'
import { InjectionFindings } from './InjectionFindings'
import { ProofViewer } from './ProofViewer'
import { Panel } from './Panel'
import { formatTimestamp } from '../lib/format'

interface ResultViewProps {
  result: ScanResult
}

/** Wrap an already-resolved value in a settled resource for {@link Panel}. */
function settled<T>(data: T): ApiResource<T> {
  return { data, error: null, loading: false, reload: () => {} }
}

/**
 * The full scan report, identical for a live scan and a replayed gallery pick.
 *
 * Composes the evidence in fixed order — verdict banner, one redirect cascade
 * per traced origin, Exa reputation, injection findings, then the re-verifiable
 * proof chain. Purely presentational: it reads only the {@link ScanResult} prop
 * and owns no scan or network state, so the render path is byte-for-byte the
 * same regardless of where the result came from.
 *
 * Time complexity: O(c + r + f + n) over chains, Exa reports, injection findings
 * and proof steps. Space complexity: O(1) beyond the rendered tree.
 */
export function ResultView({ result }: ResultViewProps): ReactNode {
  return (
    <div className="result">
      <VerdictBanner verdict={result.verdict} findingsCount={result.findings.length} />

      <Panel<LinkChain[]>
        title="Redirect Cascades"
        count={result.chains.length}
        resource={settled(result.chains)}
        emptyText="No links to trace."
        isEmpty={(data) => data.length === 0}
      >
        {(chains) => (
          <div className="result__chains">
            {chains.map((chain, index) => (
              <RedirectChain key={chain.origin} chain={chain} index={index} />
            ))}
          </div>
        )}
      </Panel>

      <ExaReputation reports={result.exa} />

      <InjectionFindings findings={result.injections} />

      <Panel<ScanResult>
        title="Proof Chain"
        count={result.proof.steps.length}
        resource={settled(result)}
        emptyText="No proof steps."
        isEmpty={(data) => data.proof.steps.length === 0}
      >
        {(data) => (
          <>
            <p className="result__scanned">Scanned {formatTimestamp(data.scannedAt)}</p>
            <ProofViewer proof={data.proof} />
          </>
        )}
      </Panel>
    </div>
  )
}
