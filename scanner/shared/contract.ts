/**
 * Cross-boundary types live in one place: `@secureai/contract` (resolved via the
 * tsconfig path alias). Re-exported here explicitly and by name (no wildcard, per
 * CLAUDE.md) so the SPA and the shared proof logic keep importing from `./contract`
 * against a single definition site, no drift between the Worker, the SPA, and the
 * SDK. Only the types the SPA actually uses are surfaced; the server-only guard
 * and pipeline types stay out of the browser's type surface.
 */
export type {
  InjectionFinding,
  LinkChain,
  Proof,
  ProofStep,
  ProofStepKind,
  RedirectHop,
  ReputationReport,
  RuleFinding,
  ScanRequest,
  ScanResult,
  Verdict,
  VerifyResult,
} from '@secureai/contract'
