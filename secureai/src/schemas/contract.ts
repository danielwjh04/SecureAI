/**
 * Cross-boundary types live in one place: `@secureai/contract` (resolved via the
 * tsconfig path alias). Re-exported here explicitly and by name (no wildcard, per
 * CLAUDE.md) so every existing `../schemas/contract` import keeps resolving against
 * a single definition site, no drift between the Worker, the SPA, and the SDK. The
 * list is the set the Worker uses.
 */
export type {
  GuardDecision,
  GuardPermissionDecision,
  InferenceClient,
  InjectionFinding,
  InjectionResult,
  LinkChain,
  McpScanInput,
  Proof,
  ProofStep,
  ProofStepKind,
  RedirectHop,
  ReputationClient,
  ReputationReport,
  RuleFinding,
  ScanRequest,
  ScanResult,
  Verdict,
  VerifyResult,
} from '@secureai/contract'
