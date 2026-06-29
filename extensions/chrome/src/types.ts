export type Verdict = 'ALLOW' | 'HUMAN_APPROVAL_REQUIRED' | 'BLOCK'
export type WireVerdict = Verdict | 'REVIEW'

export interface RuleFinding {
  ruleId: string
  severity: Verdict
  detail: string
}

export interface RedirectHop {
  from: string
  to: string
  status: number
  dangerous: boolean
  reason: string | null
}

export interface LinkChain {
  origin: string
  hops: RedirectHop[]
  finalUrl: string
  dangerousHopIndex: number | null
  depthExceeded: boolean
  loopDetected: boolean
}

export interface ReputationReport {
  url: string
  score: string
  summary: string
  title: string
  flagged: boolean
  status: string
}

export interface InjectionFinding {
  excerpt: string
  category: string
  severity: Verdict
  rationale: string
}

export interface Proof {
  genesisHash: string
  steps: unknown[]
  headHash: string
}

export interface ScanSource {
  kind: 'paste' | 'url'
  ref: string
}

export interface ScanResult {
  verdict: Verdict
  findings: RuleFinding[]
  chains: LinkChain[]
  reputation: ReputationReport[]
  injections: InjectionFinding[]
  proof: Proof
  scannedAt: string
  source: ScanSource
}

export type ScanInput =
  | { sourceUrl: string; content?: never }
  | { content: string; sourceUrl?: never }

export type ScanFailureReason =
  | 'missing-key'
  | 'timeout'
  | 'network'
  | 'http'
  | 'parse'
  | 'invalid-input'

export type ScanOutcome =
  | { ok: true; result: ScanResult }
  | { ok: false; reason: ScanFailureReason; message: string; failClosed: true }

export interface ExtensionSettings {
  apiBase: string
  apiKey: string
  pasteGuardEnabled: boolean
  pageScanEnabled: boolean
  egressBlockEnabled: boolean
  requestTimeoutMs: number
  verdictCacheTtlMs: number
  dnrRuleBudget: number
}

export interface ExtensionStats {
  recentVerdicts: number
  lastBlockedDestination: string | null
}

export interface VerdictCacheEntry {
  key: string
  result: ScanResult
  expiresAt: number
}

export interface DnrRuleMetadata {
  id: number
  destination: string
  filter: string
  kind: 'exact-url' | 'host'
  createdAt: number
  lastSeenAt: number
}

export interface DnrPlan {
  addRules: chrome.declarativeNetRequest.Rule[]
  removeRuleIds: number[]
  metadata: DnrRuleMetadata[]
}

export type ExtensionMessage =
  | { type: 'secureai.scanUrl'; sourceUrl: string; enforcement?: 'page' | 'paste' | 'submit' }
  | { type: 'secureai.scanContent'; content: string; enforcement?: 'page' | 'paste' | 'submit' }
  | { type: 'secureai.getState' }
  | { type: 'secureai.saveSettings'; settings: Partial<ExtensionSettings> }
  | { type: 'secureai.validateKey'; apiKey: string }
  | { type: 'secureai.openPairing'; apiKey: string }
