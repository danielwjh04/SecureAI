import { EXTENSION_CONFIG } from './config'
import type {
  InjectionFinding,
  LinkChain,
  Proof,
  ReputationReport,
  RuleFinding,
  ScanInput,
  ScanOutcome,
  ScanResult,
  Verdict,
  WireVerdict,
} from './types'

export interface ScanClientOptions {
  apiBase: string
  apiKey: string
  timeoutMs: number
  fetchImpl?: typeof fetch
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function normalizeVerdict(value: unknown): Verdict | null {
  const verdict = value as WireVerdict
  if (verdict === 'REVIEW') return 'HUMAN_APPROVAL_REQUIRED'
  if (verdict === 'ALLOW' || verdict === 'HUMAN_APPROVAL_REQUIRED' || verdict === 'BLOCK') {
    return verdict
  }
  return null
}

function parseFinding(value: unknown): RuleFinding | null {
  if (!isRecord(value)) return null
  const severity = normalizeVerdict(value.severity)
  if (
    typeof value.ruleId !== 'string' ||
    typeof value.detail !== 'string' ||
    severity === null
  ) {
    return null
  }
  return { ruleId: value.ruleId, detail: value.detail, severity }
}

function parseInjection(value: unknown): InjectionFinding | null {
  if (!isRecord(value)) return null
  const severity = normalizeVerdict(value.severity)
  if (
    typeof value.excerpt !== 'string' ||
    typeof value.category !== 'string' ||
    typeof value.rationale !== 'string' ||
    severity === null
  ) {
    return null
  }
  return {
    excerpt: value.excerpt,
    category: value.category,
    severity,
    rationale: value.rationale,
  }
}

function parseReputation(value: unknown): ReputationReport | null {
  if (!isRecord(value)) return null
  if (
    typeof value.url !== 'string' ||
    typeof value.score !== 'string' ||
    typeof value.summary !== 'string' ||
    typeof value.title !== 'string' ||
    typeof value.flagged !== 'boolean' ||
    typeof value.status !== 'string'
  ) {
    return null
  }
  return {
    url: value.url,
    score: value.score,
    summary: value.summary,
    title: value.title,
    flagged: value.flagged,
    status: value.status,
  }
}

function parseChain(value: unknown): LinkChain | null {
  if (!isRecord(value)) return null
  if (
    typeof value.origin !== 'string' ||
    typeof value.finalUrl !== 'string' ||
    !Array.isArray(value.hops) ||
    typeof value.depthExceeded !== 'boolean' ||
    typeof value.loopDetected !== 'boolean'
  ) {
    return null
  }
  const dangerousHopIndex =
    typeof value.dangerousHopIndex === 'number' || value.dangerousHopIndex === null
      ? value.dangerousHopIndex
      : null
  const hops = value.hops.map((hop) => {
    if (!isRecord(hop)) return null
    if (
      typeof hop.from !== 'string' ||
      typeof hop.to !== 'string' ||
      typeof hop.status !== 'number' ||
      typeof hop.dangerous !== 'boolean' ||
      !(typeof hop.reason === 'string' || hop.reason === null)
    ) {
      return null
    }
    return {
      from: hop.from,
      to: hop.to,
      status: hop.status,
      dangerous: hop.dangerous,
      reason: hop.reason,
    }
  })
  if (hops.some((hop) => hop === null)) return null
  return {
    origin: value.origin,
    finalUrl: value.finalUrl,
    hops: hops as LinkChain['hops'],
    dangerousHopIndex,
    depthExceeded: value.depthExceeded,
    loopDetected: value.loopDetected,
  }
}

function parseProof(value: unknown): Proof | null {
  if (!isRecord(value)) return null
  if (
    typeof value.genesisHash !== 'string' ||
    typeof value.headHash !== 'string' ||
    !Array.isArray(value.steps)
  ) {
    return null
  }
  return { genesisHash: value.genesisHash, headHash: value.headHash, steps: value.steps }
}

function parseArray<T>(value: unknown, parse: (entry: unknown) => T | null): T[] | null {
  if (!Array.isArray(value)) return null
  const parsed = value.map(parse)
  if (parsed.some((entry) => entry === null)) return null
  return parsed as T[]
}

/**
 * Validate and normalize a raw `/api/scan` response at the extension boundary.
 *
 * Time complexity: O(n) in the number of evidence entries. Space complexity: O(n).
 */
export function parseScanResult(value: unknown): ScanResult | null {
  if (!isRecord(value)) return null
  const verdict = normalizeVerdict(value.verdict)
  const findings = parseArray(value.findings, parseFinding)
  const chains = parseArray(value.chains, parseChain)
  const reputation = parseArray(value.reputation, parseReputation)
  const injections = parseArray(value.injections, parseInjection)
  const proof = parseProof(value.proof)
  const source = value.source
  if (
    verdict === null ||
    findings === null ||
    chains === null ||
    reputation === null ||
    injections === null ||
    proof === null ||
    typeof value.scannedAt !== 'string' ||
    !isRecord(source) ||
    !(source.kind === 'paste' || source.kind === 'url') ||
    typeof source.ref !== 'string'
  ) {
    return null
  }
  return {
    verdict,
    findings,
    chains,
    reputation,
    injections,
    proof,
    scannedAt: value.scannedAt,
    source: { kind: source.kind, ref: source.ref },
  }
}

function validateInput(input: ScanInput): boolean {
  const hasSourceUrl = 'sourceUrl' in input && typeof input.sourceUrl === 'string'
  const hasContent = 'content' in input && typeof input.content === 'string'
  return hasSourceUrl !== hasContent
}

/**
 * Call the SecureAI scan API with timeout handling and fail-closed typed errors.
 *
 * Time complexity: O(n) in request and response size. Space complexity: O(n).
 */
export async function scan(input: ScanInput, options: ScanClientOptions): Promise<ScanOutcome> {
  if (!validateInput(input)) {
    return { ok: false, reason: 'invalid-input', message: 'provide one scan input', failClosed: true }
  }
  if (options.apiKey.trim().length === 0) {
    return { ok: false, reason: 'missing-key', message: 'SecureAI API key is missing', failClosed: true }
  }

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs)
  const fetchImpl = options.fetchImpl ?? fetch
  try {
    const response = await fetchImpl(new URL(EXTENSION_CONFIG.scanPath, options.apiBase), {
      method: 'POST',
      headers: {
        authorization: `Bearer ${options.apiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(input),
      signal: controller.signal,
    })
    if (!response.ok) {
      return {
        ok: false,
        reason: 'http',
        message: `SecureAI scan failed with status ${response.status}`,
        failClosed: true,
      }
    }
    const parsed = parseScanResult(await response.json())
    if (parsed === null) {
      return {
        ok: false,
        reason: 'parse',
        message: 'SecureAI returned an invalid scan response',
        failClosed: true,
      }
    }
    return { ok: true, result: parsed }
  } catch (error) {
    const reason = error instanceof DOMException && error.name === 'AbortError' ? 'timeout' : 'network'
    const message =
      reason === 'timeout' ? 'SecureAI scan timed out' : 'SecureAI scan could not reach the API'
    return { ok: false, reason, message, failClosed: true }
  } finally {
    clearTimeout(timeout)
  }
}

/**
 * Scan one source URL through the cloud engine.
 *
 * Time complexity: O(n) in response size. Space complexity: O(n).
 */
export function scanUrl(sourceUrl: string, options: ScanClientOptions): Promise<ScanOutcome> {
  return scan({ sourceUrl }, options)
}

/**
 * Scan pasted or selected content through the cloud engine.
 *
 * Time complexity: O(n) in content and response size. Space complexity: O(n).
 */
export function scanContent(content: string, options: ScanClientOptions): Promise<ScanOutcome> {
  return scan({ content }, options)
}
