import { EXTENSION_CONFIG } from './config'
import type { DnrPlan, DnrRuleMetadata, ScanResult } from './types'

interface RuleCandidate {
  destination: string
  filter: string
  kind: DnrRuleMetadata['kind']
}

const URL_PATTERN = /https?:\/\/[^\s"'<>)]*/gi
const HOST_PATTERN = /\bhost\s*[:=]\s*([a-z0-9.-]+\.[a-z]{2,})\b/i
const MAX_RULE_ID = 2_000_000_000
const FNV_OFFSET = 2166136261
const FNV_PRIME = 16777619

function fnv1a(input: string): number {
  let hash = FNV_OFFSET
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i)
    hash = Math.imul(hash, FNV_PRIME)
  }
  return (hash >>> 0) % MAX_RULE_ID
}

function normalizeUrl(raw: string): string | null {
  try {
    const url = new URL(raw)
    url.hash = ''
    return url.toString()
  } catch {
    return null
  }
}

function normalizeHost(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase()
  try {
    return new URL(trimmed).hostname
  } catch {
    return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(trimmed) ? trimmed : null
  }
}

function exactUrlCandidate(rawUrl: string): RuleCandidate | null {
  const normalized = normalizeUrl(rawUrl)
  if (normalized === null) return null
  return {
    destination: normalized,
    filter: `|${normalized}|`,
    kind: 'exact-url',
  }
}

function hostCandidate(rawHost: string): RuleCandidate | null {
  const host = normalizeHost(rawHost)
  if (host === null) return null
  return {
    destination: host,
    filter: `||${host}^`,
    kind: 'host',
  }
}

function urlsFromText(text: string): string[] {
  return Array.from(text.matchAll(URL_PATTERN), (match) => match[0] ?? '')
    .filter((value) => value.length > 0)
    .map((value) => value.replace(/[.,;]+$/, ''))
}

function categoryAllowsDnr(category: string): boolean {
  const normalized = category.toLowerCase()
  return EXTENSION_CONFIG.destinationRiskCategories.some((token) => normalized.includes(token))
}

function addCandidate(
  candidates: Map<string, RuleCandidate>,
  candidate: RuleCandidate | null,
): void {
  if (candidate === null) return
  candidates.set(`${candidate.kind}:${candidate.destination}`, candidate)
}

/**
 * Derive a deterministic Chrome DNR rule id from a normalized destination.
 *
 * Time complexity: O(n) in the destination length. Space complexity: O(1).
 */
export function ruleIdForDestination(kind: DnrRuleMetadata['kind'], destination: string): number {
  return fnv1a(`${kind}:${destination}`) + 1
}

/**
 * Convert risky destinations in a scan result into candidate DNR block filters.
 *
 * Time complexity: O(f + c + r + i) over findings, chains, reputation reports, and
 * injection findings. Space complexity: O(k) in unique destinations.
 */
export function candidatesFromScan(result: ScanResult): RuleCandidate[] {
  const candidates = new Map<string, RuleCandidate>()
  if (result.verdict === 'ALLOW') return []

  for (const report of result.reputation) {
    if (report.flagged) addCandidate(candidates, exactUrlCandidate(report.url))
  }

  for (const chain of result.chains) {
    const dangerousHop = chain.hops.find((hop) => hop.dangerous)
    if (dangerousHop !== undefined) addCandidate(candidates, exactUrlCandidate(dangerousHop.to))
    if (chain.dangerousHopIndex !== null || chain.depthExceeded || chain.loopDetected) {
      addCandidate(candidates, exactUrlCandidate(chain.finalUrl))
    }
  }

  for (const finding of result.findings) {
    const text = `${finding.ruleId} ${finding.detail}`.toLowerCase()
    const hostMatch = finding.detail.match(HOST_PATTERN)
    if (hostMatch?.[1] !== undefined) addCandidate(candidates, hostCandidate(hostMatch[1]))
    if (categoryAllowsDnr(text)) {
      for (const url of urlsFromText(finding.detail)) {
        addCandidate(candidates, exactUrlCandidate(url))
      }
    }
  }

  for (const injection of result.injections) {
    const text = `${injection.category} ${injection.rationale}`
    if (!categoryAllowsDnr(text)) continue
    for (const url of [...urlsFromText(injection.excerpt), ...urlsFromText(injection.rationale)]) {
      addCandidate(candidates, exactUrlCandidate(url))
    }
  }

  return Array.from(candidates.values())
}

function toRule(candidate: RuleCandidate): chrome.declarativeNetRequest.Rule {
  return {
    id: ruleIdForDestination(candidate.kind, candidate.destination),
    priority: 1,
    action: { type: 'block' },
    condition: {
      urlFilter: candidate.filter,
      resourceTypes: [...EXTENSION_CONFIG.dnrResourceTypes],
    },
  }
}

/**
 * Build an idempotent dynamic-rule update plan while keeping the metadata under budget.
 *
 * Time complexity: O(n log n + k) in existing metadata and new candidates due to
 * least-recent eviction sorting. Space complexity: O(n + k).
 */
export function buildDnrPlan(
  result: ScanResult,
  existing: readonly DnrRuleMetadata[],
  now: number,
  budget: number,
): DnrPlan {
  const candidates = candidatesFromScan(result)
  const existingById = new Map(existing.map((entry) => [entry.id, entry]))
  const metadataById = new Map(existing.map((entry) => [entry.id, { ...entry }]))
  const addRules: chrome.declarativeNetRequest.Rule[] = []
  const touchedIds = new Set<number>()

  for (const candidate of candidates) {
    const rule = toRule(candidate)
    touchedIds.add(rule.id)
    const saved = existingById.get(rule.id)
    metadataById.set(rule.id, {
      id: rule.id,
      destination: candidate.destination,
      filter: candidate.filter,
      kind: candidate.kind,
      createdAt: saved?.createdAt ?? now,
      lastSeenAt: now,
    })
    if (saved === undefined) addRules.push(rule)
  }

  const removeRuleIds: number[] = []
  if (metadataById.size > budget) {
    const removable = Array.from(metadataById.values())
      .filter((entry) => !touchedIds.has(entry.id))
      .sort((left, right) => left.lastSeenAt - right.lastSeenAt)
    while (metadataById.size > budget && removable.length > 0) {
      const evicted = removable.shift()
      if (evicted === undefined) break
      metadataById.delete(evicted.id)
      removeRuleIds.push(evicted.id)
    }
  }

  return {
    addRules,
    removeRuleIds,
    metadata: Array.from(metadataById.values()).sort((left, right) => left.id - right.id),
  }
}
