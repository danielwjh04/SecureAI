/**
 * Edge cache for {@link GuardDecision}s, the guard-route analogue of the scan
 * {@link ../scanner/verdictCache}. The guard is the latency-critical inline path
 * because local agents block on it before every guarded tool call.
 *
 * The cache stores the decision only. The route still authenticates, enforces
 * the daily cap, and meters usage on every hit. Cache keys are bound to policy
 * revision, trust revision, project scope, device identity, integration version,
 * content hash, tool name, and exact tool input when those fields are present.
 *
 * Security tradeoff: a short TTL bounds how long a changed policy or indicator
 * can be masked. Setting the TTL to 0 disables the cache.
 */

import type { PreToolUsePayload } from '../schemas/validate'
import type { GuardDecision } from './claudeCode'
import { canonicalJson } from '../audit/chain'
import { log } from '../observability/logger'

/** Namespaced, versioned prefix for every guard-decision cache key. */
const CACHE_KEY_PREFIX = 'guard:v2:'

const textEncoder = new TextEncoder()

/** The minimal KV surface the guard cache uses, injectable for tests. */
export interface GuardCacheKv {
  get(key: string): Promise<string | null>
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>
}

/** Lowercase-hex SHA-256 of a UTF-8 string. */
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))
  let hex = ''
  for (const byte of new Uint8Array(digest)) {
    hex += byte.toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Derive the cache key from policy version, trust revision, project scope, and
 * scannable fields of a PreToolUse payload. Session-only fields such as
 * `session_id` and `transcript_path` never enter the key, while `cwd` does
 * because it is the project scope.
 *
 * Time complexity: O(n) in the payload byte length. Space complexity: O(n).
 */
export async function cacheKeyForPayload(
  payload: PreToolUsePayload,
  policyVersion = '1',
  trustRevision = '1',
): Promise<string> {
  const payloadRecord = payload as unknown as Record<string, unknown>
  const scannable = {
    policy_version: policyVersion,
    trust_revision: trustRevision,
    provider: stringOrNull(payloadRecord.provider),
    agent: stringOrNull(payloadRecord.agent),
    device_id: stringOrNull(payloadRecord.device_id),
    integration_version: stringOrNull(payloadRecord.integration_version),
    project_scope: stringOrNull(payload.cwd),
    content_hash: stringOrNull(payloadRecord.content_hash),
    tool_name: payload.tool_name,
    // maximum privacy mode omits tool_input; coalesce to null so the key stays
    // canonicalizable (the content hash is what distinguishes such payloads).
    tool_input: payload.tool_input ?? null,
  }
  return CACHE_KEY_PREFIX + (await sha256Hex(canonicalJson(scannable)))
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

/** Parse a cached decision, or `null` on a corrupt entry. */
function parseCached(value: string): GuardDecision | null {
  try {
    return JSON.parse(value) as GuardDecision
  } catch (error: unknown) {
    const className = error instanceof Error ? error.constructor.name : typeof error
    log.warn('guardCache', 'discarding unparseable cache entry', { errorClass: className })
    return null
  }
}

/**
 * Resolve a guard decision from cache when possible and recompute on a miss.
 * Authentication, caps, and metering run in the route on hits and misses.
 *
 * Time complexity: one KV read plus one write on a miss, plus `compute()` on a
 * miss. Space complexity: O(decision size).
 */
export async function resolveCachedDecision(
  payload: PreToolUsePayload,
  kv: GuardCacheKv | null,
  ttlSeconds: number,
  compute: () => Promise<GuardDecision>,
  policyVersion = '1',
  trustRevision = '1',
): Promise<GuardDecision> {
  if (kv === null || ttlSeconds <= 0) {
    return compute()
  }
  const key = await cacheKeyForPayload(payload, policyVersion, trustRevision)
  const hit = await kv.get(key)
  if (hit !== null) {
    const parsed = parseCached(hit)
    if (parsed !== null) {
      return parsed
    }
  }
  const decision = await compute()
  await kv.put(key, JSON.stringify(decision), { expirationTtl: ttlSeconds })
  return decision
}
