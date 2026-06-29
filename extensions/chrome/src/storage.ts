import { EXTENSION_CONFIG } from './config'
import type { DnrRuleMetadata, ExtensionSettings, ExtensionStats, VerdictCacheEntry } from './types'

/** Default extension settings used when storage has not been initialized. */
export const DEFAULT_SETTINGS: ExtensionSettings = {
  apiBase: EXTENSION_CONFIG.apiBase,
  apiKey: '',
  pasteGuardEnabled: true,
  pageScanEnabled: true,
  egressBlockEnabled: true,
  requestTimeoutMs: EXTENSION_CONFIG.requestTimeoutMs,
  verdictCacheTtlMs: EXTENSION_CONFIG.verdictCacheTtlMs,
  dnrRuleBudget: EXTENSION_CONFIG.dnrRuleBudget,
}

const DEFAULT_STATS: ExtensionStats = {
  recentVerdicts: 0,
  lastBlockedDestination: null,
}

/**
 * Load extension settings from Chrome storage with defaults filled in.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export async function loadSettings(): Promise<ExtensionSettings> {
  const data = await chrome.storage.local.get(EXTENSION_CONFIG.storageKeys.settings)
  const saved = data[EXTENSION_CONFIG.storageKeys.settings]
  if (typeof saved !== 'object' || saved === null || Array.isArray(saved)) {
    return DEFAULT_SETTINGS
  }
  return { ...DEFAULT_SETTINGS, ...saved }
}

/**
 * Merge and persist extension settings.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export async function saveSettings(settings: Partial<ExtensionSettings>): Promise<ExtensionSettings> {
  const next = { ...(await loadSettings()), ...settings }
  await chrome.storage.local.set({ [EXTENSION_CONFIG.storageKeys.settings]: next })
  return next
}

/**
 * Load popup stats from Chrome storage.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export async function loadStats(): Promise<ExtensionStats> {
  const data = await chrome.storage.local.get(EXTENSION_CONFIG.storageKeys.stats)
  const saved = data[EXTENSION_CONFIG.storageKeys.stats]
  if (typeof saved !== 'object' || saved === null || Array.isArray(saved)) {
    return DEFAULT_STATS
  }
  return { ...DEFAULT_STATS, ...saved }
}

/**
 * Merge and persist popup stats.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export async function saveStats(stats: Partial<ExtensionStats>): Promise<ExtensionStats> {
  const next = { ...(await loadStats()), ...stats }
  await chrome.storage.local.set({ [EXTENSION_CONFIG.storageKeys.stats]: next })
  return next
}

/**
 * Load local metadata for dynamic DNR rules.
 *
 * Time complexity: O(n) in stored rules. Space complexity: O(n).
 */
export async function loadDnrMetadata(): Promise<DnrRuleMetadata[]> {
  const data = await chrome.storage.local.get(EXTENSION_CONFIG.storageKeys.dnrMetadata)
  const saved = data[EXTENSION_CONFIG.storageKeys.dnrMetadata]
  return Array.isArray(saved) ? (saved as DnrRuleMetadata[]) : []
}

/**
 * Persist local metadata for dynamic DNR rules.
 *
 * Time complexity: O(n) in stored rules. Space complexity: O(n).
 */
export async function saveDnrMetadata(metadata: DnrRuleMetadata[]): Promise<void> {
  await chrome.storage.local.set({ [EXTENSION_CONFIG.storageKeys.dnrMetadata]: metadata })
}

/**
 * Load cached scan verdicts from Chrome storage.
 *
 * Time complexity: O(n) in cached entries. Space complexity: O(n).
 */
export async function loadVerdictCache(): Promise<VerdictCacheEntry[]> {
  const data = await chrome.storage.local.get(EXTENSION_CONFIG.storageKeys.verdictCache)
  const saved = data[EXTENSION_CONFIG.storageKeys.verdictCache]
  return Array.isArray(saved) ? (saved as VerdictCacheEntry[]) : []
}

/**
 * Persist cached scan verdicts.
 *
 * Time complexity: O(n) in cached entries. Space complexity: O(n).
 */
export async function saveVerdictCache(entries: VerdictCacheEntry[]): Promise<void> {
  await chrome.storage.local.set({ [EXTENSION_CONFIG.storageKeys.verdictCache]: entries })
}
