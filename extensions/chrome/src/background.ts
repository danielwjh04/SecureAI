import { EXTENSION_CONFIG } from './config'
import { buildDnrPlan } from './dnr'
import { scanContent, scanUrl } from './scanClient'
import {
  loadDnrMetadata,
  loadSettings,
  loadStats,
  loadVerdictCache,
  saveDnrMetadata,
  saveSettings,
  saveStats,
  saveVerdictCache,
} from './storage'
import type {
  ExtensionMessage,
  ExtensionSettings,
  ScanInput,
  ScanOutcome,
  ScanResult,
  VerdictCacheEntry,
} from './types'

const CONTEXT_MENU_LINK = 'secureai.scanLink'
const CONTEXT_MENU_SELECTION = 'secureai.scanSelection'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isMessage(value: unknown): value is ExtensionMessage {
  return isRecord(value) && typeof value.type === 'string' && value.type.startsWith('secureai.')
}

async function digestText(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function cacheKeyFor(input: ScanInput): Promise<string> {
  if ('sourceUrl' in input) return `url:${input.sourceUrl}`
  return `content:${await digestText(input.content)}`
}

function pruneCache(entries: VerdictCacheEntry[], now: number): VerdictCacheEntry[] {
  return entries.filter((entry) => entry.expiresAt > now)
}

async function readCached(input: ScanInput, settings: ExtensionSettings): Promise<ScanResult | null> {
  const now = Date.now()
  const key = await cacheKeyFor(input)
  const entries = pruneCache(await loadVerdictCache(), now)
  const found = entries.find((entry) => entry.key === key)
  await saveVerdictCache(entries)
  if (found === undefined || found.expiresAt <= now) return null
  if (settings.verdictCacheTtlMs <= 0) return null
  return found.result
}

async function writeCached(input: ScanInput, result: ScanResult, settings: ExtensionSettings): Promise<void> {
  if (settings.verdictCacheTtlMs <= 0) return
  const now = Date.now()
  const key = await cacheKeyFor(input)
  const entries = pruneCache(await loadVerdictCache(), now).filter((entry) => entry.key !== key)
  entries.unshift({ key, result, expiresAt: now + settings.verdictCacheTtlMs })
  await saveVerdictCache(entries.slice(0, 50))
}

async function applyDnr(result: ScanResult, settings: ExtensionSettings): Promise<void> {
  if (!settings.egressBlockEnabled) return
  const metadata = await loadDnrMetadata()
  const plan = buildDnrPlan(result, metadata, Date.now(), settings.dnrRuleBudget)
  if (plan.addRules.length === 0 && plan.removeRuleIds.length === 0) {
    await saveDnrMetadata(plan.metadata)
    return
  }
  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: plan.addRules,
    removeRuleIds: plan.removeRuleIds,
  })
  await saveDnrMetadata(plan.metadata)
  const lastRule = plan.addRules.at(-1)
  if (lastRule?.condition.urlFilter !== undefined) {
    await saveStats({ lastBlockedDestination: lastRule.condition.urlFilter })
  }
}

async function runScan(input: ScanInput): Promise<ScanOutcome> {
  const settings = await loadSettings()
  const cached = await readCached(input, settings)
  if (cached !== null) return { ok: true, result: cached }

  const outcome =
    typeof input.sourceUrl === 'string'
      ? await scanUrl(input.sourceUrl, {
          apiBase: settings.apiBase,
          apiKey: settings.apiKey,
          timeoutMs: settings.requestTimeoutMs,
        })
      : typeof input.content === 'string'
        ? await scanContent(input.content, {
            apiBase: settings.apiBase,
            apiKey: settings.apiKey,
            timeoutMs: settings.requestTimeoutMs,
          })
        : ({ ok: false, reason: 'invalid-input', message: 'missing scan input', failClosed: true } as const)

  if (!outcome.ok) return outcome

  await writeCached(input, outcome.result, settings)
  await applyDnr(outcome.result, settings)
  const stats = await loadStats()
  await saveStats({ recentVerdicts: stats.recentVerdicts + 1 })
  return outcome
}

async function statePayload(): Promise<Record<string, unknown>> {
  const [settings, stats, rules] = await Promise.all([
    loadSettings(),
    loadStats(),
    chrome.declarativeNetRequest.getDynamicRules(),
  ])
  return {
    settings: { ...settings, apiKey: settings.apiKey.length > 0 ? 'stored' : '' },
    stats,
    dnrRuleCount: rules.length,
  }
}

async function validateKey(apiKey: string): Promise<ScanOutcome> {
  const settings = await loadSettings()
  return scanContent('SecureAI extension connection test', {
    apiBase: settings.apiBase,
    apiKey,
    timeoutMs: settings.requestTimeoutMs,
  })
}

function installContextMenus(): void {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: CONTEXT_MENU_LINK,
      title: 'Scan link with SecureAI',
      contexts: ['link'],
      targetUrlPatterns: ['http://*/*', 'https://*/*'],
    })
    chrome.contextMenus.create({
      id: CONTEXT_MENU_SELECTION,
      title: 'Scan selected text with SecureAI',
      contexts: ['selection'],
      documentUrlPatterns: ['http://*/*', 'https://*/*'],
    })
  })
}

chrome.runtime.onInstalled.addListener(() => {
  installContextMenus()
})

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === CONTEXT_MENU_LINK && typeof info.linkUrl === 'string') {
    void runScan({ sourceUrl: info.linkUrl })
    return
  }
  if (info.menuItemId === CONTEXT_MENU_SELECTION && typeof info.selectionText === 'string') {
    void runScan({ content: info.selectionText.slice(0, EXTENSION_CONFIG.maxContentChars) })
  }
})

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!isMessage(message)) return false

  void (async () => {
    if (message.type === 'secureai.getState') {
      sendResponse({ ok: true, ...(await statePayload()) })
      return
    }
    if (message.type === 'secureai.saveSettings') {
      const settings = await saveSettings(message.settings)
      sendResponse({ ok: true, settings: { ...settings, apiKey: settings.apiKey.length > 0 ? 'stored' : '' } })
      return
    }
    if (message.type === 'secureai.validateKey') {
      const outcome = await validateKey(message.apiKey)
      if (outcome.ok) await saveSettings({ apiKey: message.apiKey })
      sendResponse(outcome)
      return
    }
    if (message.type === 'secureai.scanUrl') {
      sendResponse(await runScan({ sourceUrl: message.sourceUrl }))
      return
    }
    if (message.type === 'secureai.scanContent') {
      sendResponse(await runScan({ content: message.content.slice(0, EXTENSION_CONFIG.maxContentChars) }))
      return
    }
    sendResponse({ ok: false, reason: 'parse', message: 'unknown SecureAI message', failClosed: true })
  })()

  return true
})
