import type { ExtensionSettings, ScanOutcome } from './types'

interface StateResponse {
  ok: true
  settings: ExtensionSettings & { apiKey: 'stored' | '' }
  stats: { recentVerdicts: number; lastBlockedDestination: string | null }
  dnrRuleCount: number
}

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id)
  if (element === null) throw new Error(`missing popup element ${id}`)
  return element as T
}

function setStatus(message: string): void {
  byId<HTMLElement>('status').textContent = message
}

function setChecked(id: string, checked: boolean): void {
  byId<HTMLInputElement>(id).checked = checked
}

function renderState(state: StateResponse): void {
  byId<HTMLElement>('connection').textContent = state.settings.apiKey === 'stored' ? 'Paired' : 'Not paired'
  setChecked('pasteGuard', state.settings.pasteGuardEnabled)
  setChecked('pageScan', state.settings.pageScanEnabled)
  setChecked('egressBlock', state.settings.egressBlockEnabled)
  byId<HTMLElement>('recentCount').textContent = String(state.stats.recentVerdicts)
  byId<HTMLElement>('dnrCount').textContent = String(state.dnrRuleCount)
  byId<HTMLElement>('lastBlocked').textContent = state.stats.lastBlockedDestination ?? 'None'
}

async function loadState(): Promise<void> {
  const state = await chrome.runtime.sendMessage<StateResponse>({ type: 'secureai.getState' })
  if (state.ok) renderState(state)
}

async function saveToggle(id: string, key: keyof ExtensionSettings): Promise<void> {
  const checked = byId<HTMLInputElement>(id).checked
  await chrome.runtime.sendMessage({
    type: 'secureai.saveSettings',
    settings: { [key]: checked },
  })
  await loadState()
}

async function saveKey(): Promise<void> {
  const apiKey = byId<HTMLInputElement>('apiKey').value.trim()
  if (apiKey.length === 0) {
    setStatus('Enter an API key first.')
    return
  }
  setStatus('Checking key...')
  const result = await chrome.runtime.sendMessage<ScanOutcome>({
    type: 'secureai.validateKey',
    apiKey,
  })
  if (result.ok) {
    byId<HTMLInputElement>('apiKey').value = ''
    setStatus('Paired.')
    await loadState()
    return
  }
  setStatus(result.message)
}

function readPairingKey(): string | null {
  const params = new URLSearchParams(window.location.search)
  const keys = ['secureai_key', 'secureaiPairKey', 'key']
  for (const key of keys) {
    const value = params.get(key)
    if (value !== null && value.length > 0) return value
  }
  return null
}

document.addEventListener('DOMContentLoaded', () => {
  void loadState()

  const pairedKey = readPairingKey()
  if (pairedKey !== null) {
    byId<HTMLInputElement>('apiKey').value = pairedKey
  }

  byId<HTMLButtonElement>('saveKey').addEventListener('click', () => {
    void saveKey()
  })
  byId<HTMLInputElement>('pasteGuard').addEventListener('change', () => {
    void saveToggle('pasteGuard', 'pasteGuardEnabled')
  })
  byId<HTMLInputElement>('pageScan').addEventListener('change', () => {
    void saveToggle('pageScan', 'pageScanEnabled')
  })
  byId<HTMLInputElement>('egressBlock').addEventListener('change', () => {
    void saveToggle('egressBlock', 'egressBlockEnabled')
  })
})
