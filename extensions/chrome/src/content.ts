const SECUREAI_AI_HOSTS = new Set(['chatgpt.com', 'chat.openai.com', 'claude.ai', 'www.perplexity.ai'])
const SECUREAI_SCAN_HOSTS = new Set(['github.com', 'raw.githubusercontent.com'])
const SECUREAI_MAX_CONTENT_CHARS = 20000
const SECUREAI_EDITOR_SELECTOR = 'textarea, [contenteditable="true"], [role="textbox"]'
const secureAiAttachedEditors = new WeakSet<Element>()
let secureAiBypassNextEnter = false

type SecureAiOutcome =
  | { ok: true; result: { verdict: 'ALLOW' | 'HUMAN_APPROVAL_REQUIRED' | 'BLOCK'; findings: unknown[] } }
  | { ok: false; message: string; failClosed: true }

interface SecureAiState {
  ok: true
  settings: {
    pasteGuardEnabled: boolean
    pageScanEnabled: boolean
  }
}

function secureAiVerdictLabel(verdict: string): string {
  return verdict === 'HUMAN_APPROVAL_REQUIRED' ? 'REVIEW' : verdict
}

function secureAiToast(message: string, verdict: string = 'HUMAN_APPROVAL_REQUIRED'): void {
  const toast = document.createElement('div')
  toast.className = `secureai-toast secureai-toast--${verdict === 'BLOCK' ? 'block' : 'review'}`
  toast.innerHTML = `<strong>SecureAI ${secureAiVerdictLabel(verdict)}</strong><span></span>`
  const detail = toast.querySelector('span')
  if (detail !== null) detail.textContent = message
  document.documentElement.append(toast)
  window.setTimeout(() => toast.remove(), 6500)
}

async function secureAiSendScan(message: Record<string, unknown>): Promise<SecureAiOutcome> {
  return chrome.runtime.sendMessage<SecureAiOutcome>(message)
}

function secureAiEditorText(editor: Element): string {
  if (editor instanceof HTMLTextAreaElement || editor instanceof HTMLInputElement) {
    return editor.value
  }
  return editor.textContent ?? ''
}

function secureAiInsertText(editor: Element, text: string): void {
  if (editor instanceof HTMLTextAreaElement || editor instanceof HTMLInputElement) {
    const start = editor.selectionStart ?? editor.value.length
    const end = editor.selectionEnd ?? editor.value.length
    editor.setRangeText(text, start, end, 'end')
    editor.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text }))
    return
  }
  editor.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, cancelable: true, inputType: 'insertText', data: text }))
  document.execCommand('insertText', false, text)
}

async function secureAiEnforceContent(content: string, action: 'paste' | 'submit'): Promise<boolean> {
  const trimmed = content.trim()
  if (trimmed.length === 0) return true
  const outcome = await secureAiSendScan({
    type: 'secureai.scanContent',
    content: trimmed.slice(0, SECUREAI_MAX_CONTENT_CHARS),
    enforcement: action,
  })
  if (!outcome.ok) {
    secureAiToast(outcome.message, 'BLOCK')
    return false
  }
  if (outcome.result.verdict === 'BLOCK') {
    secureAiToast('Blocked before this content reached the AI page.', 'BLOCK')
    return false
  }
  if (outcome.result.verdict === 'HUMAN_APPROVAL_REQUIRED') {
    return window.confirm('SecureAI flagged this content for review. Continue anyway?')
  }
  return true
}

function secureAiAttachEditor(editor: Element): void {
  if (secureAiAttachedEditors.has(editor)) return
  secureAiAttachedEditors.add(editor)

  editor.addEventListener(
    'paste',
    (event) => {
      const clipboard = event instanceof ClipboardEvent ? event.clipboardData?.getData('text/plain') : null
      if (clipboard === null || clipboard === undefined || clipboard.length === 0) return
      event.preventDefault()
      void (async () => {
        if (await secureAiEnforceContent(clipboard, 'paste')) {
          secureAiInsertText(editor, clipboard)
        }
      })()
    },
    true,
  )

  editor.addEventListener(
    'keydown',
    (event) => {
      if (!(event instanceof KeyboardEvent)) return
      if (secureAiBypassNextEnter) {
        secureAiBypassNextEnter = false
        return
      }
      if (event.key !== 'Enter' || event.shiftKey) return
      const text = secureAiEditorText(editor)
      event.preventDefault()
      void (async () => {
        if (await secureAiEnforceContent(text, 'submit')) {
          secureAiBypassNextEnter = true
          editor.dispatchEvent(
            new KeyboardEvent('keydown', {
              key: 'Enter',
              bubbles: true,
              cancelable: true,
              ctrlKey: event.ctrlKey,
              metaKey: event.metaKey,
            }),
          )
        }
      })()
    },
    true,
  )
}

function secureAiAttachEditors(): void {
  for (const editor of document.querySelectorAll(SECUREAI_EDITOR_SELECTOR)) {
    secureAiAttachEditor(editor)
  }
}

function secureAiResultSummary(outcome: SecureAiOutcome): string {
  if (!outcome.ok) return outcome.message
  const count = outcome.result.findings.length
  const noun = count === 1 ? 'finding' : 'findings'
  return `${secureAiVerdictLabel(outcome.result.verdict)} with ${count} ${noun}`
}

async function secureAiScanCurrentPage(): Promise<void> {
  const selection = window.getSelection()?.toString().trim() ?? ''
  const message =
    selection.length > 0
      ? { type: 'secureai.scanContent', content: selection.slice(0, SECUREAI_MAX_CONTENT_CHARS), enforcement: 'page' }
      : { type: 'secureai.scanUrl', sourceUrl: window.location.href, enforcement: 'page' }
  const outcome = await secureAiSendScan(message)
  const verdict = outcome.ok ? outcome.result.verdict : 'BLOCK'
  secureAiToast(secureAiResultSummary(outcome), verdict)
}

function secureAiInstallScanButton(): void {
  if (!SECUREAI_SCAN_HOSTS.has(window.location.hostname)) return
  if (document.querySelector('.secureai-scan-button') !== null) return
  const button = document.createElement('button')
  button.type = 'button'
  button.className = 'secureai-scan-button'
  button.textContent = 'Scan with SecureAI'
  button.addEventListener('click', () => {
    void secureAiScanCurrentPage()
  })
  const target = document.querySelector('main, #repo-content-pjax-container, body')
  target?.prepend(button)
}

async function secureAiBoot(): Promise<void> {
  const state = await chrome.runtime.sendMessage<SecureAiState>({ type: 'secureai.getState' })
  if (state.ok && state.settings.pageScanEnabled) secureAiInstallScanButton()
  if (state.ok && state.settings.pasteGuardEnabled && SECUREAI_AI_HOSTS.has(window.location.hostname)) {
    secureAiAttachEditors()
    const observer = new MutationObserver(() => secureAiAttachEditors())
    observer.observe(document.documentElement, { childList: true, subtree: true })
  }
}

void secureAiBoot()
