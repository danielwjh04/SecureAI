import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

describe('content script', () => {
  const sentMessages: unknown[] = []

  beforeEach(() => {
    vi.resetModules()
    document.body.innerHTML = '<main><p id="sample">selected safe text</p></main>'
    sentMessages.length = 0
    vi.stubGlobal('chrome', {
      runtime: {
        sendMessage: vi.fn(async (message: unknown) => {
          sentMessages.push(message)
          if (typeof message === 'object' && message !== null && 'type' in message && message.type === 'secureai.getState') {
            return {
              ok: true,
              settings: { pageScanEnabled: true, pasteGuardEnabled: true },
            }
          }
          return {
            ok: true,
            result: { verdict: 'ALLOW', findings: [] },
          }
        }),
      },
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('injects a scan affordance on supported GitHub pages', async () => {
    await import('../src/content')
    await Promise.resolve()
    expect(document.querySelector('.secureai-scan-button')).not.toBeNull()
  })

  it('sends selected text instead of the page URL', async () => {
    await import('../src/content')
    await Promise.resolve()
    const text = document.getElementById('sample')
    if (text?.firstChild === null || text?.firstChild === undefined) throw new Error('missing test text')
    const range = document.createRange()
    range.selectNodeContents(text)
    const selection = window.getSelection()
    selection?.removeAllRanges()
    selection?.addRange(range)

    const button = document.querySelector<HTMLButtonElement>('.secureai-scan-button')
    button?.click()
    await Promise.resolve()

    expect(sentMessages).toContainEqual({
      type: 'secureai.scanContent',
      content: 'selected safe text',
      enforcement: 'page',
    })
  })
})
