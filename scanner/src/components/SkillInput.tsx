/**
 * The scan entry point: a mono SKILL.md paste box plus a secondary source-URL
 * input, and one primary "Scan skill" action. Exactly one input path is sent —
 * pasted text takes precedence; otherwise a trimmed URL is used. Every control
 * is inert while a scan is in flight (`busy`) so a single run can't be
 * double-submitted.
 */

import { useState } from 'react'
import type { FormEvent } from 'react'
import type { ScanRequest } from '../api/types'

interface SkillInputProps {
  /** Emits the request to scan. Exactly one of `content` / `sourceUrl` is set. */
  onScan: (request: ScanRequest) => void
  /** True while a scan is running; disables every control. */
  busy: boolean
}

export function SkillInput({ onScan, busy }: SkillInputProps) {
  const [content, setContent] = useState('')
  const [sourceUrl, setSourceUrl] = useState('')

  const trimmedContent = content.trim()
  const trimmedUrl = sourceUrl.trim()
  const canScan = !busy && (trimmedContent.length > 0 || trimmedUrl.length > 0)

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault()
    if (!canScan) return
    const request: ScanRequest =
      trimmedContent.length > 0 ? { content } : { sourceUrl: trimmedUrl }
    onScan(request)
  }

  return (
    <form className="scan-input" onSubmit={handleSubmit}>
      <textarea
        className="scan-input__area"
        value={content}
        onChange={(event) => setContent(event.target.value)}
        placeholder="Paste SKILL.md here…"
        spellCheck={false}
        disabled={busy}
        aria-label="SKILL.md content"
      />
      <input
        className="scan-input__url"
        type="url"
        value={sourceUrl}
        onChange={(event) => setSourceUrl(event.target.value)}
        placeholder="…or a source URL to fetch and scan"
        disabled={busy}
        aria-label="Source URL"
      />
      <div className="scan-input__actions">
        <span className="scan-input__hint">
          Paste the skill text, or point us at the URL your agent would fetch.
        </span>
        <button className="btn" type="submit" disabled={!canScan}>
          {busy ? 'Scanning…' : 'Scan skill'}
        </button>
      </div>
    </form>
  )
}
