export function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

const VERDICT_CLASS: Record<string, string> = {
  ALLOW: 'pill--allow',
  HUMAN_APPROVAL_REQUIRED: 'pill--approval',
  BLOCK: 'pill--block',
}

export function verdictClass(verdict: string): string {
  return VERDICT_CLASS[verdict] ?? 'pill--approval'
}

export function verdictLabel(verdict: string): string {
  return verdict === 'HUMAN_APPROVAL_REQUIRED' ? 'APPROVAL' : verdict
}

/**
 * Extract a display hostname from a URL string.
 *
 * Falls back to the raw input when the value is not a parseable absolute URL
 * (e.g. a bare host or a malformed redirect target), so the UI always renders
 * something rather than throwing.
 *
 * Time complexity: O(n) in the URL length. Space complexity: O(1).
 */
export function hostname(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return url
  }
}

/**
 * Shorten a hex digest for display as `head…tail`.
 *
 * Hashes shorter than the combined head+tail window are returned unchanged so
 * no characters are ever silently dropped.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
export function truncateHash(hex: string): string {
  const head = 8
  const tail = 6
  if (hex.length <= head + tail + 1) return hex
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`
}
