/**
 * Shell-command risk inspection for the guard capability policy. These helpers
 * inspect the raw command text (not the executable-normalized tokens) so a
 * sensitive path passed as an argument is still detected. Matching is
 * boundary-aware: a marker only hits when it is delimited by a path-ish
 * boundary (string start or end, or any non-alphanumeric character such as
 * slash, backslash, space, dot, quote, equals, or colon) so short markers like
 * "secret" do not fire inside longer words like "secretariat".
 */

/** Shell control and expansion characters that make a command non-simple. */
const SHELL_METACHARACTERS = ['&&', '||', '|', ';', '&', '$(', '${', '`', '>', '<']

/**
 * True when the command contains any shell control or expansion construct, so it
 * cannot be treated as a single safe command and must escalate to review.
 *
 * Time complexity: O(k) in metacharacter count. Space complexity: O(1).
 */
export function hasShellMetacharacters(command: string): boolean {
  return SHELL_METACHARACTERS.some((meta) => command.includes(meta))
}

/**
 * Split a command into words on whitespace, pipe, semicolon, and ampersand.
 *
 * Time complexity: O(n) in command length. Space complexity: O(w) in word count.
 */
export function tokenizeCommand(command: string): string[] {
  return command.split(/[\s|;&]+/).filter((word) => word.length > 0)
}

/** Normalize a command for marker matching: backslashes to slashes, lowercased. */
function normalizeCommand(command: string): string {
  return command.replaceAll('\\', '/').toLowerCase()
}

/**
 * True when the char at `index` in `text` is a path-ish boundary: either out
 * of range (start or end of string) or a non-alphanumeric character.
 *
 * Uses `String.prototype.charAt` which returns '' for out-of-range indices,
 * keeping this safe under noUncheckedIndexedAccess.
 *
 * Time complexity: O(1). Space complexity: O(1).
 */
function isBoundary(text: string, index: number): boolean {
  const ch = text.charAt(index)
  return ch === '' || !/[a-z0-9]/i.test(ch)
}

/**
 * True when any marker from the set appears in `normalized` surrounded by
 * path-ish boundaries on both sides. All inputs must already be normalized.
 *
 * Extracted so both `commandTouchesSensitivePath` and
 * `commandWritesToConfigPath` share the same boundary-aware matching logic,
 * preventing false positives such as "mypackage.json" triggering the
 * "package.json" marker.
 *
 * Time complexity: O(m * n) in marker count m and text length n.
 * Space complexity: O(1).
 */
function containsBoundedMarker(normalized: string, markers: ReadonlySet<string>): boolean {
  for (const marker of markers) {
    const normalizedMarker = normalizeCommand(marker)
    let searchFrom = 0
    while (searchFrom < normalized.length) {
      const index = normalized.indexOf(normalizedMarker, searchFrom)
      if (index === -1) {
        break
      }
      const beforeBound = isBoundary(normalized, index - 1)
      const afterBound = isBoundary(normalized, index + normalizedMarker.length)
      if (beforeBound && afterBound) {
        return true
      }
      searchFrom = index + 1
    }
  }
  return false
}

/**
 * True when the raw command references any sensitive-path marker (a secret file
 * or directory), whether read or written. Reading a secret is itself the risk.
 *
 * A marker matches only when it is surrounded by path-ish boundaries on both
 * sides, preventing false positives from short markers appearing inside longer
 * alphanumeric words (for example "secret" inside "secretariat").
 *
 * Time complexity: O(m * n) where m is marker count and n is command length.
 * Space complexity: O(1).
 */
export function commandTouchesSensitivePath(
  command: string,
  sensitiveMarkers: ReadonlySet<string>,
): boolean {
  if (command.length === 0 || sensitiveMarkers.size === 0) {
    return false
  }
  return containsBoundedMarker(normalizeCommand(command), sensitiveMarkers)
}

/** Shell redirection and copy operators that indicate the command writes a file. */
const WRITE_OPERATORS = ['>', '>>', 'tee ']

/**
 * True when the command writes (via redirection or tee) to a path that matches
 * any config-path marker. A plain read of a config file returns false.
 *
 * Marker matching is boundary-aware (reuses `containsBoundedMarker`) to prevent
 * false positives such as "mypackage.json" matching the "package.json" marker.
 *
 * Time complexity: O(m) in marker count. Space complexity: O(1).
 */
export function commandWritesToConfigPath(
  command: string,
  configMarkers: ReadonlySet<string>,
): boolean {
  const normalized = normalizeCommand(command)
  const hasWriteOp = WRITE_OPERATORS.some((op) => normalized.includes(op))
  if (!hasWriteOp) {
    return false
  }
  return containsBoundedMarker(normalized, configMarkers)
}
