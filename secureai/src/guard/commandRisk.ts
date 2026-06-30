/**
 * Shell-command risk inspection for the guard capability policy. These helpers
 * read the RAW command text (not the executable-normalized tokens) so a secret
 * path passed as an argument is still seen, and decide write intent from shell
 * redirection so a config-file read is not over-flagged.
 */

/** Normalize a command for marker matching: backslashes to slashes, lowercased. */
function normalizeCommand(command: string): string {
  return command.replaceAll('\\', '/').toLowerCase()
}

/**
 * True when the raw command references any sensitive-path marker (a secret file
 * or directory), whether read or written. Reading a secret is itself the risk.
 *
 * Time complexity: O(m) in marker count. Space complexity: O(1).
 */
export function commandTouchesSensitivePath(
  command: string,
  sensitiveMarkers: ReadonlySet<string>,
): boolean {
  const normalized = normalizeCommand(command)
  for (const marker of sensitiveMarkers) {
    if (normalized.includes(marker)) {
      return true
    }
  }
  return false
}
