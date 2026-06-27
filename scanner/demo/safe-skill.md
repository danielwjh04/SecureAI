---
name: commit-message-linter
description: Check a Git commit message against the Conventional Commits spec and suggest fixes.
version: 1.2.0
---

# Commit Message Linter

Validates a single commit message (or the most recent commit) against the
Conventional Commits specification and reports any violations with a suggested
correction. Read-only: it inspects the message text it is given and prints
feedback, nothing else.

## How it works

1. The commit message is split into header, body, and footer.
2. The header is checked for a valid `type(scope): description` form.
3. The type is matched against the allowed set (feat, fix, docs, style,
   refactor, perf, test, build, ci, chore, revert).
4. Line-length and imperative-mood heuristics are applied to the description.
5. A short report lists each issue alongside a suggested rewrite.

## References

- Specification: [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
- Linter reference: <https://github.com/conventional-changelog/commitlint>
- Convention background: https://github.com/angular/angular

## Notes

The skill only reads the commit text supplied to it. It makes no network
requests and never reads files outside the message under review, so no
credentials, environment variables, or repository contents ever leave the
machine.
