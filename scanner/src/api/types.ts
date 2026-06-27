/**
 * The SPA's type surface. Re-exports the shared proof-core contract so every
 * component imports its types from one app-local path, then adds the gallery
 * shapes the SPA needs but the worker contract does not define.
 *
 * `contract.ts` is types-only, so it is re-exported with `export type *` (which
 * verbatimModuleSyntax requires for type-only modules). `proof.ts` also exports
 * runtime values (`verifyChain`, `ProofBuilder`), so its symbols are re-exported
 * with a plain `export *`.
 */

export type * from '../../shared/contract'
export * from '../../shared/proof'

import type { ScanResult } from '../../shared/contract'

/** One entry in the curated scan gallery (a recorded benign or attack scan). */
export interface GalleryEntry {
  id: string
  title: string
  tag: 'benign' | 'attack'
  result: ScanResult
}

/** The full gallery dataset loaded from {@link GALLERY_DATA_PATH}. */
export interface GalleryData {
  generatedAt: string
  entries: GalleryEntry[]
}
