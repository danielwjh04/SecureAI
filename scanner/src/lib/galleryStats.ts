/**
 * Honest, gallery-derived headline numbers shared by the landing surfaces that
 * show "live" counts (the Enterprise KPI row and the landing "Verify it
 * yourself" proof section). Both read the same committed public gallery and
 * derive the same numbers, so the fetch and the reduction live here once rather
 * than being duplicated per surface.
 */

import type { GalleryData } from '../api/types'
import { GALLERY_DATA_PATH } from '../config'

/** The empty dataset used whenever the gallery file is absent or unreadable. */
const EMPTY_GALLERY: GalleryData = { generatedAt: '', entries: [] }

/** Honest, gallery-derived numbers shown in the "live" stat rows. */
export interface GalleryStats {
  /** Skills present in the live public gallery. */
  skills: number
  /** Gallery entries whose verdict was BLOCK (threats caught). */
  threats: number
  /** Total sealed proof steps across every entry (cryptographic links). */
  proofLinks: number
}

/**
 * Fetch the prebuilt public gallery, degrading to an empty dataset on any
 * failure (a missing or malformed file is an expected, non-error state, so the
 * "live" stats simply read as zero rather than surfacing an error).
 *
 * Time complexity: O(n) in the response body size. Space complexity: O(n).
 */
export async function fetchGallery(): Promise<GalleryData> {
  let response: Response
  try {
    response = await fetch(GALLERY_DATA_PATH)
  } catch {
    return EMPTY_GALLERY
  }
  if (!response.ok) return EMPTY_GALLERY
  try {
    const data = (await response.json()) as GalleryData
    return Array.isArray(data.entries) ? data : EMPTY_GALLERY
  } catch {
    return EMPTY_GALLERY
  }
}

/**
 * Reduce a gallery dataset to honest headline numbers: how many skills are in
 * the live public gallery, how many came back BLOCK (threats caught), and the
 * total number of sealed proof steps across every entry (cryptographic links).
 *
 * Time complexity: O(e) over entries e. Space complexity: O(1).
 */
export function deriveStats(data: GalleryData): GalleryStats {
  let threats = 0
  let proofLinks = 0
  for (const entry of data.entries) {
    if (entry.result.verdict === 'BLOCK') threats += 1
    proofLinks += entry.result.proof.steps.length
  }
  return { skills: data.entries.length, threats, proofLinks }
}
