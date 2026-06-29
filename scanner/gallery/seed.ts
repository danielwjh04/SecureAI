/**
 * The curated gallery seed: the fixed list of SKILL.md fixtures that the
 * hermetic gallery build (`scripts/build-gallery.ts`) scans into the static
 * `public/gallery.json` the SPA loads. Two realistic benign skills and two
 * crafted attacks, each pointing at a committed fixture under `./fixtures/`.
 *
 * This file is data only: it declares *what* to scan and how to label it. The
 * build script owns the recorded sponsor clients and the canned redirect
 * cascades that make each fixture resolve to its intended verdict, so this seed
 * stays free of any scan logic, adding a fixture is a one-line edit here plus
 * the matching recorded route in the build script.
 */

/** One curated gallery item: a fixture file plus its display metadata. */
export interface SeedItem {
  /** Stable, URL-safe identifier (used as the `GalleryEntry.id`). */
  id: string
  /** Human-readable card title shown in the gallery grid. */
  title: string
  /** Verdict-neutral classification driving the card's tag styling. */
  tag: 'benign' | 'attack'
  /** Fixture filename, relative to `gallery/fixtures/`. */
  file: string
}

/**
 * The ordered seed list. Order is the gallery display order and must stay
 * stable so the generated `gallery.json` is byte-stable across builds.
 */
export const SEED: SeedItem[] = [
  {
    id: 'pdf-summarizer',
    title: 'PDF Summarizer',
    tag: 'benign',
    file: 'benign-pdf-summarizer.md',
  },
  {
    id: 'weather-lookup',
    title: 'Weather Lookup',
    tag: 'benign',
    file: 'benign-weather-lookup.md',
  },
  {
    id: 'invoice-helper-redirect-cascade',
    title: 'Invoice Helper (redirect cascade)',
    tag: 'attack',
    file: 'attack-redirect-cascade.md',
  },
  {
    id: 'changelog-writer-prompt-injection',
    title: 'Changelog Writer (prompt injection)',
    tag: 'attack',
    file: 'attack-prompt-injection.md',
  },
]
