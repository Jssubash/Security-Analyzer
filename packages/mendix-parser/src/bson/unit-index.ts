/**
 * An index over a Mendix project's `mprcontents/**` model units.
 *
 * Two facts about the on-disk layout make this cheap, both verified against the
 * reference fixture (396/396 units):
 *
 *   1. Every unit file is named for its own `$ID`, stored at
 *      `mprcontents/<id[0:2]>/<id[2:4]>/<id>.mxunit`. Resolving a reference by ID is a
 *      path computation, not a search.
 *   2. `$Type` is a top-level scalar, so a unit can be classified by reading its header
 *      instead of its tree. Page units reach 3 MB; nothing should pay that to discover
 *      it is a page it does not need.
 *
 * Trees are therefore parsed lazily and cached. Parse failures are collected rather than
 * thrown: a single corrupt unit must degrade the affected facts to NOT_ANALYZABLE (see
 * docs/security.md §4.1), not abort the analysis of the other 395.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';

import { BsonParseError, parseBsonDocument, parseBsonHeader } from './reader.js';
import type { BsonDocument } from './reader.js';
import { elementId, elementType, walkDocuments } from './accessors.js';

/** Where a fact came from, so every Evidence can point at the model, not at a guess. */
export interface UnitProvenance {
  /** Path relative to the project root, e.g. `mprcontents/8a/76/8a76….mxunit`. */
  readonly unitPath: string;
  /** The unit's own `$ID`. */
  readonly unitId: string;
}

export interface UnitRef extends UnitProvenance {
  readonly absolutePath: string;
  readonly type: string;
  readonly sizeBytes: number;
}

export interface UnitParseFailure {
  readonly unitPath: string;
  readonly reason: string;
}

/** How much unit data the index is willing to hold in memory at once. */
const DEFAULT_TREE_CACHE_BUDGET_BYTES = 256 * 1024 * 1024;

export interface UnitIndexOptions {
  /** Cap on the total size of cached unit trees. Beyond it, the cache evicts. */
  treeCacheBudgetBytes?: number;
}

export class UnitIndex {
  private readonly byId = new Map<string, UnitRef>();
  private readonly byType = new Map<string, UnitRef[]>();
  private readonly trees = new Map<string, BsonDocument>();
  private readonly failures: UnitParseFailure[] = [];
  /** Units whose tree failed to parse, so a corrupt unit is re-read at most once. */
  private readonly failedTreeIds = new Set<string>();
  private readonly budgetBytes: number;
  private cachedBytes = 0;

  private constructor(
    public readonly projectRoot: string,
    public readonly mprContentsDir: string,
    options: UnitIndexOptions
  ) {
    this.budgetBytes = options.treeCacheBudgetBytes ?? DEFAULT_TREE_CACHE_BUDGET_BYTES;
  }

  /**
   * Scan `<projectRoot>/mprcontents` and classify every unit by `$Type`.
   *
   * Returns an index even when the directory is missing or every unit is unreadable —
   * callers inspect `unitCount` / `parseFailures` and set coverage accordingly.
   */
  public static build(
    projectRoot: string,
    mprContentsDir: string,
    options: UnitIndexOptions = {}
  ): UnitIndex {
    const index = new UnitIndex(projectRoot, mprContentsDir, options);
    let files: string[];
    try {
      files = [...collectUnitFiles(mprContentsDir)];
    } catch (err) {
      index.failures.push({
        unitPath: toPosix(relative(projectRoot, mprContentsDir)),
        reason: `mprcontents is not readable: ${describe(err)}`,
      });
      return index;
    }

    for (const absolutePath of files) {
      const unitPath = toPosix(relative(projectRoot, absolutePath));
      let bytes: Uint8Array;
      try {
        bytes = readFileSync(absolutePath);
      } catch (err) {
        index.failures.push({ unitPath, reason: `unreadable: ${describe(err)}` });
        continue;
      }

      let header: BsonDocument;
      try {
        header = parseBsonHeader(bytes);
      } catch (err) {
        index.failures.push({
          unitPath,
          reason: err instanceof BsonParseError ? err.message : describe(err),
        });
        continue;
      }

      const type = elementType(header);
      // The filename is authoritative for the ID (verified across the fixture), but fall
      // back to the parsed $ID so a renamed file still indexes correctly.
      const unitId = basename(absolutePath, '.mxunit') || elementId(header);
      if (!type || !unitId) {
        index.failures.push({
          unitPath,
          reason: `unit is missing ${!type ? '$Type' : '$ID'}; cannot be classified`,
        });
        continue;
      }

      const ref: UnitRef = { absolutePath, unitPath, unitId, type, sizeBytes: bytes.length };
      index.byId.set(unitId, ref);
      const bucket = index.byType.get(type);
      if (bucket) bucket.push(ref);
      else index.byType.set(type, [ref]);
    }

    return index;
  }

  public get unitCount(): number {
    return this.byId.size;
  }

  public get parseFailures(): readonly UnitParseFailure[] {
    return this.failures;
  }

  /** Distinct `$Type` values present, with counts. Useful for coverage diagnostics. */
  public typeHistogram(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const [type, refs] of this.byType) out[type] = refs.length;
    return out;
  }

  /** Units of a given `$Type`, e.g. `Security$ModuleSecurity`. Never throws. */
  public refsOfType(type: string): readonly UnitRef[] {
    return this.byType.get(type) ?? [];
  }

  public refById(unitId: string): UnitRef | undefined {
    return this.byId.get(unitId);
  }

  /**
   * The parsed tree for a unit, or `undefined` if it cannot be read.
   *
   * A failure is recorded once in `parseFailures` and then returns `undefined` on every
   * subsequent call, so a corrupt unit does not re-read the file per rule.
   */
  public tree(ref: UnitRef): BsonDocument | undefined {
    const cached = this.trees.get(ref.unitId);
    if (cached) return cached;
    if (this.failedTreeIds.has(ref.unitId)) return undefined;

    let doc: BsonDocument;
    try {
      doc = parseBsonDocument(readFileSync(ref.absolutePath));
    } catch (err) {
      this.failedTreeIds.add(ref.unitId);
      this.failures.push({
        unitPath: ref.unitPath,
        reason: err instanceof BsonParseError ? err.message : describe(err),
      });
      return undefined;
    }

    if (this.cachedBytes + ref.sizeBytes > this.budgetBytes) this.evictAll();
    this.trees.set(ref.unitId, doc);
    this.cachedBytes += ref.sizeBytes;
    return doc;
  }

  /**
   * Every readable unit of a type, paired with its provenance.
   *
   * This is the extractors' entry point: it yields lazily so a caller that only needs
   * the first match does not materialise the rest.
   */
  public *unitsOfType(type: string): Generator<{ tree: BsonDocument; ref: UnitRef }> {
    for (const ref of this.refsOfType(type)) {
      const tree = this.tree(ref);
      if (tree) yield { tree, ref };
    }
  }

  /** The single unit of a type that should be unique (`Security$ProjectSecurity`). */
  public soleUnitOfType(type: string): { tree: BsonDocument; ref: UnitRef } | undefined {
    for (const unit of this.unitsOfType(type)) return unit;
    return undefined;
  }

  /**
   * Every nested element of `$Type` across all units of `containerType`, with the
   * provenance of the unit it was found in.
   *
   * Access rules live nested inside domain-model units, and member access lives nested
   * inside those; a finding about one has to name the unit that holds it.
   */
  public *elementsOfType(
    containerType: string,
    nestedType: string
  ): Generator<{ element: BsonDocument; ref: UnitRef }> {
    for (const { tree, ref } of this.unitsOfType(containerType)) {
      for (const element of walkDocuments(tree)) {
        if (elementType(element) === nestedType) yield { element, ref };
      }
    }
  }

  /** Drop cached trees. The index (ids, types, sizes) is retained. */
  public evictAll(): void {
    this.trees.clear();
    this.cachedBytes = 0;
  }
}

function* collectUnitFiles(dir: string): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* collectUnitFiles(full);
    } else if (entry.isFile() && entry.name.endsWith('.mxunit')) {
      yield full;
    }
  }
}

function toPosix(p: string): string {
  return sep === '/' ? p : p.split(sep).join('/');
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
