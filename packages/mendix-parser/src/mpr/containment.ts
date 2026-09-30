/**
 * The model's containment tree, read from the `.mpr` SQLite database.
 *
 * A `.mxunit` file knows what it is but not where it lives: a `Security$ModuleSecurity`
 * unit lists module roles and never names its module, and a `Forms$Page` names itself but
 * not its module either. The `.mpr` holds that structure in one table:
 *
 *     Unit(UnitID BLOB PRIMARY KEY, ContainerID BLOB, ContainmentName TEXT, …)
 *
 * This is the replacement for the old parser's order-dependent role reconstruction
 * (`mpr-parser.ts:694-736`), which inferred ownership from the sequence units happened to
 * be scanned in. Ownership is recorded in the model; it does not need to be guessed.
 *
 * Verified against the reference fixture: 396 `Unit` rows for 396 unit files, and every
 * unit resolves to exactly one owning module.
 */

import { DatabaseSync } from 'node:sqlite';

import { formatGuid } from '../bson/accessors.js';

export interface ContainmentRecord {
  readonly unitId: string;
  readonly containerId?: string;
  /** The property of the container this unit occupies, e.g. `ModuleSecurity`, `Documents`. */
  readonly containmentName?: string;
}

export interface MprMetadata {
  readonly formatVersion?: number;
  /** The Studio Pro version that wrote the model, e.g. `11.12.4`. */
  readonly productVersion?: string;
  readonly buildVersion?: string;
}

export class ContainmentReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContainmentReadError';
  }
}

export class ContainmentTree {
  private readonly containerOfUnit = new Map<string, string>();
  private readonly containmentOfUnit = new Map<string, string>();
  private readonly childrenOfUnit = new Map<string, string[]>();
  public readonly unitCount: number;

  private constructor(
    public readonly metadata: MprMetadata,
    records: readonly ContainmentRecord[]
  ) {
    this.unitCount = records.length;
    for (const rec of records) {
      if (rec.containerId) {
        this.containerOfUnit.set(rec.unitId, rec.containerId);
        const siblings = this.childrenOfUnit.get(rec.containerId);
        if (siblings) siblings.push(rec.unitId);
        else this.childrenOfUnit.set(rec.containerId, [rec.unitId]);
      }
      if (rec.containmentName) this.containmentOfUnit.set(rec.unitId, rec.containmentName);
    }
  }

  /**
   * Read the containment tree from an `.mpr` file.
   *
   * @throws {ContainmentReadError} if the file is not a readable Mendix model database.
   *   Callers treat this as "containment is NOT_ANALYZABLE" rather than fatal: without it
   *   units cannot be attributed to modules, but the project-level security facts in
   *   `Security$ProjectSecurity` are still trustworthy on their own.
   */
  public static read(mprPath: string): ContainmentTree {
    let db: DatabaseSync;
    try {
      db = new DatabaseSync(mprPath, { readOnly: true });
    } catch (err) {
      throw new ContainmentReadError(
        `cannot open ${mprPath} as a SQLite database: ${describe(err)}`
      );
    }

    try {
      const metadata = readMetadata(db);
      const records: ContainmentRecord[] = [];
      for (const row of db.prepare('SELECT UnitID, ContainerID, ContainmentName FROM Unit').all()) {
        const unitId = toGuid(row['UnitID']);
        if (!unitId) continue; // a row with no usable primary key tells us nothing
        records.push({
          unitId,
          containerId: toGuid(row['ContainerID']),
          containmentName: typeof row['ContainmentName'] === 'string' && row['ContainmentName']
            ? row['ContainmentName']
            : undefined,
        });
      }
      return new ContainmentTree(metadata, records);
    } catch (err) {
      if (err instanceof ContainmentReadError) throw err;
      throw new ContainmentReadError(`cannot read the Unit table of ${mprPath}: ${describe(err)}`);
    } finally {
      try {
        db.close();
      } catch {
        // A close failure cannot invalidate data already read.
      }
    }
  }

  public containerOf(unitId: string): string | undefined {
    return this.containerOfUnit.get(unitId);
  }

  /** The container property this unit occupies, e.g. `ModuleSecurity` or `DomainModel`. */
  public containmentNameOf(unitId: string): string | undefined {
    return this.containmentOfUnit.get(unitId);
  }

  public childrenOf(unitId: string): readonly string[] {
    return this.childrenOfUnit.get(unitId) ?? [];
  }

  /**
   * Walk from `unitId` up to the root, yielding each ancestor's id.
   *
   * Cycle-guarded: a corrupt model that made a unit its own ancestor would otherwise hang
   * the analysis, and a hostile upload is exactly where that would show up.
   */
  public *ancestorsOf(unitId: string): Generator<string> {
    const seen = new Set<string>([unitId]);
    let current = this.containerOf(unitId);
    while (current && !seen.has(current)) {
      seen.add(current);
      yield current;
      current = this.containerOf(current);
    }
  }

  /**
   * The nearest ancestor (or `unitId` itself) that `isModule` accepts.
   *
   * The caller supplies the predicate because only the unit index knows which ids are
   * `Projects$ModuleImpl` units; keeping that knowledge out of here leaves this file
   * concerned solely with the shape of the tree.
   */
  public owningUnit(unitId: string, isOwner: (id: string) => boolean): string | undefined {
    if (isOwner(unitId)) return unitId;
    for (const ancestor of this.ancestorsOf(unitId)) {
      if (isOwner(ancestor)) return ancestor;
    }
    return undefined;
  }
}

function readMetadata(db: DatabaseSync): MprMetadata {
  try {
    const row = db
      .prepare('SELECT _FormatVersion, _ProductVersion, _BuildVersion FROM _MetaData')
      .get();
    if (!row) return {};
    return {
      formatVersion: typeof row['_FormatVersion'] === 'number' ? row['_FormatVersion'] : undefined,
      productVersion: typeof row['_ProductVersion'] === 'string' ? row['_ProductVersion'] : undefined,
      buildVersion: typeof row['_BuildVersion'] === 'string' ? row['_BuildVersion'] : undefined,
    };
  } catch {
    // An older or newer schema may not have this table; the version is a nice-to-have,
    // not a precondition for reading containment.
    return {};
  }
}

/** `UnitID` / `ContainerID` are 16-byte GUID blobs, matching the `.mxunit` filenames. */
function toGuid(value: unknown): string | undefined {
  if (value instanceof Uint8Array) return formatGuid(value);
  if (value instanceof ArrayBuffer) return formatGuid(new Uint8Array(value));
  if (typeof value === 'string' && value.length > 0) return value;
  return undefined;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
