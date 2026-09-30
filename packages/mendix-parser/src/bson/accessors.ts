/**
 * Typed, non-guessing accessors over a parsed BSON tree.
 *
 * Every accessor returns `undefined` when the property is absent or is not of the
 * expected shape. That is deliberate and load-bearing: per docs/security.md §4, an
 * unreadable fact must surface as `undefined` so the coverage contract can mark it
 * NOT_ANALYZABLE. Defaulting a missing boolean to `false` here would silently turn
 * "we could not read the security level" into "security is disabled" — or worse,
 * the reverse.
 */

import type { BsonDocument, BsonValue } from './reader.js';

export function asDocument(v: BsonValue | undefined): BsonDocument | undefined {
  if (v === null || v === undefined) return undefined;
  if (typeof v !== 'object') return undefined;
  if (Array.isArray(v) || v instanceof Uint8Array) return undefined;
  return v;
}

export function str(doc: BsonDocument | undefined, key: string): string | undefined {
  const v = doc?.[key];
  return typeof v === 'string' ? v : undefined;
}

export function bool(doc: BsonDocument | undefined, key: string): boolean | undefined {
  const v = doc?.[key];
  return typeof v === 'boolean' ? v : undefined;
}

export function num(doc: BsonDocument | undefined, key: string): number | undefined {
  const v = doc?.[key];
  if (typeof v === 'number') return v;
  if (typeof v === 'bigint') return Number(v);
  return undefined;
}

export function subDoc(doc: BsonDocument | undefined, key: string): BsonDocument | undefined {
  return asDocument(doc?.[key]);
}

/**
 * An array property, with non-document members dropped.
 *
 * Mendix model collections are always arrays of documents; a stray scalar means the
 * property is not what the caller thinks it is, so skipping it is safer than coercing.
 */
export function docArray(doc: BsonDocument | undefined, key: string): BsonDocument[] {
  const v = doc?.[key];
  if (!Array.isArray(v)) return [];
  const out: BsonDocument[] = [];
  for (const item of v) {
    const d = asDocument(item);
    if (d) out.push(d);
  }
  return out;
}

/** An array of strings, e.g. `UserRole.ModuleRoles` (qualified `Module.Role` names). */
export function strArray(doc: BsonDocument | undefined, key: string): string[] {
  const v = doc?.[key];
  if (!Array.isArray(v)) return [];
  return v.filter((item): item is string => typeof item === 'string');
}

/**
 * Format a 16-byte `$ID` as a canonical GUID string.
 *
 * Mendix writes the GUID as raw little-endian .NET layout: the first three groups are
 * byte-swapped, the last two are not. Getting this wrong would not corrupt anything —
 * IDs are only ever compared to each other — but the string must be *stable* so that
 * cross-unit references resolve, and it must match what `mxcli bson` prints so the
 * oracle test is meaningful.
 */
export function formatGuid(bytes: Uint8Array): string | undefined {
  if (bytes.length !== 16) return undefined;
  const hex = (b: number) => b.toString(16).padStart(2, '0');
  const group = (idxs: number[]) => idxs.map((i) => hex(bytes[i])).join('');
  return [
    group([3, 2, 1, 0]),
    group([5, 4]),
    group([7, 6]),
    group([8, 9]),
    group([10, 11, 12, 13, 14, 15]),
  ].join('-');
}

/** The `$ID` of a model element, as a canonical GUID string. */
export function elementId(doc: BsonDocument | undefined): string | undefined {
  const v = doc?.['$ID'];
  if (v instanceof Uint8Array) return formatGuid(v);
  if (typeof v === 'string') return v;
  return undefined;
}

/** The `$Type` discriminator, e.g. `Security$ProjectSecurity`. */
export function elementType(doc: BsonDocument | undefined): string | undefined {
  return str(doc, '$Type');
}

/**
 * Walk every document in the tree, depth-first, including the root.
 *
 * Extractors use this to find nested elements whose containment path is irrelevant
 * (e.g. every `DomainModels$AccessRule` under a unit) while still having the parent
 * available when it is not.
 */
export function* walkDocuments(root: BsonDocument): Generator<BsonDocument> {
  yield root;
  for (const key of Object.keys(root)) {
    const v = root[key];
    if (Array.isArray(v)) {
      for (const item of v) {
        const d = asDocument(item);
        if (d) yield* walkDocuments(d);
      }
    } else {
      const d = asDocument(v);
      if (d) yield* walkDocuments(d);
    }
  }
}

/** Every descendant document whose `$Type` matches, root included. */
export function findByType(root: BsonDocument, type: string): BsonDocument[] {
  const out: BsonDocument[] = [];
  for (const d of walkDocuments(root)) {
    if (elementType(d) === type) out.push(d);
  }
  return out;
}
