/**
 * Name-tolerant, non-guessing readers over snapshot nodes.
 *
 * Every reader takes a list of candidate property names because the same fact is spelled
 * differently by Studio Pro's untyped API (metamodel names, e.g. `allowedRoles`) and by the
 * `.mxunit` storage format (e.g. `AllowedModuleRoles`). Matching is case-insensitive, so only
 * genuine renames need listing.
 *
 * As in the parser's BSON accessors, an absent or wrongly-shaped value is `undefined`, never a
 * plausible default: a missing boolean must surface as "unknown" so coverage can say so,
 * rather than silently becoming "disabled".
 */

import type { RedactedSecret, SnapshotNode, SnapshotValue } from './types.js';

export function isNode(value: unknown): value is SnapshotNode {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as { $Type?: unknown }).$Type === 'string'
  );
}

export function isRedacted(value: unknown): value is RedactedSecret {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { $redacted?: unknown }).$redacted === true
  );
}

/** The raw value of the first candidate property present on the node. */
export function raw(node: SnapshotNode | undefined, names: readonly string[]): SnapshotValue | undefined {
  if (!node) return undefined;
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(node, name)) return node[name];
  }
  const keys = Object.keys(node);
  for (const name of names) {
    const lower = name.toLowerCase();
    const key = keys.find((k) => k.toLowerCase() === lower);
    if (key !== undefined) return node[key];
  }
  return undefined;
}

/** Whether any candidate property exists at all, regardless of its value. */
export function has(node: SnapshotNode | undefined, names: readonly string[]): boolean {
  if (!node) return false;
  const lowered = names.map((n) => n.toLowerCase());
  return Object.keys(node).some((k) => lowered.includes(k.toLowerCase()));
}

/**
 * A string property. By-name references that are not set arrive from Studio Pro as `""`, so
 * callers that mean "a reference" should use {@link ref}, which maps `""` to `undefined`.
 */
export function str(node: SnapshotNode | undefined, ...names: string[]): string | undefined {
  const v = raw(node, names);
  return typeof v === 'string' ? v : undefined;
}

/** A by-name reference (qualified name), with the unset value `""` read as absent. */
export function ref(node: SnapshotNode | undefined, ...names: string[]): string | undefined {
  const r = raw(node, names);
  const v = typeof r === 'string' ? r : isNode(r) ? referenceName(r) : undefined;
  return v && v.length > 0 ? v : undefined;
}

export function bool(node: SnapshotNode | undefined, ...names: string[]): boolean | undefined {
  const v = raw(node, names);
  return typeof v === 'boolean' ? v : undefined;
}

export function num(node: SnapshotNode | undefined, ...names: string[]): number | undefined {
  const v = raw(node, names);
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

/** A single child element. Scalars under the same name are ignored, not coerced. */
export function child(node: SnapshotNode | undefined, ...names: string[]): SnapshotNode | undefined {
  if (!node) return undefined;
  // Several names can exist on one node with different shapes (an entity has both a
  // `generalization` element in the metamodel and, inside it, a `generalization` reference),
  // so take the first candidate that actually holds an element.
  for (const name of names) {
    const v = raw(node, [name]);
    if (isNode(v)) return v;
  }
  return undefined;
}

/** A list of child elements; non-element members are dropped. */
export function children(node: SnapshotNode | undefined, ...names: string[]): SnapshotNode[] {
  if (!node) return [];
  for (const name of names) {
    const v = raw(node, [name]);
    if (Array.isArray(v)) return v.filter(isNode);
  }
  return [];
}

/**
 * A list of strings, e.g. qualified `Module.Role` references. Empty entries are dropped.
 *
 * A reference that arrives as the referenced element rather than its name is read by the
 * element's qualified name. Dropping it instead would turn "this role holds that module role"
 * into "holds nothing" — which is how every anonymous-access rule once passed on an app whose
 * anonymous role was plainly exposed.
 */
export function strList(node: SnapshotNode | undefined, ...names: string[]): string[] {
  if (!node) return [];
  for (const name of names) {
    const v = raw(node, [name]);
    if (Array.isArray(v)) {
      return v
        .map((item) => (typeof item === 'string' ? item : isNode(item) ? referenceName(item) : undefined))
        .filter((item): item is string => item !== undefined && item.length > 0);
    }
  }
  return [];
}

/** The name a referenced element is known by. */
function referenceName(node: SnapshotNode): string | undefined {
  return node.$QualifiedName ?? node.$Name;
}

/** A redacted secret, or a plaintext string the caller must redact itself (test sources). */
export function secret(
  node: SnapshotNode | undefined,
  ...names: string[]
): RedactedSecret | undefined {
  const v = raw(node, names);
  if (isRedacted(v)) return v;
  if (typeof v === 'string') return redact(v);
  return undefined;
}

/** Reduce a secret to the features the weakness check needs, discarding the value. */
export function redact(value: string): RedactedSecret {
  return {
    $redacted: true,
    length: value.length,
    hasDigit: /[0-9]/.test(value),
    hasLower: /[a-z]/.test(value),
    hasUpper: /[A-Z]/.test(value),
    hasSymbol: /[^A-Za-z0-9]/.test(value),
  };
}

/**
 * A unit or element's `$Type`, with the storage-only `Impl` suffix removed.
 *
 * Storage writes `DomainModels$EntityImpl` and `Projects$ModuleImpl`; the metamodel calls the
 * same things `DomainModels$Entity` and `Projects$Module`.
 */
export function typeOf(node: SnapshotNode | undefined): string | undefined {
  if (!node) return undefined;
  return normaliseType(node.$Type);
}

export function normaliseType(type: string): string {
  return type.endsWith('Impl') ? type.slice(0, -'Impl'.length) : type;
}

export function isType(node: SnapshotNode | undefined, type: string): boolean {
  return typeOf(node) === normaliseType(type);
}

/**
 * Whether a unit is of a kind, matching only the part after `$`.
 *
 * Module units are matched this way because the namespace is not stable across sources: a page
 * is `Forms$Page` in `.mxunit` storage and `Pages$Page` in Studio Pro's untyped model API.
 */
export function isKind(node: SnapshotNode | undefined, type: string): boolean {
  const own = typeOf(node);
  if (!own) return false;
  const local = (t: string) => t.slice(t.indexOf('$') + 1);
  return local(own) === local(normaliseType(type));
}

/** Every element in the tree, depth-first, root included. */
export function* walk(root: SnapshotNode): Generator<SnapshotNode> {
  yield root;
  for (const key of Object.keys(root)) {
    const v = root[key];
    if (Array.isArray(v)) {
      for (const item of v) if (isNode(item)) yield* walk(item);
    } else if (isNode(v)) {
      yield* walk(v);
    }
  }
}
