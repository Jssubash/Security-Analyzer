/**
 * Derived security facts the `SEC-*` rules share.
 *
 * These exist so that "which roles can an unauthenticated visitor reach?" has exactly one
 * answer across the catalogue. The old rules each re-derived it, and inconsistently: SEC-003
 * matched `role.toLowerCase().includes('anonymous')` on the *module role's* name, SEC-006
 * matched the *user role's* name against a hardcoded marketplace list, and SEC-009 looked for
 * a module role literally called `user`. The first could find nothing, the second missed any
 * administrator role not on its list, and the third fired on unrelated grants.
 *
 * The real relationship is one step of indirection: a *user role* is granted *module roles*,
 * and a visitor who never logs in holds the guest user role's module roles. Everything below
 * is that one traversal, done once.
 */

import type { AccessRule, Activity, ApplicationIR, Attribute, Entity, Microflow, UserRole } from '@mendix-analyzer/application-ir';

/**
 * Attribute types that can carry a secret or a piece of PII.
 *
 * This is the structural corroboration §6.6 asks for before a name match is trusted. A
 * `Boolean` named `_showEmail` matches the PII term list and cannot possibly hold an email
 * address; without this guard it is reported as unencrypted personal data.
 */
const VALUE_BEARING_TYPES = new Set([
  'String',
  'Long',
  'Integer',
  'Decimal',
  'Enum',
  'HashedString',
]);

/** The user role an unauthenticated visitor holds, or `undefined` if guest access is off. */
export function guestUserRole(ir: ApplicationIR): UserRole | undefined {
  if (!ir.security.anonymousUserEnabled) return undefined;
  const named = ir.security.anonymousRole;
  return (
    (named ? ir.security.userRoles.find((r) => r.name === named) : undefined) ??
    ir.security.userRoles.find((r) => r.isAnonymous)
  );
}

/**
 * The qualified module roles an unauthenticated visitor holds.
 *
 * Empty when guest access is disabled, which is the correct answer: no rule should fire for
 * anonymous exposure on an app that has no anonymous access.
 */
export function guestModuleRoles(ir: ApplicationIR): Set<string> {
  const guest = guestUserRole(ir);
  if (!guest) return new Set();
  return new Set(guest.moduleRoles.map((m) => `${m.module}.${m.role}`));
}

/** Every qualified module role granted to at least one user role. */
export function grantedModuleRoles(ir: ApplicationIR): Set<string> {
  return new Set(
    ir.security.userRoles.flatMap((r) => r.moduleRoles.map((m) => `${m.module}.${m.role}`))
  );
}

/**
 * Whether findings about this module belong to the team that owns the app.
 *
 * Design §22 excludes marketplace and system modules: the team cannot edit them, so a finding
 * inside one is noise rather than an action. This is the model's own answer (`FromAppStore`),
 * not a name list — the previous name list both missed renamed marketplace modules and
 * mislabelled user modules whose names happened to collide.
 */
export function isUserModule(ir: ApplicationIR, moduleName: string | undefined): boolean {
  if (!moduleName) return false;
  const module = ir.modules[moduleName];
  if (!module) {
    // A module the inventory does not know about cannot be attributed either way; treating
    // it as third-party keeps the rule from blaming the team for something unidentified.
    return false;
  }
  return !module.isSystem && !module.isMarketplace;
}

/**
 * Whether a module belongs to the platform rather than to the app.
 *
 * `System` is the case that matters: it has no `Projects$Module` unit in `mprcontents` because
 * it is built into the runtime, so it is absent from the module inventory entirely. Absence is
 * therefore how a platform module presents, and a rule that reasons about grants has to know
 * that — `System.User` is granted to every user role by Mendix itself, so reporting it as a
 * third-party module role would fire on every project and could not be acted on if it did.
 */
export function isPlatformModule(ir: ApplicationIR, moduleName: string | undefined): boolean {
  if (!moduleName) return false;
  const module = ir.modules[moduleName];
  return module ? module.isSystem : true;
}

/** Whether a module role's name marks it as an administrator role. */
export function isAdministratorRole(roleName: string): boolean {
  return /admin/i.test(roleName);
}

/** Whether a module role is one of the roles designed for unauthenticated visitors. */
export function isGuestDesignatedRole(roleName: string): boolean {
  return /^(anonymous|guest)$/i.test(roleName);
}

/** Whether a name match on this attribute is corroborated by a type that can hold a value. */
export function canHoldSensitiveValue(attribute: Attribute): boolean {
  // An unreadable type is not evidence against the name match, so it is allowed through;
  // `attributeTypes` coverage records that the type could not be confirmed.
  return attribute.type === undefined || VALUE_BEARING_TYPES.has(attribute.type);
}

/** Attributes whose name classifies as a secret, corroborated by a value-bearing type. */
export function secretAttributes(entity: Entity): Attribute[] {
  return entity.attributes.filter((a) => a.isSensitive && canHoldSensitiveValue(a));
}

/** Attributes whose name classifies as PII, corroborated by a value-bearing type. */
export function piiAttributes(entity: Entity): Attribute[] {
  return entity.attributes.filter((a) => a.isPii && canHoldSensitiveValue(a));
}

/** An access rule paired with the entity it protects, for flat iteration. */
export interface EntityAccessRule {
  entity: Entity;
  rule: AccessRule;
  /** The rule's position on the entity, used to name a rule that has no readable `$ID`. */
  ordinal: number;
}

export function entityAccessRules(ir: ApplicationIR): EntityAccessRule[] {
  const pairs: EntityAccessRule[] = [];
  for (const entity of Object.values(ir.entities)) {
    entity.accessRules.forEach((rule, index) => {
      pairs.push({ entity, rule, ordinal: index + 1 });
    });
  }
  return pairs;
}

/** The module roles on a rule that a given set also contains. */
export function rolesInCommon(rule: AccessRule, roles: ReadonlySet<string>): string[] {
  return rule.moduleRoles.filter((r) => roles.has(r));
}

/**
 * The sensitivity label to show in a finding.
 *
 * Reported as a classification, never alongside the value — §5.1 forbids copying a credential
 * into an artifact that is persisted to `data/runs/*.json` and embedded in exported reports.
 */
export function sensitivityLabel(attribute: Attribute): string {
  if (attribute.isSensitive) return `secret (matched "${attribute.sensitivityTerm}")`;
  if (attribute.isPii) return `PII (matched "${attribute.sensitivityTerm}")`;
  return 'not classified';
}

/**
 * Whether an entity stores its objects, following the generalization chain.
 *
 * A specialization inherits persistability from its generalization, so a page built on a
 * specialization of a non-persistable entity is judged by the parent. An entity outside the IR
 * (`System.User`, `System.FileDocument`) is treated as persistable: the platform's own entities
 * are stored, and assuming otherwise would let a page on `System.User` pass as harmless.
 */
export function isPersistableEntity(ir: ApplicationIR, qualifiedName: string): boolean {
  const seen = new Set<string>();
  let current: Entity | undefined = ir.entities[qualifiedName];
  if (!current) return true;
  while (current) {
    if (seen.has(current.qualifiedName)) return true;
    seen.add(current.qualifiedName);
    if (!current.generalization) return current.persistenceType === 'persistable';
    const parent: Entity | undefined = ir.entities[current.generalization];
    if (!parent) return true;
    current = parent;
  }
  return true;
}

/**
 * Whether any access rule on the entity, or on an entity it specializes, is granted to one of
 * the given module roles. Mendix applies a generalization's access rules to its specializations.
 */
export function guestHasAccessTo(
  ir: ApplicationIR,
  qualifiedName: string,
  roles: ReadonlySet<string>
): boolean {
  const seen = new Set<string>();
  let current: Entity | undefined = ir.entities[qualifiedName];
  while (current && !seen.has(current.qualifiedName)) {
    seen.add(current.qualifiedName);
    if (current.accessRules.some((rule) => rule.moduleRoles.some((r) => roles.has(r)))) return true;
    current = current.generalization ? ir.entities[current.generalization] : undefined;
  }
  return false;
}

// ======================================================================== microflow exposure

/** Documents that put a microflow behind something a user clicks or opens in the browser. */
export const UI_REFERRERS = new Set(['Page', 'Snippet', 'Layout', 'NavigationDocument', 'BuildingBlock', 'PageTemplate']);

/** The roles that are neither administrators (by name) nor System roles. */
export function nonAdministrativeRoles(roles: readonly string[]): string[] {
  return roles.filter((qualified) => {
    const dot = qualified.indexOf('.');
    return qualified.slice(0, dot) !== 'System' && !isAdministratorRole(qualified.slice(dot + 1));
  });
}

/**
 * The pages, snippets, layouts and navigation items that start the microflow; `undefined` when
 * where-used was not read, so "not used from the UI" is never concluded from missing data.
 */
export function uiTriggers(mf: Microflow): { kind: string; qualifiedName: string }[] | undefined {
  return mf.referencedBy?.filter((r) => UI_REFERRERS.has(r.kind));
}

/**
 * Whether SEC-MF-001 reports this microflow: entity access off, allowed for a non-administrative
 * role, and started from the UI. SEC-028 leaves these to SEC-MF-001 so one problem is reported once.
 */
export function isUserFacingWithoutEntityAccess(ir: ApplicationIR, mf: Microflow): boolean {
  if (mf.appliesEntityAccess !== false || isPlatformModule(ir, mf.module)) return false;
  if (nonAdministrativeRoles(mf.allowedRoles).length === 0) return false;
  return (uiTriggers(mf)?.length ?? 0) > 0;
}

/**
 * What a microflow itself does with stored data, which is what decides how much "Apply entity
 * access" off matters:
 *
 *   - `writes`: creates, changes, deletes or commits objects of a persistable entity;
 *   - `reads`: retrieves a persistable entity from the database, and writes nothing;
 *   - `calls`: no data step of its own, but calls other microflows, which may have some;
 *   - `none`: touches no stored data, so the setting changes nothing today.
 *
 * `undefined` when microflow contents were not read: the caller then keeps its default severity.
 * A step whose entity cannot be resolved counts as stored data — the cautious reading.
 */
export type DataAccess = 'writes' | 'reads' | 'calls' | 'none';

const WRITES = new Set(['CreateAction', 'ChangeAction', 'DeleteAction', 'CommitAction']);

export function dataAccess(ir: ApplicationIR, mf: Microflow): { level: DataAccess; steps: string[] } | undefined {
  if (ir.coverage?.microflowActivities === 'NOT_ANALYZABLE') return undefined;
  const stored = (a: Activity) => a.targetEntity === undefined || isPersistableEntity(ir, a.targetEntity);
  const describe = (a: Activity, verb: string) => `${verb} ${a.targetEntity ?? 'an object'}`;
  const writes = mf.activities.filter((a) => WRITES.has(a.type) && stored(a));
  if (writes.length > 0) {
    const verbs: Record<string, string> = { CreateAction: 'create', ChangeAction: 'change', DeleteAction: 'delete', CommitAction: 'commit' };
    return { level: 'writes', steps: writes.map((a) => describe(a, verbs[a.type] ?? a.type)) };
  }
  const reads = mf.activities.filter((a) => a.type === 'RetrieveAction' && a.properties['retrieveSource'] === 'database' && stored(a));
  if (reads.length > 0) return { level: 'reads', steps: reads.map((a) => describe(a, 'retrieve')) };
  const calls = mf.activities.filter((a) => a.type === 'MicroflowCall');
  if (calls.length > 0) {
    return { level: 'calls', steps: calls.map((a) => `call ${String(a.properties['callee'] ?? 'a microflow')}`) };
  }
  return { level: 'none', steps: [] };
}

/** "change Shop.Order, delete Shop.Line and 3 more" — distinct steps, at most three named. */
export function stepList(steps: string[]): string {
  const unique = [...new Set(steps)];
  return unique.length <= 3 ? unique.join(', ') : `${unique.slice(0, 3).join(', ')} and ${unique.length - 3} more`;
}
