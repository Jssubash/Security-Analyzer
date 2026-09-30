/**
 * Derived security facts the `SEC-*` rules share.
 *
 * These exist so that "which roles can an unauthenticated visitor reach?" has exactly one
 * answer across the catalogue. The old rules each re-derived it, and inconsistently: SEC-003
 * matched `role.toLowerCase().includes('anonymous')` on the *module role's* name, SEC-006
 * matched the *user role's* name against a hardcoded marketplace list, and SEC-009 looked for
 * a module role literally called `user`. On the reference project the first found nothing, the
 * second missed `Atlas_Core.Administrator`, and the third fired on an unrelated grant.
 *
 * The real relationship is one step of indirection: a *user role* is granted *module roles*,
 * and a visitor who never logs in holds the guest user role's module roles. Everything below
 * is that one traversal, done once.
 */

import type { AccessRule, ApplicationIR, Attribute, Entity, UserRole } from '@mendix-analyzer/application-ir';

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

/**
 * Module roles granted to more than one user role.
 *
 * §6.3 defines "broad" this way for SEC-021. A role held by several user roles is one whose
 * grants reach a wider audience than its name suggests, which is what makes a sensitive
 * member visible to people the modeller was not thinking about.
 */
export function broadModuleRoles(ir: ApplicationIR): Set<string> {
  const holders = new Map<string, Set<string>>();
  for (const userRole of ir.security.userRoles) {
    for (const moduleRole of userRole.moduleRoles) {
      const key = `${moduleRole.module}.${moduleRole.role}`;
      const set = holders.get(key);
      if (set) set.add(userRole.name);
      else holders.set(key, new Set([userRole.name]));
    }
  }
  return new Set([...holders].filter(([, names]) => names.size > 1).map(([key]) => key));
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
