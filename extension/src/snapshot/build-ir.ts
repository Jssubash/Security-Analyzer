/**
 * Build the Application IR from a model snapshot.
 *
 * This is the in-Studio-Pro counterpart of `packages/mendix-parser/src/build-ir.ts`, and it
 * follows the same two invariants (docs/security.md §4):
 *
 *   - Never invent. A fact that could not be read is `undefined`, and the facts a rule needs
 *     are recorded in `coverage` so the engine skips the rule instead of passing it.
 *   - Never keep a secret. Passwords arrive already redacted from the host; constant values
 *     that classify as secrets are dropped here before they reach the IR.
 *
 * Only the facts the `SEC-*` catalogue reads are populated. Everything else is present in the
 * shape the IR requires and marked NOT_ANALYZABLE in coverage where a rule could depend on it.
 */

import type {
  AccessRights,
  AccessRule,
  AdministratorAccount,
  Analyzability,
  ApplicationIR,
  Attribute,
  DemoUser,
  Entity,
  FactCoverage,
  IntegrationModel,
  JavaActionSummary,
  MemberAccessRule,
  Microflow,
  Module,
  ModuleRole,
  OperationsModel,
  Page,
  PasswordPolicy,
  ProjectType,
  RestEndpoint,
  SecurityLevel,
  SecurityModel,
  UserRole,
} from '@mendix-analyzer/application-ir';
import { classifySensitivity, isPlaceholderValue, resolveDataEntities } from '@mendix-analyzer/application-ir';

import {
  bool,
  child,
  children,
  has,
  isKind,
  isType,
  num,
  ref,
  secret,
  str,
  strList,
  typeOf,
  walk,
} from './accessors.js';
import { extractMicroflowBody } from './microflow-body.js';
import type { ModelSnapshot, RedactedSecret, SnapshotModule, SnapshotNode } from './types.js';

export const UNIT_TYPES = {
  projectSecurity: 'Security$ProjectSecurity',
  moduleSecurity: 'Security$ModuleSecurity',
  domainModel: 'DomainModels$DomainModel',
  page: 'Forms$Page',
  microflow: 'Microflows$Microflow',
  constant: 'Constants$Constant',
  navigation: 'Navigation$NavigationDocument',
  publishedRestService: 'Rest$PublishedRestService',
  snippet: 'Forms$Snippet',
  nanoflow: 'Microflows$Nanoflow',
} as const;

const SECURITY_LEVELS: readonly SecurityLevel[] = [
  'CheckNothing',
  'CheckFormsAndMicroflows',
  'CheckEverything',
];
const ACCESS_RIGHTS: readonly AccessRights[] = ['None', 'ReadOnly', 'ReadWrite'];
const HTTP_METHODS: readonly RestEndpoint['httpMethod'][] = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

/** The floor a production password policy should meet; docs/security.md §6.1. */
const PASSWORD_BASELINE_MIN_LENGTH = 8;

/** Where a finding can be opened in Studio Pro: logical artifact name → unit `$ID`. */
export type UnitLocator = Record<string, string>;

/**
 * The handful of facts every anonymous-access rule depends on, shown in the pane's Coverage tab.
 *
 * When a rule that should fire does not, the cause is almost always one of these reading as
 * empty — the guest role not found, or role references not read — so they are surfaced
 * directly rather than left for the user to infer from a pass.
 */
export interface ReadDiagnostics {
  guestAccessEnabled?: boolean;
  guestUserRole?: string;
  guestUserRoleFound: boolean;
  guestModuleRoles: string[];
  userRoles: { name: string; moduleRoleCount: number }[];
  entities: number;
  accessRules: number;
  accessRulesWithRoles: number;
  pages: number;
  pagesWithRoles: number;
  unitTypes?: Record<string, number>;
  unexpectedValueTypes?: Record<string, string>;
}

/**
 * A nanoflow's access settings. The IR's `Nanoflow` carries no allowed roles, and the Module
 * status view needs them, so they travel beside the IR rather than being bolted onto it.
 */
export interface NanoflowAccess {
  name: string;
  module: string;
  qualifiedName: string;
  allowedRoles: string[];
}

export interface SnapshotBuildResult {
  ir: ApplicationIR;
  units: UnitLocator;
  diagnostics: ReadDiagnostics;
  nanoflows: NanoflowAccess[];
  /**
   * Microflow and nanoflow qualified name → the names its contents refer to, including the flows
   * it calls. Absent when the host did not collect references (an older host), so "called by
   * nothing" is never inferred from missing data.
   */
  flowReferences?: Record<string, string[]>;
}

interface OwnedUnit {
  node: SnapshotNode;
  module: SnapshotModule;
}

export function buildIrFromSnapshot(snapshot: ModelSnapshot): SnapshotBuildResult {
  const notes: string[] = [...snapshot.notes];
  const units: UnitLocator = {};

  const owned = (type: string): OwnedUnit[] =>
    snapshot.modules.flatMap((module) =>
      module.units.filter((u) => isKind(u, type)).map((node) => ({ node, module }))
    );

  const modules = extractModules(snapshot);

  // ------------------------------------------------------------------ security
  const moduleRoleUnits = owned(UNIT_TYPES.moduleSecurity);
  const moduleRoles = extractModuleRoles(moduleRoleUnits, units, notes);
  const projectSecurityUnits = snapshot.projectUnits.filter((u) =>
    isType(u, UNIT_TYPES.projectSecurity)
  );
  const securityResult = extractSecurity(projectSecurityUnits[0], moduleRoles, notes);
  if (projectSecurityUnits[0]?.$ID) units['AppSecurity'] = projectSecurityUnits[0].$ID;

  // ------------------------------------------------------------------ domain model
  const domainModels = owned(UNIT_TYPES.domainModel);
  const entities = extractEntities(domainModels, units, notes);

  // ------------------------------------------------------------------ navigation + pages
  const navigation = snapshot.projectUnits.find((u) => isType(u, UNIT_TYPES.navigation));
  const profiles = navigation ? navigationProfiles(navigation) : [];
  if (!navigation) {
    notes.push('no navigation document was found, so no page was recognised as a home page');
  }
  const homePages = new Set(profiles.map((p) => p.homePage).filter((p): p is string => !!p));
  const pageUnits = owned(UNIT_TYPES.page);
  const pages = extractPages(pageUnits, securityResult.model, homePages, units, notes);

  // ------------------------------------------------------------------ flows, constants, services
  const microflowUnits = owned(UNIT_TYPES.microflow);
  const microflows = extractMicroflows(microflowUnits, units, notes);
  const modelReferences = indexReferences(snapshot, microflows);
  const nanoflowUnits = owned(UNIT_TYPES.nanoflow);
  resolvePageData(pages, pageUnits, microflows, nanoflowUnits, owned(UNIT_TYPES.snippet), entities);
  const nanoflows = extractNanoflowAccess(nanoflowUnits, units);
  const flowReferences = collectFlowReferences([...microflowUnits, ...nanoflowUnits]);
  const constantUnits = owned(UNIT_TYPES.constant);
  const operations = extractConstants(constantUnits, units);
  const serviceUnits = owned(UNIT_TYPES.publishedRestService);
  const integrations = extractPublishedServices(serviceUnits, notes);
  const javaActions = extractJavaActions(snapshot, modules);

  for (const entity of Object.values(entities)) modules[entity.module]?.entities.push(entity.qualifiedName);
  for (const page of Object.values(pages)) modules[page.module]?.pages.push(page.qualifiedName);
  for (const mf of Object.values(microflows)) modules[mf.module]?.microflows.push(mf.qualifiedName);

  // ------------------------------------------------------------------ coverage
  const coverage: FactCoverage = {
    projectSecurity: securityResult.analyzability,
    moduleRoles: moduleRoleUnits.length > 0 ? 'ANALYZED' : 'NOT_ANALYZABLE',
    entityAccessRules: domainModels.length > 0 ? 'ANALYZED' : 'NOT_ANALYZABLE',
    attributeTypes: domainModels.length > 0 ? 'ANALYZED' : 'NOT_ANALYZABLE',
    pageAccess: pageUnits.length > 0 ? 'ANALYZED' : 'NOT_ANALYZABLE',
    publishedServices: serviceUnits.length > 0 ? 'PARTIAL' : 'NOT_ANALYZABLE',
    // Allowed roles and entity-access settings are read; the activity graph is not.
    microflows: microflowUnits.length > 0 ? 'PARTIAL' : 'NOT_ANALYZABLE',
    microflowActivities: activityCoverage(microflowUnits),
    modelReferences: modelReferences ? 'ANALYZED' : 'NOT_ANALYZABLE',
    constants: 'ANALYZED',
    scheduledEvents: 'NOT_ANALYZABLE',
    notes,
  };
  if (moduleRoleUnits.length === 0) notes.push('no module security unit was found, so module roles could not be listed');
  if (domainModels.length === 0) notes.push('no domain model was found, so entity access could not be assessed');
  if (pageUnits.length === 0) notes.push('no page was found, so page access could not be assessed');
  if (serviceUnits.length === 0) {
    notes.push('the app publishes no REST services, so the published-endpoint check does not apply');
  }

  const applicationType = applicationTypeOf(profiles.map((p) => p.kind));
  const diagnostics = readDiagnostics(snapshot, securityResult, entities, pages);
  addReadWarnings(diagnostics, notes);

  const ir: ApplicationIR = {
    metadata: {
      name: snapshot.app.name,
      mendixVersion: snapshot.app.studioProVersion ?? 'unknown',
      applicationType,
      primaryMprPath: snapshot.app.directory ?? '',
      totalModules: Object.keys(modules).length,
      totalEntities: Object.keys(entities).length,
      totalMicroflows: Object.keys(microflows).length,
      totalNanoflows: 0,
      totalPages: Object.keys(pages).length,
    },
    coverage,
    modules,
    entities,
    // No SEC-* rule reads associations; they are not extracted in the extension.
    associations: [],
    microflows,
    nanoflows: {},
    pages,
    security: securityResult.model,
    integrations,
    customCode: {
      javaActions,
      javaScriptActions: [],
      vendorJars: [],
      widgetPackages: [],
    },
    operations,
    dependencyGraph: { nodes: [], edges: [], cycles: [], godModules: [] },
    generatedAt: snapshot.capturedAt,
  };

  return { ir, units, diagnostics, nanoflows, flowReferences };
}

function readDiagnostics(
  snapshot: ModelSnapshot,
  security: SecurityResult,
  entities: Record<string, Entity>,
  pages: Record<string, Page>
): ReadDiagnostics {
  const model = security.model;
  const guest = model.anonymousRole
    ? model.userRoles.find((r) => r.name === model.anonymousRole)
    : undefined;
  const rules = Object.values(entities).flatMap((e) => e.accessRules);
  const pageList = Object.values(pages);
  return {
    guestAccessEnabled: security.analyzability === 'NOT_ANALYZABLE' ? undefined : model.anonymousUserEnabled,
    guestUserRole: model.anonymousRole,
    guestUserRoleFound: guest !== undefined,
    guestModuleRoles: guest ? guest.moduleRoles.map((m) => `${m.module}.${m.role}`) : [],
    userRoles: model.userRoles.map((r) => ({ name: r.name, moduleRoleCount: r.moduleRoles.length })),
    entities: Object.keys(entities).length,
    accessRules: rules.length,
    accessRulesWithRoles: rules.filter((r) => r.moduleRoles.length > 0).length,
    pages: pageList.length,
    pagesWithRoles: pageList.filter((p) => p.allowedRoles.length > 0).length,
    unitTypes: snapshot.diagnostics?.unitTypes,
    unexpectedValueTypes: snapshot.diagnostics?.unexpectedValueTypes,
  };
}

/** Readings that are almost never true of a real app, reported as probable read failures. */
function addReadWarnings(d: ReadDiagnostics, notes: string[]): void {
  if (d.guestAccessEnabled && !d.guestUserRole) {
    notes.push('anonymous access is enabled but the anonymous user role could not be read, so anonymous-access rules could not find the guest role');
  } else if (d.guestAccessEnabled && !d.guestUserRoleFound) {
    notes.push(`anonymous access names user role "${d.guestUserRole}", which is not among the user roles read, so anonymous-access rules could not find the guest role`);
  }
  if (d.userRoles.length > 0 && d.userRoles.every((r) => r.moduleRoleCount === 0)) {
    notes.push('no user role lists any module role; Mendix requires at least System.User, so role references were probably not read');
  }
  if (d.accessRules > 0 && d.accessRulesWithRoles === 0) {
    notes.push(`${d.accessRules} entity access rules were read but none lists a module role, so role references on access rules were probably not read`);
  }
}

// ====================================================================== modules

function extractModules(snapshot: ModelSnapshot): Record<string, Module> {
  const modules: Record<string, Module> = {};
  for (const m of snapshot.modules) {
    const type = m.name === 'System' ? 'system' : m.fromAppStore ? 'marketplace' : 'user';
    modules[m.name] = {
      name: m.name,
      type,
      isSystem: type === 'system',
      isMarketplace: type === 'marketplace',
      entities: [],
      microflows: [],
      nanoflows: [],
      pages: [],
      dependencies: [],
    };
  }
  return modules;
}

// ====================================================================== security

interface SecurityResult {
  model: SecurityModel;
  analyzability: Analyzability;
}

function extractModuleRoles(
  unitsOfModules: OwnedUnit[],
  locator: UnitLocator,
  notes: string[]
): ModuleRole[] {
  const roles: ModuleRole[] = [];
  for (const { node, module } of unitsOfModules) {
    for (const role of children(node, 'ModuleRoles')) {
      const name = str(role, 'Name') ?? role.$Name;
      if (!name) {
        notes.push(`an unnamed module role in ${module.name} was skipped`);
        continue;
      }
      const qualifiedName = `${module.name}.${name}`;
      roles.push({
        name,
        module: module.name,
        qualifiedName,
        documentation: str(role, 'Description', 'Documentation') || undefined,
      });
      if (node.$ID) locator[qualifiedName] = node.$ID;
    }
  }
  return roles;
}

function extractSecurity(
  unit: SnapshotNode | undefined,
  moduleRoles: ModuleRole[],
  notes: string[]
): SecurityResult {
  if (!unit) {
    notes.push('no project security unit was found, so no project security setting could be read');
    return {
      analyzability: 'NOT_ANALYZABLE',
      model: {
        projectSecurityLevel: 'CheckNothing',
        isProductionReady: false,
        userRoles: [],
        moduleRoles,
        anonymousUserEnabled: false,
        demoUsers: [],
      },
    };
  }

  const rawLevel = str(unit, 'SecurityLevel');
  const level = SECURITY_LEVELS.find((l) => l === rawLevel);
  if (!level) {
    notes.push(
      rawLevel
        ? `the security level held the unrecognised value "${rawLevel}"; treated as unknown`
        : 'the security level could not be read'
    );
  }

  const passwordPolicy = extractPasswordPolicy(unit, notes);
  // Storage: `GuestUserRole`. Studio Pro's untyped model: `guestUserRoleName` (verified live, 11.12).
  const guestRoleName = ref(unit, 'GuestUserRole', 'GuestUserRoleName');
  const securityEnabled = bool(unit, 'CheckSecurity');
  if (securityEnabled === undefined) notes.push('CheckSecurity could not be read');
  const anonymousEnabled = bool(unit, 'EnableGuestAccess');
  if (anonymousEnabled === undefined) notes.push('EnableGuestAccess could not be read');

  const model: SecurityModel = {
    projectSecurityLevel: level ?? 'CheckNothing',
    isProductionReady: level === 'CheckEverything' && securityEnabled === true,
    userRoles: extractUserRoles(unit, guestRoleName, notes),
    moduleRoles,
    anonymousUserEnabled: anonymousEnabled ?? false,
    anonymousRole: guestRoleName,
    securityEnabled,
    strictMode: bool(unit, 'StrictMode'),
    strictPageUrlCheck: bool(unit, 'StrictPageUrlCheck'),
    administrator: extractAdministrator(unit, passwordPolicy, notes),
    demoUsersEnabled: bool(unit, 'EnableDemoUsers'),
    demoUsers: extractDemoUsers(unit),
    passwordPolicy,
  };

  return { model, analyzability: level ? 'ANALYZED' : 'PARTIAL' };
}

function extractUserRoles(
  unit: SnapshotNode,
  guestRoleName: string | undefined,
  notes: string[]
): UserRole[] {
  const raw = children(unit, 'UserRoles');
  if (raw.length === 0) notes.push('the project defines no user roles, or they could not be read');

  const roles: UserRole[] = [];
  for (const role of raw) {
    const name = str(role, 'Name') ?? role.$Name;
    if (!name) {
      notes.push('an unnamed user role was skipped');
      continue;
    }
    const grants: { module: string; role: string }[] = [];
    for (const qualified of strList(role, 'ModuleRoles')) {
      const dot = qualified.lastIndexOf('.');
      if (dot <= 0) {
        notes.push(`user role ${name} references "${qualified}", which is not a Module.Role name`);
        continue;
      }
      grants.push({ module: qualified.slice(0, dot), role: qualified.slice(dot + 1) });
    }
    const manageAllRoles = bool(role, 'ManageAllRoles');
    roles.push({
      name,
      moduleRoles: grants,
      manageableRoles: strList(role, 'ManageableRoles'),
      isAnonymous: guestRoleName !== undefined && name === guestRoleName,
      isAdministrator: (manageAllRoles ?? false) || /^admin/i.test(name),
      manageAllRoles,
      manageUsersWithoutRoles: bool(role, 'ManageUsersWithoutRoles'),
      checkSecurity: bool(role, 'CheckSecurity'),
    });
  }
  return roles;
}

function extractPasswordPolicy(unit: SnapshotNode, notes: string[]): PasswordPolicy | undefined {
  const policy = child(unit, 'PasswordPolicySettings', 'PasswordPolicy');
  if (!policy) {
    notes.push('the password policy could not be read, so password policy rules cannot be judged');
    return undefined;
  }
  return {
    minimumLength: num(policy, 'MinimumLength'),
    requireDigit: bool(policy, 'RequireDigit'),
    requireMixedCase: bool(policy, 'RequireMixedCase'),
    requireSymbol: bool(policy, 'RequireSymbol'),
  };
}

function extractAdministrator(
  unit: SnapshotNode,
  policy: PasswordPolicy | undefined,
  notes: string[]
): AdministratorAccount | undefined {
  const userName = str(unit, 'AdminUserName') || undefined;
  const userRole = ref(unit, 'AdminUserRole', 'AdminUserRoleName');
  const password = secret(unit, 'AdminPassword');

  if (userName === undefined && userRole === undefined && password === undefined) {
    notes.push('no administrator account settings could be read');
    return undefined;
  }
  const account: AdministratorAccount = { userName, userRole };
  if (password) {
    account.passwordLength = password.length;
    account.passwordIsWeak = isWeakPassword(password, policy);
  }
  return account;
}

/** The same judgement as the parser's `isWeakPassword`, made from redacted features. */
export function isWeakPassword(password: RedactedSecret, policy: PasswordPolicy | undefined): boolean {
  const minimumLength = Math.max(
    policy?.minimumLength ?? PASSWORD_BASELINE_MIN_LENGTH,
    PASSWORD_BASELINE_MIN_LENGTH
  );
  if (password.length < minimumLength) return true;
  if ((policy?.requireDigit ?? true) && !password.hasDigit) return true;
  if ((policy?.requireMixedCase ?? true) && !(password.hasLower && password.hasUpper)) return true;
  if ((policy?.requireSymbol ?? false) && !password.hasSymbol) return true;
  return false;
}

function extractDemoUsers(unit: SnapshotNode): DemoUser[] {
  return children(unit, 'DemoUsers').map((user) => {
    const password = secret(user, 'Password');
    return {
      userName: str(user, 'UserName') || undefined,
      entity: ref(user, 'Entity'),
      userRoles: strList(user, 'UserRoles'),
      hasPassword: password !== undefined && password.length > 0,
      passwordLength: password?.length,
    };
  });
}

// ====================================================================== domain model

function extractEntities(
  domainModels: OwnedUnit[],
  locator: UnitLocator,
  notes: string[]
): Record<string, Entity> {
  const entities: Record<string, Entity> = {};

  for (const { node, module } of domainModels) {
    for (const raw of children(node, 'Entities')) {
      const name = str(raw, 'Name') ?? raw.$Name;
      if (!name) {
        notes.push(`an unnamed entity in ${module.name} was skipped`);
        continue;
      }
      const qualifiedName = `${module.name}.${name}`;
      // Storage calls the element `MaybeGeneralization`; the metamodel calls it `generalization`.
      const generalization = child(raw, 'MaybeGeneralization', 'Generalization');
      const accessRules = children(raw, 'AccessRules');

      entities[qualifiedName] = {
        name,
        module: module.name,
        qualifiedName,
        persistenceType: persistenceOf(generalization),
        generalization: ref(generalization, 'Generalization'),
        specializations: [],
        attributes: children(raw, 'Attributes').map((a) => toAttribute(a, qualifiedName, notes)),
        indexes: [],
        accessRules: accessRules.map((r, i) => toAccessRule(r, qualifiedName, i, node.$ID)),
        isSecurityConfigured: accessRules.length > 0,
        hasOwnerAttribute: bool(generalization, 'HasOwnerAttr', 'HasOwner'),
        hasChangedByAttribute: bool(generalization, 'HasChangedByAttr', 'HasChangedBy'),
        documentation: str(raw, 'Documentation') || undefined,
        provenance: { unitPath: node.$ID ?? '', elementId: raw.$ID },
      };
      if (node.$ID) locator[qualifiedName] = node.$ID;
    }
  }

  for (const entity of Object.values(entities)) {
    if (!entity.generalization) continue;
    entities[entity.generalization]?.specializations.push(entity.qualifiedName);
  }
  return entities;
}

/**
 * A `NoGeneralization` carries `Persistable`; a `Generalization` does not, and inherits from its
 * parent. Absent means the Mendix default, persistable — the same reading as the parser.
 */
function persistenceOf(generalization: SnapshotNode | undefined): Entity['persistenceType'] {
  const persistable = bool(generalization, 'Persistable');
  if (persistable === undefined) return 'persistable';
  return persistable ? 'persistable' : 'non-persistable';
}

function toAttribute(raw: SnapshotNode, entityName: string, notes: string[]): Attribute {
  const name = str(raw, 'Name') ?? raw.$Name ?? '';
  // Storage keeps the current type under `NewType`; the metamodel calls it `type`.
  const typeNode = child(raw, 'NewType', 'Type');
  const discriminator = typeOf(typeNode);
  const match = discriminator ? /^DomainModels\$(.+)AttributeType$/.exec(discriminator) : null;
  const type = match ? match[1] : undefined;
  if (!type) notes.push(`the type of ${entityName}.${name || '(unnamed)'} could not be read`);

  const value = child(raw, 'Value');
  const sensitivity = classifySensitivity(name);
  return {
    name,
    type,
    length: num(typeNode, 'Length'),
    defaultValue: str(value, 'DefaultValue') || undefined,
    isCalculated: isType(value, 'DomainModels$CalculatedValue'),
    isSensitive: sensitivity.kind === 'secret',
    isPii: sensitivity.kind === 'pii',
    sensitivityKind: sensitivity.kind,
    sensitivityTerm: sensitivity.matchedTerm,
    documentation: str(raw, 'Documentation') || undefined,
  };
}

function toAccessRule(
  raw: SnapshotNode,
  entityName: string,
  ordinal: number,
  unitId: string | undefined
): AccessRule {
  const xPath = str(raw, 'XPathConstraint');
  return {
    id: raw.$ID ?? `${entityName}#AccessRule${ordinal + 1}`,
    // Storage: `AllowedModuleRoles`. Metamodel: `moduleRoles`.
    moduleRoles: strList(raw, 'AllowedModuleRoles', 'ModuleRoles'),
    allowCreate: bool(raw, 'AllowCreate') ?? false,
    allowDelete: bool(raw, 'AllowDelete') ?? false,
    defaultMemberAccess: accessRights(str(raw, 'DefaultMemberAccessRights')) ?? 'None',
    memberAccess: children(raw, 'MemberAccesses').map(toMemberAccess),
    xPathConstraint: xPath && xPath.length > 0 ? xPath : undefined,
    documentation: str(raw, 'Documentation') || undefined,
    provenance: { unitPath: unitId ?? '', elementId: raw.$ID },
  };
}

function toMemberAccess(raw: SnapshotNode): MemberAccessRule {
  const attribute = ref(raw, 'Attribute');
  const association = ref(raw, 'Association');
  const isAssociation = !attribute && !!association;
  return {
    attributeOrAssociation: (isAssociation ? association : attribute) ?? '',
    isAssociation,
    access: accessRights(str(raw, 'AccessRights')) ?? 'None',
  };
}

function accessRights(value: string | undefined): AccessRights | undefined {
  return ACCESS_RIGHTS.find((r) => r === value);
}

// ====================================================================== pages & navigation

interface NavigationProfile {
  kind?: string;
  homePage?: string;
}

function navigationProfiles(document: SnapshotNode): NavigationProfile[] {
  const profiles: NavigationProfile[] = [];
  for (const node of walk(document)) {
    const type = typeOf(node) ?? '';
    if (!/^Navigation\$(Native)?NavigationProfile$/.test(type)) continue;
    // Web profiles hold `homePage`; native profiles hold `nativeHomePage`.
    const home = child(node, 'HomePage', 'NativeHomePage');
    profiles.push({
      kind: str(node, 'Kind') ?? (type.includes('Native') ? 'NativePhone' : undefined),
      homePage: ref(home, 'Page'),
    });
  }
  return profiles;
}

function applicationTypeOf(kinds: (string | undefined)[]): ProjectType {
  const lowered = kinds.map((k) => (k ?? '').toLowerCase());
  if (lowered.some((k) => k.includes('native'))) return 'native';
  if (lowered.some((k) => k.includes('progressive') || k.includes('pwa'))) return 'pwa';
  return 'web';
}

function guestModuleRoleSet(security: SecurityModel): Set<string> | undefined {
  if (security.anonymousUserEnabled === false) return new Set();
  const guest = security.anonymousRole
    ? security.userRoles.find((r) => r.name === security.anonymousRole)
    : security.userRoles.find((r) => r.isAnonymous);
  if (!guest) return undefined;
  return new Set(guest.moduleRoles.map((m) => `${m.module}.${m.role}`));
}

function extractPages(
  pageUnits: OwnedUnit[],
  security: SecurityModel,
  homePages: ReadonlySet<string>,
  locator: UnitLocator,
  notes: string[]
): Record<string, Page> {
  const guestRoles = guestModuleRoleSet(security);
  if (!guestRoles) {
    notes.push('the guest user role could not be identified, so anonymous page reachability was not computed');
  }

  const pages: Record<string, Page> = {};
  for (const { node, module } of pageUnits) {
    const name = str(node, 'Name') ?? node.$Name;
    if (!name) continue;
    const qualifiedName = `${module.name}.${name}`;
    // Storage: `AllowedModuleRoles`. Metamodel: `allowedRoles`.
    const allowedRoles = strList(node, 'AllowedModuleRoles', 'AllowedRoles');
    pages[qualifiedName] = {
      name,
      module: module.name,
      qualifiedName,
      totalWidgets: 0,
      widgets: [],
      allowedRoles,
      isAccessibleAnonymously: guestRoles ? allowedRoles.some((r) => guestRoles.has(r)) : false,
      isNavigationHomePage: homePages.has(qualifiedName),
      navigationPath: str(node, 'Url') || undefined,
      documentation: str(node, 'Documentation') || undefined,
      provenance: { unitPath: node.$ID ?? '', elementId: node.$ID },
    };
    if (node.$ID) locator[qualifiedName] = node.$ID;
  }
  return pages;
}

// ====================================================================== microflows

/**
 * Whether microflow bodies were read. A host that copies microflows shallowly (older builds) sends
 * no object collection, and rules that need activities must then be skipped, not passed.
 */
function activityCoverage(flowUnits: OwnedUnit[]): Analyzability {
  if (flowUnits.length === 0) return 'NOT_ANALYZABLE';
  const withBody = flowUnits.filter(({ node }) => child(node, 'ObjectCollection') !== undefined).length;
  if (withBody === 0) return 'NOT_ANALYZABLE';
  return withBody === flowUnits.length ? 'ANALYZED' : 'PARTIAL';
}

/**
 * Fill each microflow's `referencedBy` from the host's reference index, and from Java action
 * source that names it (`Core.microflowCall("Module.Name")`). Returns false when the snapshot has
 * no index, so "referenced by nothing" is never concluded from missing data.
 */
function indexReferences(snapshot: ModelSnapshot, microflows: Record<string, Microflow>): boolean {
  if (!snapshot.referenceIndex) return false;
  const byName = new Map<string, { qualifiedName: string; kind: string }[]>();
  for (const name of Object.keys(microflows)) byName.set(name, []);
  for (const entry of snapshot.referenceIndex) {
    for (const reference of new Set(entry.references)) {
      if (reference === entry.referrer) continue;
      byName.get(reference)?.push({ qualifiedName: entry.referrer, kind: entry.kind });
    }
  }
  for (const file of snapshot.javaSources) {
    for (const [name, list] of byName) {
      if (file.content.includes(`"${name}"`)) list.push({ qualifiedName: file.relativePath, kind: 'JavaSource' });
    }
  }
  for (const [name, list] of byName) {
    list.sort((a, b) => a.qualifiedName.localeCompare(b.qualifiedName));
    microflows[name].referencedBy = list;
  }
  return true;
}

function extractMicroflows(flowUnits: OwnedUnit[], locator: UnitLocator, notes: string[]): Record<string, Microflow> {
  const microflows: Record<string, Microflow> = {};
  const unknown = new Set<string>();
  for (const { node, module } of flowUnits) {
    const name = str(node, 'Name') ?? node.$Name;
    if (!name) continue;
    const qualifiedName = `${module.name}.${name}`;
    const body = extractMicroflowBody(node);
    for (const kind of body?.unknownActions ?? []) unknown.add(kind);
    microflows[qualifiedName] = {
      name,
      module: module.name,
      qualifiedName,
      returnType: 'Unknown',
      parameters: body?.parameters ?? [],
      activities: body?.activities ?? [],
      cyclomaticComplexity: 0,
      hasErrorHandling: false,
      callsMicroflows: [],
      callsJavaActions: [],
      retrievesInsideLoops: [],
      commitsInsideLoops: [],
      deletesInsideLoops: [],
      isExposedAsService: false,
      allowedRoles: strList(node, 'AllowedModuleRoles'),
      appliesEntityAccess: bool(node, 'ApplyEntityAccess'),
      returnEntity: returnEntityOf(node),
      documentation: str(node, 'Documentation') || undefined,
      provenance: { unitPath: node.$ID ?? '', elementId: node.$ID },
    };
    if (node.$ID) locator[qualifiedName] = node.$ID;
  }
  if (unknown.size > 0) {
    notes.push(`microflow activity types kept under their model names: ${[...unknown].sort().join(', ')}`);
  }
  return microflows;
}

function collectFlowReferences(flowUnits: OwnedUnit[]): Record<string, string[]> | undefined {
  const withRefs = flowUnits.filter(({ node }) => has(node, ['$References']));
  if (flowUnits.length > 0 && withRefs.length === 0) return undefined;
  const out: Record<string, string[]> = {};
  for (const { node, module } of withRefs) {
    const name = str(node, 'Name') ?? node.$Name;
    if (name) out[`${module.name}.${name}`] = strList(node, '$References');
  }
  return out;
}

function extractNanoflowAccess(nanoflowUnits: OwnedUnit[], locator: UnitLocator): NanoflowAccess[] {
  const out: NanoflowAccess[] = [];
  for (const { node, module } of nanoflowUnits) {
    const name = str(node, 'Name') ?? node.$Name;
    if (!name) continue;
    const qualifiedName = `${module.name}.${name}`;
    out.push({ name, module: module.name, qualifiedName, allowedRoles: strList(node, 'AllowedModuleRoles') });
    if (node.$ID) locator[qualifiedName] = node.$ID;
  }
  return out;
}

/** The entity a flow returns, from its return type (`DataTypes$ObjectType` / `ListType`). */
function returnEntityOf(node: SnapshotNode): string | undefined {
  return ref(child(node, 'MicroflowReturnType', 'ReturnType'), 'Entity');
}

/**
 * Set each page's `dataEntities` from the `$References` the host collected for it, resolved
 * through snippets and data-source flows. A page without `$References` (a host that predates
 * them) keeps `dataEntities` undefined, so SEC-018 falls back to reachability rather than
 * reading "no references" as "no data".
 */
function resolvePageData(
  pages: Record<string, Page>,
  pageUnits: OwnedUnit[],
  microflows: Record<string, Microflow>,
  nanoflowUnits: OwnedUnit[],
  snippetUnits: OwnedUnit[],
  entities: Record<string, Entity>
): void {
  const flowReturnEntities = new Map<string, string | undefined>();
  for (const mf of Object.values(microflows)) flowReturnEntities.set(mf.qualifiedName, mf.returnEntity);
  for (const { node, module } of nanoflowUnits) {
    const name = str(node, 'Name') ?? node.$Name;
    if (name) flowReturnEntities.set(`${module.name}.${name}`, returnEntityOf(node));
  }
  const snippetReferences = new Map<string, string[]>();
  for (const { node, module } of snippetUnits) {
    const name = str(node, 'Name') ?? node.$Name;
    if (name && has(node, ['$References'])) snippetReferences.set(`${module.name}.${name}`, strList(node, '$References'));
  }
  const context = { entities: new Set(Object.keys(entities)), flowReturnEntities, snippetReferences };

  for (const { node, module } of pageUnits) {
    const name = str(node, 'Name') ?? node.$Name;
    const page = name ? pages[`${module.name}.${name}`] : undefined;
    if (!page || !has(node, ['$References'])) continue;
    page.dataEntities = resolveDataEntities(strList(node, '$References'), context);
  }
}

// ====================================================================== constants

function extractConstants(constantUnits: OwnedUnit[], locator: UnitLocator): OperationsModel {
  const constants: OperationsModel['constants'] = [];
  for (const { node, module } of constantUnits) {
    const name = str(node, 'Name') ?? node.$Name;
    if (!name) continue;
    const sensitivity = classifySensitivity(name);
    const isSecretShaped = sensitivity.kind === 'secret';
    const rawValue = str(node, 'DefaultValue');
    const typeMatch = /^DataTypes\$(.+)Type$/.exec(typeOf(child(node, 'Type')) ?? '');

    constants.push({
      name,
      module: module.name,
      dataType: typeMatch ? typeMatch[1] : 'Unknown',
      // A placeholder such as "changeme" is not a stored secret, so it does not count as a value.
      hasDefaultValue: rawValue !== undefined && rawValue.length > 0 && !isPlaceholderValue(rawValue),
      // The value of a secret-shaped constant is dropped here and never reaches the IR.
      defaultValue: isSecretShaped ? undefined : rawValue || undefined,
      isExposedToClient: bool(node, 'ExposedToClient') ?? false,
    });
    if (node.$ID) locator[`${module.name}.${name}`] = node.$ID;
  }
  return { constants, scheduledEvents: [] };
}

// ====================================================================== published REST services

/**
 * Published REST services, for SEC-004.
 *
 * The reference project publishes none, so this mapping is not yet verified against a real
 * service. It is written to fail quiet rather than loud: a service whose authentication setting
 * cannot be read is skipped with a note, because reporting it as "no authentication" would be a
 * Critical finding built on a missing property.
 */
function extractPublishedServices(serviceUnits: OwnedUnit[], notes: string[]): IntegrationModel {
  const publishedRestServices: IntegrationModel['publishedRestServices'] = [];

  for (const { node, module } of serviceUnits) {
    const name = str(node, 'Name') ?? node.$Name ?? '(unnamed)';
    if (!has(node, ['AuthenticationTypes'])) {
      notes.push(`the authentication setting of published REST service ${module.name}.${name} could not be read; it was not assessed`);
      continue;
    }
    const authTypes = strList(node, 'AuthenticationTypes');
    const requiresAuthentication = authTypes.length > 0;
    const authType: RestEndpoint['authType'] = !requiresAuthentication
      ? 'None'
      : authTypes.includes('Basic')
        ? 'Basic'
        : 'Custom';
    const servicePath = str(node, 'Path') ?? '';

    const endpoints: RestEndpoint[] = [];
    for (const resource of children(node, 'Resources')) {
      const resourceName = str(resource, 'Name') ?? '';
      for (const operation of children(resource, 'Operations')) {
        const method = (str(operation, 'HttpMethod') ?? 'Get').toUpperCase();
        const opPath = str(operation, 'Path') ?? '';
        endpoints.push({
          name: `${resourceName} ${method} ${opPath}`.trim(),
          module: module.name,
          path: [servicePath, resourceName, opPath].filter((s) => s.length > 0).join('/'),
          httpMethod: HTTP_METHODS.find((m) => m === method) ?? 'GET',
          microflow: ref(operation, 'Microflow') ?? '',
          requiresAuthentication,
          authType,
        });
      }
    }
    publishedRestServices.push({
      name,
      module: module.name,
      version: str(node, 'Version') ?? '',
      endpoints,
    });
  }

  if (serviceUnits.length > 0) {
    notes.push('published REST service authentication is read from the service-level setting; operation-level overrides are not assessed');
  }
  return { publishedRestServices, consumedRestServices: [], publishedODataServices: [] };
}

// ====================================================================== custom Java code

function extractJavaActions(
  snapshot: ModelSnapshot,
  modules: Record<string, Module>
): JavaActionSummary[] {
  const byLowerName = new Map(Object.keys(modules).map((m) => [m.toLowerCase(), m]));
  return snapshot.javaSources.map((file) => ({
    name: file.fileName.replace(/\.java$/i, ''),
    module: byLowerName.get(file.moduleDirectory.toLowerCase()) ?? file.moduleDirectory,
    sourceFile: file.relativePath,
    usesExternalLibraries: [],
    hasRegexXssSanitizer: usesRegexXssSanitizer(file.content),
  }));
}

/** Hand-rolled regex XSS filtering; the same test as the parser's filesystem extractor. */
export function usesRegexXssSanitizer(source: string): boolean {
  if (!/replaceAll\s*\(|replaceFirst\s*\(|Pattern\.compile/.test(source)) return false;
  return /<\s*script|javascript:|onerror\s*=|xss/i.test(source);
}
