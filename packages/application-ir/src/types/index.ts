/**
 * Canonical Mendix Application Intermediate Representation (IR)
 * Decoupled from Studio Pro, ZIP format, and database persistence.
 */

import type { SensitivityKind } from '../classifiers/sensitivity.js';
import type { FactCoverage } from './coverage.js';

export type ProjectType = 'web' | 'native' | 'hybrid' | 'pwa';
export type SecurityLevel = 'CheckNothing' | 'CheckFormsAndMicroflows' | 'CheckEverything';
export type ModuleType = 'user' | 'marketplace' | 'system';
export type PersistenceType = 'persistable' | 'non-persistable';
export type AssociationType = 'Reference' | 'ReferenceSet';
export type DeleteBehavior = 'DeleteBoth' | 'DeleteParentOnly' | 'DeleteChildOnly' | 'DeleteNever';

export interface ApplicationMetadata {
  name: string;
  projectId?: string;
  mendixVersion: string;
  javaVersion?: string;
  applicationType: ProjectType;
  primaryMprPath: string;
  archiveSha256?: string;
  extractedSizeBytes?: number;
  fileCount?: number;
  totalModules: number;
  totalEntities: number;
  totalMicroflows: number;
  totalNanoflows: number;
  totalPages: number;
}

export interface Module {
  name: string;
  type: ModuleType;
  isSystem: boolean;
  isMarketplace: boolean;
  documentation?: string;
  entities: string[];
  microflows: string[];
  nanoflows: string[];
  pages: string[];
  dependencies: string[]; // modules this module depends on
}

/** Where a fact was read from, so a finding can be traced back to the model. */
export interface Provenance {
  /** Project-relative unit path, e.g. `mprcontents/8a/76/8a76….mxunit`. */
  unitPath: string;
  /** The `$ID` of the element itself. */
  elementId?: string;
}

export interface Attribute {
  name: string;
  /** The Mendix attribute type, e.g. `String`, `Long`, `Enum`. `undefined` if unreadable. */
  type?: string;
  length?: number;
  defaultValue?: string;
  isCalculated: boolean;
  isSensitive: boolean; // detected e.g. password, ssn, secret, token
  isPii?: boolean; // detected e.g. email, phone, address, national id
  /** Which classifier matched, and on what term — so a finding can justify itself. */
  sensitivityKind?: SensitivityKind;
  sensitivityTerm?: string;
  documentation?: string;
}

export interface IndexItem {
  name: string;
  attributes: string[];
}

export type AccessRights = 'None' | 'ReadOnly' | 'ReadWrite';

export interface MemberAccessRule {
  /** Qualified member name, e.g. `MyFirstModule.RequestForm.Email`. */
  attributeOrAssociation: string;
  /** Whether this entry refers to an association rather than an attribute. */
  isAssociation: boolean;
  access: AccessRights;
}

export interface AccessRule {
  id: string;
  /** Qualified `Module.Role` names this rule applies to. */
  moduleRoles: string[];
  allowCreate: boolean;
  allowDelete: boolean;
  defaultMemberAccess: AccessRights;
  memberAccess: MemberAccessRule[];
  xPathConstraint?: string;
  documentation?: string;
  provenance?: Provenance;
}

export interface Entity {
  name: string;
  module: string;
  qualifiedName: string;
  persistenceType: PersistenceType;
  generalization?: string; // qualified parent entity name
  specializations: string[]; // qualified child entity names
  attributes: Attribute[];
  indexes: IndexItem[];
  accessRules: AccessRule[];
  /**
   * Whether the entity has at least one access rule.
   *
   * Only meaningful when `entityAccessRules` coverage is not NOT_ANALYZABLE; the old
   * parser hardcoded this to `true`, which made every entity look protected.
   */
  isSecurityConfigured: boolean;
  /** `HasOwnerAttr`: the entity carries a System.owner association. */
  hasOwnerAttribute?: boolean;
  hasChangedByAttribute?: boolean;
  documentation?: string;
  provenance?: Provenance;
}

export interface Association {
  name: string;
  module: string;
  parentEntity: string;
  childEntity: string;
  type: AssociationType;
  owner: 'Both' | 'Default';
  deleteBehavior: DeleteBehavior;
  documentation?: string;
}

export interface Activity {
  id: string;
  type: string; // Retrieve, Commit, Delete, ChangeObject, CallMicroflow, JavaAction, RestCall, etc.
  name: string;
  isWithinLoop: boolean;
  parentLoopId?: string;
  targetEntity?: string;
  xPathConstraint?: string;
  rangeLimit?: number;
  errorHandling?: {
    type: 'Rollback' | 'Custom' | 'Continue';
    targetHandler?: string;
  };
  endpointUrl?: string;
  timeoutMs?: number;
  properties: Record<string, any>;
}

export interface Microflow {
  name: string;
  module: string;
  qualifiedName: string; // Module.Name
  returnType: string;
  /** `type` is `Object`, `List` or a primitive; `entity` is set for Object and List parameters. */
  parameters: { name: string; type: string; entity?: string }[];
  /**
   * The activities in execution order: a walk of the sequence flows from the start event, then
   * any objects the walk did not reach (loop bodies). `type` is normalised across Studio Pro and
   * storage spellings: CreateAction, ChangeAction, DeleteAction, CommitAction, RetrieveAction,
   * MicroflowCall, JavaActionCall, RestCall, Decision, or the model's own name for anything else.
   */
  activities: Activity[];
  cyclomaticComplexity: number;
  hasErrorHandling: boolean;
  callsMicroflows: string[];
  callsJavaActions: string[];
  retrievesInsideLoops: Activity[];
  commitsInsideLoops: Activity[];
  deletesInsideLoops: Activity[];
  isExposedAsService: boolean;
  isUnused?: boolean;
  /** Qualified `Module.Role` names from `AllowedModuleRoles`. */
  allowedRoles: string[];
  /**
   * `ApplyEntityAccess`: whether the microflow's retrieves and changes are subject to
   * entity access rules. `false` means it runs with full rights regardless of the caller.
   */
  appliesEntityAccess?: boolean;
  /** The entity the microflow returns (object or list), if it returns one. */
  returnEntity?: string;
  /**
   * Every document that refers to this microflow — pages, layouts, navigation, other flows, entity
   * event handlers, scheduled events, workflows, published services, project settings, Java source.
   * `undefined` when references were not indexed (see `coverage.modelReferences`).
   */
  referencedBy?: { qualifiedName: string; kind: string }[];
  documentation?: string;
  provenance?: Provenance;
}

export interface Nanoflow {
  name: string;
  module: string;
  qualifiedName: string;
  returnType: string;
  parameters: { name: string; type: string }[];
  activities: Activity[];
  callsJavaScriptActions: string[];
  cyclomaticComplexity: number;
  /** The entity the nanoflow returns (object or list), if it returns one. */
  returnEntity?: string;
  documentation?: string;
}

export interface Widget {
  id: string;
  type: string; // e.g. DataView, ListView, Button, CustomWidget
  name?: string;
  dataSource?: string;
  actionName?: string;
}

export interface Page {
  name: string;
  module: string;
  qualifiedName: string;
  layout?: string;
  totalWidgets: number;
  widgets: Widget[];
  /** Qualified `Module.Role` names from `AllowedModuleRoles`. */
  allowedRoles: string[];
  /**
   * Whether a module role reachable by the guest user role can open this page.
   *
   * Computed by intersecting `allowedRoles` with the guest user role's module roles —
   * not assumed. The old parser hardcoded this to `false` for every page.
   */
  isAccessibleAnonymously: boolean;
  /**
   * Whether a navigation profile opens on this page.
   *
   * A guest-reachable home page is the intended front door of a public app, so reporting it
   * as an anonymous exposure would be a false positive on every project that has one.
   */
  isNavigationHomePage?: boolean;
  /**
   * Entities the page works with — data sources, parameters, attribute paths, embedded snippets
   * and the return types of data-source flows — resolved by `resolveDataEntities`. `undefined`
   * when the page's contents were not read, which is not the same as "uses no data".
   */
  dataEntities?: string[];
  navigationPath?: string;
  documentation?: string;
  provenance?: Provenance;
}

export interface ModuleRole {
  name: string;
  module: string;
  /** Qualified `Module.Role`, the form user roles reference. */
  qualifiedName: string;
  documentation?: string;
}

export interface UserRole {
  name: string;
  moduleRoles: { module: string; role: string }[];
  manageableRoles: string[];
  isAnonymous: boolean;
  isAdministrator: boolean;
  /** `ManageAllRoles`: this role may grant any other role, including administrators. */
  manageAllRoles?: boolean;
  manageUsersWithoutRoles?: boolean;
  /** `CheckSecurity` on the role itself; `false` disables checks for its users. */
  checkSecurity?: boolean;
}

/**
 * The project password policy.
 *
 * Absent fields mean "not readable", never "not required" — a missing `requireSymbol`
 * must not be reported as a policy weakness.
 */
export interface PasswordPolicy {
  minimumLength?: number;
  requireDigit?: boolean;
  requireMixedCase?: boolean;
  requireSymbol?: boolean;
}

/**
 * The configured administrator account.
 *
 * SECURITY: the password itself is deliberately absent. It is classified during extraction
 * and then discarded, because the IR is persisted to `data/runs/*.json` and embedded in
 * exported reports — a governance tool that copies the credentials it finds into a
 * world-readable artifact has created a second vulnerability.
 */
export interface AdministratorAccount {
  userName?: string;
  userRole?: string;
  /** Whether the configured password fails the project's own policy. */
  passwordIsWeak?: boolean;
  /** Length only. Never the value. */
  passwordLength?: number;
}

/** A demo user defined in the model. As above, the password value is never retained. */
export interface DemoUser {
  userName?: string;
  entity?: string;
  userRoles: string[];
  hasPassword: boolean;
  passwordLength?: number;
}

export interface SecurityModel {
  projectSecurityLevel: SecurityLevel;
  isProductionReady: boolean;
  userRoles: UserRole[];
  moduleRoles: ModuleRole[];
  anonymousUserEnabled: boolean;
  anonymousRole?: string;
  /** Project-level `CheckSecurity`. `false` disables security model-wide. */
  securityEnabled?: boolean;
  /** `StrictMode`: stricter runtime enforcement of entity access. */
  strictMode?: boolean;
  /** `StrictPageUrlCheck`: rejects page URLs the user has no access to. */
  strictPageUrlCheck?: boolean;
  administrator?: AdministratorAccount;
  demoUsersEnabled?: boolean;
  demoUsers: DemoUser[];
  passwordPolicy?: PasswordPolicy;
}

export interface RestEndpoint {
  name: string;
  module: string;
  path: string;
  httpMethod: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  microflow: string;
  requiresAuthentication: boolean;
  authType?: 'None' | 'Basic' | 'Token' | 'Custom';
}

export interface IntegrationModel {
  publishedRestServices: {
    name: string;
    module: string;
    version: string;
    endpoints: RestEndpoint[];
  }[];
  consumedRestServices: {
    name: string;
    module: string;
    baseUrl?: string;
    isTimeoutConfigured: boolean;
  }[];
  publishedODataServices: {
    name: string;
    module: string;
    exposedEntities: string[];
  }[];
}

export interface JavaActionSummary {
  name: string;
  module: string;
  sourceFile?: string;
  usesExternalLibraries: string[];
  hasRegexXssSanitizer?: boolean;
}

export interface JavaScriptActionSummary {
  name: string;
  module: string;
  sourceFile?: string;
}

export interface CustomCodeModel {
  javaActions: JavaActionSummary[];
  javaScriptActions: JavaScriptActionSummary[];
  vendorJars: { name: string; sizeBytes: number }[];
  widgetPackages: { name: string; sizeBytes: number }[];
}

export interface OperationsModel {
  constants: { name: string; module: string; dataType: string; hasDefaultValue: boolean; defaultValue?: string; isExposedToClient: boolean }[];
  scheduledEvents: { name: string; module: string; microflow: string; interval: string; enabled: boolean }[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'module' | 'entity' | 'microflow';
  module?: string;
  degree?: number;
  inDegree?: number;
  outDegree?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: 'depends_on' | 'calls' | 'references';
  weight?: number;
}

export interface DependencyGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  cycles: string[][]; // list of module cycles e.g. [['ModuleA', 'ModuleB', 'ModuleA']]
  godModules: string[]; // modules with abnormally high degree/concentration
}

export interface ApplicationIR {
  metadata: ApplicationMetadata;
  /**
   * What the parser was able to read. Rules declare the facts they need and the engine
   * skips those whose facts are NOT_ANALYZABLE, so an unreadable model scores as unknown
   * rather than as compliant.
   */
  coverage: FactCoverage;
  modules: Record<string, Module>;
  entities: Record<string, Entity>;
  associations: Association[];
  microflows: Record<string, Microflow>;
  nanoflows: Record<string, Nanoflow>;
  pages: Record<string, Page>;
  security: SecurityModel;
  integrations: IntegrationModel;
  customCode: CustomCodeModel;
  operations: OperationsModel;
  dependencyGraph: DependencyGraph;
  generatedAt: string;
}
