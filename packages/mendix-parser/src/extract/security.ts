/**
 * Extract the project and module security model.
 *
 * Everything here comes from two unit types, read as trees so that containment survives:
 *
 *   `Security$ProjectSecurity` (one per project) — security level, guest access, the
 *      administrator account, the password policy, demo users, and the user roles with
 *      their qualified `Module.Role` grants.
 *   `Security$ModuleSecurity` (one per module) — that module's own roles. The unit does
 *      not name its module, so ownership comes from the `.mpr` containment tree.
 *
 * SECURITY — passwords are classified and then dropped.
 *   `AdminPassword` and `DemoUserImpl.Password` are read only to judge them: what reaches
 *   the IR is a length and a weak/strong verdict, never the value. The IR is persisted to
 *   `data/runs/*.json` and embedded in exported HTML and JSON reports, so retaining the
 *   value would copy the credentials this tool exists to warn about into a second, often
 *   more widely shared, location. A governance tool must not create the finding it reports.
 */

import type {
  AdministratorAccount,
  DemoUser,
  ModuleRole,
  PasswordPolicy,
  SecurityLevel,
  SecurityModel,
  UserRole,
} from '@mendix-analyzer/application-ir';

import { bool, docArray, num, str, strArray, subDoc } from '../bson/accessors.js';
import type { BsonDocument } from '../bson/reader.js';
import type { ModelGraph } from '../model/model-graph.js';
import { analyzed, notAnalyzable } from './types.js';
import type { Extraction } from './types.js';

const PROJECT_SECURITY_TYPE = 'Security$ProjectSecurity';
const MODULE_SECURITY_TYPE = 'Security$ModuleSecurity';

const SECURITY_LEVELS: readonly SecurityLevel[] = [
  'CheckNothing',
  'CheckFormsAndMicroflows',
  'CheckEverything',
];

/** The minimum password policy a production app should enforce. */
export const PASSWORD_POLICY_BASELINE = {
  minimumLength: 8,
  requireDigit: true,
  requireMixedCase: true,
  requireSymbol: true,
} as const;

export interface SecurityExtraction {
  security: Extraction<SecurityModel>;
  /** Module roles, tracked separately because they can fail independently. */
  moduleRoles: Extraction<ModuleRole[]>;
}

export function extractSecurity(graph: ModelGraph): SecurityExtraction {
  const moduleRoles = extractModuleRoles(graph);
  const project = graph.units.soleUnitOfType(PROJECT_SECURITY_TYPE);

  if (!project) {
    // Without this unit nothing about project security is knowable. An empty model here
    // must not be mistaken for a permissive or a restrictive configuration.
    return {
      security: notAnalyzable(
        emptySecurityModel(moduleRoles.value),
        `no ${PROJECT_SECURITY_TYPE} unit was found, so no project security setting could be read`
      ),
      moduleRoles,
    };
  }

  const notes: string[] = [...moduleRoles.notes];
  const doc = project.tree;

  const rawLevel = str(doc, 'SecurityLevel');
  const level = SECURITY_LEVELS.find((l) => l === rawLevel);
  if (!level) {
    notes.push(
      rawLevel
        ? `SecurityLevel held the unrecognised value "${rawLevel}"; treated as unknown`
        : 'SecurityLevel could not be read'
    );
  }

  const passwordPolicy = extractPasswordPolicy(doc, notes);
  const guestRoleName = str(doc, 'GuestUserRole');
  const userRoles = extractUserRoles(doc, guestRoleName, notes);
  const administrator = extractAdministrator(doc, passwordPolicy, notes);
  const demoUsers = extractDemoUsers(doc);

  const securityEnabled = bool(doc, 'CheckSecurity');
  if (securityEnabled === undefined) notes.push('CheckSecurity could not be read');

  const anonymousEnabled = bool(doc, 'EnableGuestAccess');
  if (anonymousEnabled === undefined) notes.push('EnableGuestAccess could not be read');

  const model: SecurityModel = {
    // `level` is only absent when the value was unreadable or unrecognised, which the
    // note above records; CheckNothing is the safe placeholder because it cannot cause a
    // rule to conclude the project is *more* secure than it is.
    projectSecurityLevel: level ?? 'CheckNothing',
    isProductionReady: level === 'CheckEverything' && securityEnabled === true,
    userRoles,
    moduleRoles: moduleRoles.value,
    anonymousUserEnabled: anonymousEnabled ?? false,
    anonymousRole: guestRoleName || undefined,
    securityEnabled,
    strictMode: bool(doc, 'StrictMode'),
    strictPageUrlCheck: bool(doc, 'StrictPageUrlCheck'),
    administrator,
    demoUsersEnabled: bool(doc, 'EnableDemoUsers'),
    demoUsers,
    passwordPolicy,
  };

  return {
    security: level ? analyzed(model, notes) : { value: model, analyzability: 'PARTIAL', notes },
    moduleRoles,
  };
}

function extractModuleRoles(graph: ModelGraph): Extraction<ModuleRole[]> {
  const refs = graph.units.refsOfType(MODULE_SECURITY_TYPE);
  if (refs.length === 0) {
    return notAnalyzable(
      [],
      `no ${MODULE_SECURITY_TYPE} unit was found, so module roles could not be enumerated`
    );
  }

  const notes: string[] = [];
  const roles: ModuleRole[] = [];

  for (const { tree, ref } of graph.units.unitsOfType(MODULE_SECURITY_TYPE)) {
    const owner = graph.moduleOf(ref);
    if (!owner) {
      // Without the owning module the role cannot be written as `Module.Role`, which is
      // the only form user roles and access rules reference it by. An unqualified role is
      // not merely less useful — it would silently fail every cross-reference.
      notes.push(`the module owning ${ref.unitPath} could not be resolved; its roles were skipped`);
      continue;
    }
    for (const role of docArray(tree, 'ModuleRoles')) {
      const name = str(role, 'Name');
      if (!name) {
        notes.push(`an unnamed module role in ${owner.name} was skipped`);
        continue;
      }
      roles.push({
        name,
        module: owner.name,
        qualifiedName: `${owner.name}.${name}`,
        documentation: str(role, 'Documentation') || undefined,
      });
    }
  }

  return analyzed(roles, notes);
}

function extractUserRoles(
  doc: BsonDocument,
  guestRoleName: string | undefined,
  notes: string[]
): UserRole[] {
  const raw = docArray(doc, 'UserRoles');
  if (raw.length === 0) notes.push('the project defines no user roles, or they could not be read');

  const roles: UserRole[] = [];
  for (const role of raw) {
    const name = str(role, 'Name');
    if (!name) {
      notes.push('an unnamed user role was skipped');
      continue;
    }

    // `ModuleRoles` is an array of qualified `Module.Role` strings. Splitting on the last
    // dot is safe because module names cannot contain one.
    const grants: { module: string; role: string }[] = [];
    for (const qualified of strArray(role, 'ModuleRoles')) {
      const dot = qualified.lastIndexOf('.');
      if (dot <= 0) {
        notes.push(`user role ${name} references "${qualified}", which is not a Module.Role name`);
        continue;
      }
      grants.push({ module: qualified.slice(0, dot), role: qualified.slice(dot + 1) });
    }

    roles.push({
      name,
      moduleRoles: grants,
      manageableRoles: strArray(role, 'ManageableRoles'),
      isAnonymous: guestRoleName !== undefined && name === guestRoleName,
      // An administrator is identified by what it can do, not by being called "Admin":
      // `ManageAllRoles` lets it grant any role to any user, including itself.
      isAdministrator: (bool(role, 'ManageAllRoles') ?? false) || /^admin/i.test(name),
      manageAllRoles: bool(role, 'ManageAllRoles'),
      manageUsersWithoutRoles: bool(role, 'ManageUsersWithoutRoles'),
      checkSecurity: bool(role, 'CheckSecurity'),
    });
  }
  return roles;
}

function extractPasswordPolicy(
  doc: BsonDocument,
  notes: string[]
): PasswordPolicy | undefined {
  const policy = subDoc(doc, 'PasswordPolicySettings');
  if (!policy) {
    notes.push('PasswordPolicySettings could not be read; password policy rules cannot be judged');
    return undefined;
  }
  return {
    minimumLength: num(policy, 'MinimumLength'),
    requireDigit: bool(policy, 'RequireDigit'),
    requireMixedCase: bool(policy, 'RequireMixedCase'),
    requireSymbol: bool(policy, 'RequireSymbol'),
  };
}

/**
 * Read the administrator account, judging the password without keeping it.
 *
 * The password is compared against the project's own policy where one is readable, so the
 * verdict is the app's own standard rather than an external opinion. The baseline is used
 * only as a floor, because a project that set `MinimumLength: 1` should not thereby earn a
 * pass for a one-character administrator password.
 */
function extractAdministrator(
  doc: BsonDocument,
  policy: PasswordPolicy | undefined,
  notes: string[]
): AdministratorAccount | undefined {
  const userName = str(doc, 'AdminUserName');
  const userRole = str(doc, 'AdminUserRole');
  const password = str(doc, 'AdminPassword');

  if (userName === undefined && userRole === undefined && password === undefined) {
    notes.push('no administrator account settings could be read');
    return undefined;
  }

  const account: AdministratorAccount = { userName, userRole };
  if (password !== undefined) {
    account.passwordLength = password.length;
    account.passwordIsWeak = isWeakPassword(password, policy);
  }
  // `password` goes out of scope here and is never assigned to the returned object.
  return account;
}

function isWeakPassword(password: string, policy: PasswordPolicy | undefined): boolean {
  const minimumLength = Math.max(
    policy?.minimumLength ?? PASSWORD_POLICY_BASELINE.minimumLength,
    PASSWORD_POLICY_BASELINE.minimumLength
  );
  if (password.length < minimumLength) return true;
  if ((policy?.requireDigit ?? true) && !/[0-9]/.test(password)) return true;
  if ((policy?.requireMixedCase ?? true) && !(/[a-z]/.test(password) && /[A-Z]/.test(password))) {
    return true;
  }
  if ((policy?.requireSymbol ?? false) && !/[^A-Za-z0-9]/.test(password)) return true;
  return false;
}

/** Demo users, again recording only that a password exists and how long it is. */
function extractDemoUsers(doc: BsonDocument): DemoUser[] {
  return docArray(doc, 'DemoUsers').map((user) => {
    const password = str(user, 'Password');
    return {
      userName: str(user, 'UserName'),
      entity: str(user, 'Entity'),
      userRoles: strArray(user, 'UserRoles'),
      hasPassword: password !== undefined && password.length > 0,
      passwordLength: password?.length,
    };
  });
}

function emptySecurityModel(moduleRoles: ModuleRole[]): SecurityModel {
  return {
    projectSecurityLevel: 'CheckNothing',
    isProductionReady: false,
    userRoles: [],
    moduleRoles,
    anonymousUserEnabled: false,
    demoUsers: [],
  };
}
