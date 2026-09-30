/**
 * The `SEC-*` catalogue: 29 rules — the 28 of `docs/security.md` §6, plus SEC-029 (§6.9).
 *
 * Two things are different from the catalogue this replaces.
 *
 * First, every rule declares the IR facts it needs in `requires`. A rule whose facts are
 * NOT_ANALYZABLE is recorded NOT_APPLICABLE and never runs, so "the parser could not read the
 * access rules" can no longer be scored as "the access rules are fine". SEC-004 is the clear
 * case: its logic is correct and it has no input in Phase 1, so it declares
 * `requires: ['publishedServices']` and is skipped rather than passing vacuously.
 *
 * Second, the anonymous-access rules traverse the real one-step indirection — a user role
 * holds module roles, and an unauthenticated visitor holds the guest user role's module roles.
 * The previous versions pattern-matched role *names*, which is why a project whose guest role
 * holds `Atlas_Core.Administrator` and `Atlas_Web_Content.Administrator` reported no anonymous
 * findings at all.
 *
 * SECURITY: no rule below puts a password or a secret-shaped constant value into `Evidence`.
 * Findings are persisted to `data/runs/*.json` and embedded in exported HTML reports, so a
 * rule that quoted the credential it found would create a second copy of the vulnerability it
 * is reporting. Evidence carries the location and the classification only.
 */

import type { AccessRights, Page } from '@mendix-analyzer/application-ir';

import { defineRule } from './define-rule.js';
import { microflowSecurityRules } from './microflow-security.js';
import {
  broadModuleRoles,
  entityAccessRules,
  grantedModuleRoles,
  guestHasAccessTo,
  guestModuleRoles,
  guestUserRole,
  isAdministratorRole,
  isGuestDesignatedRole,
  isPersistableEntity,
  isPlatformModule,
  isUserModule,
  piiAttributes,
  rolesInCommon,
  secretAttributes,
  sensitivityLabel,
} from './security-facts.js';

const SECURITY_SKILL = 'manage-security.md';

/** The floor a production password policy should meet; see `docs/security.md` §6.1. */
const PASSWORD_POLICY_BASELINE = {
  minimumLength: 8,
  requireDigit: true,
  requireMixedCase: true,
  requireSymbol: true,
};

/** Member access levels that let a role read the member's value. */
const READABLE: AccessRights[] = ['ReadOnly', 'ReadWrite'];

/** The last segment of a qualified member name, e.g. `…RequestForm.Email` → `Email`. */
function memberName(qualified: string): string {
  const dot = qualified.lastIndexOf('.');
  return dot >= 0 ? qualified.slice(dot + 1) : qualified;
}

function plural(items: readonly unknown[], one: string, many: string): string {
  return items.length === 1 ? one : many;
}

function pageLabel(page: Page): string {
  return `Page: ${page.qualifiedName}`;
}

const coreSecurityRules = [
  // ---------------------------------------------------------------------------------------
  // 6.1 Project & platform security
  // ---------------------------------------------------------------------------------------

  defineRule({
    id: 'SEC-002',
    name: 'Application security level not production ready',
    description:
      'The project security level must be CheckEverything so that the runtime enforces entity access rules.',
    category: 'Security',
    subcategory: 'Project Security',
    severity: 'Critical',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Security Levels',
    expectedPractice: 'Production applications must use the CheckEverything security level.',
    recommendation:
      'Open App Security in Studio Pro and select "Production (Check everything)".',
    whyItMatters:
      'Below CheckEverything the runtime does not apply entity access rules, so every access rule in the model is decoration: the database is reachable in full by anyone who can reach the client.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      const level = ir.security.projectSecurityLevel;
      if (level === 'CheckEverything') return;
      emit({
        key: 'level',
        artifact: 'App Security: security level',
        observation: `The project security level is "${level}", so entity access rules are not fully enforced at runtime.`,
        objectName: 'SecurityLevel',
        objectType: 'ProjectSettings',
        artifactPath: 'AppSecurity.SecurityLevel',
        details: { currentLevel: level, requiredLevel: 'CheckEverything' },
      });
    },
  }),

  defineRule({
    id: 'SEC-011',
    name: 'Application security disabled',
    description: 'Project-level CheckSecurity must be enabled.',
    category: 'Security',
    subcategory: 'Project Security',
    severity: 'Critical',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Security Levels',
    expectedPractice: 'Security must be switched on for any application handling real data.',
    recommendation: 'Enable security in App Security and assign module roles to every user role.',
    whyItMatters:
      'With security off the runtime performs no authentication or authorisation at all; every page, microflow and entity is reachable by anyone who can reach the application URL.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      if (ir.security.securityEnabled !== false) return;
      emit({
        key: 'check-security',
        artifact: 'App Security: CheckSecurity',
        observation: 'Security is switched off for the project (CheckSecurity is false).',
        objectName: 'CheckSecurity',
        objectType: 'ProjectSettings',
        artifactPath: 'AppSecurity.CheckSecurity',
        details: { securityEnabled: false },
      });
    },
  }),

  defineRule({
    id: 'SEC-012',
    name: 'Demo users enabled',
    description: 'Demo users must be disabled before an application reaches production.',
    category: 'Security',
    subcategory: 'Project Security',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Demo Users',
    expectedPractice: 'Demo users exist for local development and must be off in production.',
    recommendation:
      'Clear "Enable demo users" in App Security and remove the demo accounts from the model.',
    whyItMatters:
      'Enabled demo users are created automatically at startup with the passwords stored in the model, which are committed to version control and visible to everyone with repository access.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      if (ir.security.demoUsersEnabled !== true) return;
      emit({
        key: 'enabled',
        artifact: 'App Security: demo users',
        observation: `Demo users are enabled, and ${ir.security.demoUsers.length} demo account(s) are defined in the model.`,
        objectName: 'EnableDemoUsers',
        objectType: 'ProjectSettings',
        artifactPath: 'AppSecurity.EnableDemoUsers',
        details: { demoUserCount: ir.security.demoUsers.length },
      });
    },
  }),

  defineRule({
    id: 'SEC-013',
    name: 'Demo user credentials stored in the model',
    description: 'Demo accounts with passwords must not be stored in the project model.',
    category: 'Security',
    subcategory: 'Credentials',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Demo Users',
    expectedPractice:
      'Accounts used for testing belong in the target environment, never in the model.',
    recommendation:
      'Delete the demo accounts from App Security and create test users in the environment instead.',
    whyItMatters:
      'A password in the model is a password in version control. It is readable by everyone with repository access, survives in history after removal, and is deployed unchanged to every environment built from that model.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      for (const user of ir.security.demoUsers) {
        if (!user.hasPassword) continue;
        const name = user.userName ?? '(unnamed)';
        emit({
          key: name,
          artifact: `Demo user: ${name}`,
          observation: `Demo account "${name}" (roles: ${user.userRoles.join(', ') || 'none'}) has a password stored in the model.`,
          objectName: name,
          objectType: 'DemoUser',
          artifactPath: `AppSecurity.DemoUsers.${name}`,
          // The password length is recorded; the password itself is deliberately absent.
          details: {
            userRoles: user.userRoles,
            entity: user.entity,
            passwordLength: user.passwordLength,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-014',
    name: 'Weak or default administrator password',
    description:
      "The administrator password in the model must satisfy the project's own password policy.",
    category: 'Security',
    subcategory: 'Credentials',
    severity: 'Critical',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Administrator Account',
    expectedPractice:
      'The administrator password must be set in the environment, not the model, and must meet the password policy.',
    recommendation:
      'Remove the administrator password from App Security and set it as an environment credential after first deployment.',
    whyItMatters:
      'The administrator account holds every role in the application. A short or guessable password on it means a single online guess is enough to take over the whole app, and because the value lives in the model it is identical in every environment.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      const admin = ir.security.administrator;
      if (!admin || admin.passwordIsWeak !== true) return;
      const name = admin.userName ?? '(unnamed)';
      emit({
        key: 'admin-password',
        artifact: `Administrator account: ${name}`,
        observation: `The password configured for administrator "${name}" is ${admin.passwordLength} character(s) long and does not satisfy the project's password policy.`,
        objectName: name,
        objectType: 'AdministratorAccount',
        artifactPath: 'AppSecurity.Administrator',
        details: {
          userRole: admin.userRole,
          passwordLength: admin.passwordLength,
          policyMinimumLength:
            ir.security.passwordPolicy?.minimumLength ?? PASSWORD_POLICY_BASELINE.minimumLength,
        },
      });
    },
  }),

  defineRule({
    id: 'SEC-015',
    name: 'Password policy below baseline',
    description:
      'The password policy must require a minimum length of 8 with digits, mixed case and a symbol.',
    category: 'Security',
    subcategory: 'Project Security',
    severity: 'Medium',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Password Policy',
    expectedPractice:
      'Require at least 8 characters including a digit, mixed case and a symbol.',
    recommendation: 'Raise the password policy in App Security to meet the baseline.',
    whyItMatters:
      'The policy is what the runtime enforces when users choose their own passwords, so every relaxation applies to every account in the application at once.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      const policy = ir.security.passwordPolicy;
      // An absent policy means "not readable", not "not required"; `projectSecurity` coverage
      // records that, and reporting a weakness here would be an unfounded claim.
      if (!policy) return;

      const shortfalls: string[] = [];
      if (
        policy.minimumLength !== undefined &&
        policy.minimumLength < PASSWORD_POLICY_BASELINE.minimumLength
      ) {
        shortfalls.push(
          `minimum length is ${policy.minimumLength}, below the baseline of ${PASSWORD_POLICY_BASELINE.minimumLength}`
        );
      }
      if (policy.requireDigit === false) shortfalls.push('a digit is not required');
      if (policy.requireMixedCase === false) shortfalls.push('mixed case is not required');
      if (policy.requireSymbol === false) shortfalls.push('a symbol is not required');
      if (shortfalls.length === 0) return;

      emit({
        key: 'policy',
        artifact: 'App Security: password policy',
        observation: `The password policy is below the baseline: ${shortfalls.join('; ')}.`,
        objectName: 'PasswordPolicy',
        objectType: 'ProjectSettings',
        artifactPath: 'AppSecurity.PasswordPolicy',
        details: { policy, baseline: PASSWORD_POLICY_BASELINE, shortfalls },
      });
    },
  }),

  defineRule({
    id: 'SEC-016',
    name: 'Strict page URL check disabled',
    description: 'StrictPageUrlCheck must remain enabled.',
    category: 'Security',
    subcategory: 'Project Security',
    severity: 'Medium',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Runtime Security Settings',
    expectedPractice: 'Leave strict page URL checking on.',
    recommendation: 'Enable "Strict page URL check" in App Security.',
    whyItMatters:
      'With the check off the runtime is more permissive about opening pages by URL, so a page a user has no role for can be reached by typing its address rather than by navigating to it.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      if (ir.security.strictPageUrlCheck !== false) return;
      emit({
        key: 'strict-page-url',
        artifact: 'App Security: StrictPageUrlCheck',
        observation: 'Strict page URL checking is disabled.',
        objectName: 'StrictPageUrlCheck',
        objectType: 'ProjectSettings',
        artifactPath: 'AppSecurity.StrictPageUrlCheck',
        details: { strictPageUrlCheck: false },
      });
    },
  }),

  // ---------------------------------------------------------------------------------------
  // 6.2 Anonymous / guest access
  // ---------------------------------------------------------------------------------------

  defineRule({
    id: 'SEC-006',
    name: 'Guest role granted a business module role',
    description:
      'The guest user role must hold only module roles designed for unauthenticated visitors.',
    category: 'Security',
    subcategory: 'Anonymous Access',
    severity: 'Critical',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Anonymous Users and Role Mapping',
    expectedPractice:
      'Grant the guest user role only roles named for guest access, covering login and public landing pages.',
    recommendation:
      'Open App Security, edit the guest user role, and remove the business module role.',
    whyItMatters:
      'Every access rule, page and microflow granted to a module role is reachable by anyone holding it. A business module role on the guest role publishes that surface to unauthenticated visitors, who can query and commit entities from the client without logging in.',
    confidence: 'High',
    requires: ['projectSecurity', 'moduleRoles'],
    check: (ir, emit) => {
      const guest = guestUserRole(ir);
      if (!guest) return;

      for (const moduleRole of guest.moduleRoles) {
        // A role named for guest access is what this grant is for; an administrator role is
        // SEC-017's subject and is reported there with its own severity and wording.
        if (isGuestDesignatedRole(moduleRole.role)) continue;
        if (isAdministratorRole(moduleRole.role)) continue;
        // `System.User` is not a business role and not optional: Mendix requires every user
        // role to hold it, so reporting it would fire on every project that has a guest role
        // at all and could not be acted on if it did.
        if (isPlatformModule(ir, moduleRole.module)) continue;

        const qualified = `${moduleRole.module}.${moduleRole.role}`;
        const ownModule = isUserModule(ir, moduleRole.module);

        emit({
          key: qualified,
          module: moduleRole.module,
          // The grant is always the team's own, but what it exposes is not. In a module they
          // wrote, a guest-held role is business surface published to the internet. In a
          // marketplace module it is often the module's documented setup — an Atlas theme role
          // is what makes a public page render — so the grant is reported for review rather
          // than asserted to be a defect.
          status: ownModule ? 'FAIL' : 'WARNING',
          severity: ownModule ? 'Critical' : 'Medium',
          confidence: ownModule ? 'High' : 'Low',
          artifact: `User role: ${guest.name} → ${qualified}`,
          observation: ownModule
            ? `The guest user role "${guest.name}" is granted module role "${qualified}", so unauthenticated visitors hold every permission that role carries.`
            : `The guest user role "${guest.name}" is granted module role "${qualified}" from marketplace module "${moduleRole.module}". Some marketplace modules require this for anonymous pages to work; confirm it is one of them.`,
          recommendation: ownModule
            ? `Remove "${qualified}" from the "${guest.name}" user role in App Security.`
            : `Check the module's documentation for whether "${qualified}" is required for anonymous access, and remove it if not.`,
          objectName: guest.name,
          objectType: 'UserRole',
          artifactPath: `AppSecurity.UserRoles.${guest.name}`,
          details: {
            userRole: guest.name,
            grantedModuleRole: qualified,
            moduleIsMarketplace: !ownModule,
            projectSecurityLevel: ir.security.projectSecurityLevel,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-017',
    name: 'Guest role granted an administrator module role',
    description:
      'The guest user role must never hold a module role named as an administrator role, in any module.',
    category: 'Security',
    subcategory: 'Anonymous Access',
    severity: 'Critical',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Anonymous Users and Role Mapping',
    expectedPractice:
      'Administrator module roles belong to authenticated administrators only.',
    recommendation:
      'Open App Security, edit the guest user role, and remove the administrator module role.',
    whyItMatters:
      'An administrator module role carries the module\'s widest permissions. Granting one to the guest role hands them to every unauthenticated visitor, and it applies whether the module is the team\'s own or a marketplace one — the grant lives in the project\'s security model, which the team controls.',
    confidence: 'High',
    requires: ['projectSecurity', 'moduleRoles'],
    check: (ir, emit) => {
      const guest = guestUserRole(ir);
      if (!guest) return;

      for (const moduleRole of guest.moduleRoles) {
        if (!isAdministratorRole(moduleRole.role)) continue;
        const qualified = `${moduleRole.module}.${moduleRole.role}`;
        emit({
          key: qualified,
          module: moduleRole.module,
          artifact: `User role: ${guest.name} → ${qualified}`,
          observation: `The guest user role "${guest.name}" is granted administrator module role "${qualified}".`,
          recommendation: `Remove "${qualified}" from the "${guest.name}" user role in App Security.`,
          objectName: guest.name,
          objectType: 'UserRole',
          artifactPath: `AppSecurity.UserRoles.${guest.name}`,
          details: {
            userRole: guest.name,
            grantedModuleRole: qualified,
            module: moduleRole.module,
            moduleIsMarketplace: ir.modules[moduleRole.module]?.isMarketplace ?? null,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-018',
    name: 'Anonymous page uses persistable data',
    description:
      'A page the anonymous user role can open must work only with non-persistable entities.',
    category: 'Security',
    subcategory: 'Anonymous Access',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Page Access',
    expectedPractice:
      'Pages open to anonymous users (login, registration, public forms) are built on non-persistable entities; stored data is shown only to authenticated roles.',
    recommendation:
      'Rebuild the page on a non-persistable entity, or remove the anonymous-held module role from the page\'s allowed roles.',
    whyItMatters:
      "A page's data sources run with the anonymous role's entity access, so an anonymous page built on a stored entity either publishes those rows to unauthenticated visitors or, where access is missing, fails for them. A page that uses only non-persistable entities holds nothing between requests and exposes no stored data.",
    confidence: 'High',
    requires: ['pageAccess', 'projectSecurity'],
    check: (ir, emit) => {
      const guestRoles = guestModuleRoles(ir);
      if (guestRoles.size === 0) return;

      for (const page of Object.values(ir.pages)) {
        if (!page.isAccessibleAnonymously) continue;
        const via = page.allowedRoles.filter((r) => guestRoles.has(r));

        if (page.dataEntities !== undefined) {
          // The page's contents were read, so judge it by the data it uses rather than by being
          // open: a login page on a non-persistable LoginContext exposes nothing.
          const stored = page.dataEntities.filter((e) => isPersistableEntity(ir, e));
          if (stored.length === 0) continue;
          const readable = stored.filter((e) => guestHasAccessTo(ir, e, guestRoles));
          const exposed = readable.length > 0;
          emit({
            key: page.qualifiedName,
            module: page.module,
            status: exposed ? 'FAIL' : 'WARNING',
            severity: exposed ? 'High' : 'Medium',
            artifact: pageLabel(page),
            observation: exposed
              ? `Page "${page.qualifiedName}" is open to the anonymous user role through ${via.join(', ')} and uses persistable ${plural(stored, 'entity', 'entities')} ${stored.join(', ')}; the anonymous role has access rules on ${readable.join(', ')}, so their stored data is visible without logging in.`
              : `Page "${page.qualifiedName}" is open to the anonymous user role through ${via.join(', ')} and uses persistable ${plural(stored, 'entity', 'entities')} ${stored.join(', ')}, which the anonymous role has no access rule on. Nothing is exposed, but the page will show nothing or fail for anonymous visitors.`,
            recommendation: exposed
              ? `Replace ${stored.join(', ')} on this page with a non-persistable entity, or remove ${via.join(', ')} from the page's allowed roles.`
              : `Build this page on a non-persistable entity, or remove ${via.join(', ')} from the page's allowed roles if anonymous visitors do not need it.`,
            objectName: page.name,
            objectType: 'Page',
            artifactPath: page.qualifiedName,
            details: {
              allowedRoles: page.allowedRoles,
              guestHeldRoles: via,
              persistableEntities: stored,
              anonymousCanRead: readable,
              nonPersistableEntities: page.dataEntities.filter((e) => !stored.includes(e)),
              unitPath: page.provenance?.unitPath,
            },
          });
          continue;
        }

        // Contents not read: fall back to reachability alone. A navigation home page is the
        // app's intended front door, and reporting it would fire on every public application.
        if (page.isNavigationHomePage) continue;
        emit({
          key: page.qualifiedName,
          module: page.module,
          artifact: pageLabel(page),
          observation: `Page "${page.qualifiedName}" is reachable without authenticating, through guest-held module role(s) ${via.join(', ')}.`,
          objectName: page.name,
          objectType: 'Page',
          artifactPath: page.qualifiedName,
          details: {
            allowedRoles: page.allowedRoles,
            guestHeldRoles: via,
            widgetCount: page.totalWidgets,
            unitPath: page.provenance?.unitPath,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-019',
    name: 'Page with no allowed module roles',
    description: 'Every page should list the module roles permitted to open it.',
    category: 'Security',
    subcategory: 'Page Access',
    severity: 'Low',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Page Access',
    expectedPractice: 'Assign the module roles that need a page in the page\'s security tab.',
    recommendation:
      'Open the page\'s security tab and grant the module roles that should be able to open it.',
    whyItMatters:
      'A page with no allowed roles cannot be opened by anyone once security is on. It is either dead weight or a page whose access was never configured, and the second case surfaces as a runtime error for the users who need it.',
    confidence: 'High',
    requires: ['pageAccess'],
    check: (ir, emit) => {
      for (const page of Object.values(ir.pages)) {
        if (page.allowedRoles.length > 0) continue;
        // Marketplace pages are third-party content the team cannot edit; §22 excludes them
        // rather than reporting a page the team has no way to fix.
        if (!isUserModule(ir, page.module)) continue;

        emit({
          key: page.qualifiedName,
          status: 'WARNING',
          module: page.module,
          artifact: pageLabel(page),
          observation: `Page "${page.qualifiedName}" lists no allowed module roles, so no user can open it while security is enabled.`,
          objectName: page.name,
          objectType: 'Page',
          artifactPath: page.qualifiedName,
          details: { widgetCount: page.totalWidgets, unitPath: page.provenance?.unitPath },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-009',
    name: 'Anonymous submissions unthrottled',
    description:
      'Applications accepting anonymous submissions should apply rate limiting or abuse prevention outside the model.',
    category: 'Security',
    subcategory: 'Abuse Prevention',
    severity: 'Informational',
    sourceSkill: 'rest-client.md',
    sourceSection: 'Rate Limiting and Throttling',
    expectedPractice:
      'Apply rate limiting, CAPTCHA or a cooldown to anonymous submission paths.',
    recommendation:
      'Confirm that rate limiting is configured at the reverse proxy or gateway, since the Mendix model cannot express it.',
    whyItMatters:
      'Rate limiting cannot be expressed in the Mendix model, so this is a prompt to check the surrounding infrastructure rather than a defect in the application.',
    confidence: 'Low',
    // Advisory only. Design §4 forbids turning guidance that the model cannot confirm into a
    // governance failure, so this is off by default and excluded from scoring when enabled.
    enabled: false,
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      const guest = guestUserRole(ir);
      if (!guest || guest.moduleRoles.length === 0) return;
      emit({
        key: 'advisory',
        status: 'WARNING',
        severity: 'Informational',
        artifact: 'App Security: anonymous access',
        observation: `Guest access is enabled and the guest role holds ${guest.moduleRoles.length} module role(s); whether anonymous submissions are rate limited cannot be determined from the model.`,
        objectName: guest.name,
        objectType: 'UserRole',
        artifactPath: `AppSecurity.UserRoles.${guest.name}`,
        details: { guestModuleRoleCount: guest.moduleRoles.length, determinable: false },
      });
    },
  }),

  // ---------------------------------------------------------------------------------------
  // 6.3 Entity & member access
  // ---------------------------------------------------------------------------------------

  defineRule({
    id: 'SEC-001',
    name: 'Persistable entity with no access rules',
    description: 'Every persistable entity in a user module must define access rules.',
    category: 'Security',
    subcategory: 'Entity Access',
    severity: 'Critical',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Entity Access Rules',
    expectedPractice:
      'Define explicit module role access rules on every persistable business entity.',
    recommendation:
      'Add access rules to the entity granting each module role the minimum rights it needs.',
    whyItMatters:
      'An entity with no access rules is unreachable for every role once security is on, so the feature that depends on it fails at runtime — and if security is later relaxed, the same entity becomes reachable in full.',
    confidence: 'High',
    requires: ['entityAccessRules'],
    check: (ir, emit) => {
      for (const entity of Object.values(ir.entities)) {
        if (entity.persistenceType !== 'persistable') continue;
        if (!isUserModule(ir, entity.module)) continue;
        if (entity.accessRules.length > 0) continue;

        emit({
          key: entity.qualifiedName,
          module: entity.module,
          artifact: `Entity: ${entity.qualifiedName}`,
          observation: `Persistable entity "${entity.qualifiedName}" defines no access rules.`,
          objectName: entity.name,
          objectType: 'Entity',
          artifactPath: entity.qualifiedName,
          details: {
            attributeCount: entity.attributes.length,
            unitPath: entity.provenance?.unitPath,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-003',
    name: 'Guest-reachable role has create or delete rights on an entity',
    description:
      'Access rules granted to guest-held module roles must not allow object creation or deletion.',
    category: 'Security',
    subcategory: 'Anonymous Access',
    severity: 'Critical',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Anonymous Users',
    expectedPractice:
      'Restrict guest-reachable access rules to read-only on data that is genuinely public.',
    recommendation:
      'Clear "Allow creating new objects" and "Allow deleting existing objects" on the access rule, or remove the guest-held role from it.',
    whyItMatters:
      'Create and delete rights on a stored entity let an unauthenticated visitor add or destroy records directly from the client, with no login and no audit trail beyond the row itself.',
    confidence: 'High',
    requires: ['entityAccessRules', 'projectSecurity', 'moduleRoles'],
    check: (ir, emit) => {
      const guestRoles = guestModuleRoles(ir);
      if (guestRoles.size === 0) return;

      for (const { entity, rule, ordinal } of entityAccessRules(ir)) {
        // A non-persistable entity is never stored, so create and delete rights on one do not
        // expose data. Skipping them is what keeps this rule off every marketplace login form.
        if (entity.persistenceType !== 'persistable') continue;

        const via = rolesInCommon(rule, guestRoles);
        if (via.length === 0) continue;
        if (!rule.allowCreate && !rule.allowDelete && rule.defaultMemberAccess !== 'ReadWrite') {
          continue;
        }

        const rights = [
          rule.allowCreate ? 'create' : undefined,
          rule.allowDelete ? 'delete' : undefined,
          rule.defaultMemberAccess === 'ReadWrite' ? 'write by default' : undefined,
        ].filter(Boolean);

        emit({
          key: `${entity.qualifiedName}#${ordinal}`,
          module: entity.module,
          artifact: `Access rule ${ordinal} on ${entity.qualifiedName}`,
          observation: `Access rule ${ordinal} on persistable entity "${entity.qualifiedName}" grants ${rights.join(', ')} to guest-held module role(s) ${via.join(', ')}.`,
          objectName: entity.name,
          objectType: 'AccessRule',
          artifactPath: entity.qualifiedName,
          details: {
            moduleRoles: rule.moduleRoles,
            guestHeldRoles: via,
            allowCreate: rule.allowCreate,
            allowDelete: rule.allowDelete,
            defaultMemberAccess: rule.defaultMemberAccess,
            xPathConstraint: rule.xPathConstraint ?? null,
            unitPath: rule.provenance?.unitPath,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-020',
    name: 'Guest-reachable role has write access to a member',
    description:
      'Access rules granted to guest-held module roles must not give ReadWrite access to members.',
    category: 'Security',
    subcategory: 'Anonymous Access',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Member Access',
    expectedPractice:
      'Give guest-reachable rules ReadOnly access, and only to members that are genuinely public.',
    recommendation:
      'Set the member to ReadOnly or None on this access rule, or remove the guest-held role from it.',
    whyItMatters:
      'Member-level write access lets an unauthenticated visitor change that field on existing records, which is enough to tamper with stored data even when object creation and deletion are blocked.',
    confidence: 'High',
    requires: ['entityAccessRules', 'projectSecurity', 'moduleRoles'],
    check: (ir, emit) => {
      const guestRoles = guestModuleRoles(ir);
      if (guestRoles.size === 0) return;

      for (const { entity, rule, ordinal } of entityAccessRules(ir)) {
        if (entity.persistenceType !== 'persistable') continue;
        const via = rolesInCommon(rule, guestRoles);
        if (via.length === 0) continue;

        for (const member of rule.memberAccess) {
          if (member.access !== 'ReadWrite') continue;
          const shortName = memberName(member.attributeOrAssociation);
          emit({
            key: `${entity.qualifiedName}.${shortName}#${ordinal}`,
            module: entity.module,
            artifact: `Member: ${entity.qualifiedName}.${shortName}`,
            observation: `Access rule ${ordinal} on "${entity.qualifiedName}" gives guest-held module role(s) ${via.join(', ')} write access to ${member.isAssociation ? 'association' : 'attribute'} "${shortName}".`,
            objectName: shortName,
            objectType: member.isAssociation ? 'Association' : 'Attribute',
            artifactPath: member.attributeOrAssociation,
            details: {
              guestHeldRoles: via,
              access: member.access,
              isAssociation: member.isAssociation,
              xPathConstraint: rule.xPathConstraint ?? null,
              unitPath: rule.provenance?.unitPath,
            },
          });
        }
      }
    },
  }),

  defineRule({
    id: 'SEC-029',
    name: 'Anonymous role has access to a persistable entity',
    description:
      'No module role held by the anonymous user role may be granted any access rule on a persistable entity.',
    category: 'Security',
    subcategory: 'Anonymous Access',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Anonymous Users',
    expectedPractice:
      'Anonymous users hold no rights on stored data. Data a public page must show is served through a non-persistable entity or a microflow that returns only what is public.',
    recommendation:
      'Remove the anonymous-held module role from this access rule, and serve any genuinely public data through a non-persistable entity.',
    whyItMatters:
      'Any access rule on a stored entity lets an unauthenticated visitor retrieve those rows straight from the client, without logging in and without going through a page. Read-only access is still a disclosure: every row the rule and its XPath allow, and every member it makes readable, is available to anyone who can reach the application URL.',
    confidence: 'High',
    requires: ['entityAccessRules', 'projectSecurity', 'moduleRoles'],
    check: (ir, emit) => {
      const guestRoles = guestModuleRoles(ir);
      if (guestRoles.size === 0) return;

      for (const { entity, rule, ordinal } of entityAccessRules(ir)) {
        // A non-persistable entity holds nothing between requests, which is why it is the
        // sanctioned way to give anonymous pages (login, registration, public forms) a data shape.
        if (entity.persistenceType !== 'persistable') continue;
        if (isPlatformModule(ir, entity.module)) continue;

        const via = rolesInCommon(rule, guestRoles);
        if (via.length === 0) continue;

        const readable = rule.memberAccess
          .filter((m) => READABLE.includes(m.access))
          .map((m) => memberName(m.attributeOrAssociation));
        const writable = rule.memberAccess
          .filter((m) => m.access === 'ReadWrite')
          .map((m) => memberName(m.attributeOrAssociation));
        const rights = [
          rule.allowCreate ? 'create' : undefined,
          rule.allowDelete ? 'delete' : undefined,
          rule.defaultMemberAccess !== 'None' ? `${rule.defaultMemberAccess} by default` : undefined,
          writable.length > 0 ? `write on ${writable.join(', ')}` : undefined,
          readable.length > writable.length
            ? `read on ${readable.filter((m) => !writable.includes(m)).join(', ')}`
            : undefined,
        ].filter((r): r is string => r !== undefined);
        const granted =
          rights.length > 0
            ? rights.join('; ')
            : 'no member rights, which still lets the visitor retrieve the objects and their associations';

        const ownModule = isUserModule(ir, entity.module);
        emit({
          key: `${entity.qualifiedName}#${ordinal}`,
          module: entity.module,
          // As with SEC-006: the grant is always the team's to withdraw, but an entity inside a
          // marketplace module is sometimes exposed on purpose by that module's anonymous role, so
          // it is reported for review rather than asserted to be a defect.
          status: ownModule ? 'FAIL' : 'WARNING',
          severity: ownModule ? 'High' : 'Medium',
          artifact: `Access rule ${ordinal} on ${entity.qualifiedName}`,
          observation:
            `Access rule ${ordinal} on persistable entity "${entity.qualifiedName}" is granted to anonymous-held module role(s) ${via.join(', ')}: ${granted}.` +
            (rule.xPathConstraint ? ` The rule is limited by the XPath ${rule.xPathConstraint}.` : ' The rule has no XPath constraint, so it covers every row.') +
            (ownModule ? '' : ` The entity belongs to marketplace module "${entity.module}"; confirm the module requires this.`),
          objectName: entity.name,
          objectType: 'AccessRule',
          artifactPath: entity.qualifiedName,
          details: {
            anonymousUserRole: ir.security.anonymousRole,
            anonymousHeldRoles: via,
            allowCreate: rule.allowCreate,
            allowDelete: rule.allowDelete,
            defaultMemberAccess: rule.defaultMemberAccess,
            readableMembers: readable,
            writableMembers: writable,
            xPathConstraint: rule.xPathConstraint ?? null,
            moduleIsMarketplace: !ownModule,
            unitPath: rule.provenance?.unitPath,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-021',
    name: 'Sensitive or PII member readable by a broad role',
    description:
      'Members classified as secret or PII must not be readable by a module role granted to several user roles.',
    category: 'Security',
    subcategory: 'Data Privacy',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Member Access',
    expectedPractice:
      'Grant read access to sensitive and personal members through a dedicated module role held by the roles that need it.',
    recommendation:
      'Set the member to None on this rule and grant it through a narrower module role.',
    whyItMatters:
      'A module role held by several user roles reaches a wider audience than its name suggests, so a sensitive member readable through it is visible to users the modeller was not considering — including, when one of those user roles is the guest, unauthenticated visitors.',
    // Medium: the classification is a name match. Where a second structural fact corroborates
    // it the corroboration is named in the evidence, per §6.6.
    confidence: 'Medium',
    requires: ['entityAccessRules', 'attributeTypes'],
    check: (ir, emit) => {
      const broad = broadModuleRoles(ir);
      if (broad.size === 0) return;
      const guestRoles = guestModuleRoles(ir);

      for (const { entity, rule, ordinal } of entityAccessRules(ir)) {
        const via = rolesInCommon(rule, broad);
        if (via.length === 0) continue;

        const classified = new Map(
          [...secretAttributes(entity), ...piiAttributes(entity)].map((a) => [a.name, a])
        );
        if (classified.size === 0) continue;

        for (const member of rule.memberAccess) {
          if (!READABLE.includes(member.access)) continue;
          const attribute = classified.get(memberName(member.attributeOrAssociation));
          if (!attribute) continue;

          const guestHeld = via.filter((r) => guestRoles.has(r));
          emit({
            key: `${entity.qualifiedName}.${attribute.name}#${ordinal}`,
            module: entity.module,
            // Stays at the rule's High even when the guest holds the role. SEC-020 already
            // reports guest reachability on the same member with its own severity, and raising
            // this one to Critical would score a single mis-set member twice at the top weight.
            // The guest involvement is stated in the observation instead.
            artifact: `Member: ${entity.qualifiedName}.${attribute.name}`,
            observation: `Attribute "${attribute.name}" on "${entity.qualifiedName}" is classified ${sensitivityLabel(attribute)} and is ${member.access} for module role(s) ${via.join(', ')}, each granted to more than one user role${guestHeld.length > 0 ? `, including the guest role via ${guestHeld.join(', ')}` : ''}.`,
            objectName: attribute.name,
            objectType: 'Attribute',
            artifactPath: member.attributeOrAssociation,
            details: {
              access: member.access,
              attributeType: attribute.type ?? null,
              sensitivityKind: attribute.sensitivityKind,
              sensitivityTerm: attribute.sensitivityTerm,
              broadRoles: via,
              guestHeldRoles: guestHeld,
              unitPath: rule.provenance?.unitPath,
            },
          });
        }
      }
    },
  }),

  defineRule({
    id: 'SEC-022',
    name: 'Owned-data entity without an XPath constraint',
    description:
      'Access rules on entities that record an owner should constrain rows to the current user.',
    category: 'Security',
    subcategory: 'Entity Access',
    severity: 'Medium',
    sourceSkill: 'xpath-constraints.md',
    sourceSection: 'Row-Level Security',
    expectedPractice:
      "Constrain non-administrator access rules on owned data with an XPath such as [System.owner = '[%CurrentUser%]'].",
    recommendation:
      'Add an XPath constraint to the access rule, or confirm that every holder of this role is meant to see all rows.',
    whyItMatters:
      'An owner attribute suggests the rows belong to individual users. Without a constraint the rule grants access to every row, so one user can read or edit another user\'s records.',
    // Low: an owner attribute is a hint, not proof that rows are private. The assumption is
    // stated in the observation so a reviewer can dismiss it in one read.
    confidence: 'Low',
    requires: ['entityAccessRules'],
    check: (ir, emit) => {
      for (const { entity, rule, ordinal } of entityAccessRules(ir)) {
        if (entity.hasOwnerAttribute !== true) continue;
        if (!isUserModule(ir, entity.module)) continue;
        if (rule.xPathConstraint) continue;
        if (rule.moduleRoles.every((r) => isAdministratorRole(r))) continue;

        emit({
          key: `${entity.qualifiedName}#${ordinal}`,
          status: 'WARNING',
          module: entity.module,
          artifact: `Access rule ${ordinal} on ${entity.qualifiedName}`,
          observation: `Entity "${entity.qualifiedName}" records an owner, and access rule ${ordinal} grants ${rule.moduleRoles.join(', ')} access to every row with no XPath constraint. This assumes the rows are per-user; if they are shared by design, the rule is correct as written.`,
          objectName: entity.name,
          objectType: 'AccessRule',
          artifactPath: entity.qualifiedName,
          details: {
            moduleRoles: rule.moduleRoles,
            hasOwnerAttribute: true,
            xPathConstraint: null,
            unitPath: rule.provenance?.unitPath,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-EE-003',
    name: 'Broad read/write access defaults (lazy rule definition)',
    description:
      'Overly permissive default entity access configurations grant dangerous write accesses automatically when new attributes are appended to an object.',
    category: 'Security',
    subcategory: 'Entity Access',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Entity Access Rules',
    expectedPractice:
      "Set an entity access rule's Default rights for new members to None, so every newly added attribute and association is evaluated and secured on purpose (https://docs.mendix.com/howto9/security/best-practices-security/).",
    recommendation:
      'Edit the entity\'s access rules, change the member default fallback options to None, and explicitly map permission grids for individual attributes.',
    whyItMatters:
      'The default applies to every member added to the entity later. With Read, a new attribute — a salary, a token, a national id — is readable by the role the moment it is created; with Read and Write it is also writable. Nobody decides to grant that access, so nobody reviews it.',
    confidence: 'High',
    requires: ['entityAccessRules'],
    check: (ir, emit) => {
      for (const { entity, rule, ordinal } of entityAccessRules(ir)) {
        // Condition 1: the fallback for new members is Read, or Read and Write.
        if (rule.defaultMemberAccess === 'None') continue;
        if (isPlatformModule(ir, entity.module)) continue;
        // Condition 2: granted to a standard, non-administrative role.
        const standard = rule.moduleRoles.filter((qualified) => {
          const dot = qualified.indexOf('.');
          return qualified.slice(0, dot) !== 'System' && !isAdministratorRole(qualified.slice(dot + 1));
        });
        if (standard.length === 0) continue;

        const own = isUserModule(ir, entity.module);
        const level = rule.defaultMemberAccess === 'ReadWrite' ? 'Read and Write' : 'Read';
        emit({
          key: `${entity.qualifiedName}#${ordinal}`,
          module: entity.module,
          // As elsewhere in the catalogue: a Marketplace entity's rule is the module's own
          // configuration, reported for review one severity lower.
          status: own ? 'FAIL' : 'WARNING',
          severity: own ? 'High' : 'Medium',
          artifact: `Access rule ${ordinal} on ${entity.qualifiedName}`,
          observation:
            `Access rule ${ordinal} on "${entity.qualifiedName}" sets Default rights for new members to ${level} for non-administrative role(s) ${standard.join(', ')}, so any attribute or association added later is ${rule.defaultMemberAccess === 'ReadWrite' ? 'readable and writable' : 'readable'} by them without review.` +
            (rule.defaultMemberAccess === 'ReadOnly'
              ? ' Mendix\'s guidance names Read and Write defaults explicitly; a Read default is flagged by this governance standard for the same reason.'
              : '') +
            (own ? '' : ` The entity belongs to Marketplace module "${entity.module}".`),
          objectName: entity.name,
          objectType: 'AccessRule',
          artifactPath: entity.qualifiedName,
          details: {
            defaultMemberAccess: rule.defaultMemberAccess,
            nonAdministrativeRoles: standard,
            allRoles: rule.moduleRoles,
            unitPath: rule.provenance?.unitPath,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-005',
    name: 'Password or secret attribute not hashed',
    description:
      'Attributes whose name identifies a credential must use the HashedString type.',
    category: 'Security',
    subcategory: 'Data Privacy',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Password and Sensitive Attributes',
    expectedPractice: 'Store credentials in a HashedString attribute.',
    recommendation:
      'Change the attribute type to HashedString, or remove the attribute if the credential is held elsewhere.',
    whyItMatters:
      'A String attribute is stored in the database as typed and appears in backups, database exports and OData feeds. HashedString applies the project\'s configured hash on commit so the stored value cannot be read back.',
    // High rather than Medium: the real attribute type is read from the model, so the name
    // match is corroborated by a structural fact (§6.6).
    confidence: 'High',
    requires: ['attributeTypes'],
    check: (ir, emit) => {
      for (const entity of Object.values(ir.entities)) {
        if (!isUserModule(ir, entity.module)) continue;

        for (const attribute of secretAttributes(entity)) {
          if (attribute.type === 'HashedString') continue;
          // An unreadable type cannot support the claim; `attributeTypes` coverage carries it.
          if (attribute.type === undefined) continue;

          emit({
            key: `${entity.qualifiedName}.${attribute.name}`,
            module: entity.module,
            artifact: `Attribute: ${entity.qualifiedName}.${attribute.name}`,
            observation: `Attribute "${attribute.name}" on "${entity.qualifiedName}" is classified ${sensitivityLabel(attribute)} but has type "${attribute.type}" rather than HashedString.`,
            objectName: attribute.name,
            objectType: 'Attribute',
            artifactPath: `${entity.qualifiedName}.${attribute.name}`,
            details: {
              currentType: attribute.type,
              expectedType: 'HashedString',
              sensitivityTerm: attribute.sensitivityTerm,
              unitPath: entity.provenance?.unitPath,
            },
          });
        }
      }
    },
  }),

  defineRule({
    id: 'SEC-008',
    name: 'PII stored without encryption',
    description:
      'Attributes holding personal data are stored in plain database columns unless the application encrypts them.',
    category: 'Security',
    subcategory: 'Data Privacy',
    severity: 'Medium',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Data at Rest Encryption',
    expectedPractice:
      'Decide deliberately whether personal data needs application-level encryption, and record the decision.',
    recommendation:
      'Confirm whether this attribute is covered by database-level encryption; if not, encrypt it in logic before commit.',
    whyItMatters:
      'Personal data in plain columns is readable in database backups and exports. Mendix has no encrypted attribute type, so whether this is a defect depends on how the platform and database are configured.',
    // Low confidence and off by default: "String-typed PII" is not a violation on its own,
    // and firing it as a High finding on every email column is the false-positive inflation
    // design §22 warns about. Enable it when a policy requires application-level encryption.
    confidence: 'Low',
    enabled: false,
    requires: ['attributeTypes'],
    check: (ir, emit) => {
      for (const entity of Object.values(ir.entities)) {
        if (!isUserModule(ir, entity.module)) continue;

        const pii = piiAttributes(entity).filter((a) => a.type === 'String');
        if (pii.length === 0) continue;
        const names = pii.map((a) => a.name);

        emit({
          key: entity.qualifiedName,
          status: 'WARNING',
          module: entity.module,
          artifact: `Entity: ${entity.qualifiedName}`,
          observation: `Entity "${entity.qualifiedName}" holds String attributes classified as personal data (${names.join(', ')}) with no application-level encryption visible in the model.`,
          objectName: entity.name,
          objectType: 'Entity',
          artifactPath: entity.qualifiedName,
          details: {
            piiAttributes: names,
            matchedTerms: pii.map((a) => a.sensitivityTerm),
            unitPath: entity.provenance?.unitPath,
          },
        });
      }
    },
  }),

  // ---------------------------------------------------------------------------------------
  // 6.4 Role hygiene
  // ---------------------------------------------------------------------------------------

  defineRule({
    id: 'SEC-023',
    name: 'User role bypasses security',
    description: 'No user role may have CheckSecurity disabled.',
    category: 'Security',
    subcategory: 'Role Hygiene',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'User Roles',
    expectedPractice: 'Leave security checking enabled on every user role.',
    recommendation: 'Enable security checking for this user role in App Security.',
    whyItMatters:
      'A user role with security checking off ignores the access rules for everyone assigned to it, so the model\'s permissions describe something the runtime is not enforcing for those users.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      for (const role of ir.security.userRoles) {
        if (role.checkSecurity !== false) continue;
        emit({
          key: role.name,
          artifact: `User role: ${role.name}`,
          observation: `User role "${role.name}" has security checking disabled.`,
          objectName: role.name,
          objectType: 'UserRole',
          artifactPath: `AppSecurity.UserRoles.${role.name}`,
          details: {
            checkSecurity: false,
            moduleRoles: role.moduleRoles.map((m) => `${m.module}.${m.role}`),
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-024',
    name: 'Non-administrator user role can manage all roles',
    description: 'ManageAllRoles must be limited to administrator user roles.',
    category: 'Security',
    subcategory: 'Role Hygiene',
    severity: 'Medium',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'User Roles',
    expectedPractice:
      'Grant "manage all roles" only to the administrator role, and list specific manageable roles elsewhere.',
    recommendation:
      'Clear "manage all roles" on this user role and list only the roles it should be able to assign.',
    whyItMatters:
      'A role that can assign any role can assign the administrator role, to itself or to anyone else. That turns a limited account into a path to full administrative access.',
    confidence: 'High',
    requires: ['projectSecurity'],
    check: (ir, emit) => {
      for (const role of ir.security.userRoles) {
        if (role.manageAllRoles !== true) continue;
        if (role.isAdministrator) continue;
        emit({
          key: role.name,
          artifact: `User role: ${role.name}`,
          observation: `User role "${role.name}" is not an administrator role but may manage all user roles, including administrator roles.`,
          objectName: role.name,
          objectType: 'UserRole',
          artifactPath: `AppSecurity.UserRoles.${role.name}`,
          details: {
            manageAllRoles: true,
            isAdministrator: false,
            moduleRoles: role.moduleRoles.map((m) => `${m.module}.${m.role}`),
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-025',
    name: 'Module role not mapped to any user role',
    description: 'Module roles should be granted to at least one user role.',
    category: 'Security',
    subcategory: 'Role Hygiene',
    severity: 'Low',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Module Roles',
    expectedPractice:
      'Every module role a module declares should be granted to a user role, or removed.',
    recommendation:
      'Grant the module role to the user roles that need it, or delete it from the module\'s security.',
    whyItMatters:
      'An ungranted module role is dead grant surface: it still carries whatever access rules, pages and microflows reference it, so granting it later silently enables all of them at once.',
    confidence: 'High',
    requires: ['moduleRoles', 'projectSecurity'],
    check: (ir, emit) => {
      const granted = grantedModuleRoles(ir);

      for (const moduleRole of ir.security.moduleRoles) {
        // Marketplace modules declare roles for use cases an app may not adopt; an unused one
        // is the module's design, not the team's oversight.
        if (!isUserModule(ir, moduleRole.module)) continue;
        if (granted.has(moduleRole.qualifiedName)) continue;

        emit({
          key: moduleRole.qualifiedName,
          status: 'WARNING',
          module: moduleRole.module,
          artifact: `Module role: ${moduleRole.qualifiedName}`,
          observation: `Module role "${moduleRole.qualifiedName}" is declared but granted to no user role.`,
          objectName: moduleRole.name,
          objectType: 'ModuleRole',
          artifactPath: moduleRole.qualifiedName,
          details: { module: moduleRole.module, grantedToUserRoles: [] },
        });
      }
    },
  }),

  // ---------------------------------------------------------------------------------------
  // 6.5 Custom code, constants & integration
  // ---------------------------------------------------------------------------------------

  defineRule({
    id: 'SEC-007',
    name: 'Regex-based XSS sanitiser',
    description:
      'Java actions must not use blacklist regular expressions to strip HTML or script content.',
    category: 'Security',
    subcategory: 'Input Sanitization',
    severity: 'High',
    sourceSkill: 'java-actions.md',
    sourceSection: 'Input Validation and Injection Prevention',
    expectedPractice:
      'Sanitise HTML with a parser-based sanitiser such as CommunityCommons.SanitizeHTML or the OWASP Java HTML Sanitizer.',
    recommendation:
      'Replace the regular-expression filtering with CommunityCommons.SanitizeHTML.',
    whyItMatters:
      'Blacklist regular expressions are bypassed by nested tags, SVG vectors and alternative encodings, so the sanitiser passes review while stored XSS still gets through.',
    confidence: 'High',
    requires: [],
    check: (ir, emit) => {
      for (const action of ir.customCode.javaActions) {
        if (!action.hasRegexXssSanitizer) continue;
        const inUserModule = isUserModule(ir, action.module);

        emit({
          key: `${action.module}.${action.name}`,
          module: action.module,
          // In a user module this is the team's own code and a defect they own. In a
          // marketplace module they cannot edit the source, so it is reported as something to
          // verify or replace rather than as their design violation — but it is still
          // reported, because a sanitiser that does not work is a real exposure either way.
          status: inUserModule ? 'FAIL' : 'WARNING',
          severity: inUserModule ? 'High' : 'Medium',
          confidence: inUserModule ? 'High' : 'Medium',
          artifact: `Java action: ${action.module}.${action.name}`,
          observation: inUserModule
            ? `Java action "${action.name}" in module "${action.module}" filters HTML or script content with regular expressions.`
            : `Java action "${action.name}" in marketplace module "${action.module}" filters HTML or script content with regular expressions. The source cannot be edited in place.`,
          recommendation: inUserModule
            ? `Refactor ${action.sourceFile ?? action.name} to use CommunityCommons.SanitizeHTML.`
            : `Check for a newer version of "${action.module}", or route input through CommunityCommons.SanitizeHTML before it reaches this action.`,
          objectName: action.name,
          objectType: 'JavaAction',
          artifactPath: action.sourceFile ?? `${action.module}.actions.${action.name}`,
          details: {
            module: action.module,
            moduleIsMarketplace: !inUserModule,
            sourceFile: action.sourceFile,
            antiPattern: 'regular-expression HTML filtering',
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-026',
    name: 'Hardcoded secret in a constant',
    description:
      'Constants whose name identifies a credential must not carry a value in the model.',
    category: 'Security',
    subcategory: 'Credentials',
    severity: 'High',
    sourceSkill: 'project-settings.md',
    sourceSection: 'Constants',
    expectedPractice:
      'Leave credential constants empty in the model and supply the value as an environment constant.',
    recommendation:
      'Clear the default value and set this constant per environment in the Mendix Cloud or deployment configuration.',
    whyItMatters:
      'A constant value is committed with the model, so the credential is readable by everyone with repository access, remains in history after removal, and is deployed identically to every environment.',
    // Medium: the classification is a name match on the constant. SEC-027 raises it to High
    // where `ExposedToClient` corroborates that the value reaches the browser.
    confidence: 'Medium',
    requires: ['constants'],
    check: (ir, emit) => {
      for (const constant of ir.operations.constants) {
        // The extractor drops the value of a secret-shaped constant before it reaches the IR,
        // so an absent `defaultValue` together with `hasDefaultValue` is the signal here — and
        // the value is unavailable to put in evidence even by accident.
        if (!constant.hasDefaultValue) continue;
        if (constant.defaultValue !== undefined) continue;

        emit({
          key: `${constant.module}.${constant.name}`,
          module: constant.module,
          artifact: `Constant: ${constant.module}.${constant.name}`,
          observation: `Constant "${constant.module}.${constant.name}" is named as a credential and carries a value in the model. The value was classified during extraction and discarded, so it is not reproduced here.`,
          objectName: constant.name,
          objectType: 'Constant',
          artifactPath: `${constant.module}.${constant.name}`,
          details: {
            dataType: constant.dataType,
            hasDefaultValue: true,
            isExposedToClient: constant.isExposedToClient,
            valueRedacted: true,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-027',
    name: 'Secret-bearing constant exposed to the client',
    description:
      'A constant that holds a credential must never be marked as exposed to the client.',
    category: 'Security',
    subcategory: 'Credentials',
    severity: 'Critical',
    sourceSkill: 'project-settings.md',
    sourceSection: 'Constants',
    expectedPractice:
      'Keep credential constants server-side; only non-sensitive configuration may be exposed to the client.',
    recommendation:
      'Clear "Expose to client" on this constant and read it from a microflow instead.',
    whyItMatters:
      'A client-exposed constant is delivered to the browser, so any visitor who can load the application can read it from the client bundle. Combined with a credential value this publishes the secret to anyone who opens the page.',
    confidence: 'High',
    requires: ['constants'],
    check: (ir, emit) => {
      for (const constant of ir.operations.constants) {
        if (!constant.isExposedToClient) continue;
        if (!constant.hasDefaultValue || constant.defaultValue !== undefined) continue;

        emit({
          key: `${constant.module}.${constant.name}`,
          module: constant.module,
          artifact: `Constant: ${constant.module}.${constant.name}`,
          observation: `Constant "${constant.module}.${constant.name}" is named as a credential, carries a value, and is exposed to the client.`,
          objectName: constant.name,
          objectType: 'Constant',
          artifactPath: `${constant.module}.${constant.name}`,
          details: {
            dataType: constant.dataType,
            isExposedToClient: true,
            hasDefaultValue: true,
            valueRedacted: true,
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-010',
    name: 'Form data cached in browser localStorage',
    description:
      'Constants indicating browser localStorage caching of user input should be reviewed.',
    category: 'Security',
    subcategory: 'Data Privacy',
    severity: 'Low',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Client Storage Security',
    expectedPractice:
      'Keep user input in server-side state, or clear the client cache as soon as it is submitted.',
    recommendation:
      'Confirm the cached data holds no personal information, and clear the key on submission.',
    whyItMatters:
      'localStorage has no expiry and is readable by any script on the same origin, so anything cached there outlives the session on a shared machine.',
    // Low/Low and scoped to user modules. The previous version's only hit was a marketplace
    // module's own cache key — third-party code, and a name coincidence rather than evidence
    // that user data is stored.
    confidence: 'Low',
    requires: ['constants'],
    check: (ir, emit) => {
      for (const constant of ir.operations.constants) {
        if (!isUserModule(ir, constant.module)) continue;
        if (!/localstorage|sessionstorage/i.test(constant.name)) continue;

        emit({
          key: `${constant.module}.${constant.name}`,
          status: 'WARNING',
          module: constant.module,
          artifact: `Constant: ${constant.module}.${constant.name}`,
          observation: `Constant "${constant.module}.${constant.name}" names a browser storage key, so client-side data may persist beyond the session.`,
          objectName: constant.name,
          objectType: 'Constant',
          artifactPath: `${constant.module}.${constant.name}`,
          details: {
            dataType: constant.dataType,
            isExposedToClient: constant.isExposedToClient,
            nameMatch: 'localStorage/sessionStorage',
          },
        });
      }
    },
  }),

  defineRule({
    id: 'SEC-004',
    name: 'Published REST endpoint without authentication',
    description: 'Published REST endpoints must require authentication.',
    category: 'Security',
    subcategory: 'Integration Security',
    severity: 'Critical',
    sourceSkill: 'rest-client.md',
    sourceSection: 'Published REST Services',
    expectedPractice:
      'Enforce token, basic or custom authentication on every published endpoint unless it is deliberately public.',
    recommendation:
      'Enable authentication on the published REST service, and restrict it to the module roles that need it.',
    whyItMatters:
      'An unauthenticated published endpoint lets anyone who can reach the application run the microflow behind it, with whatever entity access that microflow carries.',
    confidence: 'High',
    // Phase 1 has no published-services extractor, so `publishedServices` is NOT_ANALYZABLE
    // and the engine records this rule NOT_APPLICABLE. That is the point of declaring it: an
    // empty `publishedRestServices` would otherwise be scored as a pass for every project.
    requires: ['publishedServices'],
    check: (ir, emit) => {
      for (const service of ir.integrations.publishedRestServices) {
        for (const endpoint of service.endpoints) {
          if (endpoint.requiresAuthentication && endpoint.authType !== 'None') continue;
          emit({
            key: `${service.name}-${endpoint.name}`,
            module: service.module,
            artifact: `REST endpoint: ${service.name} ${endpoint.httpMethod} ${endpoint.path}`,
            observation: `Published endpoint "${endpoint.path}" on service "${service.name}" does not require authentication.`,
            objectName: endpoint.name,
            objectType: 'RestEndpoint',
            artifactPath: `${service.module}.${service.name}.${endpoint.name}`,
            details: {
              path: endpoint.path,
              httpMethod: endpoint.httpMethod,
              authType: endpoint.authType ?? 'None',
              microflow: endpoint.microflow,
            },
          });
        }
      }
    },
  }),

  defineRule({
    id: 'SEC-028',
    name: 'Reachable microflow bypasses entity access',
    description:
      'A microflow callable by a user role must apply entity access unless it is deliberately privileged.',
    category: 'Security',
    subcategory: 'Microflow Security',
    severity: 'High',
    sourceSkill: SECURITY_SKILL,
    sourceSection: 'Microflow Security',
    expectedPractice:
      'Enable "Apply entity access" on microflows callable from the client, and keep privileged logic in microflows with no allowed roles.',
    recommendation:
      'Enable "Apply entity access" on the microflow, or remove its allowed roles and call it from a microflow that does apply entity access.',
    whyItMatters:
      'With entity access off the microflow reads and writes with full rights regardless of who called it, so its retrieves ignore the access rules and XPath constraints that protect the same data everywhere else.',
    // Medium: entity access off is sometimes deliberate for privileged logic. What raises it
    // above a style note is reachability — the rule only fires where a role can call it.
    confidence: 'Medium',
    // `docs/security.md` §6.5 expected this to be NOT_ANALYZABLE in Phase 1. The microflow
    // security facts turned out to be readable (`AllowedModuleRoles`, `ApplyEntityAccess`), so
    // the rule runs. Only those two facts are used; nothing here needs the activity graph.
    requires: ['microflows', 'projectSecurity'],
    check: (ir, emit) => {
      const guestRoles = guestModuleRoles(ir);

      for (const microflow of Object.values(ir.microflows)) {
        if (microflow.appliesEntityAccess !== false) continue;
        // No allowed roles means the microflow is not callable directly; it runs in the
        // context of whatever calls it. Flagging those would report the Mendix default on
        // every internal sub-microflow in the project.
        if (microflow.allowedRoles.length === 0) continue;

        const guestHeld = microflow.allowedRoles.filter((r) => guestRoles.has(r));
        const inUserModule = isUserModule(ir, microflow.module);
        if (guestHeld.length === 0 && !inUserModule) continue;

        const guestReachable = guestHeld.length > 0;

        emit({
          key: microflow.qualifiedName,
          module: microflow.module,
          // The same split as SEC-007. In the team's own module this is their microflow and
          // their defect. In a marketplace module they cannot change the flow, and the fix is
          // to withdraw the grant that makes it reachable — so it is reported as something to
          // act on via the role mapping rather than as a failure they caused.
          severity: guestReachable && inUserModule ? 'Critical' : 'High',
          status: inUserModule ? 'FAIL' : 'WARNING',
          confidence: inUserModule ? 'High' : 'Medium',
          artifact: `Microflow: ${microflow.qualifiedName}`,
          observation: guestReachable
            ? `Microflow "${microflow.qualifiedName}" does not apply entity access and is callable by guest-held module role(s) ${guestHeld.join(', ')}, so an unauthenticated visitor can run it with full data rights.${inUserModule ? '' : ` The microflow belongs to marketplace module "${microflow.module}" and cannot be changed in place.`}`
            : `Microflow "${microflow.qualifiedName}" does not apply entity access and is callable by module role(s) ${microflow.allowedRoles.join(', ')}.`,
          recommendation: inUserModule
            ? 'Enable "Apply entity access" on the microflow, or remove its allowed roles and call it from a microflow that does apply entity access.'
            : `Remove the guest-held role(s) ${guestHeld.join(', ')} from the guest user role so this microflow is no longer callable anonymously.`,
          objectName: microflow.name,
          objectType: 'Microflow',
          artifactPath: microflow.qualifiedName,
          details: {
            appliesEntityAccess: false,
            allowedRoles: microflow.allowedRoles,
            guestHeldRoles: guestHeld,
            moduleIsMarketplace: !inUserModule,
            unitPath: microflow.provenance?.unitPath,
          },
        });
      }
    },
  }),
];

/** The full Security catalogue: the SEC-* rules above, then the SEC-MF-* microflow rules. */
export const securityRules = [...coreSecurityRules, ...microflowSecurityRules];
