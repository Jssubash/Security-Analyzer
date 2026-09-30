/**
 * `docs/security.md` §8 test 3 — one firing IR and one quiet IR for each of the 35 SEC rules.
 *
 * The quiet case is the half that earns its keep. A rule that fires on the reference project may
 * be firing for a reason nobody intended, and a rule whose quiet case is missing can be a rule
 * that fires on everything. Each pair below differs by exactly one fact, so a failure names the
 * fact the rule actually reads.
 *
 * Two further invariants are asserted across the whole catalogue at the bottom of this file:
 * every rule declares `requires`, and no finding carries a credential value in its evidence.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { getDefaultRules } from '@mendix-analyzer/rules';

import {
  accessRule,
  attribute,
  byQualifiedName,
  constant,
  entity,
  makeIr,
  microflow,
  moduleRole,
  page,
  userRole,
  withGuest,
} from './helpers/ir-builder.mjs';

const RULES = new Map(getDefaultRules().map((r) => [r.id, r]));

function evaluate(ruleId, ir) {
  const rule = RULES.get(ruleId);
  assert.ok(rule, `rule ${ruleId} is not registered`);
  return rule.evaluate(ir);
}

/** A guest user role holding `held`, with those module roles declared. */
function guestSecurity(held, extra = {}) {
  return withGuest({ userRoles: [], moduleRoles: [], ...extra }, held);
}

// ---------------------------------------------------------------------------------------------
// The table. `fires` must produce at least one finding; each `quiet` must produce none.
// ---------------------------------------------------------------------------------------------

const CASES = [
  // --- 6.1 project & platform -----------------------------------------------------------------
  {
    id: 'SEC-002',
    what: 'security level below CheckEverything',
    fires: () => makeIr({ security: { projectSecurityLevel: 'CheckFormsAndMicroflows' } }),
    quiet: [['at CheckEverything', () => makeIr()]],
  },
  {
    id: 'SEC-011',
    what: 'project CheckSecurity disabled',
    fires: () => makeIr({ security: { securityEnabled: false } }),
    quiet: [
      ['security on', () => makeIr()],
      // Unreadable is not the same as off; `projectSecurity` coverage carries that case, and
      // the rule must not invent a failure from an absent flag.
      ['flag unreadable', () => makeIr({ security: { securityEnabled: undefined } })],
    ],
  },
  {
    id: 'SEC-012',
    what: 'demo users enabled',
    fires: () => makeIr({ security: { demoUsersEnabled: true } }),
    quiet: [['demo users off', () => makeIr()]],
  },
  {
    id: 'SEC-013',
    what: 'a demo account with a password in the model',
    fires: () =>
      makeIr({
        security: {
          demoUsersEnabled: true,
          demoUsers: [
            { userName: 'demo_admin', userRoles: ['Administrator'], hasPassword: true, passwordLength: 12 },
          ],
        },
      }),
    quiet: [
      ['no demo accounts', () => makeIr()],
      [
        'a demo account with no password',
        () =>
          makeIr({
            security: {
              demoUsers: [{ userName: 'demo_admin', userRoles: ['Administrator'], hasPassword: false }],
            },
          }),
      ],
    ],
  },
  {
    id: 'SEC-014',
    what: 'a weak administrator password',
    fires: () =>
      makeIr({
        security: {
          administrator: { userName: 'MxAdmin', userRole: 'Administrator', passwordIsWeak: true, passwordLength: 1 },
        },
      }),
    quiet: [
      ['no administrator configured', () => makeIr()],
      [
        'a password that meets the policy',
        () =>
          makeIr({
            security: {
              administrator: { userName: 'MxAdmin', passwordIsWeak: false, passwordLength: 20 },
            },
          }),
      ],
    ],
  },
  {
    id: 'SEC-015',
    what: 'a password policy below baseline',
    fires: () => makeIr({ security: { passwordPolicy: { minimumLength: 6, requireSymbol: false } } }),
    quiet: [
      ['a policy at baseline', () => makeIr()],
      // An absent policy means "not readable", never "not required".
      ['no readable policy', () => makeIr({ security: { passwordPolicy: undefined } })],
    ],
  },
  {
    id: 'SEC-016',
    what: 'strict page URL check disabled',
    fires: () => makeIr({ security: { strictPageUrlCheck: false } }),
    quiet: [
      ['check enabled', () => makeIr()],
      ['setting unreadable', () => makeIr({ security: { strictPageUrlCheck: undefined } })],
    ],
  },

  // --- 6.2 guest access -----------------------------------------------------------------------
  {
    id: 'SEC-006',
    what: 'the guest role holding a business module role',
    fires: () => makeIr({ security: guestSecurity(['App.User']) }),
    quiet: [
      ['guest access off', () => makeIr()],
      ['guest holding only a guest-designated role', () => makeIr({ security: guestSecurity(['App.Anonymous']) })],
      // `System.User` is granted to every user role by Mendix and cannot be removed.
      ['guest holding System.User', () => makeIr({ security: guestSecurity(['System.User']) })],
      // Administrator roles are SEC-017's subject, reported there with their own wording.
      ['guest holding an administrator role', () => makeIr({ security: guestSecurity(['App.Administrator']) })],
    ],
  },
  {
    id: 'SEC-017',
    what: 'the guest role holding an administrator module role',
    fires: () => makeIr({ security: guestSecurity(['Market.Administrator']) }),
    quiet: [
      ['guest access off', () => makeIr()],
      ['guest holding a non-administrator role', () => makeIr({ security: guestSecurity(['App.User']) })],
    ],
  },
  {
    id: 'SEC-018',
    what: 'a page reachable anonymously',
    fires: () =>
      makeIr({
        security: guestSecurity(['App.User']),
        pages: byQualifiedName([
          page('App.SecretReport', { allowedRoles: ['App.User'], isAccessibleAnonymously: true }),
        ]),
      }),
    quiet: [
      [
        'the navigation home page',
        () =>
          makeIr({
            security: guestSecurity(['App.User']),
            pages: byQualifiedName([
              page('App.Home', {
                allowedRoles: ['App.User'],
                isAccessibleAnonymously: true,
                isNavigationHomePage: true,
              }),
            ]),
          }),
      ],
      [
        'a page no guest role reaches',
        () =>
          makeIr({
            security: guestSecurity(['App.Anonymous']),
            pages: byQualifiedName([page('App.SecretReport', { allowedRoles: ['App.Admin'] })]),
          }),
      ],
    ],
  },
  {
    id: 'SEC-019',
    what: 'a page in a user module with no allowed roles',
    fires: () => makeIr({ pages: byQualifiedName([page('App.Orphan')]) }),
    quiet: [
      ['a page with roles', () => makeIr({ pages: byQualifiedName([page('App.Orphan', { allowedRoles: ['App.User'] })]) })],
      // A marketplace page the team cannot edit is not an action they can take.
      ['a marketplace page with no roles', () => makeIr({ pages: byQualifiedName([page('Market.Orphan')]) })],
    ],
  },
  {
    id: 'SEC-009',
    what: 'guest access enabled (advisory; disabled by default)',
    fires: () => makeIr({ security: guestSecurity(['App.User']) }),
    quiet: [['guest access off', () => makeIr()]],
    expectDisabled: true,
  },

  // --- 6.3 entity & member access -------------------------------------------------------------
  {
    id: 'SEC-001',
    what: 'a persistable user-module entity with no access rules',
    fires: () => makeIr({ entities: byQualifiedName([entity('App.Order')]) }),
    quiet: [
      ['an entity with a rule', () => makeIr({ entities: byQualifiedName([entity('App.Order', { accessRules: [accessRule(['App.User'])] })]) })],
      ['a non-persistable entity', () => makeIr({ entities: byQualifiedName([entity('App.Ctx', { persistenceType: 'non-persistable' })]) })],
      ['a marketplace entity', () => makeIr({ entities: byQualifiedName([entity('Market.Thing')]) })],
    ],
  },
  {
    id: 'SEC-003',
    what: 'a guest-reachable rule allowing create or delete',
    fires: () =>
      makeIr({
        security: guestSecurity(['App.User']),
        entities: byQualifiedName([
          entity('App.Order', { accessRules: [accessRule(['App.User'], { allowCreate: true })] }),
        ]),
      }),
    quiet: [
      [
        'read-only for the guest role',
        () =>
          makeIr({
            security: guestSecurity(['App.User']),
            entities: byQualifiedName([
              entity('App.Order', { accessRules: [accessRule(['App.User'], { defaultMemberAccess: 'ReadOnly' })] }),
            ]),
          }),
      ],
      [
        // A non-persistable entity is never stored, so create/delete on one exposes no data.
        // This is what keeps the rule off every marketplace login form.
        'create rights on a non-persistable entity',
        () =>
          makeIr({
            security: guestSecurity(['App.User']),
            entities: byQualifiedName([
              entity('App.LoginContext', {
                persistenceType: 'non-persistable',
                accessRules: [accessRule(['App.User'], { allowCreate: true, allowDelete: true })],
              }),
            ]),
          }),
      ],
      [
        'create rights for a role the guest does not hold',
        () =>
          makeIr({
            security: guestSecurity(['App.Anonymous']),
            entities: byQualifiedName([
              entity('App.Order', { accessRules: [accessRule(['App.Admin'], { allowCreate: true })] }),
            ]),
          }),
      ],
    ],
  },
  {
    id: 'SEC-029',
    what: 'a read-only access rule on a persistable entity granted to an anonymous-held role',
    fires: () =>
      makeIr({
        security: guestSecurity(['App.Anonymous']),
        entities: byQualifiedName([
          entity('App.Product', {
            accessRules: [
              accessRule(['App.Anonymous'], {
                memberAccess: [
                  { attributeOrAssociation: 'App.Product.Name', isAssociation: false, access: 'ReadOnly' },
                ],
              }),
            ],
          }),
        ]),
      }),
    quiet: [
      [
        'the same grant on a non-persistable entity',
        () =>
          makeIr({
            security: guestSecurity(['App.Anonymous']),
            entities: byQualifiedName([
              entity('App.SearchForm', {
                persistenceType: 'non-persistable',
                accessRules: [accessRule(['App.Anonymous'], { defaultMemberAccess: 'ReadWrite', allowCreate: true })],
              }),
            ]),
          }),
      ],
      [
        'an access rule for a role the anonymous user does not hold',
        () =>
          makeIr({
            security: guestSecurity(['App.Anonymous']),
            entities: byQualifiedName([
              entity('App.Product', { accessRules: [accessRule(['App.User'], { defaultMemberAccess: 'ReadOnly' })] }),
            ]),
          }),
      ],
      [
        'anonymous users disabled',
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('App.Product', { accessRules: [accessRule(['App.Anonymous'], { defaultMemberAccess: 'ReadOnly' })] }),
            ]),
          }),
      ],
    ],
  },
  {
    id: 'SEC-020',
    what: 'a guest-reachable rule with member write access',
    fires: () =>
      makeIr({
        security: guestSecurity(['App.User']),
        entities: byQualifiedName([
          entity('App.Order', {
            accessRules: [
              accessRule(['App.User'], {
                memberAccess: [
                  { attributeOrAssociation: 'App.Order.Total', isAssociation: false, access: 'ReadWrite' },
                ],
              }),
            ],
          }),
        ]),
      }),
    quiet: [
      [
        'read-only member access',
        () =>
          makeIr({
            security: guestSecurity(['App.User']),
            entities: byQualifiedName([
              entity('App.Order', {
                accessRules: [
                  accessRule(['App.User'], {
                    memberAccess: [
                      { attributeOrAssociation: 'App.Order.Total', isAssociation: false, access: 'ReadOnly' },
                    ],
                  }),
                ],
              }),
            ]),
          }),
      ],
      [
        'write access on a non-persistable entity',
        () =>
          makeIr({
            security: guestSecurity(['App.User']),
            entities: byQualifiedName([
              entity('App.LoginContext', {
                persistenceType: 'non-persistable',
                accessRules: [
                  accessRule(['App.User'], {
                    memberAccess: [
                      { attributeOrAssociation: 'App.LoginContext.Password', isAssociation: false, access: 'ReadWrite' },
                    ],
                  }),
                ],
              }),
            ]),
          }),
      ],
    ],
  },
  {
    id: 'SEC-021',
    what: 'a PII member readable by a module role held by two user roles',
    fires: () =>
      makeIr({
        security: {
          userRoles: [userRole('Staff', ['App.User']), userRole('Manager', ['App.User'])],
          moduleRoles: [moduleRole('App.User')],
        },
        entities: byQualifiedName([
          entity('App.Contact', {
            attributes: [attribute('Email', 'String', { isPii: true, sensitivityTerm: 'email' })],
            accessRules: [
              accessRule(['App.User'], {
                memberAccess: [
                  { attributeOrAssociation: 'App.Contact.Email', isAssociation: false, access: 'ReadOnly' },
                ],
              }),
            ],
          }),
        ]),
      }),
    quiet: [
      [
        'the same member behind a role held by one user role',
        () =>
          makeIr({
            security: { userRoles: [userRole('Staff', ['App.User'])], moduleRoles: [moduleRole('App.User')] },
            entities: byQualifiedName([
              entity('App.Contact', {
                attributes: [attribute('Email', 'String', { isPii: true, sensitivityTerm: 'email' })],
                accessRules: [
                  accessRule(['App.User'], {
                    memberAccess: [
                      { attributeOrAssociation: 'App.Contact.Email', isAssociation: false, access: 'ReadOnly' },
                    ],
                  }),
                ],
              }),
            ]),
          }),
      ],
      [
        // The structural guard from §6.6: a Boolean cannot hold an email address, so a name
        // match on `_showEmail` is not evidence of a disclosure.
        'a Boolean whose name matches a PII term',
        () =>
          makeIr({
            security: {
              userRoles: [userRole('Staff', ['App.User']), userRole('Manager', ['App.User'])],
              moduleRoles: [moduleRole('App.User')],
            },
            entities: byQualifiedName([
              entity('App.Contact', {
                attributes: [attribute('_showEmail', 'Boolean', { isPii: true, sensitivityTerm: 'email' })],
                accessRules: [
                  accessRule(['App.User'], {
                    memberAccess: [
                      { attributeOrAssociation: 'App.Contact._showEmail', isAssociation: false, access: 'ReadOnly' },
                    ],
                  }),
                ],
              }),
            ]),
          }),
      ],
    ],
  },
  {
    id: 'SEC-022',
    what: 'an owned-data entity whose rule has no XPath constraint',
    fires: () =>
      makeIr({
        entities: byQualifiedName([
          entity('App.Note', { hasOwnerAttribute: true, accessRules: [accessRule(['App.User'])] }),
        ]),
      }),
    quiet: [
      [
        'a constrained rule',
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('App.Note', {
                hasOwnerAttribute: true,
                accessRules: [accessRule(['App.User'], { xPathConstraint: "[System.owner = '[%CurrentUser%]']" })],
              }),
            ]),
          }),
      ],
      [
        'an administrator-only rule',
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('App.Note', { hasOwnerAttribute: true, accessRules: [accessRule(['App.Administrator'])] }),
            ]),
          }),
      ],
      [
        'an entity with no owner attribute',
        () => makeIr({ entities: byQualifiedName([entity('App.Note', { accessRules: [accessRule(['App.User'])] })]) }),
      ],
    ],
  },
  {
    id: 'SEC-005',
    what: 'a credential attribute typed String',
    fires: () =>
      makeIr({
        entities: byQualifiedName([
          entity('App.Account', {
            attributes: [attribute('Password', 'String', { isSensitive: true, sensitivityTerm: 'password' })],
          }),
        ]),
      }),
    quiet: [
      [
        'the same attribute typed HashedString',
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('App.Account', {
                attributes: [attribute('Password', 'HashedString', { isSensitive: true, sensitivityTerm: 'password' })],
              }),
            ]),
          }),
      ],
      [
        // Without a readable type there is no corroboration, and `attributeTypes` coverage is
        // what records that — the rule must not assert a violation it cannot support.
        'an attribute whose type could not be read',
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('App.Account', {
                // `type` goes through the override bag, not the positional argument: passing
                // `undefined` positionally would fall back to the helper's 'String' default and
                // the test would quietly assert the opposite of what it claims.
                attributes: [
                  attribute('Password', 'String', {
                    type: undefined,
                    isSensitive: true,
                    sensitivityTerm: 'password',
                  }),
                ],
              }),
            ]),
          }),
      ],
      [
        'a marketplace entity',
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('Market.Account', {
                attributes: [attribute('Password', 'String', { isSensitive: true, sensitivityTerm: 'password' })],
              }),
            ]),
          }),
      ],
    ],
  },
  {
    id: 'SEC-008',
    what: 'String-typed PII in a user module (advisory; disabled by default)',
    fires: () =>
      makeIr({
        entities: byQualifiedName([
          entity('App.Contact', {
            attributes: [attribute('Email', 'String', { isPii: true, sensitivityTerm: 'email' })],
          }),
        ]),
      }),
    quiet: [['no PII attributes', () => makeIr({ entities: byQualifiedName([entity('App.Contact')]) })]],
    expectDisabled: true,
  },

  // --- 6.4 role hygiene -----------------------------------------------------------------------
  {
    id: 'SEC-023',
    what: 'a user role with security checking off',
    fires: () => makeIr({ security: { userRoles: [userRole('Staff', ['App.User'], { checkSecurity: false })] } }),
    quiet: [
      ['checking on', () => makeIr({ security: { userRoles: [userRole('Staff', ['App.User'])] } })],
      [
        'the flag unreadable',
        () => makeIr({ security: { userRoles: [userRole('Staff', ['App.User'], { checkSecurity: undefined })] } }),
      ],
    ],
  },
  {
    id: 'SEC-024',
    what: 'a non-administrator role that may manage all roles',
    fires: () => makeIr({ security: { userRoles: [userRole('Staff', [], { manageAllRoles: true })] } }),
    quiet: [
      [
        'an administrator role with the same right',
        () =>
          makeIr({
            security: { userRoles: [userRole('Administrator', [], { manageAllRoles: true, isAdministrator: true })] },
          }),
      ],
      ['a role without the right', () => makeIr({ security: { userRoles: [userRole('Staff')] } })],
    ],
  },
  {
    id: 'SEC-025',
    what: 'a user-module module role granted to no user role',
    fires: () => makeIr({ security: { moduleRoles: [moduleRole('App.Unused')] } }),
    quiet: [
      [
        'a granted role',
        () =>
          makeIr({
            security: { moduleRoles: [moduleRole('App.User')], userRoles: [userRole('Staff', ['App.User'])] },
          }),
      ],
      // Marketplace modules ship roles an app may never adopt; that is the module's design.
      ['an ungranted marketplace role', () => makeIr({ security: { moduleRoles: [moduleRole('Market.Unused')] } })],
    ],
  },

  // --- 6.5 code, constants & integration ------------------------------------------------------
  {
    id: 'SEC-007',
    what: 'a regex-based XSS sanitiser',
    fires: () =>
      makeIr({
        customCode: {
          javaActions: [
            { name: 'Sanitize', module: 'App', usesExternalLibraries: [], hasRegexXssSanitizer: true },
          ],
        },
      }),
    quiet: [
      [
        'a java action with no regex filtering',
        () =>
          makeIr({
            customCode: {
              javaActions: [{ name: 'Sanitize', module: 'App', usesExternalLibraries: [], hasRegexXssSanitizer: false }],
            },
          }),
      ],
    ],
  },
  {
    id: 'SEC-026',
    what: 'a credential constant carrying a value',
    // `hasDefaultValue` with the value absent is the extractor's redaction signal: a secret-shaped
    // constant's value is classified and then dropped before it reaches the IR.
    fires: () => makeIr({ operations: { constants: [constant('App.ApiKey', { hasDefaultValue: true })] } }),
    quiet: [
      ['a constant with no value', () => makeIr({ operations: { constants: [constant('App.ApiKey')] } })],
      [
        'a non-secret constant whose value was kept',
        () =>
          makeIr({
            operations: {
              constants: [constant('App.PageSize', { hasDefaultValue: true, defaultValue: '25' })],
            },
          }),
      ],
    ],
  },
  {
    id: 'SEC-027',
    what: 'a credential constant exposed to the client',
    fires: () =>
      makeIr({
        operations: {
          constants: [constant('App.ApiKey', { hasDefaultValue: true, isExposedToClient: true })],
        },
      }),
    quiet: [
      ['a credential constant kept server-side', () => makeIr({ operations: { constants: [constant('App.ApiKey', { hasDefaultValue: true })] } })],
      [
        'a non-secret constant exposed to the client',
        () =>
          makeIr({
            operations: {
              constants: [
                constant('App.PageSize', { hasDefaultValue: true, defaultValue: '25', isExposedToClient: true }),
              ],
            },
          }),
      ],
    ],
  },
  {
    id: 'SEC-010',
    what: 'a browser-storage constant in a user module',
    fires: () => makeIr({ operations: { constants: [constant('App.LocalStorageKey')] } }),
    quiet: [
      // The old rule's only hit was a marketplace module's own cache key.
      ['the same constant in a marketplace module', () => makeIr({ operations: { constants: [constant('Market.LocalStorageKey')] } })],
      ['an unrelated constant', () => makeIr({ operations: { constants: [constant('App.PageSize')] } })],
    ],
  },
  {
    id: 'SEC-004',
    what: 'a published endpoint with no authentication',
    fires: () =>
      makeIr({
        integrations: {
          publishedRestServices: [
            {
              name: 'OrderApi',
              module: 'App',
              version: '1.0',
              endpoints: [
                {
                  name: 'listOrders',
                  module: 'App',
                  path: '/orders',
                  httpMethod: 'GET',
                  microflow: 'App.ListOrders',
                  requiresAuthentication: false,
                },
              ],
            },
          ],
        },
      }),
    quiet: [
      [
        'an authenticated endpoint',
        () =>
          makeIr({
            integrations: {
              publishedRestServices: [
                {
                  name: 'OrderApi',
                  module: 'App',
                  version: '1.0',
                  endpoints: [
                    {
                      name: 'listOrders',
                      module: 'App',
                      path: '/orders',
                      httpMethod: 'GET',
                      microflow: 'App.ListOrders',
                      requiresAuthentication: true,
                      authType: 'Token',
                    },
                  ],
                },
              ],
            },
          }),
      ],
    ],
  },
  {
    id: 'SEC-028',
    what: 'a callable microflow that does not apply entity access',
    fires: () =>
      makeIr({
        microflows: byQualifiedName([
          microflow('App.LoadAll', { appliesEntityAccess: false, allowedRoles: ['App.User'] }),
        ]),
      }),
    quiet: [
      [
        // No allowed roles means the flow is not callable directly; it runs in its caller's
        // context. Flagging those would report the Mendix default on every sub-microflow.
        'a microflow with no allowed roles',
        () => makeIr({ microflows: byQualifiedName([microflow('App.SubFlow', { appliesEntityAccess: false })]) }),
      ],
      [
        'a microflow that applies entity access',
        () =>
          makeIr({
            microflows: byQualifiedName([microflow('App.LoadAll', { allowedRoles: ['App.User'] })]),
          }),
      ],
      [
        'a marketplace microflow no guest role can call',
        () =>
          makeIr({
            microflows: byQualifiedName([
              microflow('Market.LoadAll', { appliesEntityAccess: false, allowedRoles: ['Market.User'] }),
            ]),
          }),
      ],
    ],
  },

  {
    id: 'SEC-EE-003',
    what: 'an access rule whose default rights for new members are not None, for a standard role',
    fires: () =>
      makeIr({ entities: byQualifiedName([entity('App.Order', { accessRules: [accessRule(['App.User'], { defaultMemberAccess: 'ReadWrite' })] })]) }),
    quiet: [
      ['default rights for new members are None', () => makeIr({ entities: byQualifiedName([entity('App.Order', { accessRules: [accessRule(['App.User'])] })]) })],
      ['the rule applies only to an administrator role', () => makeIr({ entities: byQualifiedName([entity('App.Order', { accessRules: [accessRule(['App.Administrator'], { defaultMemberAccess: 'ReadWrite' })] })]) })],
    ],
  },

  // --- SEC-MF microflow rules ------------------------------------------------------------------
  {
    id: 'SEC-MF-001',
    what: 'a UI-triggered microflow without entity access, allowed for a non-administrative role',
    fires: () =>
      makeIr({
        microflows: byQualifiedName([
          microflow('App.ACT_Save', {
            appliesEntityAccess: false,
            allowedRoles: ['App.User'],
            referencedBy: [{ qualifiedName: 'App.Order_Edit', kind: 'Page' }],
          }),
        ]),
      }),
    quiet: [
      [
        'entity access applied',
        () => makeIr({ microflows: byQualifiedName([microflow('App.ACT_Save', { allowedRoles: ['App.User'], referencedBy: [{ qualifiedName: 'App.Order_Edit', kind: 'Page' }] })]) }),
      ],
      [
        'allowed only for an administrator role',
        () => makeIr({ microflows: byQualifiedName([microflow('App.ACT_Save', { appliesEntityAccess: false, allowedRoles: ['App.Administrator'], referencedBy: [{ qualifiedName: 'App.Order_Edit', kind: 'Page' }] })]) }),
      ],
      [
        'called only from another microflow, not from the UI',
        () => makeIr({ microflows: byQualifiedName([microflow('App.ACT_Save', { appliesEntityAccess: false, allowedRoles: ['App.User'], referencedBy: [{ qualifiedName: 'App.ACT_Other', kind: 'Microflow' }] })]) }),
      ],
    ],
  },
  {
    id: 'SEC-MF-002',
    what: 'an anonymous-callable microflow that changes a persistable entity',
    fires: () =>
      makeIr({
        security: guestSecurity(['App.Anonymous']),
        entities: byQualifiedName([entity('App.Order')]),
        microflows: byQualifiedName([
          microflow('App.ACT_Submit', {
            allowedRoles: ['App.Anonymous'],
            activities: [mfStep('CreateAction', { targetEntity: 'App.Order' })],
          }),
        ]),
      }),
    quiet: [
      [
        'the anonymous role cannot call it',
        () =>
          makeIr({
            security: guestSecurity(['App.Anonymous']),
            entities: byQualifiedName([entity('App.Order')]),
            microflows: byQualifiedName([microflow('App.ACT_Submit', { allowedRoles: ['App.User'], activities: [mfStep('CreateAction', { targetEntity: 'App.Order' })] })]),
          }),
      ],
      [
        'it only creates a non-persistable entity',
        () =>
          makeIr({
            security: guestSecurity(['App.Anonymous']),
            entities: byQualifiedName([entity('App.SignupForm', { persistenceType: 'non-persistable' })]),
            microflows: byQualifiedName([microflow('App.ACT_Submit', { allowedRoles: ['App.Anonymous'], activities: [mfStep('CreateAction', { targetEntity: 'App.SignupForm' })] })]),
          }),
      ],
      [
        'the changed object\'s entity cannot be established',
        () =>
          makeIr({
            security: guestSecurity(['App.Anonymous']),
            microflows: byQualifiedName([microflow('App.ACT_Submit', { allowedRoles: ['App.Anonymous'], activities: [mfStep('ChangeAction', { properties: { variable: 'Unknown' } })] })]),
          }),
      ],
    ],
  },
  {
    id: 'SEC-MF-003',
    what: 'a client-callable microflow without entity access that changes its object parameter unchecked',
    fires: () =>
      makeIr({
        microflows: byQualifiedName([
          microflow('App.ACT_Approve', {
            appliesEntityAccess: false,
            allowedRoles: ['App.User'],
            parameters: [{ name: 'Order', type: 'Object', entity: 'App.Order' }],
            activities: [mfStep('ChangeAction', { targetEntity: 'App.Order', properties: { variable: 'Order' } })],
          }),
        ]),
      }),
    quiet: [
      [
        'an ownership retrieve on [%CurrentUser%] comes first',
        () =>
          makeIr({
            microflows: byQualifiedName([
              microflow('App.ACT_Approve', {
                appliesEntityAccess: false,
                allowedRoles: ['App.User'],
                parameters: [{ name: 'Order', type: 'Object', entity: 'App.Order' }],
                activities: [
                  mfStep('RetrieveAction', { targetEntity: 'App.Order', xPathConstraint: "[id = $Order][System.owner = '[%CurrentUser%]']", properties: { retrieveSource: 'database' } }),
                  mfStep('ChangeAction', { targetEntity: 'App.Order', properties: { variable: 'Order' } }),
                ],
              }),
            ]),
          }),
      ],
      [
        'a decision on $currentUser comes first',
        () =>
          makeIr({
            microflows: byQualifiedName([
              microflow('App.ACT_Approve', {
                appliesEntityAccess: false,
                allowedRoles: ['App.User'],
                parameters: [{ name: 'Order', type: 'Object', entity: 'App.Order' }],
                activities: [
                  mfStep('Decision', { properties: { expression: '$Order/System.owner = $currentUser' } }),
                  mfStep('ChangeAction', { properties: { variable: 'Order' } }),
                ],
              }),
            ]),
          }),
      ],
      [
        'a sub-microflow with no allowed roles',
        () =>
          makeIr({
            microflows: byQualifiedName([
              microflow('App.SUB_Approve', {
                appliesEntityAccess: false,
                parameters: [{ name: 'Order', type: 'Object', entity: 'App.Order' }],
                activities: [mfStep('ChangeAction', { properties: { variable: 'Order' } })],
              }),
            ]),
          }),
      ],
    ],
  },
  {
    id: 'SEC-MF-004',
    what: 'an unauthenticated published endpoint whose microflow checks no header first',
    fires: () => endpointIr([mfStep('RetrieveAction', { targetEntity: 'App.Order' }), mfStep('ChangeAction')], false),
    quiet: [
      ['the endpoint requires authentication', () => endpointIr([mfStep('RetrieveAction')], true)],
      [
        'the first step reads the request headers',
        () => endpointIr([mfStep('RetrieveAction', { targetEntity: 'System.HttpHeader', properties: { text: 'System.HttpHeaders $httpRequest' } }), mfStep('ChangeAction')], false),
      ],
      [
        'the second step verifies a token',
        () => endpointIr([mfStep('CreateVariable'), mfStep('JavaActionCall', { properties: { callee: 'App.VerifyJwtToken' } })], false),
      ],
    ],
  },
  {
    id: 'SEC-MF-005',
    what: 'a user-module microflow with allowed roles that nothing references',
    fires: () => makeIr({ microflows: byQualifiedName([microflow('App.ACT_Old', { allowedRoles: ['App.User'], referencedBy: [] })]) }),
    quiet: [
      ['a page refers to it', () => makeIr({ microflows: byQualifiedName([microflow('App.ACT_Old', { allowedRoles: ['App.User'], referencedBy: [{ qualifiedName: 'App.Home', kind: 'Page' }] })]) })],
      ['it has no allowed roles', () => makeIr({ microflows: byQualifiedName([microflow('App.SUB_Old', { referencedBy: [] })]) })],
      ['references were not indexed', () => makeIr({ microflows: byQualifiedName([microflow('App.ACT_Old', { allowedRoles: ['App.User'] })]) })],
      ['it is in a Marketplace module', () => makeIr({ microflows: byQualifiedName([microflow('Market.ACT_Old', { allowedRoles: ['Market.User'], referencedBy: [] })]) })],
    ],
  },
];

/** An activity as the snapshot extractor normalises it. */
function mfStep(type, extra = {}) {
  return { id: `${type}-1`, type, name: type, isWithinLoop: false, ...extra, properties: { ...(extra.properties ?? {}) } };
}

/** A published REST endpoint bound to App.API_Handle, whose body is `activities`. */
function endpointIr(activities, requiresAuthentication) {
  return makeIr({
    microflows: byQualifiedName([microflow('App.API_Handle', { activities })]),
    integrations: {
      publishedRestServices: [
        {
          name: 'OrdersApi',
          module: 'App',
          version: '1',
          endpoints: [
            {
              name: 'orders GET',
              module: 'App',
              path: 'rest/orders/v1/orders',
              httpMethod: 'GET',
              microflow: 'App.API_Handle',
              requiresAuthentication,
              authType: requiresAuthentication ? 'Basic' : 'None',
            },
          ],
        },
      ],
    },
  });
}

describe('SEC rule catalogue: firing and quiet cases', () => {
  for (const testCase of CASES) {
    describe(`${testCase.id} — ${testCase.what}`, () => {
      it('fires on the defect', () => {
        const findings = evaluate(testCase.id, testCase.fires());
        assert.ok(findings.length > 0, `${testCase.id} produced no finding`);
        for (const finding of findings) {
          assert.equal(finding.ruleId, testCase.id);
          assert.ok(finding.observation.length > 0, 'a finding must say what was observed');
          assert.ok(finding.recommendation.length > 0, 'a finding must say what to do');
          assert.ok(['FAIL', 'WARNING'].includes(finding.status));
        }
      });

      for (const [label, build] of testCase.quiet) {
        it(`stays quiet: ${label}`, () => {
          const findings = evaluate(testCase.id, build());
          assert.deepEqual(
            findings.map((f) => f.id),
            [],
            `${testCase.id} fired on "${label}"`
          );
        });
      }
    });
  }
});

describe('SEC rule catalogue: catalogue-wide invariants', () => {
  const secRules = [...RULES.values()].filter((r) => r.id.startsWith('SEC-'));

  it('covers all 35 rules, each with a firing and a quiet case', () => {
    assert.equal(secRules.length, 35);
    const tested = new Set(CASES.map((c) => c.id));
    const untested = secRules.map((r) => r.id).filter((id) => !tested.has(id));
    assert.deepEqual(untested, []);
    for (const c of CASES) assert.ok(c.quiet.length > 0, `${c.id} has no quiet case`);
  });

  it('gives every rule a unique id', () => {
    const ids = secRules.map((r) => r.id);
    assert.equal(new Set(ids).size, ids.length);
  });

  it('declares the facts each rule depends on', () => {
    for (const rule of secRules) {
      assert.ok(Array.isArray(rule.requires), `${rule.id} has no requires array`);
      // SEC-007 legitimately needs nothing from the model: it reads custom code on disk.
      if (rule.id !== 'SEC-007') {
        assert.ok(rule.requires.length > 0, `${rule.id} declares no required facts`);
      }
    }
  });

  it('leaves SEC-004 dependent on published services, so Phase 1 skips it', () => {
    assert.deepEqual([...RULES.get('SEC-004').requires], ['publishedServices']);
  });

  it('keeps the advisory rules out of scoring by default', () => {
    // Guidance the model cannot confirm must not lower a project's score.
    assert.equal(RULES.get('SEC-009').enabled, false);
    assert.equal(RULES.get('SEC-008').enabled, false);
  });

  it('marks exactly the rules the table expects as disabled', () => {
    for (const testCase of CASES) {
      const rule = RULES.get(testCase.id);
      assert.equal(
        rule.enabled,
        !testCase.expectDisabled,
        `${testCase.id} enabled flag does not match the test table`
      );
    }
  });

  it('produces no finding id collisions when a rule fires many times', () => {
    // Three members on one rule: the ids must stay distinct, or a UI keyed on them shows one.
    const ir = makeIr({
      security: withGuest({ userRoles: [], moduleRoles: [] }, ['App.User']),
      entities: byQualifiedName([
        entity('App.Order', {
          accessRules: [
            accessRule(['App.User'], {
              memberAccess: ['A', 'B', 'C'].map((n) => ({
                attributeOrAssociation: `App.Order.${n}`,
                isAssociation: false,
                access: 'ReadWrite',
              })),
            }),
          ],
        }),
      ]),
    });
    const ids = evaluate('SEC-020', ir).map((f) => f.id);
    assert.equal(ids.length, 3);
    assert.equal(new Set(ids).size, 3);
  });

  it('inherits its rule text rather than restating it per finding', () => {
    const rule = RULES.get('SEC-002');
    const [finding] = rule.evaluate(makeIr({ security: { projectSecurityLevel: 'CheckNothing' } }));
    // The old catalogue restated these inline and the copies had drifted apart.
    assert.equal(finding.whyItMatters, rule.whyItMatters);
    assert.equal(finding.expectedPractice, rule.expectedPractice);
    assert.equal(finding.ruleTitle, rule.name);
    assert.equal(finding.sourceSkill, rule.sourceSkill);
  });
});

describe('SEC-018: anonymous pages are judged by the data they use', () => {
  const guest = () => guestSecurity(['App.Anonymous']);
  const anonPage = (dataEntities, extra = {}) =>
    page('App.Public', { allowedRoles: ['App.Anonymous'], isAccessibleAnonymously: true, dataEntities, ...extra });
  const run = (entities, pages) =>
    evaluate('SEC-018', makeIr({ security: guest(), entities: byQualifiedName(entities), pages: byQualifiedName(pages) }));

  it('stays quiet for a page that uses only a non-persistable entity, such as a login page', () => {
    const ctx = entity('App.LoginContext', { persistenceType: 'non-persistable' });
    assert.deepEqual(run([ctx], [anonPage(['App.LoginContext'])]), []);
  });

  it('stays quiet for a page that uses no data', () => {
    assert.deepEqual(run([], [anonPage([])]), []);
  });

  it('fails a page whose persistable entity the anonymous role can read', () => {
    const order = entity('App.Order', { accessRules: [accessRule(['App.Anonymous'], { defaultMemberAccess: 'ReadOnly' })] });
    const [f, ...rest] = run([order], [anonPage(['App.Order'])]);
    assert.equal(rest.length, 0);
    assert.equal(f.status, 'FAIL');
    assert.equal(f.severity, 'High');
    assert.deepEqual(f.evidence.details.anonymousCanRead, ['App.Order']);
  });

  it('asks for review when the page uses persistable data the anonymous role cannot read', () => {
    const order = entity('App.Order', { accessRules: [accessRule(['App.User'])] });
    const [f] = run([order], [anonPage(['App.Order'])]);
    assert.equal(f.status, 'WARNING');
    assert.equal(f.severity, 'Medium');
  });

  it('treats a specialization of a non-persistable entity as non-persistable', () => {
    const base = entity('App.Form', { persistenceType: 'non-persistable' });
    const child = entity('App.SignupForm', { generalization: 'App.Form' });
    assert.deepEqual(run([base, child], [anonPage(['App.SignupForm'])]), []);
  });

  it('counts access inherited from a generalization', () => {
    const base = entity('App.Document', { accessRules: [accessRule(['App.Anonymous'], { defaultMemberAccess: 'ReadOnly' })] });
    const child = entity('App.Invoice', { generalization: 'App.Document' });
    assert.equal(run([base, child], [anonPage(['App.Invoice'])])[0].status, 'FAIL');
  });

  it('treats platform entities such as System.User as persistable', () => {
    assert.equal(run([], [anonPage(['System.User'])]).length, 1);
  });

  it('judges a navigation home page by its data too, once its contents are known', () => {
    const order = entity('App.Order', { accessRules: [accessRule(['App.Anonymous'], { defaultMemberAccess: 'ReadOnly' })] });
    assert.equal(run([order], [anonPage(['App.Order'], { isNavigationHomePage: true })]).length, 1);
  });
});
