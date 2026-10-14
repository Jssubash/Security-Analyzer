/**
 * `docs/security.md` §8 test 3 — one firing IR and one quiet IR for each of the 33 SEC rules.
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
        // Never written to the database, so nothing is stored as plain text.
        'the same attribute on a non-persistable entity',
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('App.TokenResponse', {
                persistenceType: 'non-persistable',
                attributes: [attribute('Access_token', 'String', { isSensitive: true, sensitivityTerm: 'token' })],
              }),
            ]),
          }),
      ],
      [
        // Persistence is inherited: a specialization of a non-persistable entity is not stored either.
        'the same attribute on a specialization of a non-persistable entity',
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('App.Login', { persistenceType: 'non-persistable' }),
              entity('App.LoginForm', {
                generalization: 'App.Login',
                attributes: [attribute('Password', 'String', { isSensitive: true, sensitivityTerm: 'password' })],
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

  // --- 6.5 constants & integration ------------------------------------------------------------
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
      [
        'a non-persistable parameter that is only changed or deleted itself',
        () =>
          makeIr({
            entities: byQualifiedName([entity('App.PasswordData', { persistenceType: 'non-persistable' })]),
            microflows: byQualifiedName([
              microflow('App.MB_ChangePasswordSave', {
                appliesEntityAccess: false,
                allowedRoles: ['App.User'],
                parameters: [{ name: 'PasswordData', type: 'Object', entity: 'App.PasswordData' }],
                activities: [
                  mfStep('ChangeAction', { targetEntity: 'App.PasswordData', properties: { variable: 'PasswordData', text: 'PasswordData NewPassword ""' } }),
                  mfStep('DeleteAction', { targetEntity: 'App.PasswordData', properties: { variable: 'PasswordData' } }),
                ],
              }),
            ]),
          }),
      ],
      [
        "a non-persistable parameter whose values only go into another non-persistable object",
        () =>
          makeIr({
            entities: byQualifiedName([
              entity('App.PasswordData', { persistenceType: 'non-persistable' }),
              entity('App.Feedback', { persistenceType: 'non-persistable' }),
            ]),
            microflows: byQualifiedName([
              microflow('App.MB_Preview', {
                appliesEntityAccess: false,
                allowedRoles: ['App.User'],
                parameters: [{ name: 'PasswordData', type: 'Object', entity: 'App.PasswordData' }],
                activities: [mfStep('CreateAction', { targetEntity: 'App.Feedback', properties: { outputVariable: 'Feedback', text: 'App.Feedback Message $PasswordData/NewPassword' } })],
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
  {
    id: 'SEC-MF-006',
    what: 'a REST call that keeps the default "Rollback" error handling',
    fires: () => flowIr([microflow('App.ACT_Send', { activities: [mfStep('RestCall', { properties: { errorHandlingType: 'Rollback' } })] })]),
    quiet: [
      [
        'custom error handling with a Log message on the error flow',
        () => flowIr([microflow('App.ACT_Send', { activities: [handled('RestCall', { logs: true, calls: [] })] })]),
      ],
      [
        'custom error handling whose error flow calls a microflow that logs',
        () =>
          flowIr([
            microflow('App.ACT_Send', { activities: [handled('ImportMapping', { logs: false, calls: ['App.SUB_LogError'] })] }),
            microflow('App.SUB_LogError', { activities: [mfStep('LogMessage')] }),
          ]),
      ],
      [
        'a Java action whose error handling is "Continue"',
        () => flowIr([microflow('App.ACT_Send', { activities: [mfStep('JavaActionCall', { properties: { errorHandlingType: 'Continue', callee: 'App.Send' } })] })]),
      ],
      [
        'a disabled activity',
        () => flowIr([microflow('App.ACT_Send', { activities: [mfStep('RestCall', { properties: { errorHandlingType: 'Rollback', disabled: true } })] })]),
      ],
      [
        'a Java action in a Marketplace microflow that does not run in the background',
        () => flowIr([microflow('Market.ACT_Trim', { activities: [mfStep('JavaActionCall', { properties: { errorHandlingType: 'Rollback', callee: 'Market.Trim' } })] })]),
      ],
      [
        'an activity that is not an integration call',
        () => flowIr([microflow('App.ACT_Save', { activities: [mfStep('CommitAction', { properties: { errorHandlingType: 'Rollback' } })] })]),
      ],
    ],
  },
  {
    id: 'SEC-MF-007',
    what: 'a Change object that parses a value with no empty check or default',
    fires: () => memberIr([setsMember('parseInteger($Department/AgeText)')]),
    quiet: [
      ['the value is checked for empty first', () => memberIr([setsMember('if $Department/AgeText != empty then parseInteger($Department/AgeText) else 0')])],
      ['the parse has a default value', () => memberIr([setsMember('parseInteger($Department/AgeText, 0)')])],
      ['a value of the same type is copied', () => memberIr([setsMember('$Department/Name')])],
    ],
  },
  {
    id: 'SEC-MF-008',
    what: 'a microflow applying entity access, allowed for a role that may only read what it changes',
    fires: () => saveIr([changeName()]),
    quiet: [
      ['every allowed role may create what it creates', () => removeHr(saveIr([createCopy()]))],
      ['the microflow does not apply entity access', () => withoutEntityAccess(saveIr([changeName()]))],
    ],
  },
];

function removeHr(ir) {
  ir.microflows['App.ACT_Save'].allowedRoles = ['App.Admin', 'App.User'];
  return ir;
}

function withoutEntityAccess(ir) {
  ir.microflows['App.ACT_Save'].appliesEntityAccess = false;
  return ir;
}

/** A Change object activity that sets `attribute` to `value`, with object variables in scope. */
function setsMember(value, variables = { Department: 'App.Department' }) {
  return mfStep('ChangeAction', { properties: { members: [{ attribute: 'App.Request.Field', value }], variables } });
}

function memberIr(activities, extra = {}) {
  return makeIr({
    entities: byQualifiedName([
      entity('App.Department', { attributes: [attribute('AgeText', 'String'), attribute('Count', 'Integer'), attribute('Name', 'String')] }),
    ]),
    microflows: byQualifiedName([microflow('App.ACT_Map', { activities, ...extra })]),
  });
}

describe('SEC-MF-007 — value converted without an empty check', () => {
  const only = (ir) => evaluate('SEC-MF-007', ir);
  const fires = (value) => only(memberIr([setsMember(value)]));

  for (const value of [
    'parseInteger($Department/AgeText)',
    "parseDecimal($Department/AgeText, '#.##')",
    "parseDateTime($Department/AgeText, 'dd-MM-yyyy')",
    "formatDateTime($Department/JoinDate, 'dd-MM-yyyy')",
    'toString($Department/Count)',
    'getCaption($Department/Status)',
    'round($Department/Amount)',
    'addDays($Department/JoinDate, 1)',
    '$Department/Count * 2',
    '$Department/Count + 1',
  ]) {
    it(`reports ${value}`, () => {
      const findings = fires(value);
      assert.equal(findings.length, 1, value);
      assert.equal(findings[0].severity, 'Medium');
    });
  }

  for (const value of [
    '$Department/AgeText',
    "'Name: ' + $Department/Name",
    'parseInteger($Department/AgeText, 0)',
    'parseDecimal($Department/AgeText, 0)',
    "parseDateTime($Department/AgeText, 'dd-MM-yyyy', dateTime(1900))",
    'if $Department/AgeText != empty then parseInteger($Department/AgeText) else 0',
    'if empty = $Department/Count then 0 else $Department/Count * 2',
    'toString(parseInteger($Department/AgeText, 0))',
  ]) {
    it(`stays quiet on ${value}`, () => assert.deepEqual(fires(value), []));
  }

  it('accepts a Decision before the activity that checks the value', () => {
    const findings = only(memberIr([mfStep('Decision', { properties: { expression: '$Department/AgeText != empty' } }), setsMember('parseInteger($Department/AgeText)')]));
    assert.deepEqual(findings, []);
  });

  it('blames the innermost function that reads the value', () => {
    const [finding] = fires("parseDateTime(formatDateTime($Department/JoinDate, 'dd-MM-yyyy'), 'dd-MM-yyyy')");
    assert.equal(finding.evidence.details.conversions[0].problem, 'formatDateTime($Department/JoinDate) without an empty check');
    assert.match(finding.observation, /Change object → App\.Request\.Field \(formatDateTime\)/);
  });

  it('is High when the microflow runs in the background', () => {
    const findings = only(memberIr([setsMember('parseInteger($Department/AgeText)')], { referencedBy: [{ qualifiedName: 'App.Nightly', kind: 'ScheduledEvent' }] }));
    assert.equal(findings[0].severity, 'High');
  });

  it('names the activity, member and expression, one evidence item per member', () => {
    const [finding] = fires('parseInteger($Department/AgeText)');
    assert.deepEqual(finding.evidence.details.conversions, [
      {
        activity: 'Change object',
        member: 'App.Request.Field',
        expression: 'parseInteger($Department/AgeText)',
        problem: 'parseInteger($Department/AgeText) without a default value or empty check',
        activityId: 'ChangeAction-1',
      },
    ]);
    assert.match(finding.observation, /Change object → App\.Request\.Field \(parseInteger\)\. The evidence shows each expression\./);
  });
});

/**
 * The save scenario: ACT_Save applies entity access and is allowed for Admin, User and HR.
 * Department: Admin may do everything on own objects (XPath owner), User may write, HR may only read.
 * Copy: Admin and User may create and write; HR has no access rule.
 */
function saveIr(activities, extra = {}) {
  const rw = (name) => ({ attributeOrAssociation: `App.Department.${name}`, isAssociation: false, access: 'ReadWrite' });
  const ro = (name) => ({ attributeOrAssociation: `App.Department.${name}`, isAssociation: false, access: 'ReadOnly' });
  return makeIr({
    entities: byQualifiedName([
      entity('App.Department', {
        accessRules: [
          accessRule(['App.Admin'], { allowCreate: true, allowDelete: true, xPathConstraint: "[System.owner='[%CurrentUser%]']", memberAccess: [rw('Name')] }),
          accessRule(['App.User'], { memberAccess: [rw('Name')] }),
          accessRule(['App.HR'], { memberAccess: [ro('Name')] }),
        ],
      }),
      entity('App.Copy', {
        accessRules: [accessRule(['App.Admin', 'App.User'], { allowCreate: true, allowDelete: true, memberAccess: [{ attributeOrAssociation: 'App.Copy.Name', isAssociation: false, access: 'ReadWrite' }] })],
      }),
      entity('App.Draft', { persistenceType: 'non-persistable', accessRules: [] }),
    ]),
    security: {
      userRoles: [userRole('Administrator', ['App.Admin']), userRole('Initiator', ['App.User']), userRole('HR', ['App.HR'])],
      moduleRoles: [moduleRole('App.Admin'), moduleRole('App.User'), moduleRole('App.HR')],
    },
    microflows: byQualifiedName([
      microflow('App.ACT_Save', { appliesEntityAccess: true, allowedRoles: ['App.Admin', 'App.User', 'App.HR'], activities }),
      ...(extra.microflows ?? []),
    ]),
  });
}

const changeName = () => mfStep('ChangeAction', { targetEntity: 'App.Department', properties: { variable: 'Department', members: [{ attribute: 'App.Department.Name', value: "'x'" }] } });
const createCopy = () => mfStep('CreateAction', { targetEntity: 'App.Copy', properties: { outputVariable: 'NewCopy', members: [{ attribute: 'App.Copy.Name', value: "'x'" }] } });

describe('SEC-MF-008 — module role can run the microflow but lacks entity access', () => {
  const only = (ir) => evaluate('SEC-MF-008', ir);

  it('reports the read-only module role on a change and the module role with no rule on a create', () => {
    const [finding] = only(saveIr([changeName(), createCopy()]));
    assert.equal(finding.severity, 'Critical');
    assert.match(finding.observation, /module role App\.HR \(user role HR\) cannot write App\.Department\.Name \(read only\); create App\.Copy \(no access rule for this role\)/);
  });

  it('judges a rule with an XPath constraint by its access rights alone', () => {
    // Admin's rule has [System.owner=…] and Read/Write on Name: Admin may write Name.
    const [finding] = only(saveIr([changeName()]));
    assert.doesNotMatch(finding.observation, /App\.Admin/);
    assert.doesNotMatch(finding.observation, /App\.User/);
    assert.doesNotMatch(finding.observation, /XPath/);
  });

  it('reports a rule with an XPath constraint whose access rights are read only', () => {
    const ir = saveIr([changeName()]);
    const adminRule = ir.entities['App.Department'].accessRules[0];
    adminRule.memberAccess = [{ attributeOrAssociation: 'App.Department.Name', isAssociation: false, access: 'ReadOnly' }];
    const [finding] = only(ir);
    assert.match(finding.observation, /module role App\.Admin \(user role Administrator\) cannot write App\.Department\.Name \(read only\)/);
  });

  it('counts an XPath rule for an object the microflow creates itself', () => {
    const create = mfStep('CreateAction', { targetEntity: 'App.Department', properties: { outputVariable: 'NewDepartment', members: [{ attribute: 'App.Department.Name', value: "'x'" }] } });
    const change = mfStep('ChangeAction', { targetEntity: 'App.Department', properties: { variable: 'NewDepartment', members: [{ attribute: 'App.Department.Name', value: "'y'" }] } });
    const findings = only(saveIr([create, change]));
    assert.doesNotMatch(findings[0]?.observation ?? '', /App\.Admin/);
  });

  it('checks delete against "Delete objects" in the access rights', () => {
    const remove = () => mfStep('DeleteAction', { targetEntity: 'App.Department', properties: { variable: 'Department' } });
    const [finding] = only(saveIr([remove()]));
    assert.doesNotMatch(finding.observation, /App\.Admin/);
    assert.match(finding.observation, /module role App\.User \(user role Initiator\) cannot delete App\.Department \("Delete objects" is off\)/);
  });

  it('reports a retrieve with no read rule as Medium', () => {
    const [finding] = only(saveIr([mfStep('RetrieveAction', { targetEntity: 'App.Copy', properties: { retrieveSource: 'database' } })]));
    assert.equal(finding.severity, 'Medium');
    assert.match(finding.observation, /module role App\.HR \(user role HR\) cannot retrieve App\.Copy \(no access rule, so the retrieve returns nothing\)/);
  });

  it('skips microflows without "Apply entity access"', () => {
    const ir = saveIr([changeName()]);
    ir.microflows['App.ACT_Save'].appliesEntityAccess = false;
    assert.deepEqual(only(ir), []);
  });

  it('skips non-persistable entities', () => {
    assert.deepEqual(only(saveIr([mfStep('CreateAction', { targetEntity: 'App.Draft', properties: { outputVariable: 'Draft' } })])), []);
  });

  it('checks a sub-microflow with the module roles of its caller', () => {
    const ir = saveIr([mfStep('MicroflowCall', { properties: { callee: 'App.SUB_Copy' } })], {
      microflows: [microflow('App.SUB_Copy', { appliesEntityAccess: true, activities: [createCopy()] })],
    });
    const findings = only(ir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].evidence.objectName, 'SUB_Copy');
    assert.match(findings[0].observation, /module role App\.HR \(user role HR\) cannot create App\.Copy.*called from App\.ACT_Save/);
  });

  it('judges each module role by its own rules, even when a user role also holds a stronger role of the same module', () => {
    // One user role holds both Manager and Initiator; Manager may still only write Status.
    const ir = requestIr([userRole('Lead', ['App.Manager', 'App.Initiator'])]);
    const [finding] = only(ir);
    assert.match(finding.observation, /module role App\.Manager \(user role Lead\) cannot write App\.Request\.EmployeeName \(read only\)/);
    assert.doesNotMatch(finding.observation, /App\.Initiator/);
    assert.doesNotMatch(finding.observation, /write App\.Request\.Status/);
  });

  it('reports Manager (write on Status only) and HR (read only) on a save that changes status and personal data', () => {
    const [finding] = only(requestIr());
    assert.match(finding.observation, /module role App\.Manager \(user role Manager\) cannot write App\.Request\.EmployeeName \(read only\)/);
    assert.match(finding.observation, /module role App\.HR \(user role HR\) cannot write App\.Request\.Status \(read only\); write App\.Request\.EmployeeName \(read only\)/);
    assert.doesNotMatch(finding.observation, /App\.Initiator/);
  });

  it('uses the roles of another module that every holder has, for an entity in that module', () => {
    const ir = requestIr();
    ir.entities['Files.Document'] = entity('Files.Document', {
      accessRules: [accessRule(['Files.User'], { allowCreate: true, memberAccess: [{ attributeOrAssociation: 'Files.Document.Name', isAssociation: false, access: 'ReadWrite' }] })],
    });
    ir.security.userRoles = ir.security.userRoles.map((u) => ({ ...u, moduleRoles: [...u.moduleRoles, { module: 'Files', role: 'User' }] }));
    ir.microflows['App.ACT_Save'].activities = [mfStep('CreateAction', { targetEntity: 'Files.Document', properties: { outputVariable: 'Doc', members: [{ attribute: 'Files.Document.Name', value: "'x'" }] } })];
    assert.deepEqual(only(ir), []);
  });
});

/**
 * The request scenario: Initiator may create, delete and write everything, Manager may write only
 * Status, HR may only read. ACT_Save applies entity access, is allowed for all three, and changes
 * Status and EmployeeName (copied from an account parameter).
 */
function requestIr(userRoles) {
  const member = (name, access) => ({ attributeOrAssociation: `App.Request.${name}`, isAssociation: false, access });
  return makeIr({
    entities: byQualifiedName([
      entity('App.Request', {
        accessRules: [
          accessRule(['App.Initiator'], { allowCreate: true, allowDelete: true, memberAccess: [member('Status', 'ReadWrite'), member('EmployeeName', 'ReadWrite')] }),
          accessRule(['App.Manager'], { memberAccess: [member('Status', 'ReadWrite'), member('EmployeeName', 'ReadOnly')] }),
          accessRule(['App.HR'], { memberAccess: [member('Status', 'ReadOnly'), member('EmployeeName', 'ReadOnly')] }),
        ],
      }),
    ]),
    security: {
      userRoles: userRoles ?? [userRole('Initiator', ['App.Initiator']), userRole('Manager', ['App.Manager']), userRole('HR', ['App.HR'])],
      moduleRoles: [moduleRole('App.Initiator'), moduleRole('App.Manager'), moduleRole('App.HR')],
    },
    microflows: byQualifiedName([
      microflow('App.ACT_Save', {
        appliesEntityAccess: true,
        allowedRoles: userRoles ? ['App.Manager'] : ['App.Initiator', 'App.Manager', 'App.HR'],
        activities: [
          mfStep('ChangeAction', {
            targetEntity: 'App.Request',
            properties: {
              variable: 'Request',
              members: [
                { attribute: 'App.Request.Status', value: 'App.Status.Approved' },
                { attribute: 'App.Request.EmployeeName', value: '$Account/FullName' },
              ],
            },
          }),
        ],
      }),
    ]),
  });
}

/**
 * SEC-005 with the writes followed: App.Client.ApiSecret (String) and an action App.Protect whose
 * code encrypts. `activities` is the body of App.ACT_Store.
 */
function secretIr(activities, extra = {}) {
  return makeIr({
    entities: byQualifiedName([
      entity('App.Client', { attributes: [attribute('ApiSecret', 'String', { isSensitive: true, sensitivityTerm: 'secret' })] }),
    ]),
    microflows: byQualifiedName([microflow('App.ACT_Store', { activities })]),
    customCode: {
      javaActions: [
        { name: 'Protect', module: 'App', usesExternalLibraries: [], encrypts: true },
        { name: 'Reveal', module: 'App', usesExternalLibraries: [], encrypts: false },
      ],
    },
    ...extra,
  });
}
const SECRET = 'App.Client.ApiSecret';
const createClient = (value, commit = 'No') =>
  mfStep('CreateAction', { targetEntity: 'App.Client', properties: { outputVariable: 'Client', commit, members: [{ attribute: SECRET, value }] } });
const callAction = (callee, output = 'Result') => mfStep('JavaActionCall', { properties: { callee, outputVariable: output } });
const changeClient = (value, commit = 'Yes') =>
  mfStep('ChangeAction', { targetEntity: 'App.Client', properties: { variable: 'Client', commit, members: [{ attribute: SECRET, value }] } });

describe('SEC-005 — follows where a secret attribute is written', () => {
  const only = (ir) => evaluate('SEC-005', ir);

  it('passes when every write stores the result of an action whose code encrypts', () => {
    assert.deepEqual(only(secretIr([callAction('App.Protect'), createClient('$Result', 'Yes')])), []);
  });

  it('passes when a plain value is replaced by the encrypted one before the object is committed', () => {
    assert.deepEqual(only(secretIr([createClient('$Input/Secret'), callAction('App.Protect'), changeClient('$Result')])), []);
  });

  it('fails when the plain value is committed before it is replaced', () => {
    const [finding] = only(secretIr([createClient('$Input/Secret', 'Yes'), callAction('App.Protect'), changeClient('$Result')]));
    assert.equal(finding.status, 'FAIL');
    assert.match(finding.observation, /encrypted before it is stored in Change object in App\.ACT_Store, but written as plain text in Create object in App\.ACT_Store/);
  });

  it('fails when the action does not encrypt', () => {
    const [finding] = only(secretIr([callAction('App.Reveal'), createClient('$Result', 'Yes')]));
    assert.equal(finding.severity, 'High');
    assert.match(finding.observation, /no microflow writes it through a Java action that encrypts .*written as plain text in Create object in App\.ACT_Store/);
  });

  it('asks for review when a page also refers to the attribute', () => {
    const ir = secretIr([callAction('App.Protect'), createClient('$Result', 'Yes')], {
      pages: byQualifiedName([page('App.Client_Edit', { references: ['App.Client', SECRET] })]),
    });
    const [finding] = only(ir);
    assert.equal(finding.status, 'WARNING');
    assert.equal(finding.severity, 'Medium');
    assert.match(finding.observation, /Page App\.Client_Edit also refers to it/);
    assert.match(finding.recommendation, /saves through the microflow that encrypts it/);
  });

  it('follows a sub-microflow that returns the encrypted value', () => {
    const ir = secretIr([mfStep('MicroflowCall', { properties: { callee: 'App.SUB_Protect', outputVariable: 'Sealed' } }), createClient('$Sealed', 'Yes')]);
    ir.microflows['App.SUB_Protect'] = microflow('App.SUB_Protect', { activities: [callAction('App.Protect', 'Out')], returnValues: ['$Out'] });
    assert.deepEqual(only(ir), []);
  });

  it('fails when the sub-microflow returns a plain value', () => {
    const ir = secretIr([mfStep('MicroflowCall', { properties: { callee: 'App.SUB_Plain', outputVariable: 'Sealed' } }), createClient('$Sealed', 'Yes')]);
    ir.microflows['App.SUB_Plain'] = microflow('App.SUB_Plain', { activities: [callAction('App.Protect', 'Out')], returnValues: ['$Input'] });
    assert.equal(only(ir)[0].status, 'FAIL');
  });

  it('follows the encrypted value through Create and Change variable', () => {
    const steps = [
      callAction('App.Protect'),
      mfStep('CreateVariable', { properties: { outputVariable: 'Copy', value: '$Result' } }),
      mfStep('ChangeVariable', { properties: { variable: 'Final', value: '$Copy' } }),
      createClient('$Final', 'Yes'),
    ];
    // Final is changed from Copy, so it holds the encrypted value.
    assert.deepEqual(only(secretIr(steps)), []);
  });

  it('forgets the encrypted value when a variable is changed to something else', () => {
    const steps = [callAction('App.Protect'), mfStep('ChangeVariable', { properties: { variable: 'Result', value: "'other'" } }), createClient('$Result', 'Yes')];
    assert.equal(only(secretIr(steps))[0].status, 'FAIL');
  });

  it('does not loop on a sub-microflow that calls itself', () => {
    const ir = secretIr([mfStep('MicroflowCall', { properties: { callee: 'App.SUB_Loop', outputVariable: 'X' } }), createClient('$X', 'Yes')]);
    ir.microflows['App.SUB_Loop'] = microflow('App.SUB_Loop', {
      activities: [mfStep('MicroflowCall', { properties: { callee: 'App.SUB_Loop', outputVariable: 'Y' } })],
      returnValues: ['$Y'],
    });
    assert.equal(only(ir)[0].status, 'FAIL');
  });

  it('asks for review when a plain value is typed into the model, even if it is replaced', () => {
    const [finding] = only(secretIr([createClient("'s3cr3t'"), callAction('App.Protect'), changeClient('$Result')]));
    assert.equal(finding.status, 'WARNING');
    assert.match(finding.observation, /A plain value for it is typed into the model in Create object in App\.ACT_Store/);
    assert.deepEqual(finding.evidence.details.typedIntoModel, ['Create object in App.ACT_Store']);
  });
});

/** An activity with custom error handling and the given error flow. */
function handled(type, errorPath) {
  return mfStep(type, { properties: { errorHandlingType: 'CustomWithoutRollBack', errorPath } });
}

function flowIr(microflows) {
  return makeIr({ microflows: byQualifiedName(microflows) });
}

describe('SEC-MF-006 — grading and background execution', () => {
  const only = (ir) => evaluate('SEC-MF-006', ir);

  it('grades no error handling High and a missing log Medium, one finding per microflow', () => {
    const findings = only(
      flowIr([
        microflow('App.ACT_A', { activities: [mfStep('RestCall', { properties: { errorHandlingType: 'Rollback' } }), handled('ImportMapping', { logs: false, calls: [] })] }),
        microflow('App.ACT_B', { activities: [handled('WebServiceCall', { logs: false, calls: [] })] }),
      ])
    );
    const bySubject = Object.fromEntries(findings.map((f) => [f.evidence.objectName, f]));
    assert.equal(findings.length, 2);
    assert.equal(bySubject.ACT_A.severity, 'High');
    assert.match(bySubject.ACT_A.observation, /no custom error handling/);
    assert.match(bySubject.ACT_A.observation, /no Log message/);
    assert.equal(bySubject.ACT_B.severity, 'Medium');
  });

  it('treats "Custom" (with rollback) as custom handling', () => {
    const findings = only(flowIr([microflow('App.ACT_A', { activities: [mfStep('RestCall', { properties: { errorHandlingType: 'Custom', errorPath: { logs: true, calls: [] } } })] })]));
    assert.deepEqual(findings, []);
  });

  it('reports custom handling that has no error flow at all', () => {
    const findings = only(flowIr([microflow('App.ACT_A', { activities: [mfStep('RestCall', { properties: { errorHandlingType: 'Custom' } })] })]));
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'Medium');
  });

  it('checks a Call ML model activity', () => {
    const findings = only(flowIr([microflow('App.ACT_Predict', { activities: [mfStep('MLModelCall', { properties: { errorHandlingType: 'Rollback', callee: 'App.ChurnModel' } })] })]));
    assert.equal(findings.length, 1);
    assert.match(findings[0].observation, /Call ML model App\.ChurnModel/);
  });

  it('checks a Call workflow activity', () => {
    const findings = only(flowIr([microflow('App.ACT_Start', { activities: [mfStep('WorkflowCall', { properties: { errorHandlingType: 'Rollback', callee: 'App.Approval' } })] })]));
    assert.equal(findings.length, 1);
    assert.match(findings[0].observation, /Call workflow App.Approval/);
  });

  it('names an activity by its caption and endpoint, whatever it was renamed to', () => {
    const findings = only(
      flowIr([
        microflow('App.ACT_Send', {
          activities: [
            mfStep('RestCall', {
              properties: { errorHandlingType: 'Rollback', caption: 'Fetch orders', endpoint: 'GET $Config/Url', mapping: 'App.ImportOrders' },
            }),
          ],
        }),
      ])
    );
    assert.match(findings[0].observation, /Call REST service "Fetch orders" \(GET \$Config\/Url, mapping App\.ImportOrders\)/);
  });

  it('checks every Java action in your own modules', () => {
    const findings = only(flowIr([microflow('App.ACT_Trim', { activities: [mfStep('JavaActionCall', { properties: { errorHandlingType: 'Rollback', callee: 'Market.Trim' } })] })]));
    assert.equal(findings.length, 1);
    assert.match(findings[0].observation, /Java action Market\.Trim/);
  });

  it('checks Marketplace Java actions reached from a scheduled event, as Review one level lower', () => {
    const findings = only(
      flowIr([
        microflow('Market.SE_Sync', {
          referencedBy: [{ qualifiedName: 'Market.Sync', kind: 'ScheduledEvent' }],
          activities: [mfStep('MicroflowCall', { properties: { callee: 'Market.SUB_Fetch' } })],
        }),
        microflow('Market.SUB_Fetch', { activities: [mfStep('JavaActionCall', { properties: { errorHandlingType: 'Rollback', callee: 'Market.Fetch' } })] }),
      ])
    );
    assert.equal(findings.length, 1);
    assert.equal(findings[0].status, 'WARNING');
    assert.equal(findings[0].severity, 'Medium');
    assert.match(findings[0].observation, /called from Market\.SE_Sync, started by scheduled event Market\.Sync/);
  });

  it('checks Marketplace Java actions in a microflow called in a task queue', () => {
    const findings = only(
      flowIr([
        microflow('App.ACT_Start', { activities: [mfStep('MicroflowCall', { properties: { callee: 'Market.QUEUE_Run', queued: true } })] }),
        microflow('Market.QUEUE_Run', { activities: [mfStep('JavaActionCall', { properties: { errorHandlingType: 'Rollback', callee: 'Market.Run' } })] }),
      ])
    );
    assert.equal(findings.length, 1);
    assert.match(findings[0].observation, /task queue from App\.ACT_Start/);
  });

  it('checks Marketplace Java actions started by a workflow', () => {
    const findings = only(
      flowIr([
        microflow('Market.WF_Step', {
          referencedBy: [{ qualifiedName: 'Market.Approval', kind: 'Workflow' }],
          activities: [mfStep('JavaActionCall', { properties: { errorHandlingType: 'Rollback', callee: 'Market.Run' } })],
        }),
      ])
    );
    assert.equal(findings.length, 1);
  });
});

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

  it('covers all 36 rules, each with a firing and a quiet case', () => {
    assert.equal(secRules.length, 36);
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
      assert.ok(rule.requires.length > 0, `${rule.id} declares no required facts`);
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

describe('SEC-MF-003: a non-persistable parameter counts only when its values reach stored data', () => {
  const build = (steps) =>
    makeIr({
      entities: byQualifiedName([
        entity('App.PasswordData', { persistenceType: 'non-persistable' }),
        entity('App.Account', { persistenceType: 'persistable' }),
      ]),
      microflows: byQualifiedName([
        microflow('App.MB_ChangePasswordSave', {
          appliesEntityAccess: false,
          allowedRoles: ['App.User'],
          parameters: [
            { name: 'PasswordData', type: 'Object', entity: 'App.PasswordData' },
            { name: 'Account', type: 'Object', entity: 'App.Account' },
          ],
          activities: steps,
        }),
      ]),
    });
  const findings = (steps) => evaluate('SEC-MF-003', build(steps)).filter((f) => f.evidence.details.parameter === 'PasswordData');

  it('fires when a Change on a persistable object takes a value from it', () => {
    const [f] = findings([mfStep('ChangeAction', { targetEntity: 'App.Account', properties: { variable: 'Account', text: 'Account Password $PasswordData/NewPassword' } })]);
    assert.ok(f, 'expected a finding');
    assert.equal(f.evidence.details.writesTo, 'App.Account');
    assert.match(f.observation, /\$PasswordData \(Object of App.PasswordData, non-persistable\).*writes its values into persistable App.Account \(ChangeAction\)/);
  });

  it('fires when a persistable object is created from its values', () => {
    assert.equal(findings([mfStep('CreateAction', { targetEntity: 'App.Account', properties: { outputVariable: 'New', text: 'App.Account Name $PasswordData/Username' } })]).length, 1);
  });

  it('does not mistake a longer variable name for it', () => {
    assert.equal(findings([mfStep('ChangeAction', { targetEntity: 'App.Account', properties: { variable: 'Account', text: 'Account Password $PasswordDataCopy/NewPassword' } })]).length, 0);
  });

  it('stays quiet when an ownership check comes first', () => {
    assert.equal(
      findings([
        mfStep('Decision', { properties: { expression: '$Account/System.owner = $currentUser' } }),
        mfStep('ChangeAction', { targetEntity: 'App.Account', properties: { variable: 'Account', text: 'Account Password $PasswordData/NewPassword' } }),
      ]).length,
      0
    );
  });
});

describe('SEC-005: the advice follows what the value is used for', () => {
  const sec005 = RULES.get('SEC-005');
  const run = (name, term) =>
    sec005.evaluate(
      makeIr({
        entities: byQualifiedName([entity('App.Account', { attributes: [attribute(name, 'String', { isSensitive: true, sensitivityTerm: term })] })]),
      })
    )[0];

  it('a password the app only verifies: hash it first', () => {
    const f = run('Password', 'password');
    assert.match(f.recommendation, /change its type to HashedString/);
    assert.equal(f.evidence.details.suggested, 'HashedString');
  });

  it('a token the app sends on: encrypt it with the Encryption module, never hash it', () => {
    const f = run('Access_token', 'token');
    assert.match(f.recommendation, /EncryptString \(Encryption module\)/);
    assert.match(f.recommendation, /DecryptString/);
    assert.equal(f.evidence.details.suggested, 'encrypt with the Encryption module');
  });

  it('the rule text explains both options', () => {
    assert.match(sec005.expectedPractice, /HashedString/);
    assert.match(sec005.expectedPractice, /EncryptString/);
    assert.match(sec005.whyItMatters, /cannot be read back/);
    assert.equal(sec005.name, 'Password or secret attribute stored as plain text');
  });
});

describe('SEC-028 and SEC-MF-001: one finding per problem, graded by what the microflow does', () => {
  const sec028 = RULES.get('SEC-028');
  const mf001 = RULES.get('SEC-MF-001');
  const order = entity('App.Order');
  const fromPage = [{ kind: 'Page', qualifiedName: 'App.Order_Overview' }];
  const ir = (mf, extra = {}) =>
    makeIr({ entities: byQualifiedName([order]), microflows: byQualifiedName([mf]), ...extra });
  const flow = (extra) => microflow('App.ACT_Order', { appliesEntityAccess: false, allowedRoles: ['App.User'], referencedBy: [], ...extra });
  const writes = [mfStep('ChangeAction', { targetEntity: 'App.Order' })];
  const reads = [mfStep('RetrieveAction', { targetEntity: 'App.Order', properties: { retrieveSource: 'database' } })];
  const calls = [mfStep('MicroflowCall', { properties: { callee: 'App.SUB_Order' } })];

  it('a microflow a page starts is reported by SEC-MF-001 only, not twice', () => {
    const subject = ir(flow({ referencedBy: fromPage, activities: writes }));
    assert.equal(mf001.evaluate(subject).length, 1);
    assert.equal(sec028.evaluate(subject).length, 0);
  });

  it('SEC-028 keeps the ones SEC-MF-001 does not report', () => {
    // No page starts it, but a role can still call it from the browser.
    assert.equal(sec028.evaluate(ir(flow({ activities: writes }))).length, 1);
    // A page starts it, but only administrators may call it: SEC-MF-001 skips it, so SEC-028 keeps it.
    assert.equal(sec028.evaluate(ir(flow({ allowedRoles: ['App.Administrator'], referencedBy: fromPage, activities: writes }))).length, 1);
    // Where-used was not read: never assume "no page starts it" from missing data.
    assert.equal(sec028.evaluate(ir(flow({ referencedBy: undefined, activities: writes }))).length, 1);
  });

  it('SEC-MF-001 grades by data access: writes Critical, reads High, calls Medium, nothing Low', () => {
    const grade = (activities) => {
      const [f] = mf001.evaluate(ir(flow({ referencedBy: fromPage, activities })));
      return `${f.status} ${f.severity}`;
    };
    assert.equal(grade(writes), 'FAIL Critical');
    assert.equal(grade(reads), 'FAIL High');
    assert.equal(grade(calls), 'WARNING Medium');
    assert.equal(grade([]), 'WARNING Low');
  });

  it('SEC-028 grades by data access: writes High, reads Medium, calls or nothing Low', () => {
    const grade = (activities) => {
      const [f] = sec028.evaluate(ir(flow({ activities })));
      return `${f.status} ${f.severity}`;
    };
    assert.equal(grade(writes), 'FAIL High');
    assert.equal(grade(reads), 'FAIL Medium');
    assert.equal(grade(calls), 'WARNING Low');
    assert.equal(grade([]), 'WARNING Low');
  });

  it('a write to a non-persistable helper is not stored data', () => {
    const helper = entity('App.Form', { persistenceType: 'non-persistable' });
    const subject = makeIr({
      entities: byQualifiedName([helper]),
      microflows: byQualifiedName([flow({ activities: [mfStep('ChangeAction', { targetEntity: 'App.Form' })] })]),
    });
    assert.equal(sec028.evaluate(subject)[0].evidence.details.dataAccess, 'none');
  });

  it('one level higher when the anonymous role can call it', () => {
    const security = withGuest({}, ['App.User']);
    assert.equal(sec028.evaluate(ir(flow({ activities: reads }), { security }))[0].severity, 'High');
    assert.equal(mf001.evaluate(ir(flow({ referencedBy: fromPage, activities: reads }), { security }))[0].severity, 'Critical');
  });

  it('says in plain words what the microflow does', () => {
    const [f] = mf001.evaluate(ir(flow({ referencedBy: fromPage, activities: writes })));
    assert.match(f.observation, /is started from page App\.Order_Overview/);
    assert.match(f.observation, /writes stored data \(change App\.Order\)/);
  });

  it('without microflow contents the previous grading is kept', () => {
    const subject = ir(flow({ activities: [] }), { coverage: { microflowActivities: 'NOT_ANALYZABLE' } });
    const [f] = sec028.evaluate(subject);
    assert.equal(`${f.status} ${f.severity}`, 'FAIL High');
    assert.equal(f.evidence.details.dataAccess, 'not read');
  });
});
