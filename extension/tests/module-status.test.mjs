/**
 * The Module status tab: each module's entity, page, microflow and nanoflow access, with the
 * item that makes a section incomplete named rather than summarised away.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { analyzeSnapshot } from '../dist/analyzer.cjs';

const security = {
  $Type: 'Security$ProjectSecurity',
  $ID: 'ps',
  securityLevel: 'CheckEverything',
  checkSecurity: true,
  enableGuestAccess: true,
  guestUserRoleName: 'Anonymous',
  userRoles: [
    { $Type: 'Security$UserRole', name: 'User', moduleRoles: ['Shop.User', 'System.User'] },
    { $Type: 'Security$UserRole', name: 'Anonymous', moduleRoles: ['Shop.Anonymous', 'System.User'] },
  ],
};

const units = [
  {
    $Type: 'Security$ModuleSecurity',
    $ID: 'ms',
    moduleRoles: [
      { $Type: 'Security$ModuleRole', name: 'User' },
      { $Type: 'Security$ModuleRole', name: 'Anonymous' },
      { $Type: 'Security$ModuleRole', name: 'Auditor' },
    ],
  },
  {
    $Type: 'DomainModels$DomainModel',
    $ID: 'dm',
    entities: [
      { $Type: 'DomainModels$Entity', name: 'Unprotected', generalization: { $Type: 'DomainModels$NoGeneralization', persistable: true }, accessRules: [] },
      {
        $Type: 'DomainModels$Entity',
        name: 'Order',
        generalization: { $Type: 'DomainModels$NoGeneralization', persistable: true },
        accessRules: [
          { $Type: 'DomainModels$AccessRule', moduleRoles: ['Shop.User'], allowCreate: true, allowDelete: false, defaultMemberAccessRights: 'None', xPathConstraint: '[x]', memberAccesses: [
            { $Type: 'DomainModels$MemberAccess', attribute: 'Shop.Order.Total', accessRights: 'ReadWrite' },
            { $Type: 'DomainModels$MemberAccess', attribute: 'Shop.Order.Date', accessRights: 'ReadOnly' },
          ] },
        ],
      },
      { $Type: 'DomainModels$Entity', name: 'LoginForm', generalization: { $Type: 'DomainModels$NoGeneralization', persistable: false }, accessRules: [
        { $Type: 'DomainModels$AccessRule', moduleRoles: ['Shop.Anonymous'], allowCreate: true, defaultMemberAccessRights: 'ReadWrite', memberAccesses: [] },
      ] },
    ],
  },
  { $Type: 'Pages$Page', $ID: 'p1', name: 'Login', allowedRoles: ['Shop.Anonymous'], $References: ['Shop.LoginForm'] },
  { $Type: 'Pages$Page', $ID: 'p2', name: 'Orphan', allowedRoles: [], $References: [] },
  { $Type: 'Pages$Page', $ID: 'p3', name: 'PublicOrders', allowedRoles: ['Shop.Anonymous'], $References: ['Shop.Order'] },
  { $Type: 'Microflows$Microflow', $ID: 'm1', name: 'ACT_Save', allowedModuleRoles: ['Shop.User'], applyEntityAccess: false, $References: ['Shop.SUB_Helper', 'Shop.Order'] },
  { $Type: 'Microflows$Microflow', $ID: 'm2', name: 'SUB_Helper', allowedModuleRoles: [], applyEntityAccess: false, $References: [] },
  { $Type: 'Microflows$Microflow', $ID: 'm3', name: 'SUB_Unused', allowedModuleRoles: [], applyEntityAccess: true, $References: [] },
  { $Type: 'Microflows$Nanoflow', $ID: 'n1', name: 'NAV_Open', allowedModuleRoles: ['Shop.Anonymous'], $References: ['Shop.ACT_Save'] },
];

const snapshot = {
  schemaVersion: 1,
  source: 'studio-pro',
  app: { name: 'Shop' },
  projectUnits: [security],
  modules: [{ name: 'Shop', fromAppStore: false, units }, { name: 'Market', fromAppStore: true, units: [] }],
  javaSources: [],
  notes: [],
  capturedAt: new Date(0).toISOString(),
};

const shop = () => analyzeSnapshot(snapshot).modules.find((m) => m.name === 'Shop');

describe('Module status', () => {
  test('lists your modules before Marketplace ones', () => {
    assert.deepEqual(analyzeSnapshot(snapshot).modules.map((m) => m.name), ['Shop', 'Market']);
  });

  test('marks entity access incomplete and names the entity without rules', () => {
    const { entities } = shop();
    assert.equal(entities.state, 'incomplete');
    assert.equal(entities.summary, '1 of 2 persistable entities have access rules');
    assert.equal(entities.rows[0].name, 'Unprotected');
    assert.equal(entities.rows[0].state, 'no-rules');
  });

  test('describes each role grant in words', () => {
    const order = shop().entities.rows.find((r) => r.name === 'Order');
    assert.deepEqual(order.grants, [{ role: 'Shop.User', rights: 'create · read 2 · write 1 · XPath', anonymous: false }]);
  });

  test('does not treat anonymous access to a non-persistable entity as exposure', () => {
    const login = shop().entities.rows.find((r) => r.name === 'LoginForm');
    assert.equal(login.state, 'ok');
    assert.equal(login.anonymous, true);
  });

  test('judges anonymous pages by their data, as SEC-018 does', () => {
    const pages = Object.fromEntries(shop().pages.rows.map((r) => [r.name, r.state]));
    assert.deepEqual(pages, { Orphan: 'no-roles', PublicOrders: 'anonymous', Login: 'ok' });
    assert.equal(shop().pages.state, 'incomplete');
  });

  test('flags a callable microflow that skips entity access, not an internal one', () => {
    const flows = Object.fromEntries(shop().microflows.rows.map((r) => [r.name, r.state]));
    assert.deepEqual(flows, { ACT_Save: 'no-entity-access', SUB_Helper: 'internal', SUB_Unused: 'internal' });
    assert.equal(shop().microflows.state, 'review');
  });

  test('counts what the anonymous role can reach', () => {
    assert.deepEqual(shop().anonymous, { entities: 0, pages: 1, microflows: 0, nanoflows: 1, total: 2 });
  });

  test('shows which user roles hold each module role', () => {
    const roles = Object.fromEntries(shop().roles.map((r) => [r.name, r.grantedTo]));
    assert.deepEqual(roles, { User: ['User'], Anonymous: ['Anonymous'], Auditor: [] });
  });

  test('takes the worst section as the module status', () => {
    assert.equal(shop().overall, 'incomplete');
  });
});

describe('Open in Studio Pro selects the entity', () => {
  test('resolves a finding on an entity, an attribute or an access rule to its entity', async () => {
    const { entityForFinding } = await import('../dist/analyzer.cjs');
    const names = ['Shop.Order', 'Shop.OrderLine'];
    const at = (artifactPath) => ({ evidence: { artifactPath } });
    assert.equal(entityForFinding(at('Shop.Order'), names), 'Shop.Order');
    assert.equal(entityForFinding(at('Shop.OrderLine.Amount'), names), 'Shop.OrderLine');
    assert.equal(entityForFinding(at('Shop.Checkout'), names), undefined);
    assert.equal(entityForFinding(at('AppSecurity.UserRoles.Anonymous'), names), undefined);
  });

  test('lists every entity in the result', () => {
    assert.deepEqual(analyzeSnapshot(snapshot).entityNames.sort(), ['Shop.LoginForm', 'Shop.Order', 'Shop.Unprotected']);
  });
});

describe('sub-microflows and sub-nanoflows', () => {
  const flow = (name) => shop().microflows.rows.find((r) => r.name === name);

  test('names the flows that call a sub-microflow', () => {
    assert.deepEqual(flow('SUB_Helper').calledBy, [{ qualifiedName: 'Shop.ACT_Save', kind: 'microflow' }]);
    assert.match(flow('SUB_Helper').note, /Used as a sub-microflow by Shop\.ACT_Save\./);
  });

  test('marks a nanoflow caller as a nanoflow', () => {
    assert.deepEqual(flow('ACT_Save').calledBy, [{ qualifiedName: 'Shop.NAV_Open', kind: 'nanoflow' }]);
    assert.match(flow('ACT_Save').note, /Shop\.NAV_Open \(nanoflow\)/);
  });

  test('says when an internal flow is called by nothing', () => {
    assert.deepEqual(flow('SUB_Unused').calledBy, []);
    assert.match(flow('SUB_Unused').note, /not called by any microflow or nanoflow/);
  });

  test('draws no conclusion when call information was not read', () => {
    const old = structuredClone(snapshot);
    for (const u of old.modules[0].units) delete u.$References;
    const m = analyzeSnapshot(old).modules.find((x) => x.name === 'Shop');
    assert.equal(m.microflows.rows.find((r) => r.name === 'SUB_Unused').calledBy, undefined);
  });
});
