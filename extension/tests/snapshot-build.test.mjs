/**
 * Snapshot → IR behaviour that the reference project cannot exercise: published REST services,
 * weak-password judgement from redacted features, and the fail-quiet paths.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { analyzeSnapshot, buildIrFromSnapshot, isWeakPassword, redact } from '../dist/analyzer.cjs';

function snapshot({ projectUnits = [], units = [] } = {}) {
  return {
    schemaVersion: 1,
    source: 'studio-pro',
    app: { name: 'Unit', studioProVersion: '10.24.0' },
    projectUnits,
    modules: [{ name: 'Shop', fromAppStore: false, units }],
    javaSources: [],
    notes: [],
    capturedAt: new Date(0).toISOString(),
  };
}

const lockedDownSecurity = {
  $Type: 'Security$ProjectSecurity',
  $ID: 'ps',
  securityLevel: 'CheckEverything',
  checkSecurity: true,
  enableGuestAccess: false,
  enableDemoUsers: false,
  strictPageUrlCheck: true,
  adminUserName: 'MxAdmin',
  adminPassword: redact('Correct-Horse-9'),
  passwordPolicySettings: {
    $Type: 'Security$PasswordPolicySettings',
    minimumLength: 12,
    requireDigit: true,
    requireMixedCase: true,
    requireSymbol: true,
  },
  userRoles: [{ $Type: 'Security$UserRole', name: 'User', moduleRoles: ['Shop.User'], checkSecurity: true }],
  demoUsers: [],
};

const moduleSecurity = {
  $Type: 'Security$ModuleSecurity',
  $ID: 'ms',
  moduleRoles: [{ $Type: 'Security$ModuleRole', name: 'User' }],
};

function restService(extra) {
  return {
    $Type: 'Rest$PublishedRestService',
    $ID: 'svc',
    name: 'OrdersApi',
    path: 'rest/orders/v1',
    resources: [
      {
        $Type: 'Rest$PublishedRestServiceResource',
        name: 'order',
        operations: [
          { $Type: 'Rest$PublishedRestServiceOperation', httpMethod: 'Get', path: '{id}', microflow: 'Shop.GetOrder' },
        ],
      },
    ],
    ...extra,
  };
}

describe('published REST services (SEC-004)', () => {
  test('fires for a service with no authentication types', () => {
    const r = analyzeSnapshot(
      snapshot({ projectUnits: [lockedDownSecurity], units: [moduleSecurity, restService({ authenticationTypes: [] })] })
    );
    const sec004 = r.findings.filter((f) => f.ruleId === 'SEC-004');
    assert.equal(sec004.length, 1);
    assert.match(sec004[0].observation, /rest\/orders\/v1\/order\/\{id\}/);
  });

  test('stays quiet for an authenticated service', () => {
    const r = analyzeSnapshot(
      snapshot({ projectUnits: [lockedDownSecurity], units: [moduleSecurity, restService({ authenticationTypes: ['Basic'] })] })
    );
    assert.equal(r.findings.filter((f) => f.ruleId === 'SEC-004').length, 0);
    assert.equal(r.rules.find((x) => x.id === 'SEC-004').status, 'PASSED');
  });

  test('does not assess a service whose authentication setting is unreadable', () => {
    const { ir } = buildIrFromSnapshot(
      snapshot({ projectUnits: [lockedDownSecurity], units: [moduleSecurity, restService({})] })
    );
    assert.equal(ir.integrations.publishedRestServices.length, 0);
    assert.ok(ir.coverage.notes.some((n) => n.includes('OrdersApi')));
  });
});

describe('administrator password', () => {
  test('is judged from redacted features against the project policy', () => {
    const policy = { minimumLength: 12, requireDigit: true, requireMixedCase: true, requireSymbol: true };
    assert.equal(isWeakPassword(redact('1'), policy), true);
    assert.equal(isWeakPassword(redact('longbutnodigitsorcaps'), policy), true);
    assert.equal(isWeakPassword(redact('Correct-Horse-9'), policy), false);
    // A policy below the baseline does not lower the bar for the administrator.
    assert.equal(isWeakPassword(redact('Ab1'), { minimumLength: 1 }), true);
  });

  test('a locked-down project produces no project-level findings', () => {
    const r = analyzeSnapshot(snapshot({ projectUnits: [lockedDownSecurity], units: [moduleSecurity] }));
    const projectRules = ['SEC-002', 'SEC-011', 'SEC-012', 'SEC-013', 'SEC-014', 'SEC-015', 'SEC-016'];
    assert.deepEqual(r.findings.filter((f) => projectRules.includes(f.ruleId)), []);
    assert.equal(r.securityScore, 100);
  });
});

describe('unset references', () => {
  test('an empty by-name reference is read as absent, not as a role called ""', () => {
    const { ir } = buildIrFromSnapshot(
      snapshot({ projectUnits: [{ ...lockedDownSecurity, guestUserRole: '', enableGuestAccess: true }] })
    );
    assert.equal(ir.security.anonymousRole, undefined);
  });
});

describe('Studio Pro type names', () => {
  const pageSecurity = {
    ...lockedDownSecurity,
    enableGuestAccess: true,
    guestUserRole: 'Anonymous',
    userRoles: [
      ...lockedDownSecurity.userRoles,
      { $Type: 'Security$UserRole', name: 'Anonymous', moduleRoles: ['Shop.Anonymous', 'System.User'], checkSecurity: true },
    ],
  };
  const guestModuleSecurity = {
    $Type: 'Security$ModuleSecurity',
    $ID: 'ms',
    moduleRoles: [{ $Type: 'Security$ModuleRole', name: 'User' }, { $Type: 'Security$ModuleRole', name: 'Anonymous' }],
  };

  test('reads a page typed Pages$Page, as the untyped model API names it', () => {
    const page = { $Type: 'Pages$Page', $ID: 'p1', name: 'Orders', allowedRoles: ['Shop.Anonymous'] };
    const r = analyzeSnapshot(snapshot({ projectUnits: [pageSecurity], units: [guestModuleSecurity, page] }));
    assert.equal(r.coverage.pageAccess, 'ANALYZED');
    assert.deepEqual(r.findings.filter((f) => f.ruleId === 'SEC-018').map((f) => f.evidence.objectName), ['Orders']);
  });

  test('flags guest create/delete and member write on a persistable specialization', () => {
    // The shape of MyFirstModule.FileUploader: a System.FileDocument specialization whose rule
    // grants the guest-held module role create, delete and write on Name.
    const domainModel = {
      $Type: 'DomainModels$DomainModel',
      $ID: 'dm',
      entities: [
        {
          $Type: 'DomainModels$Entity',
          name: 'FileUploader',
          generalization: { $Type: 'DomainModels$Generalization', generalization: 'System.FileDocument' },
          attributes: [],
          accessRules: [
            {
              $Type: 'DomainModels$AccessRule',
              moduleRoles: ['Shop.Anonymous'],
              allowCreate: true,
              allowDelete: true,
              defaultMemberAccessRights: 'None',
              xPathConstraint: '',
              memberAccesses: [
                { $Type: 'DomainModels$MemberAccess', attribute: 'Shop.FileUploader.Name', association: '', accessRights: 'ReadWrite' },
              ],
            },
          ],
        },
      ],
    };
    const r = analyzeSnapshot(snapshot({ projectUnits: [pageSecurity], units: [guestModuleSecurity, domainModel] }));
    assert.equal(r.findings.filter((f) => f.ruleId === 'SEC-003').length, 1);
    assert.equal(r.findings.filter((f) => f.ruleId === 'SEC-020').length, 1);
    assert.deepEqual(r.diagnostics.guestModuleRoles, ['Shop.Anonymous', 'System.User']);
    assert.equal(r.diagnostics.accessRulesWithRoles, 1);
  });

  test('says so when role references come back empty', () => {
    const blank = { ...pageSecurity, userRoles: pageSecurity.userRoles.map((u) => ({ ...u, moduleRoles: [] })) };
    const { ir } = buildIrFromSnapshot(snapshot({ projectUnits: [blank], units: [guestModuleSecurity] }));
    assert.ok(ir.coverage.notes.some((n) => n.includes('role references were probably not read')));
  });
});

describe('references delivered as elements', () => {
  // Studio Pro's untyped API may hand a by-name reference over as the referenced element. The
  // extension must still read it as the qualified name, or the anonymous role appears to hold
  // nothing and every anonymous-access rule passes on an exposed app.
  const roleRef = (q) => ({ $Type: 'Security$ModuleRole', $QualifiedName: q, $Name: q.split('.')[1] });
  const security = {
    ...lockedDownSecurity,
    enableGuestAccess: true,
    guestUserRole: { $Type: 'Security$UserRole', $QualifiedName: 'Anonymous', $Name: 'Anonymous' },
    userRoles: [
      { $Type: 'Security$UserRole', name: 'User', moduleRoles: [roleRef('Shop.User')], checkSecurity: true },
      { $Type: 'Security$UserRole', name: 'Anonymous', moduleRoles: [roleRef('Shop.Anonymous'), roleRef('System.User')], checkSecurity: true },
    ],
  };
  const moduleSec = {
    $Type: 'Security$ModuleSecurity',
    $ID: 'ms',
    moduleRoles: [{ $Type: 'Security$ModuleRole', name: 'User' }, { $Type: 'Security$ModuleRole', name: 'Anonymous' }],
  };
  const domainModel = {
    $Type: 'DomainModels$DomainModel',
    $ID: 'dm',
    entities: [
      {
        $Type: 'DomainModels$Entity',
        name: 'FileUploader',
        generalization: { $Type: 'DomainModels$Generalization', generalization: 'System.FileDocument' },
        attributes: [],
        accessRules: [
          {
            $Type: 'DomainModels$AccessRule',
            moduleRoles: [roleRef('Shop.Anonymous')],
            allowCreate: true,
            allowDelete: true,
            defaultMemberAccessRights: 'None',
            memberAccesses: [
              { $Type: 'DomainModels$MemberAccess', attribute: { $Type: 'DomainModels$Attribute', $QualifiedName: 'Shop.FileUploader.Name' }, accessRights: 'ReadWrite' },
            ],
          },
        ],
      },
    ],
  };
  const page = { $Type: 'Pages$Page', $ID: 'p', name: 'Upload', allowedRoles: [roleRef('Shop.Anonymous')] };

  test('fires every anonymous-access rule it should', () => {
    const r = analyzeSnapshot(snapshot({ projectUnits: [security], units: [moduleSec, domainModel, page] }));
    const fired = new Set(r.findings.map((f) => f.ruleId));
    for (const id of ['SEC-003', 'SEC-018', 'SEC-020', 'SEC-029']) assert.ok(fired.has(id), `${id} did not fire`);
    assert.deepEqual(r.diagnostics.guestModuleRoles, ['Shop.Anonymous', 'System.User']);
  });
});
