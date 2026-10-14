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
  userRoles: [{ $Type: 'Security$UserRole', name: 'User', moduleRoles: ['Shop.User'], checkSecurity: true, manageAllRoles: false }],
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

describe('no rule passes on a value it could not read', () => {
  const statusOf = (r, id) => r.rules.find((x) => x.id === id);
  const withSecurity = (overrides, drop = []) => {
    const unit = { ...lockedDownSecurity, ...overrides };
    for (const key of drop) delete unit[key];
    return analyzeSnapshot(snapshot({ projectUnits: [unit], units: [moduleSecurity] }));
  };

  test('a fully read project passes the project-level rules on its own values', () => {
    const r = withSecurity({});
    for (const id of ['SEC-002', 'SEC-011', 'SEC-012', 'SEC-014', 'SEC-015', 'SEC-016', 'SEC-023', 'SEC-024']) {
      assert.equal(statusOf(r, id).status, 'PASSED', id);
    }
    assert.deepEqual(r.diagnostics.unreadFacts, {});
  });

  for (const [property, ids] of [
    ['strictPageUrlCheck', ['SEC-016']],
    ['checkSecurity', ['SEC-011']],
    ['enableDemoUsers', ['SEC-012']],
    ['adminPassword', ['SEC-014']],
    ['passwordPolicySettings', ['SEC-014', 'SEC-015']],
    ['enableGuestAccess', ['SEC-006', 'SEC-017']],
  ]) {
    test(`an unreadable ${property} makes ${ids.join(', ')} "not verified", not passed`, () => {
      const r = withSecurity({}, [property]);
      for (const id of ids) {
        const rule = statusOf(r, id);
        assert.equal(rule.status, 'NOT_VERIFIED', id);
        assert.match(rule.reason, /could not be read/);
      }
    });
  }

  test('an unreadable security level is not reported as CheckNothing', () => {
    const r = withSecurity({}, ['securityLevel']);
    assert.equal(statusOf(r, 'SEC-002').status, 'NOT_VERIFIED');
    assert.equal(r.findings.filter((f) => f.ruleId === 'SEC-002').length, 0);
  });

  test('a user role without a readable security flag makes SEC-023 not verified', () => {
    const r = withSecurity({ userRoles: [{ $Type: 'Security$UserRole', name: 'User', moduleRoles: ['Shop.User'] }] });
    assert.equal(statusOf(r, 'SEC-023').status, 'NOT_VERIFIED');
    assert.equal(statusOf(r, 'SEC-024').status, 'NOT_VERIFIED');
  });

  test('a rule that still finds something keeps its findings', () => {
    const r = withSecurity({ strictPageUrlCheck: false, checkSecurity: undefined });
    assert.equal(statusOf(r, 'SEC-016').status, 'FAILED');
  });

  test('not-verified rules are left out of the score, not counted as passes', () => {
    const full = withSecurity({});
    const partial = withSecurity({}, ['strictPageUrlCheck']);
    assert.equal(partial.score.rulesPassed ?? partial.rules.filter((x) => x.status === 'PASSED').length,
      full.rules.filter((x) => x.status === 'PASSED').length - 1);
    assert.ok(!partial.findings.some((f) => f.status === 'NOT_APPLICABLE'));
  });

  test('a microflow without a readable "Apply entity access" makes the microflow rules not verified', () => {
    const r = analyzeSnapshot(
      snapshot({
        projectUnits: [lockedDownSecurity],
        units: [moduleSecurity, { $Type: 'Microflows$Microflow', name: 'ACT_Save', allowedModuleRoles: ['Shop.User'], objectCollection: { $Type: 'Microflows$MicroflowObjectCollection', objects: [] }, flows: [] }],
      })
    );
    for (const id of ['SEC-028', 'SEC-MF-003']) assert.equal(statusOf(r, id).status, 'NOT_VERIFIED', id);
    // SEC-MF-001 also needs the reference index, which this snapshot lacks, so the engine skips it.
    assert.equal(statusOf(r, 'SEC-MF-001').status, 'NOT_APPLICABLE');
  });
});

describe('owned data and specializations (SEC-022)', () => {
  const domainModel = (entities) => ({ $Type: 'DomainModels$DomainModel', $ID: 'dm', entities });
  const entity = (name, generalization, rules = []) => ({
    $Type: 'DomainModels$Entity',
    name,
    generalization,
    accessRules: rules,
    attributes: [],
  });
  const userRule = (roles) => ({ $Type: 'DomainModels$AccessRule', moduleRoles: roles, allowCreate: false, allowDelete: false, defaultMemberAccessRights: 'None', memberAccesses: [], xPathConstraint: '' });

  test('a specialization of an owned entity is owned data too', () => {
    const r = analyzeSnapshot(
      snapshot({
        projectUnits: [lockedDownSecurity],
        units: [
          moduleSecurity,
          domainModel([
            entity('Base', { $Type: 'DomainModels$NoGeneralization', persistable: true, hasOwner: true }),
            entity('Order', { $Type: 'DomainModels$Generalization', generalization: 'Shop.Base' }, [userRule(['Shop.User'])]),
          ]),
        ],
      })
    );
    assert.deepEqual(r.findings.filter((f) => f.ruleId === 'SEC-022').map((f) => f.evidence.artifactPath), ['Shop.Order']);
  });

  test('a module name containing "admin" does not make its roles administrative', () => {
    const snap = snapshot({
      projectUnits: [lockedDownSecurity],
      units: [
        moduleSecurity,
        domainModel([entity('Ticket', { $Type: 'DomainModels$NoGeneralization', persistable: true, hasOwner: true }, [userRule(['AdminPortal.User'])])]),
      ],
    });
    const r = analyzeSnapshot(snap);
    assert.equal(r.findings.filter((f) => f.ruleId === 'SEC-022').length, 1);
  });
});

describe('microflows named by a constant', () => {
  const run = (withConstant) =>
    analyzeSnapshot({
      ...snapshot({
        projectUnits: [lockedDownSecurity],
        units: [
          moduleSecurity,
          { $Type: 'Microflows$Microflow', name: 'Hook', allowedModuleRoles: ['Shop.User'], applyEntityAccess: true, objectCollection: { $Type: 'Microflows$MicroflowObjectCollection', objects: [] }, flows: [], $References: [] },
          ...(withConstant ? [{ $Type: 'Constants$Constant', name: 'HookName', defaultValue: 'Shop.Hook', exposedToClient: false }] : []),
        ],
      }),
      referenceIndex: [],
    });

  test('count as referenced, so SEC-MF-005 does not call them dead', () => {
    assert.equal(run(false).findings.filter((f) => f.ruleId === 'SEC-MF-005').length, 1);
    assert.equal(run(true).findings.filter((f) => f.ruleId === 'SEC-MF-005').length, 0);
  });
});

describe('error handling on integration calls (SEC-MF-006)', () => {
  const action = (id, $Type, extra = {}) => ({ $Type: 'Microflows$ActionActivity', $ID: id, disabled: false, action: { $Type, $ID: `${id}-a`, ...extra } });
  const flow = (origin, destination, isErrorHandler = false) => ({ $Type: 'Microflows$SequenceFlow', $ID: `${origin}-${destination}`, origin, destination, isErrorHandler });
  const run = (handling, withLog) =>
    analyzeSnapshot({
      ...snapshot({
        projectUnits: [lockedDownSecurity],
        units: [
          moduleSecurity,
          {
            $Type: 'Microflows$Microflow',
            name: 'ACT_Send',
            allowedModuleRoles: [],
            applyEntityAccess: true,
            objectCollection: {
              $Type: 'Microflows$MicroflowObjectCollection',
              objects: [
                { $Type: 'Microflows$StartEvent', $ID: 'start' },
                action('rest', 'Microflows$RestCallAction', { errorHandlingType: handling }),
                { $Type: 'Microflows$EndEvent', $ID: 'end' },
                ...(withLog ? [action('log', 'Microflows$LogMessageAction', { errorHandlingType: 'Rollback' })] : []),
                { $Type: 'Microflows$EndEvent', $ID: 'error-end' },
              ],
            },
            flows: [
              flow('start', 'rest'),
              flow('rest', 'end'),
              ...(withLog ? [flow('rest', 'log', true), flow('log', 'error-end')] : [flow('rest', 'error-end', true)]),
            ],
            $References: [],
          },
        ],
      }),
      referenceIndex: [],
    }).findings.filter((f) => f.ruleId === 'SEC-MF-006' && f.status !== 'PASSED');

  test('reads the error handling type and follows the error flow to a Log message', () => {
    assert.deepEqual(run('CustomWithoutRollBack', true), []);
    assert.deepEqual(run('Custom', true), []);
  });

  test('reports the default Rollback as High and an error flow without a log as Medium', () => {
    assert.deepEqual(run('Rollback', false).map((f) => f.severity), ['High']);
    assert.deepEqual(run('CustomWithoutRollBack', false).map((f) => f.severity), ['Medium']);
  });
});

describe('naming integration calls (SEC-MF-006)', () => {
  const activity = (id, caption, action) => ({ $Type: 'Microflows$ActionActivity', $ID: id, disabled: false, caption, autoGenerateCaption: caption === 'Activity', action: { $ID: `${id}-a`, errorHandlingType: 'Rollback', ...action } });
  const observation = () =>
    analyzeSnapshot({
      ...snapshot({
        projectUnits: [lockedDownSecurity],
        units: [
          moduleSecurity,
          {
            $Type: 'Microflows$Microflow',
            name: 'ACT_Calls',
            allowedModuleRoles: [],
            applyEntityAccess: true,
            objectCollection: {
              $Type: 'Microflows$MicroflowObjectCollection',
              objects: [
                activity('ml', 'Activity', { $Type: 'Microflows$MLModelCallAction', mlMappingDocument: 'Shop.ChurnModel' }),
                activity('rest', 'Renamed call', {
                  $Type: 'Microflows$RestCallAction',
                  httpConfiguration: {
                    $Type: 'Microflows$HttpConfiguration',
                    newHttpMethod: 'Get',
                    customLocationTemplate: { $Type: 'Microflows$StringTemplate', text: '{1}/orders', arguments: [{ $Type: 'Microflows$TemplateArgument', expression: '@Shop.BaseUrl' }] },
                  },
                }),
              ],
            },
            flows: [],
            $References: [],
          },
        ],
      }),
      referenceIndex: [],
    }).findings.find((f) => f.ruleId === 'SEC-MF-006')?.observation ?? '';

  test('checks a Call ML model activity, named by its mapping', () => {
    assert.match(observation(), /Call ML model Shop\.ChurnModel/);
  });

  test('checks a renamed activity by its type and names it by caption, method and URL', () => {
    assert.match(observation(), /Call REST service "Renamed call" \(GET @Shop\.BaseUrl\/orders\)/);
  });
});

describe('conversions without an empty check (SEC-MF-007)', () => {
  const domainModel = {
    $Type: 'DomainModels$DomainModel',
    entities: [
      { $Type: 'DomainModels$Entity', name: 'Item', attributes: [{ $Type: 'DomainModels$Attribute', name: 'Count', type: { $Type: 'DomainModels$IntegerAttributeType' } }] },
    ],
  };
  const run = (value, decision) =>
    analyzeSnapshot({
      ...snapshot({
        projectUnits: [lockedDownSecurity],
        units: [
          moduleSecurity,
          domainModel,
          {
            $Type: 'Microflows$Microflow',
            name: 'ACT_Total',
            allowedModuleRoles: [],
            applyEntityAccess: true,
            objectCollection: {
              $Type: 'Microflows$MicroflowObjectCollection',
              objects: [
                { $Type: 'Microflows$StartEvent', $ID: 'start' },
                {
                  $Type: 'Microflows$ActionActivity',
                  $ID: 'retrieve',
                  action: { $Type: 'Microflows$RetrieveAction', outputVariableName: 'ItemList', retrieveSource: { $Type: 'Microflows$DatabaseRetrieveSource', entity: 'Shop.Item' } },
                },
                {
                  $Type: 'Microflows$LoopedActivity',
                  $ID: 'loop',
                  loopSource: { $Type: 'Microflows$IterableList', listVariableName: 'ItemList', variableName: 'IteratorItem' },
                  objectCollection: {
                    $Type: 'Microflows$MicroflowObjectCollection',
                    objects: [
                      ...(decision ? [{ $Type: 'Microflows$ExclusiveSplit', $ID: 'check', splitCondition: { $Type: 'Microflows$ExpressionSplitCondition', expression: decision } }] : []),
                      {
                        $Type: 'Microflows$ActionActivity',
                        $ID: 'change',
                        action: {
                          $Type: 'Microflows$ChangeObjectAction',
                          changeVariableName: 'IteratorItem',
                          items: [{ $Type: 'Microflows$MemberChange', attribute: 'Shop.Item.Count', type: 'Set', value }],
                        },
                      },
                    ],
                  },
                },
              ],
            },
            flows: [
              { $Type: 'Microflows$SequenceFlow', origin: 'start', destination: 'retrieve' },
              { $Type: 'Microflows$SequenceFlow', origin: 'retrieve', destination: 'loop' },
              ...(decision ? [{ $Type: 'Microflows$SequenceFlow', origin: 'check', destination: 'change' }] : []),
            ],
            $References: [],
          },
        ],
      }),
      referenceIndex: [],
    }).findings.filter((f) => f.ruleId === 'SEC-MF-007' && f.status !== 'PASSED');

  test('reads member expressions and knows a loop iterator\'s entity, so + on a number is a calculation', () => {
    const [finding] = run('$IteratorItem/Count + 1');
    assert.deepEqual(finding?.evidence.details.conversions, [
      { activity: 'Change object', member: 'Shop.Item.Count', expression: '$IteratorItem/Count + 1', problem: 'calculation with $IteratorItem/Count without an empty check', activityId: 'change' },
    ]);
  });

  test('accepts an earlier Decision that checks the value for empty', () => {
    assert.deepEqual(run('$IteratorItem/Count + 1', '$IteratorItem/Count != empty'), []);
  });
});

describe('Java actions that encrypt (SEC-005)', () => {
  const java = (fileName, content) => ({ moduleDirectory: 'shop', fileName, relativePath: `javasource/shop/actions/${fileName}`, content });
  const ir = () => {
    const built = buildIrFromSnapshot({
      ...snapshot({ projectUnits: [lockedDownSecurity], units: [moduleSecurity] }),
      javaSources: [
        java('Seal.java', 'import javax.crypto.Cipher; class Seal { void run() { Cipher c = Cipher.getInstance("AES"); c.init(Cipher.ENCRYPT_MODE, key); } }'),
        java('Unseal.java', 'import javax.crypto.Cipher; class Unseal { void run() { c.init(Cipher.DECRYPT_MODE, key); } }'),
        java('SealVia.java', 'class SealVia { String run() { return CryptoHelper.protect(value); } }'),
        java('CryptoHelper.java', 'import javax.crypto.Cipher; class CryptoHelper { static String protect(String v) { c.init(Cipher.ENCRYPT_MODE, k); return v; } }'),
      ],
    });
    return built.ir ?? built;
  };

  test('reads from the code whether an action encrypts, also through a helper class of its module', () => {
    const encrypts = Object.fromEntries(ir().customCode.javaActions.map((j) => [j.name, j.encrypts]));
    assert.equal(encrypts.Seal, true);
    assert.equal(encrypts.Unseal, false);
    assert.equal(encrypts.SealVia, true);
  });
});
