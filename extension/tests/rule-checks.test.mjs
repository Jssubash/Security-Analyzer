/**
 * Every rule the extension runs must explain itself in the Rules tab, and SEC-024 must be able to fail.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyzeSnapshot, redact, securityCatalogue } from '../dist/analyzer.cjs';

test('every rule the extension runs has a description of what it checks', () => {
  const r = analyzeSnapshot({ schemaVersion: 1, source: 'studio-pro', app: { name: 'Empty' }, projectUnits: [], modules: [], javaSources: [], notes: [], capturedAt: new Date(0).toISOString() });
  assert.equal(r.rules.length, securityCatalogue().length);
  for (const rule of r.rules) {
    assert.ok(rule.checks, `${rule.id} has no entry in RULE_CHECKS`);
    assert.ok(rule.checks.reads.length > 0, rule.id);
    assert.ok(rule.checks.flagged.length > 0, rule.id);
    assert.ok(rule.whyItMatters && rule.recommendation, rule.id);
  }
});

test('SEC-024 fails for a non-administrator role that can manage all roles', () => {
  const security = (roles) => ({
    $Type: 'Security$ProjectSecurity',
    securityLevel: 'CheckEverything', checkSecurity: true, enableGuestAccess: false, enableDemoUsers: false, strictPageUrlCheck: true,
    adminUserName: 'MxAdmin', adminUserRoleName: 'Administrator', adminPassword: redact('Correct-Horse-9'),
    userRoles: roles, demoUsers: [],
  });
  const role = (name, manageAllRoles) => ({ $Type: 'Security$UserRole', name, moduleRoles: ['Shop.User'], checkSecurity: true, manageAllRoles });
  const run = (roles) => analyzeSnapshot({ schemaVersion: 1, source: 'studio-pro', app: { name: 'U' }, projectUnits: [security(roles)], modules: [{ name: 'Shop', fromAppStore: false, units: [] }], javaSources: [], notes: [], capturedAt: new Date(0).toISOString() });

  const flagged = run([role('Administrator', true), role('HR', true), role('User', false)]);
  assert.deepEqual(flagged.findings.filter((f) => f.ruleId === 'SEC-024').map((f) => f.evidence.objectName), ['HR']);
  assert.equal(run([role('Administrator', true), role('User', false)]).rules.find((x) => x.id === 'SEC-024').status, 'PASSED');
});
