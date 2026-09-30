/**
 * The extension must reach the same verdict as the governance analyzer on the reference project.
 *
 * TestApp is read into a snapshot (the shape Studio Pro's host produces), analysed by the
 * extension, and compared finding-for-finding with two oracles:
 *
 *   1. the locked expected-findings list from `tests/expected-findings.test.mjs` (the SEC-* part),
 *   2. the parser path itself — the same SEC-* rules run over `parseExtractedProject`'s IR.
 *
 * The second oracle is what makes the port trustworthy: any divergence between the snapshot
 * extractor and the BSON extractor shows up as a finding present on one side only.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { ModelGraph } from '@mendix-analyzer/mendix-parser';

import { describeFixture, FIXTURE_MPR, FIXTURE_ROOT } from '../../tests/helpers/fixture.mjs';
import { snapshotFromMprContents } from './helpers/snapshot-from-mprcontents.mjs';
import { analyzeSnapshot, securityCatalogue } from '../dist/analyzer.cjs';

/** The SEC-* lines of the locked TestApp snapshot in tests/expected-findings.test.mjs. */
const EXPECTED = [
  'SEC-003-MyFirstModule.RequestForm#1 | FAIL | Critical',
  'SEC-006-Atlas_Core.User | WARNING | Medium',
  'SEC-EE-003-Administration.AccountPasswordData#1 | WARNING | Medium',
  'SEC-EE-003-FeedbackModule.Feedback#1 | WARNING | Medium',
  'SEC-EE-003-NanoflowCommons.Geolocation#1 | WARNING | Medium',
  'SEC-EE-003-NanoflowCommons.Position#1 | WARNING | Medium',
  'SEC-006-Atlas_Web_Content.User | WARNING | Medium',
  'SEC-006-MyFirstModule.User | FAIL | Critical',
  'SEC-007-FeedbackModule.XSS_Sanitizer | WARNING | Medium',
  'SEC-012-enabled | FAIL | High',
  'SEC-013-demo_administrator | FAIL | High',
  'SEC-013-demo_user | FAIL | High',
  'SEC-014-admin-password | FAIL | Critical',
  'SEC-015-policy | FAIL | Medium',
  'SEC-017-Atlas_Core.Administrator | FAIL | Critical',
  'SEC-017-Atlas_Web_Content.Administrator | FAIL | Critical',
  'SEC-020-MyFirstModule.RequestForm.Email#1 | FAIL | High',
  'SEC-020-MyFirstModule.RequestForm.Name#1 | FAIL | High',
  'SEC-020-MyFirstModule.RequestForm.PhoneNumber#1 | FAIL | High',
  'SEC-021-MyFirstModule.RequestForm.Email#1 | FAIL | High',
  'SEC-021-MyFirstModule.RequestForm.PhoneNumber#1 | FAIL | High',
  'SEC-028-Atlas_Core.DS_Account_CurrentUser | WARNING | High',
  'SEC-029-MyFirstModule.RequestForm#1 | FAIL | High',
  // SEC-MF rules read microflow bodies and the reference index, which only the extension extracts.
  'SEC-MF-001-Administration.ShowMyPasswordForm | WARNING | High',
  'SEC-MF-001-Atlas_Core.DS_Account_CurrentUser | WARNING | High',
  'SEC-MF-003-FeedbackModule.SUB_Feedback_SendToServer.Feedback | WARNING | Medium',
];

/** Rules the parser path skips (it does not read microflow bodies or the reference index). */
const EXTENSION_ONLY = /^SEC-MF-/;

const line = (f) => `${f.id} | ${f.status} | ${f.severity}`;

let cached;
function run() {
  cached ??= analyzeSnapshot(snapshotFromMprContents(FIXTURE_ROOT, FIXTURE_MPR));
  return cached;
}

async function parserPath() {
  const { parseExtractedProject } = await import('@mendix-analyzer/mendix-parser');
  const { RuleEngine, RuleRegistry } = await import('@mendix-analyzer/rule-engine');
  const { ScoringEngine } = await import('@mendix-analyzer/scoring');
  const ir = parseExtractedProject(FIXTURE_ROOT, FIXTURE_MPR);
  const registry = new RuleRegistry();
  registry.registerMany(securityCatalogue());
  const summary = new RuleEngine(registry).evaluate(ir);
  return { summary, score: new ScoringEngine().calculateScores(summary, ir.coverage) };
}

describeFixture('Security Analyzer extension on the reference project', () => {
  test('reports exactly the locked SEC-* findings', () => {
    assert.deepEqual(run().findings.map(line).sort(), [...EXPECTED].sort());
  });

  test('agrees finding-for-finding with the parser path', async () => {
    const { summary } = await parserPath();
    const oracle = summary.findings
      .filter((f) => f.status === 'FAIL' || f.status === 'WARNING')
      .map((f) => `${line(f)} | ${f.observation}`)
      .sort();
    // Compared on the rules both paths can run; the SEC-MF rules are locked above instead.
    const mine = run()
      .findings.filter((f) => !EXTENSION_ONLY.test(f.ruleId))
      .map((f) => `${line(f)} | ${f.observation}`)
      .sort();
    assert.deepEqual(mine, oracle);
  });

  test('produces the same Security score as the parser path, on the rules both can run', async () => {
    const { score } = await parserPath();
    const disabled = Object.fromEntries(securityCatalogue().filter((r) => EXTENSION_ONLY.test(r.id)).map((r) => [r.id, false]));
    const result = analyzeSnapshot(snapshotFromMprContents(FIXTURE_ROOT, FIXTURE_MPR), { enabledRules: disabled });
    assert.equal(typeof result.securityScore, 'number');
    assert.equal(result.securityScore, score.categoryScores['Security']);
    assert.equal(result.score.overallScore, score.overallScore);
    assert.equal(result.score.riskRating, score.riskRating);
  });

  test('reads which entities each page uses, the same way the parser does', async () => {
    const { buildIrFromSnapshot } = await import('../dist/analyzer.cjs');
    const { parseExtractedProject } = await import('@mendix-analyzer/mendix-parser');
    const mine = buildIrFromSnapshot(snapshotFromMprContents(FIXTURE_ROOT, FIXTURE_MPR)).ir.pages;
    const oracle = parseExtractedProject(FIXTURE_ROOT, FIXTURE_MPR).pages;
    const view = (pages) => Object.fromEntries(Object.values(pages).map((p) => [p.qualifiedName, p.dataEntities]));
    assert.deepEqual(view(mine), view(oracle));
    // Guard against a vacuous match: contents must actually have been resolved.
    assert.ok(Object.values(mine).every((p) => Array.isArray(p.dataEntities)));
    assert.ok(Object.values(mine).some((p) => p.dataEntities.length > 0));
  });

  test('skips SEC-004 because the app publishes no REST service, and says why', () => {
    const sec004 = run().rules.find((r) => r.id === 'SEC-004');
    assert.equal(sec004.status, 'NOT_APPLICABLE');
    assert.match(sec004.reason, /publishedServices/);
  });

  test('keeps the advisory rules switched off by default', () => {
    const disabled = run()
      .rules.filter((r) => r.status === 'DISABLED')
      .map((r) => r.id)
      .sort();
    assert.deepEqual(disabled, ['SEC-008', 'SEC-009']);
  });

  test('reports all 35 rules with a status', () => {
    const { rules } = run();
    assert.equal(rules.length, 35);
    for (const r of rules) assert.ok(r.status, `${r.id} has no status`);
  });

  test('records the inventory the snapshot contained', () => {
    const { inventory } = run();
    assert.equal(inventory.entities, 8);
    assert.equal(inventory.pages, 16);
    assert.equal(inventory.microflows, 17);
    assert.equal(inventory.userRoles, 3);
    assert.equal(inventory.moduleRoles, 16);
  });

  test('can locate a Studio Pro unit for every finding outside custom Java code', async () => {
    const { unitForFinding } = await import('../dist/analyzer.cjs');
    const result = run();
    for (const f of result.findings) {
      if (f.ruleId === 'SEC-007') continue; // anchored to a .java file, not a model unit
      assert.ok(unitForFinding(f, result.units), `no unit for ${f.id} (${f.evidence.artifactPath})`);
    }
  });

  test('never carries a credential from the model into the result', async () => {
    const graph = ModelGraph.build(FIXTURE_ROOT, FIXTURE_MPR);
    const [unitRef] = graph.units.refsOfType('Security$ProjectSecurity');
    const securityUnit = readFileSync(unitRef.absolutePath);
    // The demo passwords are read from the fixture itself, so no credential is committed here.
    const { parseBsonDocument } = await import('@mendix-analyzer/mendix-parser');
    const demoPasswords = (parseBsonDocument(securityUnit).DemoUsers ?? []).map((u) => u.Password).filter(Boolean);
    // A redaction test hunting values the fixture never held would pass forever.
    assert.ok(demoPasswords.length > 0, 'the fixture no longer has demo user passwords');

    const snapshot = JSON.stringify(snapshotFromMprContents(FIXTURE_ROOT, FIXTURE_MPR));
    const result = JSON.stringify(run());
    for (const value of demoPasswords) {
      assert.ok(!snapshot.includes(value), 'snapshot contains a demo password');
      assert.ok(!result.includes(value), 'result contains a demo password');
    }
  });

  test('suppresses the Security score when project security cannot be read', () => {
    const snapshot = snapshotFromMprContents(FIXTURE_ROOT, FIXTURE_MPR, {
      dropTypes: ['Security$ProjectSecurity'],
    });
    const result = analyzeSnapshot(snapshot);
    assert.equal(result.coverage.projectSecurity, 'NOT_ANALYZABLE');
    assert.equal(result.securityScore, null);
    assert.equal(result.rules.find((r) => r.id === 'SEC-002').status, 'NOT_APPLICABLE');
    assert.ok(result.score.coveragePercentage < run().score.coveragePercentage);
  });
});

describeFixture('SEC-MF rules on the reference project', () => {
  test('run on the microflow bodies instead of being skipped', () => {
    const { rules, coverage } = run();
    assert.equal(coverage.microflowActivities, 'ANALYZED');
    assert.equal(coverage.modelReferences, 'ANALYZED');
    const status = Object.fromEntries(rules.filter((r) => r.id.startsWith('SEC-MF')).map((r) => [r.id, r.status]));
    assert.deepEqual(status, {
      'SEC-MF-001': 'WARNING',
      'SEC-MF-002': 'PASSED',
      'SEC-MF-003': 'WARNING',
      // TestApp publishes no REST service, so there is no endpoint to judge.
      'SEC-MF-004': 'NOT_APPLICABLE',
      'SEC-MF-005': 'PASSED',
    });
  });

  test('are skipped, not passed, when the host sent no microflow bodies or reference index', () => {
    const snapshot = snapshotFromMprContents(FIXTURE_ROOT, FIXTURE_MPR, { withoutReferenceIndex: true });
    for (const m of snapshot.modules) for (const u of m.units) if (u.$Type === 'Microflows$Microflow') delete u.ObjectCollection;
    const status = Object.fromEntries(analyzeSnapshot(snapshot).rules.filter((r) => r.id.startsWith('SEC-MF')).map((r) => [r.id, r.status]));
    for (const [id, st] of Object.entries(status)) assert.equal(st, 'NOT_APPLICABLE', id);
  });
});
