/**
 * `docs/security.md` §8 test 4 — the reference project's finding set, reviewed by hand and locked.
 *
 * The snapshot below is exact, and both directions matter. A new finding appearing means a rule
 * started firing on something nobody reviewed; a finding disappearing means a real defect stopped
 * being reported. §9.7 names five of these as the acceptance criterion — SEC-014, SEC-017,
 * SEC-012, SEC-013, SEC-015 are five genuine defects in this project that the old analyzer missed
 * entirely — so they are asserted individually as well as through the snapshot.
 *
 * Findings that do *not* appear are asserted too. SEC-010 staying silent is the point of the
 * marketplace attribution work: the constant it used to flag belongs to FeedbackModule.
 */

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { it } from 'node:test';

import {
  FIXTURE_ROOT,
  REPO_ROOT,
  describeFixture,
  findingsOf,
  firedRuleIds,
  fixtureEvaluation,
  fixtureIr,
} from './helpers/fixture.mjs';

/** `id | status | severity` for every finding, sorted. */
const EXPECTED = [
  'MNT-002-MyFirstLogic | WARNING | Low',
  'SEC-003-MyFirstModule.RequestForm#1 | FAIL | Critical',
  'SEC-006-Atlas_Core.User | WARNING | Medium',
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
  'SEC-EE-003-Administration.AccountPasswordData#1 | WARNING | Medium',
  'SEC-EE-003-FeedbackModule.Feedback#1 | WARNING | Medium',
  'SEC-EE-003-NanoflowCommons.Geolocation#1 | WARNING | Medium',
  'SEC-EE-003-NanoflowCommons.Position#1 | WARNING | Medium',
  'UI-001-Home_Web | WARNING | Low',
];

/** Rules that ran against a model they could read and correctly found nothing. */
const EXPECTED_SILENT = [
  'SEC-001', // every persistable user-module entity has an access rule
  'SEC-005', // no credential attribute in a user module
  'SEC-010', // the one browser-storage constant belongs to a marketplace module
  'SEC-018', // the one anonymous page is the navigation home page
  'SEC-019', // no user-module page is left without roles
  'SEC-022', // no entity carries an owner attribute
  'SEC-025', // every user-module module role is granted
  'SEC-026', // no constant holds a credential value
  'SEC-027',
  'SEC-002', // the project is at CheckEverything
  'SEC-011',
  'SEC-016',
  'SEC-023',
  'SEC-024',
];

/** Rules skipped because Phase 1 does not read the facts they need, with the fact named. */
const EXPECTED_SKIPS = {
  'SEC-004': 'publishedServices',
  'INT-001': 'publishedServices',
  'INT-002': 'publishedServices',
  'PERF-003': 'publishedServices',
  'PERF-001': 'microflowActivities',
  'PERF-002': 'microflowActivities',
  'PERF-004': 'microflowActivities',
  'MF-001': 'microflowActivities',
  'MF-002': 'microflowActivities',
  'NF-001': 'microflowActivities',
  'OPS-002': 'scheduledEvents',
  // The SEC-MF rules need microflow bodies and the model-wide reference index, which only the
  // Studio Pro extension reads; the archive parser skips them rather than passing them.
  'SEC-MF-001': 'modelReferences',
  'SEC-MF-002': 'microflowActivities',
  'SEC-MF-003': 'microflowActivities',
  'SEC-MF-004': 'publishedServices,microflowActivities',
  'SEC-MF-005': 'modelReferences',
};

describeFixture('expected findings for the reference project', () => {
  it('produces exactly the reviewed finding set', async () => {
    const summary = await fixtureEvaluation();
    const actual = summary.findings
      .map((f) => `${f.id} | ${f.status} | ${f.severity}`)
      .sort((a, b) => a.localeCompare(b));
    assert.deepEqual(actual, EXPECTED);
  });

  it('reports the five defects §9.7 names as the acceptance criterion', async () => {
    const summary = await fixtureEvaluation();

    // The administrator password is one character long in this project.
    const [admin] = findingsOf(summary, 'SEC-014');
    assert.equal(admin.severity, 'Critical');
    assert.equal(admin.evidence.objectName, 'MxAdmin');
    assert.equal(admin.evidence.details.passwordLength, 1);

    // The guest role holds two marketplace administrator roles.
    const adminRoles = findingsOf(summary, 'SEC-017').map((f) => f.evidence.details.grantedModuleRole);
    assert.deepEqual(adminRoles, ['Atlas_Core.Administrator', 'Atlas_Web_Content.Administrator']);

    // Demo users are enabled, and both accounts carry a password in the model.
    assert.equal(findingsOf(summary, 'SEC-012').length, 1);
    assert.deepEqual(
      findingsOf(summary, 'SEC-013').map((f) => f.evidence.objectName),
      ['demo_administrator', 'demo_user']
    );

    // The password policy does not require a symbol.
    const [policy] = findingsOf(summary, 'SEC-015');
    assert.equal(policy.evidence.details.policy.requireSymbol, false);
    assert.deepEqual(policy.evidence.details.shortfalls, ['a symbol is not required']);
  });

  it('keeps the rules that should find nothing silent', async () => {
    const summary = await fixtureEvaluation();
    const fired = firedRuleIds(summary);
    const wronglyFired = EXPECTED_SILENT.filter((id) => fired.has(id));
    assert.deepEqual(wronglyFired, []);

    // Silent because they ran and found nothing, not because they were skipped — those are
    // different results and the distinction is the whole point of the coverage contract.
    const skipped = new Set(summary.skippedRules.map((r) => r.ruleId));
    const quietlySkipped = EXPECTED_SILENT.filter((id) => skipped.has(id));
    assert.deepEqual(quietlySkipped, []);
  });

  it('skips exactly the rules whose facts Phase 1 does not read, naming the fact', async () => {
    const summary = await fixtureEvaluation();
    const actual = Object.fromEntries(
      summary.skippedRules.map((r) => [r.ruleId, (r.missingFacts ?? []).join(',')])
    );
    assert.deepEqual(actual, EXPECTED_SKIPS);
    assert.equal(summary.totalNotApplicable, Object.keys(EXPECTED_SKIPS).length);
  });

  it('counts outcomes the way the score divides them', async () => {
    const summary = await fixtureEvaluation();
    assert.equal(summary.totalRulesEvaluated, 38);
    assert.equal(summary.totalPassed, 23);
    assert.equal(summary.totalFailed, 15);
    assert.equal(summary.totalWarnings, 10);
    assert.deepEqual(summary.severityBreakdown, {
      Critical: 5,
      High: 10,
      Medium: 8,
      Low: 2,
      Informational: 0,
    });
    // `rulesPassed + rulesViolated` is the denominator, so it must exclude the skips.
    const security = summary.categoryBreakdown.Security;
    assert.equal(security.rulesPassed + security.rulesViolated, 27);
    assert.equal(security.rulesNotApplicable, 6);
  });

  it('scores the categories it could assess and names the ones it could not', async () => {
    const { ScoringEngine } = await import('@mendix-analyzer/scoring');
    const summary = await fixtureEvaluation();
    const ir = await fixtureIr();
    const score = new ScoringEngine().calculateScores(summary, ir.coverage);

    // SEC-029 (docs/security.md §6.9) added one failing rule: 79 → 78, Compliance 64 → 62.
    assert.equal(score.overallScore, 78);
    // Five Critical findings: the rating is driven by severity, not just the average.
    assert.equal(score.riskRating, 'F');
    assert.equal(score.categoryScores.Security, 65);
    assert.equal(score.categoryScores.Architecture, 100);
    // SEC-EE-003 (docs/security.md §6.12) added one rule that warns: Compliance 62 → 61.
    assert.equal(score.categoryScores.Compliance, 61);
    assert.equal(score.notApplicableCount, 16);

    // Categories with no rule outcomes are absent rather than 100 — a perfect score for
    // something the analyzer never looked at is the §2.1 defect this work exists to fix.
    const unassessed = score.unassessedCategories.map((c) => c.category).sort();
    assert.deepEqual(unassessed, ['Integration', 'Logic', 'Operations', 'Performance']);
    for (const category of unassessed) {
      assert.equal(score.categoryScores[category], undefined);
    }
  });

  it('grounds every finding in a real unit file and a real skill', async () => {
    const summary = await fixtureEvaluation();
    for (const finding of summary.findings) {
      assert.ok(finding.evidence?.artifactPath, `${finding.id} has no artifactPath`);
      // `sourceSkill` names an mxcli MDL skill document (e.g. manage-security.md). Those documents
      // belong to the mxcli tooling and are not redistributed here, so the citation is checked for
      // shape rather than for a file on disk.
      assert.match(finding.sourceSkill, /^[a-z0-9-]+\.md$/, `${finding.id} cites "${finding.sourceSkill}"`);

      // Not every finding is anchored to a unit — SEC-007 points at a .java file — but a
      // `unitPath` that is present must resolve, or the evidence cannot be followed up.
      const unitPath = finding.evidence.details?.unitPath;
      if (unitPath) {
        assert.ok(
          existsSync(join(FIXTURE_ROOT, unitPath)),
          `${finding.id} cites ${unitPath}, which does not exist`
        );
        assert.match(unitPath, /^mprcontents\/.*\.mxunit$/);
      }
    }
  });

  it('states what it saw and what to do for every finding', async () => {
    const summary = await fixtureEvaluation();
    for (const finding of summary.findings) {
      for (const field of ['observation', 'whyItMatters', 'expectedPractice', 'recommendation']) {
        assert.ok(finding[field]?.length > 20, `${finding.id}.${field} is empty or a stub`);
      }
      assert.ok(['High', 'Medium', 'Low'].includes(finding.confidence));
    }
  });
});
