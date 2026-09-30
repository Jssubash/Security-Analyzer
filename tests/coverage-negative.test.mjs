/**
 * `docs/security.md` §8 test 5 — a project whose security model cannot be read.
 *
 * This is the §2.1 defect written as a test. The reference project is copied with its single
 * `Security$ProjectSecurity` unit removed and re-analyzed. Everything else about the project is
 * unchanged, so the only thing that can move is what the analyzer is willing to claim.
 *
 * Before the scoring correction this run reported Security 100 and overall 100, against 65 and 79
 * for the same project with its security model intact: deleting one file turned a failing
 * assessment into a perfect one, because the rules that were failing could no longer run. The
 * assertions below are what make that outcome impossible rather than merely unlikely.
 */

import assert from 'node:assert/strict';
import { cpSync, copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { after, before, it } from 'node:test';

import { getDefaultRules } from '@mendix-analyzer/rules';

import {
  FIXTURE_MPR,
  FIXTURE_ROOT,
  describeFixture,
  fixtureEvaluation,
  fixtureIr,
} from './helpers/fixture.mjs';

describeFixture('a project with no Security$ProjectSecurity unit', () => {
  let workspace;
  let degraded;

  before(async () => {
    const { ModelGraph } = await import('@mendix-analyzer/mendix-parser');
    const { parseExtractedProject } = await import('@mendix-analyzer/mendix-parser');
    const { RuleEngine, RuleRegistry } = await import('@mendix-analyzer/rule-engine');
    const { ScoringEngine } = await import('@mendix-analyzer/scoring');

    // The unit's path is looked up rather than hardcoded: a hardcoded GUID that stopped
    // matching would leave this test passing against an untouched project.
    const graph = ModelGraph.build(FIXTURE_ROOT, FIXTURE_MPR);
    const [securityUnit] = graph.units.refsOfType('Security$ProjectSecurity');
    assert.ok(securityUnit, 'the reference project must have the unit this test removes');
    const removed = basename(securityUnit.unitPath);

    workspace = mkdtempSync(join(tmpdir(), 'mx-no-security-'));
    cpSync(join(FIXTURE_ROOT, 'mprcontents'), join(workspace, 'mprcontents'), {
      recursive: true,
      filter: (src) => basename(src) !== removed,
    });
    copyFileSync(FIXTURE_MPR, join(workspace, basename(FIXTURE_MPR)));

    const ir = parseExtractedProject(workspace, join(workspace, basename(FIXTURE_MPR)));
    const registry = new RuleRegistry();
    for (const rule of getDefaultRules()) registry.register(rule);
    const summary = new RuleEngine(registry).evaluate(ir);
    degraded = { ir, summary, score: new ScoringEngine().calculateScores(summary, ir.coverage) };
  });

  after(() => {
    if (workspace) rmSync(workspace, { recursive: true, force: true });
  });

  it('reports the fact as unreadable and says so in the notes', () => {
    assert.equal(degraded.ir.coverage.projectSecurity, 'NOT_ANALYZABLE');
    assert.ok(
      degraded.ir.coverage.notes.some((n) => n.includes('Security$ProjectSecurity')),
      'the missing unit must be named in the coverage notes'
    );
    // The facts that are still readable must still be reported as readable — a blanket
    // NOT_ANALYZABLE would hide which part of the model was lost.
    assert.equal(degraded.ir.coverage.moduleRoles, 'ANALYZED');
    assert.equal(degraded.ir.coverage.entityAccessRules, 'ANALYZED');
    assert.equal(degraded.ir.coverage.pageAccess, 'ANALYZED');
  });

  it('invents no security model to stand in for the one it could not read', () => {
    assert.deepEqual(degraded.ir.security.userRoles, []);
    assert.deepEqual(degraded.ir.security.demoUsers, []);
    assert.equal(degraded.ir.security.administrator, undefined);
    assert.equal(degraded.ir.security.anonymousUserEnabled, false);
    // The placeholder level is the *least* permissive reading, so no rule can conclude the
    // project is more secure than it is.
    assert.equal(degraded.ir.security.projectSecurityLevel, 'CheckNothing');
    assert.equal(degraded.ir.security.isProductionReady, false);
  });

  it('passes no rule that reads project security', () => {
    // Disabled rules are never handed to the engine, so they are neither skipped nor reported;
    // including them here would assert something about a code path that does not run.
    const dependsOnProjectSecurity = getDefaultRules()
      .filter((r) => r.enabled && r.requires.includes('projectSecurity'))
      .map((r) => r.id);
    assert.ok(dependsOnProjectSecurity.length >= 14, 'most SEC rules read project security');

    const skipped = new Set(degraded.summary.skippedRules.map((r) => r.ruleId));
    const notSkipped = dependsOnProjectSecurity.filter((id) => !skipped.has(id));
    assert.deepEqual(notSkipped, [], 'a rule that reads an unreadable fact must not be evaluated');

    // And none of them produced a finding either way: no pass, no fail.
    const reported = new Set(degraded.summary.findings.map((f) => f.ruleId));
    for (const id of dependsOnProjectSecurity) {
      assert.ok(!reported.has(id), `${id} reported a result from a model it could not read`);
    }
  });

  it('suppresses the Security score rather than computing it from the survivors', () => {
    assert.equal(degraded.score.categoryScores.Security, undefined);
    const security = degraded.score.unassessedCategories.find((c) => c.category === 'Security');
    assert.ok(security, 'Security must be listed as unassessed');
    assert.match(security.reason, /projectSecurity/);
  });

  it('reports no compliance figure, so the gap cannot read as an improvement', async () => {
    const full = await fullRunScore();
    assert.equal(degraded.score.categoryScores.Compliance, undefined);
    assert.ok(
      degraded.score.unassessedCategories.some((c) => c.category === 'Compliance'),
      'Compliance must be listed as unassessed'
    );
    // The number this replaces was 90 against the full run's 64.
    assert.ok(full.categoryScores.Compliance < 90);
    assert.equal(degraded.score.assessmentIsIncomplete, true);
    assert.equal(full.assessmentIsIncomplete, false);
  });

  it('reports lower coverage than the same project with its security model intact', async () => {
    const full = await fullRunScore();
    assert.ok(
      degraded.score.coveragePercentage < full.coveragePercentage,
      `coverage ${degraded.score.coveragePercentage}% must be below the full run's ${full.coveragePercentage}%`
    );
    assert.ok(degraded.summary.totalNotApplicable > full.notApplicableCount);
  });

  it('carries the reason all the way to the score report', () => {
    assert.ok(
      degraded.score.coverageNotes.some((n) => n.includes('Security$ProjectSecurity')),
      'the score report must carry the coverage notes, not just the IR'
    );
  });
});

/** The reference project's score, for the comparisons this file's assertions rest on. */
async function fullRunScore() {
  const { ScoringEngine } = await import('@mendix-analyzer/scoring');
  const ir = await fixtureIr();
  return new ScoringEngine().calculateScores(await fixtureEvaluation(), ir.coverage);
}
