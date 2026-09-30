/**
 * Shared fixture access for the Phase 1 test suite.
 *
 * TestApp's `mprcontents` is ~4 MB across 397 units and is deliberately *not* committed; it is
 * referenced from `scratch/` instead. Every test that needs it therefore has to survive its
 * absence, which is what `describeFixture` is for: on a checkout without the fixture the suite
 * skips those tests and still runs everything that does not need a real model.
 *
 * Skipping is visible in the test output on purpose. A fixture-dependent test that silently
 * passed when the fixture was missing would be the same defect this analyzer exists to find:
 * "could not look" reported as "looked and found nothing".
 */

import { existsSync } from 'node:fs';
import { describe } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = resolve(here, '..', '..');
/**
 * The reference project (an unpacked Mendix app with `mprcontents`). Not committed: set
 * MENDIX_TEST_FIXTURE to its folder, or place it at fixtures/TestApp-main.
 */
export const FIXTURE_ROOT = process.env.MENDIX_TEST_FIXTURE ?? join(REPO_ROOT, 'fixtures', 'TestApp-main');
export const FIXTURE_MPR = join(FIXTURE_ROOT, 'TestApp.mpr');

export const fixtureAvailable = existsSync(FIXTURE_MPR);

/** `describe`, but skipped with a stated reason when the reference project is not present. */
export function describeFixture(name, fn) {
  return describe(
    name,
    {
      skip: fixtureAvailable
        ? false
        : `reference project not found at ${FIXTURE_MPR} — see docs/security.md §8`,
    },
    fn
  );
}

let cachedIr;

/** The IR for the reference project, built once for the whole suite. */
export async function fixtureIr() {
  if (!cachedIr) {
    const { parseExtractedProject } = await import('@mendix-analyzer/mendix-parser');
    cachedIr = parseExtractedProject(FIXTURE_ROOT, FIXTURE_MPR);
  }
  return cachedIr;
}

let cachedSummary;

/** The rule-engine result for the reference project, evaluated once for the whole suite. */
export async function fixtureEvaluation() {
  if (!cachedSummary) {
    const { RuleEngine, RuleRegistry } = await import('@mendix-analyzer/rule-engine');
    const { getDefaultRules } = await import('@mendix-analyzer/rules');
    const registry = new RuleRegistry();
    for (const rule of getDefaultRules()) registry.register(rule);
    cachedSummary = new RuleEngine(registry).evaluate(await fixtureIr());
  }
  return cachedSummary;
}

/** The ids of every rule that produced at least one FAIL or WARNING. */
export function firedRuleIds(summary) {
  return new Set(
    summary.findings
      .filter((f) => f.status === 'FAIL' || f.status === 'WARNING')
      .map((f) => f.ruleId)
  );
}

/** Findings for one rule, in id order so a comparison is stable. */
export function findingsOf(summary, ruleId) {
  return summary.findings
    .filter((f) => f.ruleId === ruleId)
    .sort((a, b) => a.id.localeCompare(b.id));
}
