/**
 * Accepted-risk decisions: a reviewed advisory stops counting until its review date, for exactly
 * the library version it was made for, and counts again when the date passes.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { acceptedByText, addDays, riskKey, splitByAcceptance, staleRisks, today, validateRisk } from '../dist/analyzer.cjs';

const vuln = (id, pkg = 'lodash', version = '4.17.21') => ({ id, cves: [], summary: id, severity: 'High', package: pkg, version, bundled: true, cwes: [] });
const decision = (over = {}) => ({
  advisoryId: 'GHSA-r5fr-rjxr-66jc',
  scope: 'widget',
  target: 'com.mendix.widget.native.BarChart.mpk',
  package: 'lodash',
  version: '4.17.21',
  reason: 'Chart data comes from our own model; no attacker-controlled template input.',
  acceptedBy: 'dev',
  acceptedAt: '2026-10-05T10:00:00Z',
  reviewBy: '2027-01-03',
  ...over,
});

describe('which advisories still count', () => {
  const list = [vuln('GHSA-r5fr-rjxr-66jc'), vuln('GHSA-f23m-r3pf-42rh')];

  test('an accepted advisory moves aside; the others stay open', () => {
    const s = splitByAcceptance(list, [decision()], 'widget', 'com.mendix.widget.native.BarChart.mpk', '2026-10-05');
    assert.deepEqual(s.open.map((v) => v.id), ['GHSA-f23m-r3pf-42rh']);
    assert.deepEqual(s.accepted.map((a) => a.vulnerability.id), ['GHSA-r5fr-rjxr-66jc']);
    assert.equal(s.overdue.length, 0);
  });

  test('after the review date it counts again and is marked overdue', () => {
    const s = splitByAcceptance(list, [decision({ reviewBy: '2026-10-04' })], 'widget', 'com.mendix.widget.native.BarChart.mpk', '2026-10-05');
    assert.equal(s.open.length, 2);
    assert.deepEqual(s.overdue.map((a) => a.vulnerability.id), ['GHSA-r5fr-rjxr-66jc']);
  });

  test('the review date itself still counts as accepted', () => {
    const s = splitByAcceptance(list, [decision({ reviewBy: '2026-10-05' })], 'widget', 'com.mendix.widget.native.BarChart.mpk', '2026-10-05');
    assert.equal(s.accepted.length, 1);
  });

  test('a decision covers one library version, in one widget or library only', () => {
    const upgraded = [vuln('GHSA-r5fr-rjxr-66jc', 'lodash', '4.17.22')];
    assert.equal(splitByAcceptance(upgraded, [decision()], 'widget', 'com.mendix.widget.native.BarChart.mpk', '2026-10-05').open.length, 1);
    assert.equal(splitByAcceptance(list, [decision()], 'widget', 'com.mendix.widget.native.LineChart.mpk', '2026-10-05').open.length, 2);
    assert.equal(splitByAcceptance(list, [decision()], 'library', 'com.mendix.widget.native.BarChart.mpk', '2026-10-05').open.length, 2);
  });

  test('decisions that match nothing any more are found, so they can be cleaned up', () => {
    const live = new Set([riskKey(decision())]);
    assert.deepEqual(staleRisks([decision(), decision({ version: '4.17.20' })], live).map((r) => r.version), ['4.17.20']);
  });
});

describe('what a decision must contain', () => {
  const on = '2026-10-05';
  test('a reason long enough for a reviewer to judge', () => {
    assert.match(validateRisk(decision({ reason: 'ok' }), on), /at least 15 characters/);
    assert.equal(validateRisk(decision(), on), undefined);
  });
  test('a review date in the future, within a year', () => {
    assert.match(validateRisk(decision({ reviewBy: on }), on), /must be in the future/);
    assert.match(validateRisk(decision({ reviewBy: '2027-12-01' }), on), /within 365 days/);
    assert.match(validateRisk(decision({ reviewBy: 'soon' }), on), /review-by date/);
  });
  test('the advisory it is about', () => {
    assert.match(validateRisk(decision({ advisoryId: '' }), on), /not identified/);
  });
});

describe('dates', () => {
  test('calendar arithmetic across months and years', () => {
    assert.equal(addDays('2026-12-30', 3), '2027-01-02');
    assert.equal(addDays('2026-10-05', 90), '2027-01-03');
    assert.match(today(), /^\d{4}-\d{2}-\d{2}$/);
  });
});

describe('who accepted it', () => {
  test('a Git identity names the person, with their email and the Windows account as detail', () => {
    assert.deepEqual(
      acceptedByText({ acceptedBy: 'Subash JS', acceptedByEmail: 'subash.js@example.com', acceptedByAccount: 'mx', acceptedBySource: 'git' }),
      { who: 'Subash JS (subash.js@example.com)', detail: 'Windows account mx' }
    );
  });

  test('without a Git identity it says the name is a Windows account', () => {
    assert.deepEqual(acceptedByText({ acceptedBy: 'mx', acceptedByAccount: 'mx', acceptedBySource: 'windows' }), {
      who: 'mx (Windows account)',
      detail: 'no Git identity was set on that computer',
    });
  });

  test('a decision recorded before identities were used is shown as the Windows account it holds', () => {
    assert.deepEqual(acceptedByText({ acceptedBy: 'mx' }), { who: 'mx (Windows account)', detail: undefined });
    assert.deepEqual(acceptedByText({}), { who: 'unknown' });
  });
});
