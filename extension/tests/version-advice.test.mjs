/**
 * How to resolve: which release a vulnerable Java library should move to, and the steps to get there.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import {
  appJavaVersion,
  candidateVersions,
  chooseVersion,
  isStableRelease,
  javaOfClassMajor,
  resolutionPlan,
  splitVersion,
  upgradeTargets,
} from '../dist/analyzer.cjs';

const JAVA_8 = 52;
const JAVA_21 = 65;
const JAVA_22 = 66;

function lib(overrides = {}) {
  return {
    key: 'vendorlib/jsoup-1.23.1.jar',
    folder: 'vendorlib',
    fileName: 'jsoup-1.23.1.jar',
    sizeBytes: 1,
    coordinates: { group: 'org.jsoup', artifact: 'jsoup', version: '1.23.1' },
    identifiedBy: 'sbom',
    bundled: [],
    requiredBy: [
      { module: 'SAML20', moduleType: 'marketplace', direct: true, settingsUnitId: 'settings-1', declaredVersion: '1.23.1', exclusions: [] },
    ],
    origin: 'marketplace',
    originReason: 'Required by Marketplace module SAML20.',
    otherVersions: [],
    ...overrides,
  };
}

function vuln(overrides = {}) {
  return { id: 'GHSA-1', cves: [], summary: 's', severity: 'High', package: 'org.jsoup:jsoup', version: '1.23.1', bundled: false, fixedIn: '1.23.2', cwes: [], ...overrides };
}

const velocity = lib({
  key: 'vendorlib/velocity-engine-core-2.3.jar',
  fileName: 'velocity-engine-core-2.3.jar',
  coordinates: { group: 'org.apache.velocity', artifact: 'velocity-engine-core', version: '2.3' },
  bundled: [{ group: 'commons-io', artifact: 'commons-io', version: '2.8.0' }],
  requiredBy: [
    {
      module: 'SAML20',
      moduleType: 'marketplace',
      direct: true,
      settingsUnitId: 'settings-1',
      declaredVersion: '2.3',
      exclusions: ['org.apache.commons:commons-lang3', 'org.slf4j:slf4j-api'],
    },
  ],
});
const bundledVuln = vuln({ id: 'GHSA-io', package: 'commons-io:commons-io', version: '2.8.0', bundled: true, fixedIn: '2.14.0' });

describe('versions', () => {
  test('stable releases and their flavour', () => {
    assert.ok(isStableRelease('1.23.1'));
    assert.ok(isStableRelease('33.0.0-jre'));
    for (const v of ['2.0.0-M1', '1.0-rc1', '2.4-beta', '1.0-alpha-2', '3.0.0-SNAPSHOT', '5.0.0.CR1']) assert.ok(!isStableRelease(v), v);
    assert.deepEqual(splitVersion('32.0.1-jre'), { numbers: [32, 0, 1], suffix: '-jre' });
  });

  test('candidates stay in the major version, at or above the fix, newest first', () => {
    const r = candidateVersions({ current: '1.23.1', minimum: '1.23.2' }, ['1.16.1', '1.23.1', '1.23.2', '1.23.3', '1.24.0-rc1', '2.0.0']);
    assert.deepEqual(r.candidates, ['1.23.3', '1.23.2']);
    assert.equal(r.newerMajor, '2.0.0');
  });

  test('candidates keep the flavour of the installed release', () => {
    const r = candidateVersions({ current: '32.0.1-jre' }, ['32.0.1-jre', '32.1.0-android', '32.1.3-jre', '33.1.0-jre']);
    assert.deepEqual(r.candidates, ['32.1.3-jre']);
    assert.equal(r.newerMajor, '33.1.0-jre');
  });

  test('the app Java version comes from its settings, else from Mendix 11, else unknown', () => {
    assert.equal(appJavaVersion('Java21', '10.24.0'), 21);
    assert.equal(appJavaVersion(undefined, '11.12.4'), 21);
    assert.equal(appJavaVersion(undefined, '10.24.0'), undefined);
    assert.equal(javaOfClassMajor(JAVA_8), 8);
  });
});

describe('choosing a version', () => {
  const target = { libKey: 'k', group: 'org.jsoup', artifact: 'jsoup', current: '1.23.1', minimum: '1.23.2', unfixed: [], bundled: [] };
  const jar = (classMajor, poms = []) => ({ classMajor, poms });

  test('passes over releases with their own advisories or a newer Java than the app', () => {
    const advice = chooseVersion(
      target,
      ['1.23.4', '1.23.3', '1.23.2'],
      { osv: { '1.23.4': ['GHSA-new'], '1.23.3': [], '1.23.2': [] }, jars: { '1.23.4': jar(JAVA_8), '1.23.3': jar(JAVA_22), '1.23.2': jar(JAVA_8) } },
      21
    );
    assert.equal(advice.suggested, '1.23.2');
    assert.equal(advice.suggestedJava, 8);
    assert.deepEqual(advice.rejected.map((r) => r.version), ['1.23.4', '1.23.3']);
    assert.match(advice.rejected[0].reason, /GHSA-new/);
    assert.match(advice.rejected[1].reason, /needs Java 22; this app runs Java 21/);
  });

  test('does not judge Java when the app version is unknown', () => {
    const advice = chooseVersion(target, ['1.23.3'], { osv: { '1.23.3': [] }, jars: { '1.23.3': jar(JAVA_22) } }, undefined);
    assert.equal(advice.suggested, '1.23.3');
  });

  test('a release that still bundles the vulnerable library is passed over', () => {
    const t = { ...target, group: 'org.apache.velocity', artifact: 'velocity-engine-core', current: '2.3', minimum: undefined, bundled: [{ group: 'commons-io', artifact: 'commons-io', version: '2.8.0', minimum: '2.14.0' }] };
    const advice = chooseVersion(
      t,
      ['2.4.1', '2.4'],
      {
        osv: { '2.4.1': [], '2.4': [] },
        jars: {
          '2.4.1': jar(JAVA_8, [{ group: 'commons-io', artifact: 'commons-io', version: '2.8.0' }]),
          '2.4': jar(JAVA_8, [{ group: 'org.apache.velocity', artifact: 'velocity-engine-core', version: '2.4' }]),
        },
      },
      21
    );
    assert.equal(advice.suggested, '2.4');
    assert.match(advice.rejected[0].reason, /still bundles commons-io 2.8.0/);
  });

  test('says why when nothing qualifies', () => {
    const advice = chooseVersion(target, [], { osv: {}, jars: {} }, 21, '2.0.0');
    assert.equal(advice.suggested, undefined);
    assert.match(advice.note, /no newer stable jsoup 1.x release at or above 1.23.2/);
    assert.equal(advice.newerMajor, '2.0.0');
  });

  test('targets come from open advisories, with bundled ones kept apart', () => {
    const targets = upgradeTargets([lib(), velocity], { byLibrary: { [lib().key]: [vuln()], [velocity.key]: [bundledVuln] } });
    assert.deepEqual(targets.map((t) => [t.artifact, t.minimum, t.bundled.map((b) => b.minimum)]), [
      ['jsoup', '1.23.2', []],
      ['velocity-engine-core', undefined, ['2.14.0']],
    ]);
  });
});

describe('steps', () => {
  test('vendorlib: edit the declaring module row, keep exclusions, test the module, mind Marketplace updates', () => {
    const plan = resolutionPlan(velocity, [bundledVuln], { suggested: '2.4.1', rejected: [] });
    const text = plan.steps.join('\n');
    assert.match(text, /Open SAML20 ▸ Settings ▸ Java Dependencies/);
    assert.match(text, /org\.apache\.velocity:velocity-engine-core 2\.3, click Edit, set Version to 2\.4\.1/);
    assert.match(text, /2 exclusions \(org\.apache\.commons:commons-lang3, org\.slf4j:slf4j-api\)/);
    assert.match(text, /velocity-engine-core-2\.4\.1\.jar/);
    assert.match(text, /Test the features that use SAML20/);
    assert.match(plan.notes.join('\n'), /updating SAML20 from the Marketplace later puts back/);
    assert.deepEqual(plan.openSettings, [{ module: 'SAML20', unitId: 'settings-1' }]);
  });

  test('without a suggestion the advisories minimum is used, but never for a bundled-only problem', () => {
    assert.equal(resolutionPlan(lib(), [vuln()], undefined, '1.23.2').versionText, '1.23.2 or later');
    const bundledOnly = resolutionPlan(velocity, [bundledVuln], undefined, '2.14.0');
    assert.match(bundledOnly.versionText, /a newer release that bundles commons-io 2\.14\.0 or later/);
    assert.equal(bundledOnly.maven.version, undefined);
  });

  test('a library pulled in by another one is declared directly', () => {
    const transitive = lib({ requiredBy: [{ module: 'MyModule', moduleType: 'user', direct: false, via: 'com.acme:client', settingsUnitId: 's2' }] });
    const text = resolutionPlan(transitive, [vuln()], { suggested: '1.23.3', rejected: [] }).steps.join('\n');
    assert.match(text, /comes in through com\.acme:client/);
    assert.match(text, /Click New and add Group ID org\.jsoup, Artifact ID jsoup, Version 1\.23\.3/);
  });

  test('userlib: replace the jar by hand and rename its marker', () => {
    const userlib = lib({ key: 'userlib/jsoup-1.23.1.jar', folder: 'userlib', requiredBy: [{ module: 'MyModule', moduleType: 'user', direct: true }] });
    const plan = resolutionPlan(userlib, [vuln()], { suggested: '1.23.3', rejected: [] });
    const text = plan.steps.join('\n');
    assert.match(text, /Download jsoup-1\.23\.3\.jar from Maven Central/);
    assert.match(text, /delete userlib\\jsoup-1\.23\.1\.jar/);
    assert.match(text, /jsoup-1\.23\.1\.jar\.MyModule\.RequiredLib to jsoup-1\.23\.3\.jar\.MyModule\.RequiredLib/);
    assert.deepEqual(plan.maven, { group: 'org.jsoup', artifact: 'jsoup', version: '1.23.3' });
    assert.deepEqual(plan.openSettings, []);
  });

  test('no fixed release: no steps, a pointer to Accept risk', () => {
    const plan = resolutionPlan(lib(), [vuln({ fixedIn: undefined })], { rejected: [] });
    assert.deepEqual(plan.steps, []);
    assert.match(plan.notes[0], /Accept risk/);
  });
});
