/**
 * The Java libraries tab: which jars are Marketplace and which are custom, why, and what an OSV
 * answer means for each of them.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import {
  applyOsvResult,
  buildJavaLibraryReport,
  compareVersions,
  cvss3BaseScore,
  packagesToCheck,
  parseFileName,
  remediation,
  severityOf,
  duplicateAdvice,
  libraryName,
} from '../dist/analyzer.cjs';

const settings = (deps) => ({
  $Type: 'Projects$ModuleSettings',
  jarDependencies: deps.map(([groupId, artifactId, version, isIncluded = true]) => ({
    $Type: 'Projects$JarDependency',
    groupId,
    artifactId,
    version,
    isIncluded,
  })),
});

const pom = (groupId, artifactId, version) => ({ groupId, artifactId, version, path: `META-INF/maven/${groupId}/${artifactId}/pom.properties` });
const ref = (g, a, v) => `pkg:maven/${g}/${a}@${v}?type=jar`;

function snapshot() {
  return {
    schemaVersion: 1,
    source: 'studio-pro',
    app: { name: 'Shop' },
    projectUnits: [],
    javaSources: [],
    notes: [],
    capturedAt: '2026-01-01T00:00:00Z',
    modules: [
      // Storage spelling for one module, metamodel spelling for the other: both must be read.
      { name: 'CommunityCommons', fromAppStore: true, units: [settings([['com.google.guava', 'guava', '33.0.0-jre']])] },
      {
        name: 'Shop',
        fromAppStore: false,
        units: [
          {
            $Type: 'Projects$ModuleSettings',
            JarDependencies: [
              { $Type: 'Projects$JarDependency', GroupId: 'org.apache.commons', ArtifactId: 'commons-text', Version: '1.9', IsIncluded: true },
              { $Type: 'Projects$JarDependency', GroupId: 'org.excluded', ArtifactId: 'gone', Version: '1', IsIncluded: false },
            ],
          },
        ],
      },
    ],
    javaLibraries: {
      scanned: true,
      jars: [
        { folder: 'vendorlib', fileName: 'guava-33.0.0-jre.jar', sizeBytes: 3000000, sha256: 'aa' },
        { folder: 'vendorlib', fileName: 'failureaccess-1.0.2.jar', sizeBytes: 4000 },
        { folder: 'vendorlib', fileName: 'commons-text-1.9.jar', sizeBytes: 200000 },
        { folder: 'vendorlib', fileName: 'commons-lang3-3.11.jar', sizeBytes: 500000 },
        // Hand-placed, with its pom; and a fat jar that shades log4j.
        { folder: 'userlib', fileName: 'mylib-2.0.jar', sizeBytes: 1000, pomProperties: [pom('com.acme', 'mylib', '2.0')] },
        {
          folder: 'userlib',
          fileName: 'reporting-all-1.4.jar',
          sizeBytes: 9000000,
          pomProperties: [pom('com.acme', 'reporting-all', '1.4'), pom('org.apache.logging.log4j', 'log4j-core', '2.14.1')],
        },
        // Claimed by a module that is gone, and a second version of commons-lang3.
        { folder: 'userlib', fileName: 'commons-lang3-3.1.jar', sizeBytes: 300000, pomProperties: [pom('org.apache.commons', 'commons-lang3', '3.1')] },
        // No metadata at all.
        { folder: 'userlib', fileName: 'legacy.jar', sizeBytes: 10 },
      ],
      requiredLibMarkers: [{ jarFileName: 'commons-lang3-3.1.jar', module: 'OldModule' }],
      sbom: {
        components: [
          { ref: ref('com.google.guava', 'guava', '33.0.0-jre'), group: 'com.google.guava', name: 'guava', version: '33.0.0-jre', sha256: 'aa' },
          { ref: ref('com.google.guava', 'failureaccess', '1.0.2'), group: 'com.google.guava', name: 'failureaccess', version: '1.0.2' },
          { ref: ref('org.apache.commons', 'commons-text', '1.9'), group: 'org.apache.commons', name: 'commons-text', version: '1.9' },
          { ref: ref('org.apache.commons', 'commons-lang3', '3.11'), group: 'org.apache.commons', name: 'commons-lang3', version: '3.11' },
        ],
        dependencies: [
          { ref: ref('com.google.guava', 'guava', '33.0.0-jre'), dependsOn: [ref('com.google.guava', 'failureaccess', '1.0.2')] },
          { ref: ref('org.apache.commons', 'commons-text', '1.9'), dependsOn: [ref('org.apache.commons', 'commons-lang3', '3.11')] },
        ],
      },
    },
  };
}

const types = { CommunityCommons: 'marketplace', Shop: 'user', System: 'system' };
const byFile = (report) => Object.fromEntries(report.libraries.map((l) => [l.fileName, l]));

describe('which jars are Marketplace and which are custom', () => {
  const libs = byFile(buildJavaLibraryReport(snapshot(), types));

  test('a library a Marketplace module declares, and what it pulls in, are Marketplace', () => {
    assert.equal(libs['guava-33.0.0-jre.jar'].origin, 'marketplace');
    assert.deepEqual(libs['guava-33.0.0-jre.jar'].requiredBy, [
      { module: 'CommunityCommons', moduleType: 'marketplace', direct: true, via: undefined, settingsUnitId: undefined, declaredVersion: '33.0.0-jre', exclusions: [] },
    ]);
    const transitive = libs['failureaccess-1.0.2.jar'];
    assert.equal(transitive.origin, 'marketplace');
    assert.equal(transitive.requiredBy[0].via, 'com.google.guava:guava');
    assert.match(transitive.originReason, /Pulled in for Marketplace module CommunityCommons/);
  });

  test("a library the team's module declares is custom, and so is its dependency", () => {
    assert.equal(libs['commons-text-1.9.jar'].origin, 'custom');
    assert.match(libs['commons-text-1.9.jar'].originReason, /Declared by your module Shop/);
    assert.equal(libs['commons-lang3-3.11.jar'].origin, 'custom');
    assert.match(libs['commons-lang3-3.11.jar'].originReason, /A dependency of org.apache.commons:commons-text/);
  });

  test('a userlib jar no module claims is custom, added by hand', () => {
    assert.equal(libs['mylib-2.0.jar'].origin, 'custom');
    assert.match(libs['mylib-2.0.jar'].originReason, /by hand/);
    assert.deepEqual(libs['mylib-2.0.jar'].coordinates, { group: 'com.acme', artifact: 'mylib', version: '2.0' });
    assert.equal(libs['mylib-2.0.jar'].identifiedBy, 'pom');
  });

  test('a jar claimed by a module that is no longer in the app is called out as left behind', () => {
    const lib = libs['commons-lang3-3.1.jar'];
    assert.equal(lib.origin, 'custom');
    assert.equal(lib.requiredBy[0].moduleType, 'missing');
    assert.match(lib.originReason, /OldModule, which is no longer in the app/);
  });

  test('two versions of one library are a duplicate, on both copies', () => {
    assert.deepEqual(libs['commons-lang3-3.1.jar'].otherVersions, ['3.11']);
    assert.deepEqual(libs['commons-lang3-3.11.jar'].otherVersions, ['3.1']);
    assert.equal(libs['commons-lang3-3.1.jar'].duplicateOf, 'commons-lang3');
    assert.equal(libs['mylib-2.0.jar'].duplicateOf, undefined);
  });

  test('libraries shaded inside a jar are listed, and the jar keeps its own identity', () => {
    const fat = libs['reporting-all-1.4.jar'];
    assert.equal(fat.coordinates.artifact, 'reporting-all');
    assert.deepEqual(fat.bundled, [{ group: 'org.apache.logging.log4j', artifact: 'log4j-core', version: '2.14.1' }]);
  });

  test('vendorlib jars are identified from the SBOM, by hash first', () => {
    assert.equal(libs['guava-33.0.0-jre.jar'].identifiedBy, 'sbom');
    assert.equal(libs['legacy.jar'].identifiedBy, 'file name');
    assert.equal(libs['legacy.jar'].coordinates.group, undefined);
  });

  test('an excluded declaration does not claim anything', () => {
    const report = buildJavaLibraryReport(snapshot(), types);
    assert.ok(!report.notes.some((n) => n.includes('org.excluded')));
  });

  test('without the extension inventory the tab says so instead of showing an empty list', () => {
    const s = snapshot();
    delete s.javaLibraries;
    const report = buildJavaLibraryReport(s, types);
    assert.equal(report.scanned, false);
    assert.match(report.notes[0], /older version of the extension/);
  });
});

describe('the vulnerability check', () => {
  const report = buildJavaLibraryReport(snapshot(), types);

  test('asks about every library with coordinates, including shaded ones, once each', () => {
    const names = packagesToCheck(report).map((p) => `${p.name}@${p.version}`);
    assert.ok(names.includes('org.apache.logging.log4j:log4j-core@2.14.1'));
    assert.ok(names.includes('com.acme:mylib@2.0'));
    assert.ok(!names.some((n) => n.includes('legacy')));
    assert.equal(new Set(names).size, names.length);
  });

  const osv = {
    source: 'OSV.dev',
    checkedAt: '2026-10-01T10:00:00Z',
    results: packagesToCheck(report).map((p) => ({
      ...p,
      ids:
        p.name === 'org.apache.commons:commons-text' ? ['GHSA-599f-7c49-w659'] : p.name === 'org.apache.logging.log4j:log4j-core' ? ['GHSA-jfh8-c2jp-5v3q'] : [],
    })),
    vulns: {
      'GHSA-599f-7c49-w659': {
        id: 'GHSA-599f-7c49-w659',
        summary: 'Arbitrary code execution in Apache Commons Text',
        aliases: ['CVE-2022-42889'],
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
        databaseSeverity: 'CRITICAL',
        affected: [{ package: { ecosystem: 'Maven', name: 'org.apache.commons:commons-text' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.5' }, { fixed: '1.10.0' }] }] }],
      },
      'GHSA-jfh8-c2jp-5v3q': {
        id: 'GHSA-jfh8-c2jp-5v3q',
        summary: 'Remote code injection in Log4j',
        aliases: ['CVE-2021-44228'],
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' }],
        affected: [
          {
            package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' },
            ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.13.0' }, { fixed: '2.15.0' }, { introduced: '2.0-beta9' }, { fixed: '2.12.2' }] }],
          },
        ],
      },
    },
  };

  test('maps advisories to the library, with severity, score, CVE and the first fixed release above the version in use', () => {
    const vr = applyOsvResult(report, osv);
    const [text] = vr.byLibrary['vendorlib/commons-text-1.9.jar'];
    assert.equal(text.severity, 'Critical');
    assert.equal(text.score, 9.8);
    assert.deepEqual(text.cves, ['CVE-2022-42889']);
    assert.equal(text.fixedIn, '1.10.0');
    assert.equal(text.bundled, false);

    const [shaded] = vr.byLibrary['userlib/reporting-all-1.4.jar'];
    assert.equal(shaded.id, 'GHSA-jfh8-c2jp-5v3q');
    assert.equal(shaded.bundled, true);
    assert.equal(shaded.score, 10);
    assert.equal(shaded.severity, 'Critical', 'derived from the CVSS score when the database gives no severity');
    assert.equal(shaded.fixedIn, '2.15.0', 'not 2.12.2, which is older than the version in use');

    assert.deepEqual(vr.byLibrary['vendorlib/guava-33.0.0-jre.jar'], []);
    assert.ok(vr.unchecked.includes('userlib/legacy.jar'));
  });

  test('a library added after the check is unchecked, not clean', () => {
    const later = buildJavaLibraryReport(snapshot(), types);
    later.libraries.push({ ...later.libraries.find((l) => l.fileName === 'mylib-2.0.jar'), key: 'userlib/new-1.0.jar', fileName: 'new-1.0.jar', coordinates: { group: 'com.acme', artifact: 'new', version: '1.0' } });
    const vr = applyOsvResult(later, osv);
    assert.equal(vr.byLibrary['userlib/new-1.0.jar'], undefined);
    assert.ok(vr.unchecked.includes('userlib/new-1.0.jar'));
  });

  test('the advice depends on who owns the library', () => {
    const vr = applyOsvResult(report, osv);
    const libs = byFile(report);
    const text = vr.byLibrary['vendorlib/commons-text-1.9.jar'][0];
    assert.match(remediation(libs['commons-text-1.9.jar'], text), /Shop ▸ Settings ▸ Java Dependencies, raise org.apache.commons:commons-text to 1.10.0/);
    const shaded = vr.byLibrary['userlib/reporting-all-1.4.jar'][0];
    assert.match(remediation(libs['reporting-all-1.4.jar'], shaded), /bundled inside reporting-all-1.4.jar/);
    const market = { ...libs['guava-33.0.0-jre.jar'] };
    assert.match(remediation(market, { ...text, package: 'com.google.guava:guava', version: '33.0.0-jre', bundled: false }), /Update CommunityCommons from the Marketplace/);
  });
});

describe('helpers', () => {
  test('CVSS v3 base scores match the specification examples', () => {
    assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
    assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
    assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'), 5.9);
    assert.equal(cvss3BaseScore('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N'), 0);
    assert.equal(cvss3BaseScore('not a vector'), undefined);
  });

  test('severity prefers the database rating and falls back to the score', () => {
    assert.equal(severityOf('MODERATE', 9.8), 'Medium');
    assert.equal(severityOf(undefined, 7.5), 'High');
    assert.equal(severityOf(undefined, undefined), 'Unknown');
  });

  test('versions order the Maven way', () => {
    assert.ok(compareVersions('1.10.0', '1.9') > 0);
    assert.ok(compareVersions('2.0-rc1', '2.0') < 0);
    assert.equal(compareVersions('1.0', '1.0.0'), 0);
    assert.ok(compareVersions('33.5.0-jre', '33.0.0-jre') > 0);
  });

  test('file names split into artifact and version', () => {
    assert.deepEqual(parseFileName('commons-text-1.10.0.jar'), { artifact: 'commons-text', version: '1.10.0' });
    assert.deepEqual(parseFileName('guava-33.5.0-jre.jar'), { artifact: 'guava', version: '33.5.0-jre' });
    assert.deepEqual(parseFileName('legacy.jar'), { artifact: 'legacy' });
  });
});

describe('duplicate libraries', () => {
  const jar = (folder, fileName, pomProperties) => ({ folder, fileName, sizeBytes: 1, pomProperties });
  const withJars = (jars, markers = []) => {
    const s = snapshot();
    s.javaLibraries = { scanned: true, jars, requiredLibMarkers: markers };
    return buildJavaLibraryReport(s, types);
  };

  test('are matched by name, not version, even without any Maven metadata', () => {
    const report = withJars([jar('userlib', 'commons-io-2.3.4.jar'), jar('userlib', 'commons-io-3.4.5.jar'), jar('userlib', 'other-1.0.jar')]);
    assert.equal(report.duplicates.length, 1);
    const [d] = report.duplicates;
    assert.equal(d.name, 'commons-io');
    assert.equal(d.kind, 'versions');
    assert.deepEqual(d.versions, ['3.4.5', '2.3.4'], 'newest first');
    assert.equal(d.newest, '3.4.5');
    assert.deepEqual(d.libraries, ['userlib/commons-io-3.4.5.jar', 'userlib/commons-io-2.3.4.jar']);
    assert.match(duplicateAdvice(d, report.libraries), /Decide which version the app uses — the newest present is 3.4.5/);
  });

  test('span userlib and vendorlib, and file-name spelling differences', () => {
    const report = withJars([jar('userlib', 'Commons_IO_2.3.4.jar'), jar('vendorlib', 'commons-io-2.11.0.jar', [pom('commons-io', 'commons-io', '2.11.0')])]);
    assert.equal(report.duplicates.length, 1);
    assert.equal(report.duplicates[0].libraries.length, 2);
    assert.equal(libraryName({ fileName: 'Commons_IO 2.3.4.jar' }), 'commons-io');
  });

  test('the same version twice is reported as copies', () => {
    const report = withJars([jar('userlib', 'guava-33.0.0-jre.jar'), jar('vendorlib', 'guava-33.0.0-jre.jar')]);
    const [d] = report.duplicates;
    assert.equal(d.kind, 'copies');
    assert.match(duplicateAdvice(d, report.libraries), /same version is present 2 times/);
  });

  test('different publishers are flagged rather than silently merged', () => {
    const report = withJars([
      jar('userlib', 'mail-1.4.jar', [pom('javax.mail', 'mail', '1.4')]),
      jar('userlib', 'mail-1.6.2.jar', [pom('com.sun.mail', 'mail', '1.6.2')]),
    ]);
    const [d] = report.duplicates;
    assert.deepEqual(d.groups, ['com.sun.mail', 'javax.mail']);
    assert.match(duplicateAdvice(d, report.libraries), /different publishers/);
  });

  test('when a Marketplace module owns one copy, the advice is to remove the custom one', () => {
    const report = withJars(
      [jar('userlib', 'commons-io-2.3.4.jar'), jar('userlib', 'commons-io-2.11.0.jar')],
      [{ jarFileName: 'commons-io-2.11.0.jar', module: 'CommunityCommons' }]
    );
    const [d] = report.duplicates;
    assert.deepEqual(d.marketplaceCopies, ['userlib/commons-io-2.11.0.jar']);
    assert.match(duplicateAdvice(d, report.libraries), /remove the custom copy \(userlib\/commons-io-2.3.4.jar\)/);
  });

  test('a clean app has none', () => {
    assert.deepEqual(withJars([jar('userlib', 'a-1.jar'), jar('userlib', 'b-1.jar')]).duplicates, []);
  });
});
