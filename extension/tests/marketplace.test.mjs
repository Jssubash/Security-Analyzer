/**
 * The Upgrades tab: which Marketplace module and widget versions suit the app's Mendix version,
 * and the version the team is moving to.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { assessItem, assessWidget, buildUpgradeInventory, contentIdsToCheck, matchWidgets, normaliseMendixVersion } from '../dist/analyzer.cjs';

function snapshot(studioProVersion = '10.24.0.73019') {
  return {
    schemaVersion: 1,
    source: 'studio-pro',
    app: { name: 'Shop', studioProVersion },
    projectUnits: [],
    javaSources: [],
    notes: [],
    capturedAt: '2026-01-01T00:00:00Z',
    modules: [
      { name: 'Shop', fromAppStore: false, units: [] },
      { name: 'CommunityCommons', fromAppStore: true, appStorePackageId: 170, appStoreVersion: '9.0.1', units: [] },
      { name: 'DataWidgets', fromAppStore: true, appStorePackageId: 116540, appStoreVersion: '2.5.0', isThemeModule: true, units: [] },
      { name: 'NativeMobileResources', fromAppStore: true, appStorePackageId: 109513, appStoreVersion: '9.0.0', units: [] },
      { name: 'FileUploader', fromAppStore: true, appStorePackageId: 235351, appStoreVersion: '2.2.1', units: [] },
      { name: 'HandImported', fromAppStore: true, units: [] },
    ],
    widgets: {
      scanned: true,
      packages: [
        { fileName: 'com.mendix.widget.web.Datagrid.mpk', name: 'Datagrid', version: '2.5.0', widgets: [{ id: 'com.mendix.widget.web.datagrid.Datagrid', name: 'Data grid 2' }] },
        { fileName: 'com.mendix.widget.native.Maps.mpk', name: 'Maps', version: '5.1.1', widgets: [{ id: 'com.mendix.widget.native.maps.Maps', name: 'Maps', supportedPlatform: 'Native' }] },
        { fileName: 'com.mendix.widget.web.FileUploader.mpk', name: 'FileUploader', version: '2.2.1', widgets: [{ id: 'com.mendix.widget.web.fileuploader.FileUploader', name: 'File Uploader' }] },
        { fileName: 'Badge.mpk', name: 'Badge', version: '2.0.0', widgets: [{ id: 'com.mendix.widget.custom.badge.Badge', name: 'Badge' }] },
        { fileName: 'Maps.mpk', name: 'Maps', version: '3.0.0', widgets: [{ id: 'com.mendix.widget.custom.Maps.Maps', name: 'Maps' }] },
        { fileName: 'AcmeChart.mpk', name: 'AcmeChart', version: '1.0.0', widgets: [{ id: 'com.acme.AcmeChart', name: 'Acme chart' }] },
      ],
    },
  };
}

/** Community Commons: a 9.x line built for Mendix 9.24, a 10.x line for 10.x, an 11.x line for 11. */
const communityCommons = [
  { versionNumber: '9.0.1', minSupportedMendixVersion: '9.24.0' },
  { versionNumber: '9.2.0', minSupportedMendixVersion: '9.24.0' },
  { versionNumber: '10.0.0', minSupportedMendixVersion: '10.6.0' },
  { versionNumber: '10.1.3', minSupportedMendixVersion: '10.24.0' },
  { versionNumber: '11.0.0', minSupportedMendixVersion: '11.0.0' },
  { versionNumber: '11.5.1', minSupportedMendixVersion: '11.6.0' },
];

describe('inventory', () => {
  const inv = buildUpgradeInventory(snapshot());

  test("reads the app's Mendix version and every Marketplace module with its content id", () => {
    assert.equal(inv.mendixVersion, '10.24.0');
    assert.deepEqual(
      inv.modules.map((m) => [m.name, m.contentId, m.installedVersion]),
      [
        ['CommunityCommons', 170, '9.0.1'],
        ['DataWidgets', 116540, '2.5.0'],
        ['FileUploader', 235351, '2.2.1'],
        ['HandImported', undefined, undefined],
        ['NativeMobileResources', 109513, '9.0.0'],
      ]
    );
  });

  test('widgets that ship inside a module are attributed to it', () => {
    const w = Object.fromEntries(inv.widgets.map((x) => [x.fileName, x]));
    assert.equal(w['com.mendix.widget.web.Datagrid.mpk'].bundledWith, 'DataWidgets');
    assert.equal(w['com.mendix.widget.native.Maps.mpk'].bundledWith, 'NativeMobileResources');
    assert.equal(w['com.mendix.widget.web.FileUploader.mpk'].bundledWith, 'FileUploader', 'same name, same version as the module');
    assert.equal(w['Badge.mpk'].bundledWith, undefined);
    assert.deepEqual(w['com.mendix.widget.native.Maps.mpk'].platforms, ['Native']);
  });

  test('standalone widgets are matched to catalog widgets by name, preferring Mendix for Mendix widgets, never guessing', () => {
    const catalog = [
      { contentId: 50, name: 'Badge', type: 'Widget', publisher: 'Mendix' },
      { contentId: 51, name: 'Maps', type: 'Widget', publisher: 'Mendix' },
      { contentId: 52, name: 'Maps', type: 'Widget', publisher: 'Someone' },
      { contentId: 53, name: 'Badge', type: 'Module', publisher: 'Mendix' },
    ];
    const matches = matchWidgets(inv, catalog);
    assert.deepEqual(matches, { 'widget:Badge.mpk': 50, 'widget:Maps.mpk': 51 });
    assert.deepEqual(contentIdsToCheck(inv, matches), [50, 51, 170, 109513, 116540, 235351]);
  });
});

describe('the version to use for a target Mendix version', () => {
  const cc = buildUpgradeInventory(snapshot()).modules.find((m) => m.name === 'CommunityCommons');

  test('after upgrading to 10.24, a module still on its 9.x release is flagged and the 10.x release named', () => {
    const a = assessItem(cc, communityCommons, '10.24.0');
    assert.equal(a.status, 'update-recommended');
    assert.equal(a.recommended.versionNumber, '10.1.3');
    assert.match(a.note, /built for Mendix 9.24.0. For Mendix 10.24.0, move to 10.1.3/);
    assert.match(a.note, /11.5.1 is newer but needs Mendix 11.6.0/);
  });

  test('planning a move to 11.6 names the 11.x release', () => {
    assert.equal(assessItem(cc, communityCommons, '11.6.0').recommended.versionNumber, '11.5.1');
    assert.equal(assessItem(cc, communityCommons, '11.2.0').recommended.versionNumber, '11.0.0');
  });

  test('on the version it was built for, a newer release in the same line is an ordinary update', () => {
    const a = assessItem(cc, communityCommons, '9.24.5');
    assert.equal(a.status, 'update-available');
    assert.equal(a.recommended.versionNumber, '9.2.0');
  });

  test('the newest suitable release installed is up to date', () => {
    assert.equal(assessItem({ ...cc, installedVersion: '10.1.3' }, communityCommons, '10.24.0').status, 'up-to-date');
  });

  test('an installed release that needs a newer Mendix than the target is incompatible', () => {
    const a = assessItem({ ...cc, installedVersion: '11.5.1' }, communityCommons, '10.24.0');
    assert.equal(a.status, 'incompatible');
    assert.equal(a.recommended.versionNumber, '10.1.3');
    assert.match(a.note, /needs Mendix 11.6.0, newer than 10.24.0/);
  });

  test('a target older than every release has no compatible version', () => {
    assert.equal(assessItem(cc, communityCommons, '9.12.0').status, 'no-compatible');
  });

  test('a history that stops short of the installed version is reported as incomplete, not as no compatible version', () => {
    // What a single 20-item page looks like for Native Mobile Resources: only 11.x releases.
    const firstPageOnly = [
      { versionNumber: '12.5.0', minSupportedMendixVersion: '11.12.3' },
      { versionNumber: '11.3.7', minSupportedMendixVersion: '11.6.0' },
    ];
    const nmr = buildUpgradeInventory(snapshot()).modules.find((m) => m.name === 'NativeMobileResources');
    const a = assessItem({ ...nmr, installedVersion: '10.1.17' }, firstPageOnly, '10.24.0');
    assert.equal(a.status, 'not-checked');
    assert.match(a.note, /only part of the version history \(back to 11.3.7\), which does not reach the installed 10.1.17/);
  });

  test('without a content id or before the check, nothing is claimed', () => {
    const hand = buildUpgradeInventory(snapshot()).modules.find((m) => m.name === 'HandImported');
    assert.equal(assessItem(hand, undefined, '10.24.0').status, 'not-found');
    assert.equal(assessItem(cc, undefined, '10.24.0').status, 'not-checked');
  });

  test('a bundled widget follows its module', () => {
    const inv = buildUpgradeInventory(snapshot());
    const grid = inv.widgets.find((w) => w.bundledWith === 'DataWidgets');
    const owner = assessItem(inv.modules.find((m) => m.name === 'DataWidgets'), [
      { versionNumber: '2.5.0', minSupportedMendixVersion: '9.24.0' },
      { versionNumber: '3.11.6', minSupportedMendixVersion: '10.24.0' },
    ], '10.24.0');
    const a = assessWidget(grid, assessItem(grid, undefined, '10.24.0'), owner);
    assert.equal(a.status, 'update-recommended');
    assert.match(a.note, /Ships with the DataWidgets module and is updated with it/);
  });

  test('versions typed as 10.24 are read as 10.24.0', () => {
    assert.equal(normaliseMendixVersion('10.24'), '10.24.0');
  });
});

describe('widget vulnerabilities', async () => {
  const { applyWidgetOsv, widgetPackagesToCheck, widgetSecurityAdvice, assessItem: assess } = await import('../dist/analyzer.cjs');

  function inventory() {
    const s = snapshot();
    s.widgets.packages.find((p) => p.fileName === 'Badge.mpk').dependencies = [
      { name: 'dompurify', version: '3.2.4', transitive: false },
      { name: 'svgo', version: '2.8.0', transitive: true },
      { name: '@mendix/widget-plugin-platform', version: '0.2.0' },
    ];
    s.widgets.packages.find((p) => p.fileName === 'com.mendix.widget.web.Datagrid.mpk').dependencies = [{ name: 'mobx', version: '6.12.3' }];
    return buildUpgradeInventory(s);
  }
  const advisory = (id, pkg, fixed, severity = 'MODERATE') => ({
    id,
    summary: `${pkg} issue`,
    aliases: [`CVE-${id}`],
    databaseSeverity: severity,
    affected: [{ package: { ecosystem: 'npm', name: pkg }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed }] }] }],
  });
  const osv = {
    source: 'OSV.dev',
    checkedAt: '2026-10-05T10:00:00Z',
    results: [
      { name: 'dompurify', version: '3.2.4', ecosystem: 'npm', ids: ['GHSA-dp'] },
      { name: 'svgo', version: '2.8.0', ecosystem: 'npm', ids: ['GHSA-svgo'] },
      { name: 'mobx', version: '6.12.3', ecosystem: 'npm', ids: [] },
    ],
    vulns: { 'GHSA-dp': advisory('GHSA-dp', 'dompurify', '3.4.0'), 'GHSA-svgo': advisory('GHSA-svgo', 'svgo', '2.8.3', 'HIGH') },
  };

  test("looks up each bundled npm library once, leaving out Mendix's unpublished internal helpers", () => {
    const names = widgetPackagesToCheck(inventory()).map((p) => `${p.ecosystem}:${p.name}@${p.version}`);
    assert.deepEqual(names.sort(), ['npm:dompurify@3.2.4', 'npm:mobx@6.12.3', 'npm:svgo@2.8.0']);
  });

  test('counts only direct libraries; indirect ones (build tooling, for native widgets) are listed apart', () => {
    const wv = applyWidgetOsv(inventory(), osv);
    assert.deepEqual(wv.byWidget['widget:Badge.mpk'].map((v) => [v.id, v.package, v.fixedIn]), [['GHSA-dp', 'dompurify', '3.4.0']]);
    assert.deepEqual(wv.indirectByWidget['widget:Badge.mpk'].map((v) => v.id), ['GHSA-svgo']);
    assert.deepEqual(wv.byWidget['widget:com.mendix.widget.web.Datagrid.mpk'], [], 'checked and clean');
    assert.ok(wv.unchecked.includes('widget:AcmeChart.mpk'), 'no bundled-library list, nothing to look up');
  });

  test('suggests the newest release for the Mendix version, or says when only a newer Mendix has one', () => {
    const inv = inventory();
    const badge = inv.widgets.find((w) => w.fileName === 'Badge.mpk');
    const vulns = applyWidgetOsv(inv, osv).byWidget[badge.key];
    const history = [
      { versionNumber: '2.0.0', minSupportedMendixVersion: '9.24.0' },
      { versionNumber: '3.2.2', minSupportedMendixVersion: '10.24.0' },
      { versionNumber: '4.0.0', minSupportedMendixVersion: '11.6.0' },
    ];
    const withId = { ...badge, contentId: 50 };
    assert.match(
      widgetSecurityAdvice(badge, vulns, assess(withId, history, '10.24.0'), '10.24.0'),
      /Update Badge to 3.2.2, the newest release for Mendix 10.24.0, which may bundle a fixed copy of dompurify 3.2.4 \(fixed in 3.4.0\)/
    );
    const onNewest = { ...withId, installedVersion: '3.2.2' };
    assert.match(widgetSecurityAdvice(onNewest, vulns, assess(onNewest, history, '10.24.0'), '10.24.0'), /4.0.0 is newer but needs Mendix 11.6.0: plan that Mendix upgrade/);
  });

  test('a bundled widget whose module is already on the newest release is not told to update to it', () => {
    const inv = inventory();
    const grid = inv.widgets.find((w) => w.bundledWith === 'DataWidgets');
    const module = { ...inv.modules.find((m) => m.name === 'DataWidgets'), installedVersion: '3.11.6' };
    const owner = assess(module, [
      { versionNumber: '3.11.6', minSupportedMendixVersion: '10.24.0' },
      { versionNumber: '4.0.0', minSupportedMendixVersion: '11.6.0' },
    ], '10.24.0');
    const vuln = [{ id: 'X', cves: [], summary: 's', severity: 'High', package: 'mobx', version: '6.12.3', bundled: true, fixedIn: '6.13.0', cwes: [] }];
    const advice = widgetSecurityAdvice({ ...grid, moduleVersion: '3.11.6' }, vuln, assessWidget(grid, { status: 'not-checked', note: '' }, owner), '10.24.0');
    assert.match(advice, /The installed DataWidgets 3.11.6 is already the newest release for Mendix 10.24.0, and it still bundles mobx 6.12.3/);
    assert.match(advice, /Updating from the Marketplace will not change it. 4.0.0 is newer but needs Mendix 11.6.0/);
  });

  test('a vulnerable widget that ships with a module is fixed by updating that module', () => {
    const inv = inventory();
    const grid = inv.widgets.find((w) => w.bundledWith === 'DataWidgets');
    const owner = assess(inv.modules.find((m) => m.name === 'DataWidgets'), [
      { versionNumber: '2.5.0', minSupportedMendixVersion: '9.24.0' },
      { versionNumber: '3.11.6', minSupportedMendixVersion: '10.24.0' },
    ], '10.24.0');
    const vuln = [{ id: 'X', cves: [], summary: 's', severity: 'High', package: 'mobx', version: '6.12.3', bundled: true, fixedIn: '6.13.0', cwes: [] }];
    assert.match(widgetSecurityAdvice(grid, vuln, assessWidget(grid, { status: 'not-checked', note: '' }, owner), '10.24.0'), /Update the DataWidgets module to 3.11.6/);
  });
});
