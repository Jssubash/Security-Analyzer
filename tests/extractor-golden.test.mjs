/**
 * `docs/security.md` §8 test 2 — the extractor golden counts.
 *
 * These numbers are regression anchors. Each one was verified against the model by hand, and each
 * one disagreed with what the old parser reported: it claimed 0 microflows and 73 nanoflows for a
 * project with 17 and 15, because it was counting JavaScript source files on disk instead of
 * reading the model. A golden test is what stops that class of mistake coming back quietly.
 *
 * The counts are exact, not lower bounds. A lower bound would have passed for the old parser too.
 */

import assert from 'node:assert/strict';
import { it } from 'node:test';

import { describeFixture, fixtureIr } from './helpers/fixture.mjs';

describeFixture('extractor golden counts for the reference project', () => {
  it('reports the project metadata read from the model, not a fallback', async () => {
    const ir = await fixtureIr();
    // From `_MetaData._ProductVersion` in the .mpr. The old parser hardcoded a version string,
    // so this assertion is what keeps a guess from passing as a fact.
    assert.equal(ir.metadata.mendixVersion, '11.12.4');
    assert.equal(ir.metadata.javaVersion, '21');
    assert.equal(ir.metadata.applicationType, 'web');
    assert.match(ir.metadata.primaryMprPath, /TestApp\.mpr$/);
    // POSIX-normalised so the path in a report is the same on the machine that produced it and
    // the machine that reads it.
    assert.ok(!ir.metadata.primaryMprPath.includes('\\'));
  });

  it('counts 396 model units', async () => {
    const { ModelGraph } = await import('@mendix-analyzer/mendix-parser');
    const { FIXTURE_ROOT, FIXTURE_MPR } = await import('./helpers/fixture.mjs');
    const graph = ModelGraph.build(FIXTURE_ROOT, FIXTURE_MPR);
    // `docs/security.md` §8 says 397; that is the file count under `mprcontents`, which includes
    // `mprname`. There are 396 `.mxunit` documents.
    assert.equal(graph.units.unitCount, 396);
  });

  it('counts the documents in each module', async () => {
    const ir = await fixtureIr();
    assert.equal(Object.keys(ir.modules).length, 8);
    assert.equal(Object.keys(ir.entities).length, 8);
    assert.equal(Object.keys(ir.microflows).length, 17);
    assert.equal(Object.keys(ir.nanoflows).length, 15);
    assert.equal(Object.keys(ir.pages).length, 16);
    assert.equal(ir.associations.length, 1);
    assert.equal(ir.operations.constants.length, 1);
  });

  it('classifies modules from the model, not from a name list', async () => {
    const ir = await fixtureIr();
    // `FromAppStore` in `Projects$ModuleImpl`. MyFirstModule is the only module the team wrote.
    const userModules = Object.values(ir.modules)
      .filter((m) => !m.isMarketplace && !m.isSystem)
      .map((m) => m.name);
    assert.deepEqual(userModules, ['MyFirstModule']);
    assert.equal(ir.modules.Atlas_Core.isMarketplace, true);
    assert.equal(ir.modules.FeedbackModule.isMarketplace, true);
  });

  it('counts the security model', async () => {
    const ir = await fixtureIr();
    assert.equal(ir.security.userRoles.length, 3);
    assert.equal(ir.security.moduleRoles.length, 16);
    assert.equal(ir.security.projectSecurityLevel, 'CheckEverything');
    assert.equal(ir.security.securityEnabled, true);
    assert.equal(ir.security.anonymousUserEnabled, true);
    assert.equal(ir.security.anonymousRole, 'Anonymous');
    assert.equal(ir.security.demoUsersEnabled, true);
    assert.equal(ir.security.demoUsers.length, 2);
    assert.equal(ir.security.strictPageUrlCheck, true);
  });

  it('counts 14 access rules with 59 member-access entries', async () => {
    const ir = await fixtureIr();
    const rules = Object.values(ir.entities).flatMap((e) => e.accessRules);
    assert.equal(rules.length, 14);
    assert.equal(
      rules.reduce((n, r) => n + r.memberAccess.length, 0),
      59
    );
  });

  it('reads the access rule that makes this fixture worth having', async () => {
    const ir = await fixtureIr();
    const entity = ir.entities['MyFirstModule.RequestForm'];
    assert.ok(entity, 'MyFirstModule.RequestForm is the fixture\'s business entity');
    assert.equal(entity.persistenceType, 'persistable');

    const rule = entity.accessRules.find((r) => r.moduleRoles.includes('MyFirstModule.User'));
    assert.ok(rule, 'the guest-reachable rule on RequestForm');
    assert.equal(rule.allowCreate, true);
    assert.equal(rule.allowDelete, true);
    assert.equal(rule.xPathConstraint, undefined);
    for (const member of ['Name', 'Email', 'PhoneNumber']) {
      const entry = rule.memberAccess.find((m) => m.attributeOrAssociation.endsWith(`.${member}`));
      assert.ok(entry, `member access for ${member}`);
      assert.equal(entry.access, 'ReadWrite');
    }
  });

  it('resolves the guest role\'s module roles through the real indirection', async () => {
    const ir = await fixtureIr();
    const guest = ir.security.userRoles.find((r) => r.name === 'Anonymous');
    assert.ok(guest);
    const held = guest.moduleRoles.map((m) => `${m.module}.${m.role}`).sort();
    assert.deepEqual(held, [
      'Atlas_Core.Administrator',
      'Atlas_Core.User',
      'Atlas_Web_Content.Administrator',
      'Atlas_Web_Content.Anonymous',
      'Atlas_Web_Content.User',
      'MyFirstModule.User',
      'System.User',
    ]);
  });

  it('classifies custom code by what it is, not by which directory it sits in', async () => {
    const ir = await fixtureIr();
    assert.equal(ir.customCode.javaActions.length, 3);
    // The old parser counted these 73 JavaScript action files as nanoflows.
    assert.equal(ir.customCode.javaScriptActions.length, 73);
    const sanitizer = ir.customCode.javaActions.find((a) => a.name === 'XSS_Sanitizer');
    assert.ok(sanitizer);
    assert.equal(sanitizer.hasRegexXssSanitizer, true);
  });

  it('marks the one navigation home page, so a public front door is not a finding', async () => {
    const ir = await fixtureIr();
    const home = ir.pages['MyFirstModule.Home_Web'];
    assert.ok(home);
    assert.equal(home.isAccessibleAnonymously, true);
    assert.equal(home.isNavigationHomePage, true);
  });

  it('attributes the one constant to the marketplace module that owns it', async () => {
    const ir = await fixtureIr();
    const [constant] = ir.operations.constants;
    assert.equal(constant.name, 'LocalStorageKey');
    assert.equal(constant.module, 'FeedbackModule');
    assert.equal(ir.modules.FeedbackModule.isMarketplace, true);
    assert.equal(constant.isExposedToClient, true);
  });

  it('records coverage honestly and produces no parse or attribution diagnostics', async () => {
    const ir = await fixtureIr();
    assert.equal(ir.coverage.projectSecurity, 'ANALYZED');
    assert.equal(ir.coverage.moduleRoles, 'ANALYZED');
    assert.equal(ir.coverage.entityAccessRules, 'ANALYZED');
    assert.equal(ir.coverage.attributeTypes, 'ANALYZED');
    assert.equal(ir.coverage.pageAccess, 'ANALYZED');
    assert.equal(ir.coverage.constants, 'ANALYZED');
    // Read, but not completely: the allowed roles and entity-access flags are there, the
    // activity graph is not.
    assert.equal(ir.coverage.microflows, 'PARTIAL');
    assert.equal(ir.coverage.microflowActivities, 'NOT_ANALYZABLE');
    assert.equal(ir.coverage.publishedServices, 'NOT_ANALYZABLE');
    assert.equal(ir.coverage.scheduledEvents, 'NOT_ANALYZABLE');

    // Exactly the two documented Phase 1 gaps, and nothing about unreadable units.
    assert.equal(ir.coverage.notes.length, 2);
    for (const note of ir.coverage.notes) {
      assert.doesNotMatch(note, /could not be (parsed|attributed|read)/);
    }
  });
});
