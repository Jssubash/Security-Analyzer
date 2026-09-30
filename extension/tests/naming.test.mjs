/**
 * Studio Pro's untyped model API names properties by the metamodel (`allowedRoles`,
 * `generalization`, `hasOwner`), while `.mxunit` storage uses different names for some of the
 * same facts (`AllowedModuleRoles`, `MaybeGeneralization`, `HasOwnerAttr`). The extension sees
 * the first spelling in production and the second in the reference fixture.
 *
 * This test rewrites the fixture snapshot into metamodel naming and asserts the analysis is
 * unchanged. A reader that only knew one spelling would silently lose facts on the other —
 * and a lost access-rule role list reads as "grants nothing", which is a false pass.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { describeFixture, FIXTURE_MPR, FIXTURE_ROOT } from '../../tests/helpers/fixture.mjs';
import { snapshotFromMprContents } from './helpers/snapshot-from-mprcontents.mjs';
import { analyzeSnapshot } from '../dist/analyzer.cjs';

/** Storage name → metamodel name, where they differ by more than case. Keyed by owner type. */
const RENAMES = {
  'DomainModels$AccessRule': { AllowedModuleRoles: 'moduleRoles' },
  'Forms$Page': { AllowedModuleRoles: 'allowedRoles' },
  'DomainModels$Entity': { MaybeGeneralization: 'generalization' },
  'DomainModels$Attribute': { NewType: 'type' },
  'DomainModels$NoGeneralization': { HasOwnerAttr: 'hasOwner', HasChangedByAttr: 'hasChangedBy' },
  // Observed in Studio Pro 11.12's untyped model: the role settings carry a `Name` suffix.
  'Security$ProjectSecurity': { GuestUserRole: 'guestUserRoleName', AdminUserRole: 'adminUserRoleName' },
  // Microflow bodies, as the Model SDK metamodel names them.
  'Microflows$SequenceFlow': { OriginPointer: 'origin', DestinationPointer: 'destination' },
  'Microflows$CreateChangeAction': { VariableName: 'outputVariableName' },
  'Microflows$RetrieveAction': { ResultVariableName: 'outputVariableName' },
  'Microflows$DatabaseRetrieveSource': { XpathConstraint: 'xPathConstraint' },
  'Microflows$AssociationRetrieveSource': { AssociationId: 'association' },
};

/** Unit types the untyped model names differently from storage (observed live, 11.12). */
const TYPE_RENAMES = {
  'Forms$Page': 'Pages$Page',
  'Microflows$CreateChangeAction': 'Microflows$CreateObjectAction',
  'Microflows$ChangeAction': 'Microflows$ChangeObjectAction',
  'Microflows$MicroflowParameter': 'Microflows$MicroflowParameterObject',
};

const lowerFirst = (s) => s.charAt(0).toLowerCase() + s.slice(1);
const stripImpl = (t) => (t.endsWith('Impl') ? t.slice(0, -4) : t);

function toMetamodel(value) {
  if (Array.isArray(value)) return value.map(toMetamodel);
  if (value === null || typeof value !== 'object' || value.$redacted) return value;
  const type = TYPE_RENAMES[stripImpl(value.$Type)] ?? stripImpl(value.$Type);
  const renames = RENAMES[stripImpl(value.$Type)] ?? RENAMES[type] ?? {};
  const out = { $Type: type };
  for (const [key, v] of Object.entries(value)) {
    if (key === '$Type') continue;
    const name = key.startsWith('$') ? key : (renames[key] ?? lowerFirst(key));
    out[name] = toMetamodel(v);
  }
  return out;
}

function metamodelSnapshot(snapshot) {
  return {
    ...snapshot,
    source: 'studio-pro',
    projectUnits: snapshot.projectUnits.map(toMetamodel),
    modules: snapshot.modules.map((m) => ({ ...m, units: m.units.map(toMetamodel) })),
  };
}

describeFixture('property naming', () => {
  test('metamodel names and storage names give the same findings', () => {
    const storage = snapshotFromMprContents(FIXTURE_ROOT, FIXTURE_MPR);
    const metamodel = metamodelSnapshot(storage);

    // Guard against a vacuous pass: the rewrite must actually have renamed things.
    const text = JSON.stringify(metamodel);
    assert.ok(!text.includes('"AllowedModuleRoles"'));
    assert.ok(!text.includes('"MaybeGeneralization"'));
    assert.ok(text.includes('"allowedRoles"'));
    assert.ok(text.includes('"guestUserRoleName"'));
    assert.ok(text.includes('"Pages$Page"'));
    assert.ok(text.includes('"Microflows$CreateObjectAction"'));
    assert.ok(text.includes('"destination"'));

    const a = analyzeSnapshot(storage);
    const b = analyzeSnapshot(metamodel);
    const view = (r) => r.findings.map((f) => `${f.id} | ${f.status} | ${f.observation}`);
    assert.deepEqual(view(b), view(a));
    assert.equal(b.securityScore, a.securityScore);
    assert.deepEqual(b.inventory, a.inventory);
  });
});
