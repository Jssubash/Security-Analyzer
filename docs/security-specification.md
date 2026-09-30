# Phase 1 — Security Analysis Specification

**Product:** MDA – Mendix Governance & Compliance Analyzer
**Scope:** Phase 1 (Security analyzer + the intake controls it depends on)
**Status:** Phase 1 implemented (work items 1–11 and 14; see §11 for what is deliberately not built)
**Baseline commit state:** 33 rules across 9 categories, 10 of them `SEC-*`
**Delivered state:** 47 rules across 9 categories, 28 of them `SEC-*`
**Reference fixture:** `scratch/testapp_unpacked/TestApp-main` (TestApp, Mendix 11.12.4, 396 `.mxunit` units)

---

## 1. Purpose

The master design (`Mendix_Governance_Compliance_Analyzer_Complete.md`) names Security as the
highest-value analyzer (§23) and defines a hard rule in §6: **rules operate on the Application IR,
never on files.** Phase 1 delivers the Security analyzer *for real* — meaning every `SEC-*` finding
is derived from a fact actually present in the uploaded Mendix model, with an evidence path a
reviewer can open in Studio Pro and verify.

The existing implementation is a complete, working end-to-end skeleton — upload → extract → IR →
rules → score → dashboard → report all function. What it does not yet have is a trustworthy
foundation under the security layer. Phase 1 fixes that, then builds the rule catalogue on top.

This document is the contract for that work: what is wrong today, what must be extracted, which
rules ship, and how we will know they are correct.

---

## 2. Current-state assessment

Findings below were verified by reading the source and by replaying a completed run
(`apps/api/data/runs/run-1789030022188.json`, TestApp, reported score 85/100, Security 66/100,
risk rating D, 14 findings).

### 2.1 The reported security score is not evidence-backed

Of the 10 `SEC-*` rules, **four can never produce a finding** regardless of the uploaded
application, because the IR field they test is hardcoded or always empty:

| Rule | Tests | Why it can never fire |
|---|---|---|
| `SEC-001` Unrestricted entity access | `entity.isSecurityConfigured` | `mpr-parser.ts:274` sets `hasAccessRules: true` for every entity unconditionally; `ir-builder.ts:79` then derives `isSecurityConfigured` from it. Always `true`. |
| `SEC-003` Anonymous modify/delete | `entity.accessRules[].moduleRoles` contains `anonymous` | `ir-builder.ts:66-78` synthesises exactly one fabricated rule per entity, always `moduleRoles: ['User']`. No anonymous rule can exist. |
| `SEC-004` REST endpoint without auth | `publishedRestServices[].endpoints[]` | `mpr-parser.ts:845-851` always pushes `endpoints: []`. The inner loop has nothing to iterate. |
| `SEC-002` Security level | `security.projectSecurityLevel` | Fires correctly *when a `Security$ProjectSecurity` unit is found*, but the no-unit fallback (`mpr-parser.ts:762`) returns `CheckEverything`. A project the parser cannot read is reported as production-secure. |

The rule engine counts a rule that returns zero findings as **`totalPassed++`**
(`engine.ts:48-52`). So these four rules are currently scored as four security passes. The
`Compliance` category score is `totalPassed / totalRulesEvaluated`, which means unreadable input
raises the score. This is the single most serious integrity defect in the product: *the analyzer is
most confident about the applications it understands least.*

The same mechanism inflates other categories. TestApp produced **0 microflows**
(`microflowDetails` is declared in `mpr-parser.ts:177` and never written to), so every `MF-*`,
`PERF-*` and `NF-*` rule returned zero findings and scored as a pass — hence `Performance: 100`,
`Logic: 100` on an application the analyzer never read a single microflow from. The model actually
contains **17 `Microflows$Microflow` units.**

### 2.2 The security IR is derived from generated artifacts, not the model

`MendixMprParser.parseWorkspace` builds entities by reading `javasource/<module>/proxies/*.java` —
**mxbuild-generated deployment output**, which §3 of the design explicitly says must not be treated
as the authoring model. Consequences:

- **Entity count is inflated.** The run reports `totalEntities: 72`. The actual design-time model
  contains **8 `DomainModels$EntityImpl`** units. The other ~64 are System-module proxies that are
  not part of the customer's application at all.
- **Attribute types are invented.** `mpr-parser.ts:231-241`: if the name looks sensitive and no
  `String` getter is matched, the type is *assigned* `HashedString`. A guessed type is then used as
  the evidence for `SEC-005` ("stored as plain text"). The real type is available —
  `DomainModels$StringAttributeType`, `BooleanAttributeType`, etc.
- **Associations are fabricated.** Every `getX(IContext)` proxy method becomes a `Reference`
  association with `deleteBehavior: 'DeleteParentOnly'` (`mpr-parser.ts:254-267`). These feed the
  dependency graph and `DAT-*` rules.
- **Pages are fictional.** `mpr-parser.ts:373-381` emits one synthetic `<Module>_Overview` page per
  module with `totalWidgets: 16`, and `ir-builder.ts:180-186` gives it three invented widgets and
  `isAccessibleAnonymously: false`. The model contains **16 real `Forms$Page` units**, each carrying
  a real `AllowedModuleRoles` list. Page-level access control — a core Security analyzer concern
  (§Analyzer Catalogue, "page access") — is therefore entirely unimplemented while appearing
  implemented.
- **Nanoflows are JavaScript actions.** `mpr-parser.ts:294-300` registers each `actions/*.js` file
  as a nanoflow with `activitiesCount: 4, complexity: 2` hardcoded.

### 2.3 Real security facts in the model are not read at all

The `.mxunit` files are **BSON documents** (verified: header is a little-endian int32 total length;
element tags `0x02` string, `0x03` embedded document, `0x04` array, `0x05` binary for the 16-byte
`$ID` GUID, `0x08` boolean, `0x0A` null, `0x10` int32, `0x12` int64; arrays use key `"0"` as an
int32 version marker followed by items keyed `"1"`, `"2"`, …). The repo already knows this — see
`.ai-context/skills/debug-bson/SKILL.md` — and `./mxcli bson` can dump them for cross-checking.

`parseUnitBinaryEvents` (`mpr-parser.ts:570-615`) instead scans for `0x02`/`0x08` tag bytes and
emits a **flat, unnested** `{propName, val}` stream, discarding all containment. That is why role
assignment has to be reconstructed by "any string value containing a dot"
(`mpr-parser.ts:720-726`) and why nothing nested deeper than one level is recoverable.

Reading TestApp's `Security$ProjectSecurity` unit shows what is being left on the table — all of
the following is present and currently unused:

```
SecurityLevel          = "CheckEverything"
CheckSecurity          = true
AdminUserName           = "MxAdmin"
AdminPassword           = "1"              ← weak admin credential, in the model
AdminUserRole           = "Administrator"
EnableDemoUsers         = true             ← demo users active
EnableGuestAccess       = true             ← the real anonymous flag
GuestUserRole           = "Anonymous"
StrictMode              = false
StrictPageUrlCheck      = true
PasswordPolicySettings  { MinimumLength=12, RequireDigit=true, RequireMixedCase=true,
                          RequireSymbol=false }
DemoUserImpl[]          { Entity="Administration.Account", UserName="demo_administrator",
                          Password="<redacted>", roles=["Administrator"] }
                        { UserName="demo_user", Password="<redacted>", roles=["User"] }
```

`anonymousUserEnabled` is currently hardcoded `true` (`mpr-parser.ts:749`) while the authoritative
`EnableGuestAccess` flag sits unread two lines away. A hardcoded admin password of `"1"` and two
plaintext demo credentials are exactly the findings a governance analyzer exists to surface, and
none of the three is detected.

Entity access rules are likewise fully present. TestApp has **14 `DomainModels$AccessRule`** units
with complete structure:

```
DomainModels$AccessRule
  AllowCreate = true          AllowDelete = true
  "1" = "Administration.Administrator"        ← granted module roles
  DefaultMemberAccessRights = "None"
  XPathConstraint = "[id='[%CurrentUser%]']"
  MemberAccess[] { AccessRights="ReadWrite", Attribute="Administration.Account.Email" }
                 { AccessRights="ReadOnly",  Association="Administration.AccountPasswordData_Account" }
```

And a real finding the current `SEC-006` misses: TestApp's **`Anonymous` user role is granted
`Atlas_Core.Administrator` and `Atlas_Web_Content.Administrator`.** `SEC-006` only flags non-system,
non-marketplace modules (`security.ts:270`), so it treats Atlas as safe and reports neither.

### 2.4 Intake controls versus design §16

| §16 control | Status |
|---|---|
| Treat ZIP as untrusted | Partial |
| Path traversal / absolute path guard | Present (`extractor.ts:122-127`) but weak — see below |
| Max compressed & extracted size | Extracted only (500 MB); no compressed-size or ratio check |
| File-count limit | Present (15 000) |
| Isolated temporary workspace | Present (OS temp) |
| Do not execute uploaded code | Holds — analysis is read-only |
| Exclude `.git`/`node_modules`/deployment from metrics | **Not done** — everything is extracted, and `javasource` deployment output is the primary metrics source (§2.2) |
| SHA-256 archive hash | Present (`extractor.ts:38`) |
| Delete extracted content per retention policy | Partial — `cleanup()` runs in a `finally` (`index.ts:45-52`) and swallows errors, so a locked file leaves the workspace behind. No TTL sweep for workspaces orphaned by a crash, and no retention policy for `data/uploads` or `data/runs`. |

Specific intake defects:

- **Traversal guard is substring-based.** `entryPath.includes('..')` rejects the legitimate filename
  `my..file.txt` (false positive) and, more importantly, is the wrong check — the correct one is to
  resolve the join and confirm it stays inside the workspace root. Symlink entries are not
  considered at all.
- **Decompression-bomb limit is self-reported.** `totalExtractedBytes += entry.header.size` trusts
  the ZIP's own declared size, then writes `entry.getData()` in full. A crafted header declaring a
  small size passes the check while the real write proceeds.
- **Whole archive read into memory.** `fs.readFileSync(archivePath)` (`extractor.ts:37`) plus
  `new AdmZip(archivePath)` loads the upload twice before any limit applies. TestApp is 61 MB
  extracted; the 500 MB ceiling is above the default Node heap.
- **No upload authentication, size cap, or MIME/magic-byte validation** on
  `POST /api/applications`. `multer` accepts any file of any size to disk.
- **`origin: '*'` with `credentials: true`** (`main.ts:8-12`) is an invalid and unsafe CORS
  combination.
- **Findings are persisted with full IR** to `data/runs/*.json` world-readable, including any secret
  values the analyzer extracts (see `SEC-041`). Retention and redaction are unspecified.
- **A hardcoded local path** to `c:\Users\<user>\Downloads\SampleNativeApplication.zip` is a fallback in
  `app.controller.ts:129-131`. Unknown application IDs silently analyse a developer's local file.

### 2.5 What is genuinely working and should be preserved

- The package decomposition matches §18 and the engine is UI-independent, as §6 requires.
- The `Rule` / `Finding` / `Evidence` contracts (`rule-engine/src/types.ts`) already carry
  `sourceSkill`, `confidence`, `expectedPractice`, `whyItMatters` and structured evidence — the
  §9/§11 model is in place and does not need redesign.
- Per-rule error isolation (`engine.ts:73-96`) turns a throwing rule into a Low warning rather than
  failing the run.
- The BSON property decoder, though flat, does read real values correctly — `SecurityLevel`,
  `GuestUserRole` and user-role→module-role mappings in the run output match the fixture exactly.
  The decoder needs to be *completed*, not replaced wholesale.
- `SEC-006`, `SEC-007` and `SEC-010` operate on real (if narrowly parsed) data.

---

## 3. Phase 1 scope

### In scope

1. **A correct BSON unit reader** producing a nested object tree, replacing the flat event scan.
2. **A real security-facing IR**: project security, user/module roles, entities with genuine access
   rules and attribute types, pages with real allowed roles, constants.
3. **`NOT_ANALYZABLE` / `NOT_APPLICABLE` status handling** so unreadable input can never score as a
   pass.
4. **Scoring correction** so only rules that actually evaluated contribute.
5. **The `SEC-*` rule catalogue** (§6), every rule grounded in a verified model field.
6. **Intake hardening** to close the §16 gaps in §2.4.
7. **Fixture-based tests** with expected-finding assertions against TestApp.

### Out of scope for Phase 1

- Microflow / nanoflow activity graphs (Phase 3). Security rules that need them are specified here
  but ship as `NOT_ANALYZABLE`, not as passes.
- Published REST / OData parsing beyond detecting that a service exists (`Rest$*` units are absent
  from the TestApp fixture; a fixture that has them is a prerequisite).
- `DAT-*`, `PERF-*`, `ARC-*`, `MF-*`, `UI-*` re-grounding. They are wrong for the same reasons, but
  fixing them is Phase 2–3. Phase 1 must at minimum stop them from *inflating* the score.
- Policy profiles, rule overrides, exceptions (Phase 6).
- Dashboard redesign. The existing UI consumes the same contracts and needs only a
  `NOT_ANALYZABLE` affordance.

---

## 4. Architecture changes

```
packages/mendix-parser/src/
  bson/reader.ts          NEW  BSON document → JS object tree. No deps, no dynamic eval.
  bson/unit-index.ts      NEW  Walk mprcontents/**/*.mxunit, index units by $ID and $Type.
  extract/security.ts     NEW  Security$ProjectSecurity + Security$ModuleSecurity → SecurityFacts
  extract/domain-model.ts NEW  DomainModels$DomainModel → entities, attributes, access rules
  extract/pages.ts        NEW  Forms$Page → name, AllowedModuleRoles
  extract/constants.ts    REWRITE  Constants$Constant with correct owning module
  extract/project.ts      NEW  Projects$ModuleImpl, Settings$ProjectSettings, Navigation$*
  mpr-parser.ts           SHRINK  orchestration only; proxy scanning limited to Java-action source
  ir-builder.ts           EDIT  stop fabricating; carry analyzability through
```

Two invariants for every extractor:

- **Never invent.** A field that could not be read is `undefined`, never a plausible default. Where
  today's code writes `hasAccessRules: true` or `totalWidgets: 16`, Phase 1 writes nothing.
- **Always carry provenance.** Every extracted fact records the `.mxunit` relative path and the
  `$ID` it came from, so `Evidence.artifactPath` is a real locator rather than a reconstructed
  string.

### 4.1 Analyzability contract

Add to `application-ir`:

```ts
export type Analyzability = 'ANALYZED' | 'PARTIAL' | 'NOT_ANALYZABLE';

export interface FactCoverage {
  projectSecurity: Analyzability;
  moduleRoles: Analyzability;
  entityAccessRules: Analyzability;
  attributeTypes: Analyzability;
  pageAccess: Analyzability;
  publishedServices: Analyzability;
  microflows: Analyzability;
  microflowActivities: Analyzability;   // added during implementation; see §6.8
  constants: Analyzability;
  scheduledEvents: Analyzability;       // added during implementation; see §6.8
  notes: string[];          // e.g. "no Security$ProjectSecurity unit found in mprcontents"
}
```

`ApplicationIR` gains `coverage: FactCoverage`. Each `Rule` gains:

```ts
requires: (keyof Omit<FactCoverage, 'notes'>)[];
```

The engine checks `requires` **before** calling `evaluate`. If any required fact is
`NOT_ANALYZABLE`, the rule is recorded as `NOT_ANALYZABLE` with a finding of status
`NOT_APPLICABLE`, is excluded from `totalPassed`, and contributes zero penalty *and zero credit*.
This is the design's §22 instruction ("those checks must be marked NOT_ANALYZABLE rather than
guessed") made enforceable rather than advisory.

### 4.2 Scoring correction

In `packages/scoring/src/scorer.ts`:

- Denominators become `evaluatedRules` (`ANALYZED` + `PARTIAL`), not `totalRulesEvaluated`.
- `Compliance` becomes `passed / evaluated`, and is reported alongside a **coverage percentage**
  (`evaluated / total`). A run with 40 % coverage must not present a 90 % compliance score without
  that number next to it.
- If `coverage.projectSecurity === 'NOT_ANALYZABLE'`, the Security category score is suppressed
  entirely (`null`, rendered as "Not assessed") rather than computed from the rules that happened to
  run. A security score derived from an unreadable security model is worse than no score.

**As implemented.** `CATEGORY_CRITICAL_FACTS` names the facts a category cannot be scored without —
`Security: ['projectSecurity']` — and is checked separately from `CATEGORY_FACTS`. The original
guard only suppressed a category when *every* fact backing it was unreadable, which was too weak:
with the reference project's `Security$ProjectSecurity` unit removed, module roles, access rules and
pages were all still readable, nine Security rules still ran and passed, and the category scored
**100** against the 65 it scores when the security model is intact.

Three consequences, all covered by `tests/coverage-negative.test.mjs`:

- A category missing a critical fact is unassessed, and the reason names the fact.
- **`Compliance` is suppressed under the same condition.** `passed / evaluated` *rises* when the
  failing rules drop out of the ratio — 64 % intact, 90 % with the unit removed — and §9.5 requires
  that a less readable project never produce a higher compliance score. The only number that cannot
  be read as an improvement is no number.
- `ScoreReport` gains `coveragePercentage` (evaluated ÷ considered) and `assessmentIsIncomplete`.
  `overallScore` remains a number even when the assessment is incomplete, because it is the penalty
  per rule that *ran*; `assessmentIsIncomplete` is what tells a reader that two such numbers are not
  comparable. Rendering it next to the score is work item 15, which is out of scope here.

---

## 5. Security IR — required facts

The authoritative field mapping. Every row was verified present in the TestApp fixture unless marked.

### 5.1 `Security$ProjectSecurity` → `SecurityModel`

| BSON field | IR field | Notes |
|---|---|---|
| `SecurityLevel` | `projectSecurityLevel` | `CheckNothing` / `CheckFormsAndMicroflows` / `CheckEverything` |
| `CheckSecurity` | `securityEnabled` | NEW |
| `EnableGuestAccess` | `anonymousUserEnabled` | Replaces the hardcoded `true` |
| `GuestUserRole` | `anonymousRole` | |
| `AdminUserName` / `AdminUserRole` | `administrator.userName` / `.role` | NEW |
| `AdminPassword` | `administrator.passwordIsWeak`, `.passwordLength` | **Never store the value.** Classify, discard. |
| `EnableDemoUsers` | `demoUsers.enabled` | NEW |
| `Security$DemoUserImpl[]` | `demoUsers.accounts[]` | `{ entity, userName, roles[], passwordIsWeak }` — value discarded |
| `Security$PasswordPolicySettings` | `passwordPolicy` | `{ minimumLength, requireDigit, requireMixedCase, requireSymbol }` — `MinimumLength` is an int64; TestApp = 12 |
| `StrictMode` | `strictMode` | NEW |
| `StrictPageUrlCheck` | `strictPageUrlCheck` | NEW |
| `Security$UserRole[]` | `userRoles[]` | `{ name, moduleRoles[], manageableRoles[], manageAllRoles, manageUsersWithoutRoles, checkSecurity }`. `ModuleRoles` is a **properly named BSON array** of qualified `Module.Role` strings — the "any string value containing a dot" reconstruction at `mpr-parser.ts:720-726` becomes unnecessary once containment is preserved. |
| `Security$FileDocumentAccessRuleContainer` | `fileDocumentAccessRules[]` | Parse; rules deferred to Phase 2 |
| `Security$ImageAccessRuleContainer` | `imageAccessRules[]` | Parse; rules deferred to Phase 2 |

> **Secret handling.** Passwords and secret-shaped constant values are read only to classify them,
> then dropped before the fact reaches the IR. The IR is persisted to
> `data/runs/*.json` and shipped in HTML/JSON reports; a governance tool that copies the
> credentials it finds into a world-readable artifact has created a second vulnerability. Evidence
> for these rules carries the *location and a classification*, never the value.

### 5.2 `Security$ModuleSecurity` → `moduleRoles[]`

`ModuleRoles: Security$ModuleRole[] { Name, Description }`, owning module resolved from the unit's
containing `Projects$ModuleImpl`. TestApp: 8 units, 16 module roles.

### 5.3 `DomainModels$DomainModel` → entities

| BSON | IR |
|---|---|
| `DomainModels$EntityImpl.Name` | `Entity.name` |
| `Persistable` (absent ⇒ `true`) | `persistenceType` |
| `Generalization` \| `NoGeneralization` | `generalization` |
| `HasOwnerAttr`, `HasChangedByAttr`, `HasCreatedDateAttr`, `HasChangedDateAttr` | `systemMembers` (NEW) |
| `DomainModels$Attribute.Name` | `Attribute.name` |
| child `$Type` `DomainModels$*AttributeType` | `Attribute.type` — **real**, e.g. `String`, `Boolean`, `HashedString` |
| `DomainModels$StoredValue.DefaultValue` / `CalculatedValue` | `defaultValue`, `isCalculated` |
| `DomainModels$AccessRule.AllowCreate` / `AllowDelete` | `AccessRule.allowCreate` / `.allowDelete` |
| `AccessRule` numeric keys `"1".."n"` | `AccessRule.moduleRoles[]` — qualified `Module.Role` |
| `DefaultMemberAccessRights` | `defaultMemberAccess` |
| `XPathConstraint` | `xPathConstraint` (empty string ⇒ `undefined`) |
| `DomainModels$MemberAccess` | `memberAccess[] { attributeOrAssociation, access }` |
| `DomainModels$Association` + `DeleteBehavior` | `Association` with real `Parent`/`ChildDeleteBehavior` |

Entities from `javasource/*/proxies` are **dropped**. Marketplace and System modules are retained in
the IR (rules need them to resolve role mappings) but tagged so rules can scope themselves — a
System-module finding is not a customer design violation (§22).

### 5.4 `Forms$Page` → pages

`AllowedModuleRoles: string[]` of qualified `Module.Role` (verified: `["FeedbackModule.User"]`).
`isAccessibleAnonymously` is then **computed**, not asserted: true iff
`AllowedModuleRoles ∩ (module roles mapped to the guest user role) ≠ ∅`.

### 5.5 Deferred but detected

`Microflows$Microflow` (17 units), `JavaActions$JavaAction` (2),
`JavaScriptActions$JavaScriptAction` (71), `Settings$ProjectSettings`,
`Navigation$NavigationDocument` / `NavigationProfile` / `HomePage`, `Constants$Constant` (1).
Phase 1 records their existence and count so coverage is honest, and parses only what the rules
below need.

---

## 6. `SEC-*` rule catalogue

Severity follows §9. `Conf` is detection confidence (§9, "Confidence"). Existing rule IDs are
retained where the semantics are unchanged — §9 calls `RuleId` a stable identifier and the dashboard
and stored runs key on it.

### 6.1 Project & platform security

| ID | Rule | Sev | Conf | Detection |
|---|---|---|---|---|
| `SEC-002` | Security level not production-ready | Critical | High | `projectSecurityLevel !== 'CheckEverything'`. *Existing; the fix is the fallback — no `Security$ProjectSecurity` unit ⇒ `NOT_ANALYZABLE`, never `CheckEverything`.* |
| `SEC-011` | App security disabled | Critical | High | `securityEnabled === false` (`CheckSecurity`) |
| `SEC-012` | Demo users enabled | High | High | `demoUsers.enabled === true` |
| `SEC-013` | Demo user credentials stored in the model | High | High | `demoUsers.accounts.length > 0`. Evidence: account name + role, **never the password**. |
| `SEC-014` | Weak or default administrator password | Critical | High | `AdminPassword` length < 8, or in a small default list (`1`, `admin`, `password`, `Admin1!`, project name). TestApp: `"1"`. |
| `SEC-015` | Password policy below baseline | Medium | High | Any of `requireDigit`, `requireMixedCase`, `requireSymbol` false, or `minimumLength < 8`. TestApp: `requireSymbol=false`. |
| `SEC-016` | Strict page-URL check disabled | Medium | High | `strictPageUrlCheck === false` |

*Source skill: `manage-security.md`, `project-settings.md`.*

### 6.2 Anonymous / guest access

| ID | Rule | Sev | Conf | Detection |
|---|---|---|---|---|
| `SEC-006` | Guest role granted a business module role | Critical | High | Existing, re-grounded on real `EnableGuestAccess` + role mappings. Remove the marketplace exemption at `security.ts:270`. |
| `SEC-017` | Guest role granted an administrator module role | Critical | High | Guest user role maps to any module role whose name matches `/admin/i`, in **any** module including Atlas. TestApp: `Atlas_Core.Administrator`, `Atlas_Web_Content.Administrator`. |
| `SEC-018` | Anonymous page uses persistable data | High | High | *Revised; see §6.10.* A page the guest-mapped roles can open is judged by the entities it uses (`Page.dataEntities`): persistable and readable by the guest ⇒ `FAIL`/High; persistable but not readable ⇒ `WARNING`/Medium; only non-persistable or no data ⇒ no finding. Falls back to reachability (home page exempt) when contents were not read. |
| `SEC-019` | Page with no allowed module roles | Low | High | `AllowedModuleRoles` empty on a non-layout page. Unreachable page or a security oversight; status `WARNING`. |
| `SEC-009` | Anonymous submissions unthrottled | Informational | Low | **Demote.** Rate limiting is not expressible in the Mendix model; the current heuristic ("guest has a `User` role") tests something unrelated. Keep as an advisory prompt, `status: WARNING`, excluded from scoring — §4 of the design forbids converting advisory guidance into a governance failure. |

*Source skill: `manage-security.md`, `manage-navigation.md`.*

### 6.3 Entity & member access

| ID | Rule | Sev | Conf | Detection |
|---|---|---|---|---|
| `SEC-001` | Persistable entity with no access rules | Critical | High | Existing, re-grounded: `persistable && accessRules.length === 0`, scoped to user modules. Requires `entityAccessRules`. |
| `SEC-003` | Guest-reachable role has create/delete on an entity | Critical | High | Existing, re-grounded: any `accessRule.moduleRoles ∩ guestModuleRoles` with `allowCreate \|\| allowDelete \|\| defaultMemberAccess === 'ReadWrite'`. |
| `SEC-020` | Guest-reachable role has write access to a member | High | High | `memberAccess[].access === 'ReadWrite'` on a rule granted to a guest-mapped module role. |
| `SEC-029` | Anonymous role has access to a persistable entity | High | High | Any access rule on a persistable, non-platform entity granted to a guest-mapped module role, whatever its rights. Added after Phase 1; see §6.9. |
| `SEC-021` | Sensitive or PII member readable by a broad role | High | Medium | Member matches the sensitive/PII classifier (§6.6) and is `ReadOnly`/`ReadWrite` for a role mapped to more than one user role. |
| `SEC-022` | Owned-data entity without an XPath constraint | Medium | Low | `systemMembers.hasOwner === true` (or an association to `System.User`) and a non-admin access rule has no `xPathConstraint`. Heuristic: §22 forbids asserting a constraint is required without evidence, so this ships as `WARNING` with Low confidence and a plain statement of the assumption. |
| `SEC-005` | Password/secret attribute not hashed | High | High | Existing, re-grounded on the **real** attribute type: classifier-sensitive name with type `String` rather than `HashedString`. Confidence rises from Medium to High because the type is now read, not guessed. |
| `SEC-008` | PII stored unencrypted | Medium | Low | Existing, **downgraded from High/High.** "String-typed PII" is not a violation on its own — Mendix has no native encrypted attribute type and encryption is normally applied in logic. Ships as `WARNING`, policy-gated (`enabled: false` by default), Low confidence. Firing it four times on TestApp as a High finding is exactly the false-positive inflation §22 warns about. |

*Source skill: `manage-security.md`, `xpath-constraints.md`, `mdl-entities.md`, `system-module.md`.*

### 6.4 Role hygiene

| ID | Rule | Sev | Conf | Detection |
|---|---|---|---|---|
| `SEC-023` | User role bypasses security | High | High | `userRole.checkSecurity === false` |
| `SEC-024` | Non-admin user role can manage all roles | Medium | High | `manageAllRoles === true` on a role that is not the designated administrator role |
| `SEC-025` | Module role not mapped to any user role | Low | High | Declared `Security$ModuleRole` absent from every `userRole.moduleRoles`. Dead grant surface. |

*Source skill: `manage-security.md`.*

### 6.5 Custom code, constants & integration

| ID | Rule | Sev | Conf | Detection |
|---|---|---|---|---|
| `SEC-007` | Regex-based XSS sanitiser | High | High | Existing. Scope-limit to `javasource/<user module>/actions/**` — a marketplace module's internals are not a customer design violation. |
| `SEC-026` | Hardcoded secret in a constant | High | Medium | `Constants$Constant` whose `Name` or `DefaultValue` matches the secret classifier and has a non-empty `DefaultValue`. Evidence records name + `ExposedToClient`, **not the value**. |
| `SEC-027` | Secret-bearing constant exposed to the client | Critical | High | `SEC-026` conditions **and** `ExposedToClient === true`. Client-exposed constants are readable by any browser session. |
| `SEC-004` | Published REST endpoint without authentication | Critical | High | Existing logic is correct; it has no input. Phase 1 declares `requires: ['publishedServices']` so absence of `Rest$*` units yields `NOT_APPLICABLE`, not a pass. Endpoint parsing lands when a fixture with published services exists. |
| `SEC-028` | Retrieve bypasses entity access | High | Medium | `ApplyEntityAccess === false` on a microflow retrieve (17 occurrences in the fixture). `requires: ['microflows']` ⇒ `NOT_ANALYZABLE` in Phase 1; specified now so Phase 3 has the contract. |
| `SEC-010` | Form data in browser localStorage | Low | Low | Existing. **Downgrade from Medium/High** and scope to user modules. Its one hit on TestApp is `FeedbackModule.LocalStorageKey = "mxfeedback-form-data"` (`ExposedToClient = true`) — a marketplace module's own cache key, i.e. a false positive on both counts: it is third-party code (§22) and the name match is a naming coincidence, not evidence of stored PII. Keep as `WARNING`, Low confidence. |

*Source skill: `manage-security.md`, `rest-client.md`, `java-actions.md`, `javascript-actions.md`, `project-settings.md`.*

### 6.6 Sensitive / PII classifier

`SEC-005`, `SEC-008`, `SEC-021`, `SEC-026` and `SEC-027` all depend on name classification, which is
currently duplicated as inline regexes in two files. Phase 1 extracts one module,
`packages/rules/src/classifiers/sensitivity.ts`, returning
`{ kind: 'secret' | 'pii' | 'none', matchedTerm, confidence }`.

- **secret**: `password`, `passwd`, `pwd`, `secret`, `token`, `apikey`, `api_key`, `privatekey`,
  `clientsecret`, `credential`, `ssn`, `creditcard`, `cvv`, `pin`
- **pii**: `email`, `phone`, `mobile`, `address`, `postcode`, `zipcode`, `dateofbirth`, `dob`,
  `passport`, `nationalid`, `bsn`, `iban`
- **Deny-list** to suppress known false positives: `tokenize`, `passwordpolicy`,
  `passwordhelptext`, `emailtemplate`, `addressline_label`, `hasphone`, `*_caption`, `*_label`

Any classifier hit must set finding confidence to at most Medium unless a second structural fact
corroborates it (e.g. `SEC-005` also reads the real attribute type ⇒ High).

### 6.7 Summary

| | Count |
|---|---|
| Existing `SEC-*` retained, re-grounded | 10 |
| New `SEC-*` | 18 |
| **Phase 1 catalogue total** | **28** |
| Added after Phase 1 (§6.9) | 1 (`SEC-029`) |
| Of which `NOT_ANALYZABLE` in Phase 1 by design | 1 (`SEC-004`) |
| Of which policy-gated off by default | 2 (`SEC-008`, `SEC-009`) |

Against §21's acceptance criteria this satisfies "every failed rule produces an evidence-backed
observation" and "every rule identifies its governance/skill source" for the Security family, and
partially satisfies the 30–40 rule target from Phase 3 — with 28 security rules alone.

### 6.8 Calibration changes made during implementation

Everything here was forced by running the catalogue against the reference project. Each change
removed a finding that was either untrue or unactionable; none of them weakened a rule that was
firing correctly.

**`SEC-028` is not `NOT_ANALYZABLE` after all.** §6.5 expected a microflow's entity-access setting
to be unreadable in Phase 1. `ApplyEntityAccess` and the allowed module roles are both top-level
scalars on the flow unit, so the rule runs. Only `SEC-004` is skipped by design, because it requires
`publishedServices`.

**Marketplace ownership splits severity, not just noise filtering.** `SEC-006`, `SEC-007` and
`SEC-028` each report a user module as `FAIL`/Critical-to-High and a marketplace module as
`WARNING` at one severity lower, with wording that says the source cannot be edited in place. The
reference project's three `SEC-006` hits were all Critical before this: one real
(`MyFirstModule.User` granted to guest) and two Atlas theme roles that are standard for a public
app. `SEC-028`'s only hit is `Atlas_Core.DS_Account_CurrentUser`, where the actionable change is to
withdraw the guest grant, not to edit a marketplace microflow — so that is what the recommendation
now says.

**Absence from the module inventory is how a platform module presents.** The `System` module has no
`Projects$Module` unit in `mprcontents` at all, so `ir.modules['System']` is `undefined` and the
first version of the platform check reported `System.User` as coming from "marketplace module
System". `isPlatformModule` in `packages/rules/src/security-facts.ts` treats an unknown module name
as platform for exactly this reason. `System.User` is granted to every user role by Mendix itself:
reporting it would fire on every project and could not be acted on if it did.

**`SEC-021` stays at High even when a guest role is involved.** Escalating to Critical made it
compound with `SEC-020` on the same member at the top weight — one member, two Critical findings.
Guest involvement is stated in the observation instead.

**`SEC-003` and `SEC-020` are restricted to persistable entities.** Create and write rights on a
non-persistable entity expose no stored data, and marketplace login forms are full of them.

**Two non-security rules were switched off as superseded.** `OPS-001` (hardcoded credential
constant) only fired when the constant's value survived into the IR, which redaction prevents;
`SEC-027` covers it from the redaction signature instead. `UI-002` (page without roles) scored the
same defect as `SEC-019` at High/`FAIL` against `SEC-019`'s Low/`WARNING`, and two contradictory
calibrations of one defect is worse than either.

**Two fact keys were added to close vacuous passes.** `microflowActivities` and `scheduledEvents`
are both `NOT_ANALYZABLE` in Phase 1. Without them, `factsAvailable` counts `PARTIAL` as available,
so `PERF-001/002/004` and `MF-001/002`/`NF-001` would have run against empty `activities` arrays and
*passed* — a project with a retrieve inside every loop would have scored full marks on performance —
and `OPS-002` would have read `extract/constants.ts`'s hardcoded empty `scheduledEvents` array as
"this project schedules nothing".

---

### 6.9 SEC-029 — no anonymous access to stored data

Added after Phase 1 at the request of the governance owner, whose standard is that the anonymous
user role holds **no** rights on persistable entities. `SEC-003` and `SEC-020` only covered create,
delete and write, so a guest-held role with read-only access to a stored entity passed everything.

- **Detection.** For every access rule on a persistable entity outside the platform modules, fire if
  the rule's module roles intersect the module roles of the user role selected on App Security's
  *Anonymous users* tab. One finding per access rule; the observation lists the rights granted
  and whether an XPath limits the rows.
- **Why no rights at all.** A rule with no member rights still lets a visitor retrieve the objects
  and follow their associations, so "no provision" means no access rule.
- **Non-persistable entities are exempt.** They store nothing, and they are how anonymous login,
  registration and public forms are meant to be modelled.
- **Marketplace entities** are reported as `WARNING` / Medium, as `SEC-006` does, because some
  marketplace modules expose data to their own anonymous role by design.
- **Overlap.** A rule that also allows create, delete or write additionally fires `SEC-003` /
  `SEC-020`. That is intentional: SEC-029 states the standard, the other two state how severe the
  breach is. TestApp gains one finding, `SEC-029-MyFirstModule.RequestForm#1`.

### 6.10 SEC-018 — anonymous pages judged by their data

Revised at the governance owner's request. Reachability alone reported every login page, although
a login page built on a non-persistable `LoginContext` exposes nothing. The rule now asks what the
page works with.

- **Page data.** `Page.dataEntities` lists the entities a page uses: data-source entity refs, page
  parameter types, attribute and association paths, embedded snippets (transitively), and the
  return entity of microflow and nanoflow data sources. Both the parser and the Studio Pro extension
  collect the page's qualified-name references and resolve them with the shared
  `resolveDataEntities` (`packages/application-ir/src/page-data.ts`), so they cannot disagree.
- **Persistability** follows the generalization chain; entities outside the IR (`System.*`) count as
  persistable. **Guest access** includes access rules inherited from a generalization.
- **Over-approximation.** A flow called from a button, not a data source, is counted if it returns an
  entity. For an exposure check, over-counting is the safe direction.
- **Fallback.** When a page's contents were not read (`dataEntities` undefined), the rule reverts to
  the Phase 1 behaviour rather than reading "no references" as "no data".

### 6.11 SEC-MF — microflow security rules

Five rules supplied by the governance owner, implemented in `packages/rules/src/microflow-security.ts`.
They read microflow bodies (`Microflow.parameters`, `Microflow.activities` in execution order) and
the model-wide reference index (`Microflow.referencedBy`, fact `modelReferences`). Only the Studio Pro
extension extracts these today; the archive parser marks both facts NOT_ANALYZABLE, so the web
analyzer skips the rules rather than passing them.

| ID | Rule | Sev | Detection as implemented |
|---|---|---|---|
| `SEC-MF-001` | Missing entity access on client interactions | Critical | Apply entity access off; an allowed role that is neither System nor named as an administrator; referenced by a page, snippet, layout or navigation document. |
| `SEC-MF-002` | Anonymous user write permissions | Critical | Allowed for a module role the Anonymous-tab user role holds; a create, change or delete whose entity resolves (through the variable) to a persistable entity. An unresolvable entity does not fire. |
| `SEC-MF-003` | Parameter ID tampering | High | Entity access off; client-callable (allowed roles set); an Object/List parameter changed or deleted with no earlier database retrieve constrained on `[%CurrentUser%]` and no earlier decision on `$currentUser`. |
| `SEC-MF-004` | Public endpoint missing auth logic | High | Published REST operation without authentication whose first two steps show no HttpRequest/HttpHeader use and no Java action named for auth, token, JWT or API-key checks. OData is not extracted yet. |
| `SEC-MF-005` | Dead/exposed privilege code | Medium | Allowed roles set, user module, and no reference from any unit (pages, layouts, navigation, flows, entity events, scheduled events, workflows, services, project settings) or from Java source. |

Activity types are normalised across spellings (`CreateChangeAction`/`CreateObjectAction` →
`CreateAction`, `ChangeAction`/`ChangeObjectAction` → `ChangeAction`). A Marketplace microflow is
reported as `WARNING` one severity lower, as elsewhere in the catalogue. SEC-MF-001 overlaps SEC-028,
which reports any role-callable microflow without entity access; SEC-MF-001 is the UI-triggered case.

### 6.12 SEC-EE-003 — broad default member rights

Supplied by the governance owner. Fires on every access rule whose *Default rights for new members*
is Read or Read and Write and which is granted to at least one standard role (not System, not named as
an administrator). High for the team's own entities; `WARNING`/Medium for Marketplace entities.

Basis: the Mendix security best practices (Implementing Access Rules) advise not setting a default
rule for read-and-write access, "this forces you to think about each attribute that is added to an
entity". A Read default is flagged by this governance standard for the same reason; the finding says
which of the two applies. Runs in both the archive parser and the Studio Pro extension, because it
needs only the access rule's default and roles. TestApp gains four Marketplace findings.

## 7. Intake hardening

Closing §2.4 against design §16.

**`packages/mendix-parser/src/extractor.ts`**

1. Replace the traversal check with resolution-based containment:
   `path.resolve(root, entry)` must satisfy `resolved === root || resolved.startsWith(root + sep)`.
   Reject entries whose ZIP attributes mark them as symlinks or non-regular files.
2. Enforce a **compressed-size limit** and a **compression-ratio limit** per entry and in aggregate
   (reject above ~100:1) before writing anything.
3. Count written bytes from the actual write, not `entry.header.size`; abort mid-extraction on
   breach and clean up the partial workspace.
4. Stream entries rather than `readFileSync` the whole archive; compute SHA-256 incrementally over
   a read stream.
5. **Skip-list on extraction**: `.git/`, `node_modules/`, `deployment/`, `.mendix-cache/`,
   `theme-cache/`, `releases/`. This serves §16's exclusion requirement *and* removes the bulk of
   TestApp's 61 MB. Record skipped paths and counts in `ExtractionResult` so dependency rules can
   still see that vendored content exists.
6. Keep the existing `finally`-based cleanup but stop swallowing its errors silently — report a
   failed cleanup on the run record — and add a startup sweep for workspaces under
   `tmpdir/mendix-analyzer` older than a configured TTL, plus a retention policy for `data/uploads`
   and `data/runs`.

**`apps/api`**

7. Cap upload size (`multer` `limits.fileSize`, default 250 MB, configurable) and validate the
   magic bytes `PK\x03\x04` plus a `.zip`/`.mpk` extension before accepting.
8. Replace `origin: '*', credentials: true` with an allow-list from `CORS_ORIGINS`, defaulting to
   `http://localhost:5173`.
9. Delete the hardcoded `c:\Users\<user>\Downloads\...` fallback in `app.controller.ts:128-141`; an
   unknown application ID returns 404.
10. Redact classified secrets before `StorageService.saveRun` and before report generation. Add a
    documented retention policy for `data/runs` and `data/uploads` with a configurable TTL.

These are the analyzer's own security posture. They are in Phase 1 because the security analyzer
cannot credibly report on an application's handling of untrusted input while mishandling its own.

---

## 8. Testing

TestApp is the primary security fixture. It is a strong one: it contains a weak admin password,
enabled demo users with plaintext credentials, a guest role holding two administrator module roles,
a permissive password policy, and 14 real access rules including XPath-constrained ones.

It is **referenced from `scratch/testapp_unpacked/TestApp-main`, not committed** — `mprcontents` is
18 MB, and a fixture that large is a poor thing to carry in the repository. `tests/helpers/fixture.mjs`
skips the fixture-dependent suites with a stated reason when it is absent, so a checkout without it
still runs the BSON reader tests and all 93 per-rule tests. The skip is loud on purpose: a
fixture-dependent test that silently passed when the fixture was missing would be the same defect
this analyzer exists to find.

Run with `npm test` (builds the packages first) or `npm run test:quick`.

1. **BSON reader unit tests** — `tests/bson-reader.test.mjs`. Round-trips all 14 element tags
   against an independent encoder written in the test file, so the reader is not verified against
   itself. Eight malformed-input cases each assert a `BsonParseError` with a byte offset, and one
   asserts explicitly that the reader does not return the elements it read before the corruption.
   Cross-validated against `./mxcli bson dump` for a sample of three page units — `mxcli` is a test
   oracle here, not a runtime dependency, and the test skips when the binary is absent.
2. **Extractor golden test** — `tests/extractor-golden.test.mjs`. Exact counts: **396** units
   (see Appendix A on the 397 in this spec), 8 modules, 8 entities, 17 microflows, 15 nanoflows,
   16 pages, 1 association, 14 access rules with 59 member-access entries, 3 user roles, 16 module
   roles, 2 demo users, 1 constant, 3 Java actions, 73 JavaScript actions. Lower bounds would have
   passed for the old parser too, so every figure is exact.
3. **Per-rule tests** — `tests/security-rules.test.mjs`. For each of the 28 rules, one IR that must
   fire and one or more that must not, built by hand in `tests/helpers/ir-builder.mjs` from a clean
   locked-down baseline that differs from the firing case by exactly one fact. 93 assertions in all.
   The quiet cases are the half that earns its keep: a rule that fires on TestApp may be firing for
   a reason nobody intended.
4. **Expected-findings snapshot** — `tests/expected-findings.test.mjs`. The full 20-finding set
   locked exactly, both directions: a new finding means a rule started firing on something nobody
   reviewed, a missing one means a real defect stopped being reported. `SEC-014`, `SEC-017`,
   `SEC-012`/`SEC-013` and `SEC-015` are also asserted individually per §9.7, along with the rules
   that must stay *silent* and the rules that must be *skipped* with the fact named.
5. **Negative-coverage test** — `tests/coverage-negative.test.mjs`. The fixture is copied with its
   one `Security$ProjectSecurity` unit removed and re-analyzed, so the only thing that can move is
   what the analyzer is willing to claim. Asserts `coverage.projectSecurity === 'NOT_ANALYZABLE'`,
   that no enabled rule reading that fact is evaluated, that the Security *and* Compliance scores
   are suppressed, and that coverage drops. This test failed when first written: the run reported
   Security 100 and overall 100 against 65 and 79 for the same project intact, because the rules
   that were failing could no longer run. §4.2 records the fix.
6. **Malicious-archive tests** — **not implemented.** These belong to work item 12 (extractor
   hardening, §7.1–7.6), which is outside the selected Phase 1 scope; the intake path they would
   exercise has not been changed. §9.9 therefore remains unmet, and this is the only acceptance
   criterion that is unmet by choice rather than by defect.
7. **Secret-redaction test** — `tests/redaction.test.mjs`. Searches the IR, a run record persisted
   exactly as `StorageService.saveRun` writes it, the JSON report and the HTML report for
   `AdminPassword`, the two demo user passwords. It first asserts those three strings really
   are in the fixture's security unit: a redaction test hunting a value the fixture never contained
   would pass forever and prove nothing. The administrator *username* `MxAdmin` is expected to
   appear — that is what makes the finding actionable — and is the only credential-adjacent string
   anywhere in the output.

---

## 9. Acceptance criteria

Phase 1 is done when, with the verifying test named against each:

1. ✅ Entity, page and attribute facts in the IR come from `mprcontents` BSON units; no field is
   populated by a hardcoded or inferred default. — §8.2
2. ✅ Entity count for TestApp is 8, not 72. Page count is 16 real pages, not 8 synthetic ones.
   Attribute types are the model's types. — §8.2
3. ✅ No `SEC-*` rule is structurally incapable of firing. Every rule has a test that makes it fire.
   — §8.3, which also asserts the catalogue is exactly 28 rules and that every one of them appears
   in the table.
4. ✅ A rule whose required facts are unavailable reports `NOT_APPLICABLE` and is excluded from both
   the numerator and the denominator of every score. — §8.4, §8.5
5. ✅ An unreadable or malformed project produces a **lower** coverage figure and a suppressed
   Security score — never a higher compliance score. — §8.5. This one needed the §4.2 scoring fix
   and the suppression of `Compliance`; it was failing when the test was written.
6. ✅ Every `SEC-*` finding's `Evidence.artifactPath` resolves to a real `.mxunit` path plus `$ID`,
   and its `sourceSkill` names a file that exists in `skills/`. — §8.4. `artifactPath` is the
   logical path (`MyFirstModule.RequestForm.Email`); the `.mxunit` path is asserted through
   `Evidence.details.unitPath`, which is checked to exist on disk wherever a finding carries one.
   `SEC-007` is anchored to a `.java` file rather than a unit, by nature.
7. ✅ TestApp's `SEC-014`, `SEC-017`, `SEC-012`, `SEC-013` and `SEC-015` findings are produced —
   five real security defects the analyzer missed. — §8.4, asserted individually.
8. ✅ No secret value appears in the IR, any persisted run, or any generated report. — §8.7
9. ❌ All seven malicious-archive tests pass; temp workspaces are removed after every run. —
   **not met**, and not attempted: work item 12 is out of the selected scope. The intake path is
   unchanged from the state §2.4 describes.
10. ❌ The dashboard shows a coverage indicator and renders `NOT_APPLICABLE` findings distinctly
    from passes. — **not met**, and not attempted: work item 15 is out of the selected scope. The
    figures it needs (`coveragePercentage`, `assessmentIsIncomplete`, `unassessedCategories`) are
    in `ScoreReport` already.

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| BSON layout differs across Mendix versions | Version-tolerant reader: read by property name, never by offset; unknown `$Type` values are collected into `coverage.notes` rather than dropped silently. Fixtures for each supported major version. |
| Only one fixture (Mendix 11.12.4, web profile) | Acceptance criteria are fixture-count-specific; a second fixture (native, and one with published REST services) is a Phase 2 prerequisite. Recorded as a known limitation, not silently assumed away. |
| Correct extraction raises finding counts and lowers scores | Expected and correct — current scores are inflated by rules that cannot fire. Communicate as a **baseline reset**; the trend view (§Dashboard) must not compare pre- and post-Phase-1 runs as if they were commensurable. |
| Classifier false positives on names | Deny-list, confidence caps, and `SEC-008` off by default. |
| `SEC-017` may fire on legitimate Atlas configurations | Verify against a second fixture before shipping at Critical; if Atlas admin-on-guest turns out to be a Studio Pro default, reclassify to Medium with the rationale recorded in the rule's `whyItMatters`. |
| Renumbering breaks stored runs | Existing IDs are retained. New rules only append. |

---

## 11. Work breakdown

| # | Deliverable | Depends on | Status |
|---|---|---|---|
| 1 | BSON reader + unit index + tests | — | Done |
| 2 | `FactCoverage` / `Analyzability` in `application-ir`; `Rule.requires` | — | Done |
| 3 | Engine honours `requires`; `NOT_APPLICABLE` accounting | 2 | Done |
| 4 | Scoring correction + coverage reporting + Security suppression | 3 | Done (§4.2) |
| 5 | Security extractor (`Security$ProjectSecurity`, `ModuleSecurity`) | 1, 2 | Done |
| 6 | Domain-model extractor (entities, attributes, access rules, associations) | 1, 2 | Done |
| 7 | Page extractor + computed anonymous reachability | 1, 5 | Done |
| 8 | Constants extractor with correct module attribution | 1 | Done |
| 9 | `ir-builder` de-fabrication; drop proxy-derived entities and synthetic pages | 5–8 | Done |
| 10 | Sensitivity classifier module | — | Done |
| 11 | Rule catalogue: re-ground 10, add 18 | 5–10 | Done (§6.8) |
| 12 | Extractor hardening (§7.1–7.6) | — | **Not built** — out of selected scope |
| 13 | API hardening + secret redaction (§7.7–7.10) | 10 | **Not built** — out of selected scope |
| 14 | Fixture reference + full test suite | 1–13 | Done, less the item-12 tests (§8.6) |
| 15 | Dashboard coverage indicator + `NOT_APPLICABLE` rendering | 4 | **Not built** — out of selected scope |

Items 12, 13 and 15 were deliberately excluded. The consequence to be aware of when reading a run:
the intake path still has the §2.4 archive weaknesses, redaction is enforced in the extractor (and
tested, §8.7) but not at the API boundary, and the dashboard shows scores without the coverage
figure that qualifies them. `assessmentIsIncomplete` and `coveragePercentage` are in the
`ScoreReport` and waiting for item 15 to render them.

Items 1–4 are the critical path; nothing else can be trusted until the analyzability contract
exists. Items 12 and 13 are independent and can run in parallel.

---

## Appendix A — Verified fixture facts

TestApp (`scratch/testapp_unpacked/TestApp-main`), Mendix 11.12.4, 396 `.mxunit` units.

> The figure was 397 in the specification. `mprcontents` holds 397 *files*: 396 `.mxunit`
> documents plus `mprname`. `tests/extractor-golden.test.mjs` asserts 396.

| Unit `$Type` | Occurrences |
|---|---|
| `Security$ProjectSecurity` | 1 |
| `Security$PasswordPolicySettings` | 1 |
| `Security$DemoUserImpl` | 2 |
| `Security$UserRole` | 3 (Administrator, User, Anonymous) |
| `Security$ModuleSecurity` | 8 |
| `Security$ModuleRole` | 16 |
| `Projects$ModuleImpl` | 8 |
| `DomainModels$EntityImpl` | 8 |
| `DomainModels$AccessRule` | 14 |
| `Forms$Page` | 16 |
| `Forms$Snippet` | 5 |
| `Microflows$Microflow` | 17 |
| `JavaScriptActions$JavaScriptAction` | 71 |
| `JavaActions$JavaAction` | 2 |
| `Constants$Constant` | 1 |
| `Settings$ProjectSettings` | 1 |
| `Navigation$NavigationDocument` | 1 |
| `Rest$PublishedRestService` | 0 |

Reported by the analyzer today for the same project: 72 entities, 0 microflows, 8 pages,
73 nanoflows, Security 66/100, 14 findings.

## Appendix B — `.mxunit` BSON encoding

Standard BSON. Document: `int32 totalLength` · elements · `0x00`.

| Tag | Type | Used for |
|---|---|---|
| `0x02` | UTF-8 string (`int32` length incl. terminator) | `$Type`, `Name`, `XPathConstraint`, enum values |
| `0x03` | Embedded document | nested objects (`Appearance`, `MicroflowSettings`, `DeleteBehavior`) |
| `0x04` | Array | `AccessRules`, `Attributes`, `Widgets`, `ModuleRoles` |
| `0x05` | Binary, subtype `0x00`, 16 bytes | `$ID` (GUID) |
| `0x08` | Boolean | `AllowCreate`, `Persistable`, `CheckSecurity`, `EnableGuestAccess` |
| `0x0A` | Null | absent optional references |
| `0x10` | int32 | `CanvasHeight`, array version markers |
| `0x12` | int64 | `LabelWidth`, `TabIndex` |

Arrays carry an int32 **version marker** at key `"0"`; real items start at key `"1"`. Property
order within a document is not semantically meaningful and must not be relied on — the current
flat scanner's dependence on ordering (`mpr-parser.ts:694-736`) is the root cause of §2.3.

Cross-check any reader change with `./mxcli bson` on the same unit.
