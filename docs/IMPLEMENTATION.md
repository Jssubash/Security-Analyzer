# How the Security Analyzer is built

This document explains the architecture, how the model is read, how each group of rules decides,
and the design decisions behind them. For installing and using the extension, see the
[README](../README.md).

---

## 1. Architecture

The extension has two halves: a small C# host that Studio Pro loads, and a web page shown in a
dockable pane that does all of the analysis.

```
 Studio Pro
 ┌──────────────────────────────────────────────────────────────────────┐
 │  C# host (extension/dotnet)                                          │
 │   SecurityAnalyzerMenu        Extensions ▸ SecurityAnalyzer ▸ Open   │
 │   SecurityAnalyzerPane        dockable pane + message handling       │
 │   SecurityAnalyzerWebServer   serves index.html / app.js / app.css   │
 │   ModelSnapshotReader         untyped model API → JSON snapshot      │
 │   SecretRedactor              passwords → length + character classes │
 └───────────────▲──────────────────────────────┬───────────────────────┘
                 │ RunAnalysis, OpenUnit,       │ Snapshot (JSON),
                 │ ExportReport, …              │ OpenUnitResult, ExportDone
 ┌───────────────┴──────────────────────────────▼───────────────────────┐
 │  Pane (extension/src, runs in Studio Pro's WebView2)                 │
 │   snapshot/build-ir.ts     snapshot → Application IR                 │
 │   snapshot/microflow-body  parameters + activities in execution order│
 │   analyze.ts               rule engine + scoring (packages/*)        │
 │   module-status.ts         the Module status tab's model             │
 │   ui/                      Findings, Rules, Module status, export    │
 └──────────────────────────────────────────────────────────────────────┘
```

**Why split it this way.** Studio Pro gives extensions a C# API. Everything that decides — the
mapping from model to facts, the rules, the scoring — lives in TypeScript, where it is shared with
the rest of the governance analyzer (`packages/*`) and can be tested with Node against a real app
without Studio Pro. The C# host copies the model and never interprets it, so there is one place
where a rule's logic can be wrong, and it is tested.

**Version support.** The host is compiled against `Mendix.StudioPro.ExtensionsAPI` 10.23.0, the
newest 10.x package below 10.24, targeting `net8.0`. Studio Pro 10.24 runs on .NET 8 and 11.x on
.NET 10; a net8.0 assembly referencing an older API version loads in both. Studio Pro supplies the
API assembly at run time, so none of it is copied into the output.

---

## 2. The run, step by step

1. The user presses **Run analysis**. The pane posts `RunAnalysis` to the host
   (`window.chrome.webview.postMessage`).
2. `ModelSnapshotReader` walks the open model through `IUntypedModelAccessService` and builds a JSON
   **snapshot** (§3). It runs on Studio Pro's UI thread, where the model may be read, so unsaved
   changes are included.
3. The host saves a copy to `%LOCALAPPDATA%\Mendix Security Analyzer\last-snapshot.json` for
   troubleshooting and posts the snapshot to the pane.
4. `buildIrFromSnapshot` turns it into the **Application IR** — the model the rules read — and
   records which facts could and could not be read (`coverage`).
5. `analyzeSnapshot` runs the rule catalogue with the rule engine and scores the result.
6. The pane renders the result. **Open in Studio Pro** posts `OpenUnit` back to the host, which opens
   the document (selecting the entity, for entity findings).

---

## 3. Reading the model

### 3.1 The snapshot

The host collects, per module:

| Unit | Read | Why |
|---|---|---|
| `Security$ModuleSecurity` | in full | module roles |
| `DomainModels$DomainModel` | in full | entities, attributes, access rules, generalizations |
| `Pages$Page`, `Forms$Snippet` | shallow + `$References` | allowed roles; which entities and flows they name |
| `Microflows$Microflow` | in full | allowed roles, entity access, parameters, activities, flows |
| `Microflows$Nanoflow` | shallow + `$References` | allowed roles; which flows they call |
| `Constants$Constant` | in full | secret-shaped constants |
| `Rest$PublishedRestService` | in full | endpoints and authentication |

and at project level `Security$ProjectSecurity` and `Navigation$NavigationDocument`, plus the Java
action sources under `javasource/*/actions` (for the regex-sanitiser rule).

"Shallow" means top-level properties only. Pages can be megabytes of widgets; the rules need their
allowed roles and a compact **`$References`** list — every by-name reference found anywhere in the
unit (entity refs, attribute paths, snippet calls, data-source microflows) — not the widget tree.

The **reference index** records, for *every* unit in the app (layouts, scheduled events, workflows,
entity event handlers, import mappings, published services, project settings…), which microflows it
refers to. It is what lets SEC-MF-005 say a microflow is referenced *nowhere*.

### 3.2 Two naming conventions

Studio Pro's untyped API names things by the metamodel; the `.mxunit` files on disk (what the tests
read) use storage names. They differ in places, verified against Studio Pro 11.12:

| Fact | On disk | In Studio Pro |
|---|---|---|
| Page unit type | `Forms$Page` | `Pages$Page` |
| Anonymous user role | `GuestUserRole` | `guestUserRoleName` |
| Page allowed roles | `AllowedModuleRoles` | `allowedRoles` |
| Access rule roles | `AllowedModuleRoles` | `moduleRoles` |
| Entity generalization | `MaybeGeneralization` | `generalization` |
| Attribute type | `NewType` | `type` |
| Create-object activity | `CreateChangeAction` | `CreateObjectAction` |

All reads go through `snapshot/accessors.ts`, which matches property names case-insensitively and
takes every candidate spelling. `tests/naming.test.mjs` rewrites the reference project into
metamodel naming and asserts the analysis is identical, so a reader that knew only one spelling
would fail the build.

### 3.3 Never invent, never keep a secret

- **Never invent.** A fact that could not be read stays `undefined`, and the facts each rule needs
  are declared in its `requires`. When one is `NOT_ANALYZABLE` the engine records the rule *Not
  applicable* instead of running it — an analyzer that could not read the access rules must not
  report "access rules are fine". If project security cannot be read, the Security score is
  withheld.
- **Never keep a secret.** `SecretRedactor` replaces the administrator and demo-user passwords with
  their length and character classes before the snapshot leaves the host. Constant values that
  classify as secrets are dropped during IR building. Nothing the pane shows or exports contains a
  credential; `tests/golden.test.mjs` checks this against the reference project.

### 3.4 Microflow bodies

`snapshot/microflow-body.ts` reads a microflow's `ObjectCollection` (including loop bodies) and its
sequence flows, and recovers **execution order** by walking the flows from the start event.
Activities are normalised (`CreateAction`, `ChangeAction`, `DeleteAction`, `CommitAction`,
`RetrieveAction`, `MicroflowCall`, `JavaActionCall`, `Decision`, …). For each change, delete and
commit it resolves the entity through the variable: parameters, create outputs and database
retrieves carry their entity; an association retrieve does not, so its entity stays unknown.

---

## 4. How the rules decide

The catalogue is `packages/rules/src/security.ts` and `microflow-security.ts`. Each rule declares
its metadata (severity, why it matters, recommendation, source), the facts it `requires`, and a
`check` that emits findings. Evidence carries locations and classifications, never values.

### 4.1 Anonymous access

The anonymous user is found through App Security's **Anonymous users** tab: if anonymous users are
allowed, the selected user role's module roles are the *anonymous-held* roles. Every anonymous rule
reasons over those roles — never over role names.

- **SEC-003 / SEC-020 / SEC-029** — access rules on persistable entities granted to an anonymous-held
  role: create/delete (Critical), member write (High), any access at all (High). Non-persistable
  entities are exempt: they store nothing, and they are how login and registration forms are built.
- **SEC-018** — an anonymous page is judged by **the data it uses**, not by being open. Its entities
  are resolved from its references, embedded snippets and data-source flows' return types
  (`packages/application-ir/src/page-data.ts`, shared by parser and extension). Only non-persistable
  data → no finding (a login page on `LoginContext`). Persistable data the anonymous role can read →
  High. Persistable data it cannot read → Review.

### 4.2 Entity access

- **SEC-001** — a persistable entity in your module with no access rule.
- **SEC-EE-003** — an access rule whose *Default rights for new members* is Read or Read and Write,
  for a standard (non-System, non-administrator) role. Mendix's security best practices advise
  against read-and-write defaults so each new attribute is considered; this standard also flags Read.
- Persistability follows the generalization chain; access rules of a generalization count for its
  specializations.

### 4.3 Microflow rules (SEC-MF)

| Rule | Decides on |
|---|---|
| **SEC-MF-001** | entity access off + allowed for a non-administrative role + referenced by a page, snippet, layout or navigation |
| **SEC-MF-002** | allowed for an anonymous-held role + a create/change/delete whose entity resolves to a persistable one |
| **SEC-MF-003** | entity access off + client-callable (has allowed roles) + an Object/List parameter changed or deleted before any `[%CurrentUser%]` retrieve or `$currentUser` decision |
| **SEC-MF-004** | published REST operation without authentication + neither of the first two steps reads HttpRequest/HttpHeader or calls an auth/token/JWT Java action |
| **SEC-MF-005** | allowed roles set, in your module, and no reference anywhere in the reference index or Java source |

SEC-MF-004 recognises header checks by pattern and is marked Medium confidence; published OData
services are not read yet. The archive parser does not extract microflow bodies or the reference
index, so outside the extension these rules are *Not applicable*, not passed.

### 4.4 Severity calibration

- **Marketplace code** is reported as *Review* one severity lower. The team cannot edit it in place,
  and the fix is usually the role mapping.
- **Platform modules** (`System`) are ignored — `System.User` is granted to every user role by Mendix.
- Two advisory rules (SEC-008, SEC-009) are off by default because the model cannot confirm them.

---

## 5. Scoring

Each failing finding costs `Critical 25 · High 10 · Medium 4 · Low 1`, half for a *Review*; the
Security score is `100 − 4 × penalty ÷ rules that ran`. Rules that could not run count neither for
nor against, and the pane shows **coverage** (the share of rules that ran) next to the score. The
risk rating comes from the overall score (all rules, `100 − 3.5 × penalty ÷ rules that ran`) and the
Critical count: F below 50 or with three or more Critical findings, D below 65 or with any Critical
finding, then C below 75, B below 88, otherwise A.

---

## 6. Opening documents in Studio Pro

`OpenUnit` tries, in order:

1. open the unit by id (`IModel.TryGetAbstractUnitById` + `IDockingWindowService.TryOpenEditor`);
   for entity findings, open the module's domain model with the entity passed as the element to
   focus;
2. look the document up by name among its module's documents;
3. if Studio Pro still cannot open it — the extensions API has no nanoflow type through 11.12 — tell
   the user its App Explorer path (worked out from the folders that contain it) and copy its name
   for the App Explorer search.

---

## 7. Testing

| Suite | What it proves |
|---|---|
| `tests/security-rules.test.mjs` | every rule fires on its defect and stays quiet on near-misses, each pair differing by one fact |
| `tests/expected-findings.test.mjs` | the exact finding set, counts and scores on the reference project |
| `tests/coverage-negative.test.mjs` | removing the security unit lowers coverage and withholds scores — never raises them |
| `extension/tests/golden.test.mjs` | the extension reaches the same findings and score as the archive parser; no credential leaks |
| `extension/tests/naming.test.mjs` | Studio Pro and storage naming give identical results |
| `extension/tests/snapshot-build.test.mjs` | REST services, weak passwords, element-shaped references, page data |
| `extension/tests/module-status.test.mjs` | Module status sections, grants, callers, entity focus |

The reference-project suites need an unpacked Mendix app; see the README.

---

## 8. Known limitations

- Published **OData** services, scheduled-event settings and consumed services are not read.
- **SEC-MF-004** detects header checks by pattern; a custom check under another name can be missed.
- An object retrieved **over an association** has no resolved entity, so SEC-MF-002 does not count a
  change to it.
- **Nanoflows** cannot be opened directly through the extensions API; the pane gives their location.
- Studio Pro's App Security dialog remains the authority on its own *Complete / Incomplete* status;
  Module status explains this analyzer's own checks.
