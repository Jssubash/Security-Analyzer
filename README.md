# Mendix Security Analyzer

A Mendix Studio Pro extension that checks the app you have open against **36 security governance
rules**: project security, anonymous access, entity and page access, role hygiene, credentials,
constants and microflow security. Findings explain what was found, why it matters and how to fix it,
and link straight to the document in Studio Pro.

It also inventories what the app ships beyond the model:

- **Java libraries** — every jar in `userlib` and `vendorlib`, split into Marketplace and custom
  libraries, with duplicates and known vulnerabilities.
- **Upgrades** — every Marketplace module and widget, the version that suits the app's Mendix
  version (or the one you are moving to), and known vulnerabilities in the libraries bundled into
  widgets.
- **Accepted risks** — reviewed advisories the team has decided to live with, with a reason, who
  accepted them and a review date, kept in the app folder and committed with the app.

- **Studio Pro 10.24.0 and later**, including 11.x
- Reads the model **as it is open**, unsaved changes included
- The analysis runs on your machine. The optional checks send only what they must — see
  [What leaves your machine](#what-leaves-your-machine)

---

## Contents

1. [What it checks](#what-it-checks)
2. [Requirements](#requirements)
3. [Build](#build)
4. [Install into a Mendix app](#install-into-a-mendix-app)
5. [Using the extension](#using-the-extension)
6. [What leaves your machine](#what-leaves-your-machine)
7. [Sharing it as an add-on module](#sharing-it-as-an-add-on-module)
8. [Troubleshooting](#troubleshooting)
9. [Repository layout](#repository-layout)
10. [Tests](#tests)

For how it is built — architecture, data flow and how each rule is detected — see
[docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md). The original rule specification is in
[docs/security-specification.md](docs/security-specification.md).

---

## What it checks

| Rule | Checks | Severity | Area |
|---|---|---|---|
| `SEC-002` | Application security level not production ready | Critical | Project Security |
| `SEC-011` | Application security disabled | Critical | Project Security |
| `SEC-012` | Demo users enabled | High | Project Security |
| `SEC-013` | Demo user credentials stored in the model | High | Credentials |
| `SEC-014` | Weak or default administrator password | Critical | Credentials |
| `SEC-015` | Password policy below baseline | Medium | Project Security |
| `SEC-016` | Strict page URL check disabled | Medium | Project Security |
| `SEC-006` | Guest role granted a business module role | Critical | Anonymous Access |
| `SEC-017` | Guest role granted an administrator module role | Critical | Anonymous Access |
| `SEC-018` | Anonymous page uses persistable data | High | Anonymous Access |
| `SEC-019` | Page with no allowed module roles | Low | Page Access |
| `SEC-009` | Anonymous submissions unthrottled *(advisory, off by default)* | Informational | Abuse Prevention |
| `SEC-001` | Persistable entity with no access rules | Critical | Entity Access |
| `SEC-003` | Guest-reachable role has create or delete rights on an entity | Critical | Anonymous Access |
| `SEC-020` | Guest-reachable role has write access to a member | High | Anonymous Access |
| `SEC-029` | Anonymous role has access to a persistable entity | High | Anonymous Access |
| `SEC-022` | Owned-data entity without an XPath constraint | Medium | Entity Access |
| `SEC-EE-003` | Broad read/write access defaults (lazy rule definition) | High | Entity Access |
| `SEC-005` | Password or secret attribute stored as plain text | High | Data Privacy |
| `SEC-008` | PII stored without encryption *(advisory, off by default)* | Medium | Data Privacy |
| `SEC-023` | User role bypasses security | High | Role Hygiene |
| `SEC-024` | Non-administrator user role can manage all roles | Medium | Role Hygiene |
| `SEC-025` | Module role not mapped to any user role | Low | Role Hygiene |
| `SEC-026` | Hardcoded secret in a constant | High | Credentials |
| `SEC-027` | Secret-bearing constant exposed to the client | Critical | Credentials |
| `SEC-010` | Form data cached in browser localStorage | Low | Data Privacy |
| `SEC-004` | Published REST endpoint without authentication | Critical | Integration Security |
| `SEC-028` | Microflow callable by a role runs without entity access (not started from a page) | High | Microflow Security |
| `SEC-MF-001` | Microflow started from a page runs without entity access | Critical | Microflow Security |
| `SEC-MF-002` | Anonymous user write permissions | Critical | Anonymous Access |
| `SEC-MF-003` | Microflow trusts the object the browser sends (ID tampering) | High | Microflow Security |
| `SEC-MF-004` | Public endpoint missing auth logic | High | Integration Security |
| `SEC-MF-005` | Dead/exposed privilege code | Medium | Microflow Security |
| `SEC-MF-006` | Integration call without error handling and logging | High | Integration Security |
| `SEC-MF-007` | Value converted without an empty check | Medium | Data Integrity |
| `SEC-MF-008` | Role can run the microflow but lacks the entity access its activities need | Critical | Microflow Security |

Findings in **Marketplace modules** are shown as *Review* one severity lower: you cannot edit that
code in place, and the fix is usually the role mapping rather than the module.

---

## Requirements

| To | You need |
|---|---|
| Use the extension | Mendix Studio Pro 10.24.0 or later, on Windows |
| Build it | [Node.js](https://nodejs.org) 20 or later, and the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) |

> **Windows Smart App Control.** If Smart App Control is on (Windows Security ▸ App & browser
> control), Windows blocks unsigned DLLs you build yourself, and Studio Pro cannot load the
> extension. Sign `SecurityAnalyzer.dll` with a trusted code-signing certificate, or build and use it
> on a machine where Smart App Control is off.

---

## Build

```bash
npm install
npm run build
```

`npm run build` does three things:

1. builds the shared packages (`packages/*`: model types, rule engine, rules, scoring, parser);
2. builds the pane's web page into `extension/dotnet/wwwroot/` (`index.html`, `app.js`, `app.css`);
3. compiles the Studio Pro extension, `extension/dotnet/bin/Release/net8.0/SecurityAnalyzer.dll`.

---

## Install into a Mendix app

Studio Pro loads extensions from the app's own `extensions` folder. Close Studio Pro first (it
locks the DLL while the app is open), then run from the `extension` folder:

```powershell
.\scripts\install.ps1 -AppDirectory "C:\path\to\YourApp" -Build
```

- `-AppDirectory` is the folder that contains your app's `.mpr` file.
- `-Build` rebuilds everything first; leave it out to copy the last build.

This creates `YourApp\extensions\SecurityAnalyzer\` with `manifest.json`, `SecurityAnalyzer.dll`
and `wwwroot\`. You can also copy those three by hand from `extension\dotnet\bin\Release\net8.0\`.

To update **every app that already has the extension** in one go:

```powershell
.\scripts\update-installed.ps1                 # apps under %USERPROFILE%\Mendix that have it
.\scripts\update-installed.ps1 -Build          # rebuild once first
.\scripts\update-installed.ps1 -All            # install into every app found, not only those that have it
.\scripts\update-installed.ps1 -AppsRoot "D:\Projects\Mendix" -WhatIf   # another folder; list only
```

Start Studio Pro with extension development enabled — required for extensions not installed from
the Marketplace:

```powershell
& "C:\Program Files\Mendix\<version>\modeler\studiopro.exe" --enable-extension-development
```

> If the app is under version control, Studio Pro's Changes pane will list the extension's files.
> Add `extensions/SecurityAnalyzer/` to the app's `.gitignore` if you do not want to commit them.

---

## Using the extension

Open the app, then choose **Extensions ▸ SecurityAnalyzer ▸ Open Security Analyzer**. The pane opens
docked in Studio Pro. Press **Run analysis**.

### Summary

- **Security score** out of 100 and a **risk rating** (A–F). The score is *Not assessed* when the
  project's security settings cannot be read — a score is never shown for data the analyzer did not see.
- **Critical / High / Medium / Low** counts. Click a tile to filter the findings to that severity.
- **Rules passed**, **failed / warnings**, **not applicable**, and **coverage** — the share of rules
  that could run.

### Findings tab

Each finding shows its severity, the rule, the affected document and what was observed. Click it to
expand:

- **Why it matters**, **Recommendation** and **Expected practice**
- **Evidence** — the roles, entities, members or settings involved
- **Open in Studio Pro** — opens the document. For entity findings the domain model opens with the
  entity selected.
- **Show activity** (SEC-MF-007, next to each member in the evidence) — opens the microflow with that
  Create or Change object activity selected.

Filters: search text, the rule drop-down, and the severity tiles above the tabs.

### Rules tab

All 36 rules grouped by area, each marked **Passed**, **Failed**, **Review**, **Not applicable**
(with the reason, e.g. the app publishes no REST services), **Not verified** or **Off**.

Click a rule to expand exactly what it validates: where in Studio Pro it looks, each condition that
reports a finding, what it deliberately leaves alone, why it matters and how to fix it.

**Not verified** means a value the rule depends on (a flag, a role list, a password policy setting)
could not be read from the open app. Finding nothing in a value that was never read proves nothing,
so the rule is not counted as a pass and is left out of the score.

SEC-007 (regex-based XSS sanitiser in a Java action) and SEC-021 (sensitive or PII member readable by
a broad role) were removed from the catalogue; see `docs/security-specification.md` §6.13.

### Module status tab

Studio Pro's *App Security ▸ Module status* only says *Complete* or *Incomplete*. This tab says why,
for each of your modules (Marketplace modules behind a toggle):

- **Tiles** for Entity access, Page access, Microflow access, Nanoflow access and Anonymous exposure,
  each with a status and a one-line summary, e.g. *3 of 4 persistable entities have access rules*.
- **Entity access** — every entity and each role's rights in words
  (`MyModule.User — create · delete · read 6 · write 3 · XPath`); entities without rules in red,
  anonymous grants highlighted.
- **Page access** — every page and its allowed roles; anonymous pages judged by the data they use.
- **Microflow / Nanoflow access** — allowed roles, whether entity access is applied, and **where the
  flow is used as a sub-microflow or sub-nanoflow** (*Called by*), with each caller clickable.
- **Module roles** — which user roles hold each module role.

### Java libraries tab

Every `.jar` in `userlib` and `vendorlib`, in two groups:

- **Marketplace libraries** — needed by a Marketplace module. The module chooses the version, so the
  fix is to update the module, not the jar.
- **Custom libraries** — declared by your own modules (*Settings ▸ Java Dependencies*), added to
  `userlib` by hand, or left behind by a removed module.

Which module needs a jar is worked out from each module's declared Java dependencies and the
dependency graph in `vendorlib/vendorlib-sbom.json` (transitive dependencies included), and from the
`.RequiredLib` marker files in `userlib`.

- **Duplicate libraries** — the same library present more than once, matched **by name whatever the
  version** (`commons-io-2.3.4.jar` and `commons-io-3.4.5.jar`). Only one copy is loaded at run time,
  so each group says which copy is owned by whom and what to remove.
- **Check for vulnerabilities** — re-reads `userlib` and `vendorlib`, looks every library (and
  libraries shaded inside jars) up in [OSV.dev](https://osv.dev), then finds a safe version on Maven
  Central for each vulnerable one. Each advisory shows severity, CVE and the fixed version.
- **How to resolve** — on every vulnerable library: the release to move to and numbered steps.
  The suggested release is the newest one in the same major version that fixes every advisory, has
  no known advisory of its own, is compiled for the app's Java version (read from the jar's class
  files), and — when the problem was a bundled library — bundles a fixed version of it or none.
  - *vendorlib*: which module's *Settings ▸ Java Dependencies* row to edit, the version to set, the
    exclusions to keep, then test the module's features. **Open <Module> settings in Studio Pro**
    opens that dialog. Editing a Marketplace module's row is lost when the module is updated, so
    check again after each module update.
  - *userlib*: download the jar from Maven Central (**Open on Maven Central**), replace the old one,
    rename its `.RequiredLib` marker, run the app to confirm the Java actions compile, and test.
- **Cards** (Libraries, Marketplace, Custom, Vulnerable, Critical / High, Duplicates, Accepted risks,
  Cannot be checked) filter the list; click again to show everything.
- **Open folder** shows the jar selected in Windows Explorer.

### Upgrades tab

The Marketplace modules and widgets in the app, judged against the Mendix version of the app the
extension is running in (read from the app, not chosen).

- **Modules** are identified exactly by the Marketplace content id the model records. **Widgets**
  (`widgets/*.mpk`) are grouped by what the files show: a widget with the same name and version as a
  Marketplace module is shown with that module, and widgets whose ids share a namespace are shown as
  one family. Each widget is matched to the Marketplace catalog by name; a widget the Marketplace does
  not list on its own (or whose only name match has releases all older than the installed one) is
  reported as probably installed by a module. Mendix records no other link between a module and the
  widgets its import wrote, so the extension assumes none.
- **Run checks** does both checks in one go:
  - **Compatibility** — reads every published version and its minimum Mendix version from the
    Marketplace Content API. Needs a Mendix Personal Access Token (*user-settings.mendix.com ▸
    Developer Settings ▸ Personal Access Tokens*, Marketplace content read scope); type it once, or
    tick *Remember on this computer* (encrypted with Windows DPAPI for your account), or set
    `MENDIX_PAT`.
  - **Widget vulnerabilities** — looks the npm libraries bundled into each widget (its
    `dependencies.json`) up in OSV.dev. Only a widget's **direct** libraries count; for native
    widgets the indirect ones include the build toolchain and are listed separately, not counted.
- Each item says **Up to date**, **Update available**, **Update recommended** (built for an older
  major Mendix line), **Incompatible** (needs a newer Mendix) or **No compatible version**, with the
  version to use. A vulnerable widget gets a secure-version suggestion for the Mendix version: the
  release to move to, the module to update, or — when only a newer Mendix has one — which.
- **Cards**: Everything, Marketplace modules, Widgets, Updates available (everything that should
  change, vulnerable widgets included), Vulnerable widgets, Accepted risks, Up to date, Not assessed.

### Accepted risks

An advisory that has been reviewed and judged acceptable for now can be **accepted**: expand the
library (Java libraries tab) or widget (Upgrades tab), and click **Accept risk…** under the advisory.

- Give a **reason** (at least 15 characters) and a **review-by date** (90 days by default, at most a
  year). Who accepted it and when are recorded by the extension, not typed in: your Git name and email (`user.name` / `user.email`
  from the app's `.git/config`, else your global `.gitconfig` — the identity your commits carry), with the Windows
  account beside it. Without a Git identity the Windows account is recorded and shown as such.
- The advisory then shows under **Accepted risks — not counted**, the item says **Accepted risk**, and
  it leaves the Vulnerable and Updates counts. **Revoke** removes the decision.
- A decision covers **one advisory in one library version** in one library or widget. When the review
  date passes it counts again, marked *review overdue*; when the library version changes it no longer
  applies.
- Decisions are saved in the app folder as **`.security-analyzer/accepted-risks.json`**. Commit it, so
  the team shares and reviews them like any other change.

### Export

**Export report** saves a self-contained HTML report and **JSON** the raw result, both to
`Documents\Mendix Security Analyzer\`. Both include findings, rules, Java libraries (with
duplicates and vulnerabilities), widget vulnerabilities and accepted risks with their reasons.
Neither contains a password: credentials in the model are reduced to their length and character
classes before the analysis sees them.

---

## What leaves your machine

The analysis itself never sends anything. The optional checks, each started by a button:

| Check | Sent to | What is sent |
|---|---|---|
| Java library vulnerabilities | api.osv.dev | Maven `group:artifact` and version of each library |
| Safe version for a vulnerable library | repo1.maven.org, api.osv.dev | Maven `group:artifact` of the library; the few candidate releases are downloaded and read in memory (Java level, bundled libraries), never stored |
| Widget vulnerabilities | api.osv.dev | npm package name and version of each library bundled into a widget |
| Marketplace compatibility | marketplace-api.mendix.com | Marketplace content ids (e.g. 170), with your Personal Access Token |

No model data, file names, paths or credentials from the app are sent. Answers are cached under
`%LOCALAPPDATA%\Mendix Security Analyzer\` (version lists for an hour, the catalog for a day;
Maven Central release lists for 12 hours, facts read from a release jar permanently).

---

## Sharing it as an add-on module

The extension is shared as an **add-on module package** (`.mxmodule`): a module named
**`SecurityAnalyser`** that carries the extension. Importing it is all another app needs — no
`--enable-extension-development` and no install script.

**Build the package** (Studio Pro 10.24 must be installed; it is used to build the package so that it
imports into 10.24 and every later version):

```powershell
npm run package
```

This builds the extension and writes `release/SecurityAnalyser-<version>.mxmodule` (the version comes
from `extension/package.json`). `extension/scripts/package-module.mjs` creates a temporary Mendix app
in `.package/`, imports the empty module `extension/packaging/SecurityAnalyser.mpk`, adds the built
extension, sets the module's Export settings (*Add-on module*, *Extension name* **SecurityAnalyzer**,
the version), runs `mx check`, exports with `mx create-module-package` and verifies the result. Pass
`--mx "<path to mx.exe>"` (or set `MENDIX_MX`) when Studio Pro 10.24 is not in the default folder.

The same package can be made by hand in Studio Pro: add a module, put the built extension in the
app's `extensions/SecurityAnalyzer` folder, set the module's **Settings ▸ Export** to *Add-on module*
with *Extension name* **SecurityAnalyzer**, then right-click the module ▸ **Export add-on module package**.

**Import it** in Studio Pro 10.24 or later: right-click the app ▸ **Import module package**, choose the
`.mxmodule` file, and **trust** the extension when Studio Pro asks. Then open
**Extensions ▸ SecurityAnalyzer**. To update, import the newer package the same way. The package can
also be published to your company's private Marketplace.

---

## Troubleshooting

| Symptom | What to do |
|---|---|
| No **Extensions ▸ SecurityAnalyzer** menu | Start Studio Pro with `--enable-extension-development`; check `extensions\SecurityAnalyzer\manifest.json` exists; check Smart App Control. |
| `install.ps1` cannot copy the DLL | Close Studio Pro first. |
| A rule is *Not applicable* | The Rules tab gives the reason — usually that the app has nothing to check (e.g. no published REST service). |
| A rule is *Not verified* | The reason names the value Studio Pro did not return. Run again; if it persists, send `last-snapshot.json` (below). |
| A result looks wrong | Every run saves what Studio Pro returned to `%LOCALAPPDATA%\Mendix Security Analyzer\last-snapshot.json` (passwords redacted). Studio Pro's own log records any failure to read or open a document. |
| Compatibility check says the token was refused | The token expired, or was created without the Marketplace content read scope. Create a new one; a remembered token that is refused is forgotten. |
| A vulnerability or Marketplace check fails | The machine needs internet access to api.osv.dev / marketplace-api.mendix.com (Studio Pro's proxy settings apply). The message on the tab names the reason. |
| An update from the Marketplace did not clear a widget advisory | The newest release for the app's Mendix version may still bundle the library. The advice says so and names the release (and Mendix version) that is newer; review the exposure and accept the risk until then. |
| `accepted-risks.json` could not be read | The tab shows the reason. Fix the JSON or delete the file; the extension never overwrites a file it cannot read. |
| **Open** shows a message instead of opening a nanoflow | The extensions API has no nanoflow type, so the extension opens nanoflows through Studio Pro's internal editor manager (verified on 10.24 and 11.12). If a Studio Pro version changes that, the pane tells you the nanoflow's place in the App Explorer and copies its name; the reason is in Studio Pro's log. |

---

## Repository layout

```
extension/                 the Studio Pro extension
  dotnet/                  C# host: menu, dockable pane, model reader, web server,
                           JavaLibraryScanner, WidgetScanner, OsvClient, MarketplaceClient,
                           AcceptedRiskStore
  src/                     TypeScript: snapshot → model → rules → UI
    snapshot/              reading the model snapshot (both naming conventions)
    ui/                    the pane (HTML, CSS, TypeScript)
    analyze.ts             runs the rule catalogue and scoring
    module-status.ts       the Module status tab's model
    java-libraries.ts      the Java libraries tab: origin, duplicates, vulnerabilities, fixes
    marketplace.ts         the Upgrades tab: versions per Mendix version, widget vulnerabilities
    accepted-risks.ts      accepted-risk decisions: matching, lapsing, validation
  scripts/                 build.mjs (web assets), install.ps1 (one app),
                           update-installed.ps1 (every app that has it)
  tests/                   extension tests
packages/
  application-ir/          the application model the rules read, and shared helpers
  rule-engine/             runs rules; skips a rule whose facts could not be read
  rules/                   the rule catalogue (security.ts, microflow-security.ts)
  scoring/                 scores and risk rating
  mendix-parser/           reads .mxunit files from disk (used by the tests)
tests/                     rule and parser tests
docs/
  IMPLEMENTATION.md        how it is built
  security-specification.md  the rule specification and calibration notes
```

---

## Tests

```bash
npm test
```

Runs about 220 tests: every rule has a case that must fire and cases that must stay quiet, plus the
extension's snapshot, naming, module status, Java libraries, Upgrades and accepted-risk tests.

The **reference-project tests** additionally need an unpacked Mendix app (MPR v2, with
`mprcontents`). It is not committed. Point at one with:

```bash
MENDIX_TEST_FIXTURE="C:/path/to/TestApp-main" npm test
```

or place it at `fixtures/TestApp-main/`. Without it those suites are skipped with a stated reason.
The locked expected findings were recorded against the reference project *TestApp* (Mendix 11.12.4).

Findings cite a `sourceSkill` such as `manage-security.md`: these are the MDL skill documents of the
mxcli tooling, which are not redistributed here.
