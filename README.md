# Mendix Security Analyzer

A Mendix Studio Pro extension that checks the app you have open against **35 security governance
rules**: project security, anonymous access, entity and page access, role hygiene, credentials,
constants and microflow security. Findings explain what was found, why it matters and how to fix it,
and link straight to the document in Studio Pro.

- **Studio Pro 10.24.0 and later**, including 11.x
- Reads the model **as it is open**, unsaved changes included
- Runs entirely on your machine; nothing is uploaded

---

## Contents

1. [What it checks](#what-it-checks)
2. [Requirements](#requirements)
3. [Build](#build)
4. [Install into a Mendix app](#install-into-a-mendix-app)
5. [Using the extension](#using-the-extension)
6. [Sharing it as an add-on module](#sharing-it-as-an-add-on-module)
7. [Troubleshooting](#troubleshooting)
8. [Repository layout](#repository-layout)
9. [Tests](#tests)

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
| `SEC-021` | Sensitive or PII member readable by a broad role | High | Data Privacy |
| `SEC-022` | Owned-data entity without an XPath constraint | Medium | Entity Access |
| `SEC-EE-003` | Broad read/write access defaults (lazy rule definition) | High | Entity Access |
| `SEC-005` | Password or secret attribute not hashed | High | Data Privacy |
| `SEC-008` | PII stored without encryption *(advisory, off by default)* | Medium | Data Privacy |
| `SEC-023` | User role bypasses security | High | Role Hygiene |
| `SEC-024` | Non-administrator user role can manage all roles | Medium | Role Hygiene |
| `SEC-025` | Module role not mapped to any user role | Low | Role Hygiene |
| `SEC-007` | Regex-based XSS sanitiser in a Java action | High | Input Sanitization |
| `SEC-026` | Hardcoded secret in a constant | High | Credentials |
| `SEC-027` | Secret-bearing constant exposed to the client | Critical | Credentials |
| `SEC-010` | Form data cached in browser localStorage | Low | Data Privacy |
| `SEC-004` | Published REST endpoint without authentication | Critical | Integration Security |
| `SEC-028` | Reachable microflow bypasses entity access | High | Microflow Security |
| `SEC-MF-001` | Missing entity access on client interactions | Critical | Microflow Security |
| `SEC-MF-002` | Anonymous user write permissions | Critical | Anonymous Access |
| `SEC-MF-003` | Parameter ID tampering vulnerability | High | Microflow Security |
| `SEC-MF-004` | Public endpoint missing auth logic | High | Integration Security |
| `SEC-MF-005` | Dead/exposed privilege code | Medium | Microflow Security |

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

Filters: search text, **Warnings** (include findings to review), **Only my modules** (hide
Marketplace modules), **Advisory checks** (also run the two rules that are off by default).

### Rules tab

All 35 rules grouped by area, each marked **Passed**, **Failed**, **Review**, **Not applicable**
(with the reason, e.g. the app publishes no REST services) or **Off**.

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

### Export

**Export report** saves a self-contained HTML report and **JSON** the raw result, both to
`Documents\Mendix Security Analyzer\`. Neither contains a password: credentials in the model are
reduced to their length and character classes before the analysis sees them.

---

## Sharing it as an add-on module

On Studio Pro 11 you can ship the extension inside a module, so other apps get it by importing that
module:

1. Install the extension into any app (above) and open it with `--enable-extension-development`.
2. Add a module named exactly **`SecurityAnalyzer`** (it must match the extension folder name).
3. Module **Settings ▸ Export**: *Module type* **Add-on module**, a *Module version*, and
   *Extension name* **SecurityAnalyzer**.
4. Right-click the module ▸ **Export add-on module package** → `SecurityAnalyzer.mxmodule`.

In another app: right-click the app ▸ **Import module package**, choose the file, and choose to
**trust** the extension when Studio Pro asks. For Studio Pro 10.24 apps, check whether the module's
Export tab offers *Extension name*; if not, use `install.ps1` per app.

---

## Troubleshooting

| Symptom | What to do |
|---|---|
| No **Extensions ▸ SecurityAnalyzer** menu | Start Studio Pro with `--enable-extension-development`; check `extensions\SecurityAnalyzer\manifest.json` exists; check Smart App Control. |
| `install.ps1` cannot copy the DLL | Close Studio Pro first. |
| A rule is *Not applicable* | The Rules tab gives the reason — usually that the app has nothing to check (e.g. no published REST service). |
| A result looks wrong | Every run saves what Studio Pro returned to `%LOCALAPPDATA%\Mendix Security Analyzer\last-snapshot.json` (passwords redacted). Studio Pro's own log records any failure to read or open a document. |
| **Open** does not open a nanoflow | The extensions API has no nanoflow type in 10.24–11.12. The pane then tells you the nanoflow's place in the App Explorer and copies its name for the App Explorer search. |

---

## Repository layout

```
extension/                 the Studio Pro extension
  dotnet/                  C# host: menu, dockable pane, model reader, web server
  src/                     TypeScript: snapshot → model → rules → UI
    snapshot/              reading the model snapshot (both naming conventions)
    ui/                    the pane (HTML, CSS, TypeScript)
    analyze.ts             runs the rule catalogue and scoring
    module-status.ts       the Module status tab's model
  scripts/                 build.mjs (web assets), install.ps1 (install into an app)
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

Runs about 170 tests: every rule has a case that must fire and cases that must stay quiet, plus the
extension's snapshot, naming, module status and UI-model tests.

The **reference-project tests** additionally need an unpacked Mendix app (MPR v2, with
`mprcontents`). It is not committed. Point at one with:

```bash
MENDIX_TEST_FIXTURE="C:/path/to/TestApp-main" npm test
```

or place it at `fixtures/TestApp-main/`. Without it those suites are skipped with a stated reason.
The locked expected findings were recorded against the reference project *TestApp* (Mendix 11.12.4).

Findings cite a `sourceSkill` such as `manage-security.md`: these are the MDL skill documents of the
mxcli tooling, which are not redistributed here.
