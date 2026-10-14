/**
 * The Security Analyzer pane.
 *
 * Flow: the user presses Run → the pane asks the host for a model snapshot → the host reads
 * the open app through Studio Pro's model API and posts it back → the pane runs the SEC-*
 * catalogue locally and renders the result. Nothing leaves the machine.
 */

import { analyzeSnapshot, entityForFinding, securityCatalogue, unitForFinding } from '../analyze.js';
import type { RuleOutcome, SecurityAnalysisResult } from '../analyze.js';
import { applyOsvResult, compareVersions, duplicateAdvice, gaOf, isCheckable, packagesToCheck } from '../java-libraries.js';
import { appJavaVersion, candidateVersions, chooseVersion, resolutionPlan, upgradeTargets } from '../version-advice.js';
import type { CandidateFacts, UpgradeTarget, VersionAdvice } from '../version-advice.js';
import type { DuplicateGroup, JavaLibrary, LibraryVulnerability, OsvCheckResult, VulnerabilityReport } from '../java-libraries.js';
import { applyWidgetOsv, assessItem, assessWidget, contentIdsToCheck, matchWidgets, widgetPackagesToCheck, widgetSecurityAdvice } from '../marketplace.js';
import type { ItemAssessment, MarketplaceAnswer, MarketplaceItem, MarketplaceVersion, UpgradeStatus, WidgetVulnerabilityReport } from '../marketplace.js';
import type { AccessState, ModuleStatus } from '../module-status.js';
import { DEFAULT_REVIEW_DAYS, MAX_REVIEW_DAYS, MIN_REASON_LENGTH, acceptedByText, addDays, riskKey, splitByAcceptance, today as todayIso, validateRisk } from '../accepted-risks.js';
import type { AcceptedRisk, AcceptedRisksFile, AcceptedVulnerability, RiskScope } from '../accepted-risks.js';
import type { ModelSnapshot } from '../snapshot/types.js';
import type { Finding, RuleSeverity } from '@mendix-analyzer/rule-engine';

import { append, clear, h } from './dom.js';
import { connect, inStudioPro, onHostMessage, send } from './host.js';
import { buildHtmlReport, buildJsonReport, reportFileStem } from './report.js';

type Phase = 'idle' | 'reading' | 'analyzing' | 'done' | 'error';
type Tab = 'findings' | 'rules' | 'modules' | 'libraries' | 'upgrades';
type LibraryFilter = 'all' | 'marketplace' | 'custom' | 'vulnerable' | 'critical-high' | 'duplicates' | 'accepted' | 'unchecked';
type ModuleSection = 'entities' | 'pages' | 'microflows' | 'nanoflows' | 'roles';

const SEVERITIES: RuleSeverity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

const state = {
  phase: 'idle' as Phase,
  error: '',
  snapshot: undefined as ModelSnapshot | undefined,
  result: undefined as SecurityAnalysisResult | undefined,
  tab: 'findings' as Tab,
  severities: new Set<RuleSeverity>(SEVERITIES),
  query: '',
  /** Findings tab: show only this rule's findings; '' = every rule. */
  ruleFilter: '',
  expanded: new Set<string>(),
  toast: '',
  /** Module status tab: open cards (by module) with their selected section, and whether Marketplace modules show. */
  openModules: new Map<string, ModuleSection>(),
  showMarketplace: false,
  /** Java libraries tab: the last OSV.dev answer (kept across re-runs), and the tab's filters. */
  osv: undefined as OsvCheckResult | undefined,
  vulnPhase: 'idle' as 'idle' | 'checking' | 'error',
  vulnError: '',
  libQuery: '',
  /** The summary card the user clicked; `all` shows every section. */
  libFilter: 'all' as LibraryFilter,
  openLibraries: new Set<string>(),
  /** Upgrades tab: the Mendix version to plan for ('' = the app's), the Marketplace answer, the filters. */
  marketplace: undefined as MarketplaceAnswer | undefined,
  widgetMatches: {} as Record<string, number>,
  catalogRead: false,
  mpPhase: 'idle' as 'idle' | 'checking' | 'error',
  mpError: '',
  tokenSource: 'None' as 'None' | 'Typed' | 'Remembered' | 'Environment',
  upFilter: 'all' as UpgradeFilter,
  /** Upgrades tab: open groups of widgets that ship inside a module, by module name. */
  openBundles: new Set<string>(),
  /** The widget vulnerability check: the OSV.dev answer for the npm libraries bundled into widgets. */
  widgetOsv: undefined as OsvCheckResult | undefined,
  wvPhase: 'idle' as 'idle' | 'checking' | 'error',
  wvError: '',
  upQuery: '',
  openUpgrades: new Set<string>(),
  /** Accepted-risk decisions from the app folder, the open accept form (by risk key) and its draft. */
  acceptedRisks: { risks: [] } as AcceptedRisksFile,
  riskForm: '',
  riskDraft: { reason: '', reviewBy: '' },
  riskError: '',
  /**
   * A check to run once the app has been re-read. The library and widget checks start with a fresh
   * read so that jars or widgets added since the last run are included; otherwise "Check again"
   * would only re-ask OSV.dev or the Marketplace about the files seen at the last full run.
   */
  afterRead: undefined as ((result: SecurityAnalysisResult) => void) | undefined,
  /**
   * Which tab's check started the current re-read. While set, progress is shown in that tab rather
   * than in the header, because the user asked for a library or widget check, not a new analysis.
   */
  recheck: '' as '' | 'libraries' | 'upgrades',
  /**
   * The safe-version lookup that follows a library check: which release to move each vulnerable
   * library to, chosen from Maven Central (see version-advice.ts). Keyed by library key.
   */
  advice: {
    phase: 'idle' as 'idle' | 'versions' | 'inspecting' | 'done' | 'error',
    error: '',
    targets: [] as UpgradeTarget[],
    candidates: {} as Record<string, { candidates: string[]; newerMajor?: string; error?: string }>,
    byLibrary: {} as Record<string, VersionAdvice>,
  },
};

/** Accepted and lapsed decisions per library or widget key, alongside the still-open advisories. */
interface AcceptanceView {
  accepted: Record<string, AcceptedVulnerability[]>;
  overdue: Record<string, AcceptedVulnerability[]>;
}

const root = document.getElementById('app')!;

// ====================================================================== flow

function run(): void {
  if (state.phase === 'reading' || state.phase === 'analyzing') return;
  state.afterRead = undefined;
  state.recheck = '';
  if (inStudioPro) {
    state.phase = 'reading';
    state.error = '';
    render();
    send('RunAnalysis');
  } else {
    pickSnapshotFile();
  }
}

function analyze(snapshot: ModelSnapshot): void {
  state.snapshot = snapshot;
  state.acceptedRisks = snapshot.acceptedRisks ?? { risks: [] };
  state.phase = 'analyzing';
  render();
  // Let the "Analysing" state paint before the (synchronous) analysis runs.
  setTimeout(() => {
    try {
      state.result = analyzeSnapshot(snapshot);
      state.phase = 'done';
      // A tab's re-check keeps what the user had open; a new analysis starts collapsed.
      if (!state.recheck) state.expanded.clear();
      state.recheck = '';
      const pending = state.afterRead;
      state.afterRead = undefined;
      // Runs after the render below, so the check's own "Checking…" state is what stays on screen.
      if (pending) setTimeout(() => state.result && pending(state.result), 0);
      const failures = state.result.findings.filter((f) => f.status === 'FAIL').length;
      send('AnalysisComplete', { failures, findings: state.result.findings.length });
    } catch (err) {
      state.phase = 'error';
      state.error = `The analysis failed: ${(err as Error)?.message ?? String(err)}`;
      state.afterRead = undefined;
      state.recheck = '';
    }
    render();
  }, 30);
}

function pickSnapshotFile(): void {
  const input = h('input', { type: 'file', accept: '.json,application/json' });
  input.addEventListener('change', async () => {
    const file = input.files?.[0];
    if (!file) return;
    try {
      analyze(JSON.parse(await file.text()) as ModelSnapshot);
    } catch (err) {
      state.phase = 'error';
      state.error = `That file is not a model snapshot: ${(err as Error).message}`;
      render();
    }
  });
  input.click();
}

onHostMessage((msg) => {
  switch (msg.message) {
    case 'Snapshot':
      try {
        analyze(JSON.parse(msg.data.json) as ModelSnapshot);
      } catch (err) {
        state.phase = 'error';
        state.error = `The model snapshot could not be read: ${(err as Error).message}`;
        render();
      }
      break;
    case 'SnapshotFailed':
      state.afterRead = undefined;
      if (state.recheck && state.result) {
        // The previous result is still valid; report the failed re-read where the check was asked for.
        const message = `The app could not be re-read, so the check did not run: ${msg.data.error}`;
        if (state.recheck === 'libraries') {
          state.vulnPhase = 'error';
          state.vulnError = message;
        } else {
          state.wvPhase = 'error';
          state.wvError = message;
        }
        state.recheck = '';
        state.phase = 'done';
        render();
        break;
      }
      state.phase = 'error';
      state.error = msg.data.error;
      render();
      break;
    case 'VulnerabilityResult':
      if (msg.data.purpose === 'widgets') {
        onWidgetVulnerabilityResult(msg.data);
        break;
      }
      if (msg.data.ok && msg.data.json) {
        try {
          state.osv = JSON.parse(msg.data.json) as OsvCheckResult;
          state.vulnPhase = 'idle';
          if (state.result) startVersionAdvice(state.result);
        } catch (err) {
          state.vulnPhase = 'error';
          state.vulnError = `The answer from OSV.dev could not be read: ${(err as Error).message}`;
        }
      } else {
        state.vulnPhase = 'error';
        state.vulnError = msg.data.error ?? 'The vulnerability check failed.';
      }
      render();
      break;
    case 'VersionAdviceResult':
      onVersionAdvice(msg.data);
      break;
    case 'AcceptedRisks':
      if (msg.data.ok && msg.data.json) {
        state.acceptedRisks = JSON.parse(msg.data.json) as AcceptedRisksFile;
        state.riskForm = '';
        state.riskError = '';
        showToast(`Saved to ${state.acceptedRisks.path ?? 'the app folder'} — commit it with the app so the decision is shared and reviewed.`, 8000);
      } else {
        state.riskError = msg.data.error ?? 'The decision could not be saved.';
      }
      render();
      break;
    case 'MarketplaceTokenStatus':
      state.tokenSource = msg.data.source;
      if (state.tab === 'upgrades') render();
      break;
    case 'MarketplaceResult':
      onMarketplaceResult(msg.data);
      break;
    case 'OpenFolderResult':
      if (msg.data.error) showToast(msg.data.error);
      break;
    case 'ExportDone':
      showToast(msg.data.error ? `Export failed: ${msg.data.error}` : `Saved to ${msg.data.path}`);
      break;
    case 'OpenUnitResult': {
      if (msg.data.ok) {
        // Opened, with a note — e.g. the activity changed since the analysis, so only the microflow opened.
        if (msg.data.error) showToast(msg.data.error);
        break;
      }
      const { name, error } = msg.data;
      if (!name) {
        showToast(error ?? 'Studio Pro could not open that document.');
        break;
      }
      // Copy the name so it can be pasted straight into the App Explorer's search box.
      const fallback = () => showToast(error ?? '', 12000);
      if (!navigator.clipboard) {
        fallback();
        break;
      }
      navigator.clipboard
        .writeText(name)
        .then(() => showToast(`${error} "${name}" is copied — paste it into the App Explorer search.`, 12000))
        .catch(fallback);
      break;
    }
  }
});

function exportReport(kind: 'html' | 'json'): void {
  const result = state.result;
  if (!result) return;
  const vulnerabilities = vulnerabilityReport(result);
  const extras = {
    widgetVulnerabilities: widgetVulnerabilities(result),
    acceptedRisks: state.acceptedRisks.risks,
    acceptedByLibrary: vulnerabilities?.accepted,
  };
  const content = kind === 'html' ? buildHtmlReport(result, vulnerabilities, extras) : buildJsonReport(result, vulnerabilities, extras);
  const fileName = `${reportFileStem(result)}.${kind}`;
  if (inStudioPro) {
    send('ExportReport', { fileName, content });
    return;
  }
  const url = URL.createObjectURL(new Blob([content], { type: kind === 'html' ? 'text/html' : 'application/json' }));
  const a = h('a', { href: url, download: fileName });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Open a document; with `entity`, the domain model opens with that entity selected. */
/** Whether `candidate` is a later version than `current` (an unknown current version counts as older). */
function isNewer(candidate: string, current: string | undefined): boolean {
  return !current || compareVersions(candidate, current) > 0;
}

function openInStudioPro(unitId: string, entity?: string, activity?: string): void {
  send('OpenUnit', { unitId, ...(entity ? { entity } : {}), ...(activity ? { activity } : {}) });
}

let toastTimer: number | undefined;
function showToast(text: string, durationMs = 6000): void {
  state.toast = text;
  renderToast();
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    state.toast = '';
    renderToast();
  }, durationMs);
}

// ====================================================================== rendering

function render(): void {
  clear(root);
  append(root, [header(), body(), h('div', { id: 'toast', class: 'toast', role: 'status' })]);
  renderToast();
}

function renderToast(): void {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = state.toast;
  el.classList.toggle('visible', state.toast.length > 0);
}

function header(): HTMLElement {
  const working = state.phase === 'reading' || state.phase === 'analyzing';
  // A tab's re-check shows its progress in that tab; the header only reflects a full analysis.
  const busy = working && !state.recheck;
  const result = state.result;
  return h(
    'header',
    { class: 'topbar' },
    h(
      'div',
      { class: 'title' },
      shieldIcon(),
      h(
        'div',
        {},
        h('div', { class: 'name' }, 'Security Analyzer'),
        h(
          'div',
          { class: 'sub' },
          result
            ? `${result.app.name} · analysed ${new Date(result.analyzedAt).toLocaleTimeString()} in ${result.durationMs} ms`
            : inStudioPro
              ? 'Checks the open app against the security governance rules'
              : 'Development mode — load a model snapshot to analyse'
        )
      )
    ),
    h(
      'div',
      { class: 'actions' },
      result && state.phase === 'done'
        ? [
            h('button', { class: 'btn ghost', onclick: () => exportReport('html'), title: 'Save an HTML report' }, 'Export report'),
            h('button', { class: 'btn ghost', onclick: () => exportReport('json'), title: 'Save the raw result as JSON' }, 'JSON'),
          ]
        : null,
      h(
        'button',
        { class: 'btn primary', onclick: run, disabled: working },
        busy ? spinner() : playIcon(),
        busy ? (state.phase === 'reading' ? 'Reading model…' : 'Analysing…') : result ? 'Run again' : 'Run analysis'
      )
    )
  );
}

function body(): HTMLElement {
  if (state.phase === 'error') {
    return h(
      'main',
      { class: 'empty' },
      h('div', { class: 'empty-title' }, 'The analysis could not run'),
      h('p', { class: 'error-text' }, state.error),
      h('button', { class: 'btn primary', onclick: run }, 'Try again')
    );
  }
  if (!state.result) {
    const busy = state.phase !== 'idle';
    return h(
      'main',
      { class: 'empty' },
      h('div', { class: 'hero-icon' }, shieldIcon()),
      h('div', { class: 'empty-title' }, busy ? 'Analysing your app…' : 'Check this app’s security configuration'),
      h(
        'p',
        { class: 'muted' },
        `Runs ${securityCatalogue().length} security governance checks against the model as it is open in Studio Pro — project security, anonymous access, entity and page access, role hygiene, credentials and constants. Unsaved changes are included. Nothing leaves your machine.`
      ),
      busy
        ? h('div', { class: 'progress' }, h('div', { class: 'bar' }))
        : h('button', { class: 'btn primary large', onclick: run }, playIcon(), inStudioPro ? 'Run analysis' : 'Load snapshot…')
    );
  }
  return h('main', { class: 'results' }, summary(state.result), tabs(), tabBody(state.result));
}

function summary(result: SecurityAnalysisResult): HTMLElement {
  const { score } = result;
  const counts = result.rules.reduce<Record<string, number>>((acc, r) => {
    acc[r.status] = (acc[r.status] ?? 0) + 1;
    return acc;
  }, {});
  const scoreValue = result.securityScore;
  const scoreClass = scoreValue === null ? 'na' : scoreValue >= 88 ? 'good' : scoreValue >= 65 ? 'fair' : 'poor';

  return h(
    'section',
    { class: 'summary' },
    h(
      'div',
      { class: `score ${scoreClass}` },
      h('div', { class: 'label' }, 'Security score'),
      h('div', { class: 'value' }, scoreValue === null ? '—' : String(scoreValue), scoreValue === null ? null : h('span', { class: 'of' }, '/100')),
      h('div', { class: 'caption' }, scoreValue === null ? 'Not assessed: project security could not be read' : `Risk rating ${score.riskRating}`)
    ),
    h(
      'div',
      { class: 'severity-grid' },
      (['Critical', 'High', 'Medium', 'Low'] as const).map((s) =>
        h(
          'button',
          {
            class: `sev-tile sev-${s.toLowerCase()}${onlySeverity(s) ? ' active' : ''}`,
            title: `Show only ${s} findings`,
            onclick: () => toggleOnlySeverity(s),
          },
          h('span', { class: 'n' }, String(score.severityCounts[s] ?? 0)),
          h('span', { class: 't' }, s)
        )
      )
    ),
    h(
      'div',
      { class: 'facts' },
      fact('Rules passed', `${counts.PASSED ?? 0} of ${result.rules.length}`),
      fact('Failed / warnings', `${counts.FAILED ?? 0} / ${counts.WARNING ?? 0}`),
      fact('Not applicable', String(counts.NOT_APPLICABLE ?? 0)),
      ...(counts.NOT_VERIFIED ? [fact('Not verified', String(counts.NOT_VERIFIED))] : []),
      fact('Coverage', `${score.coveragePercentage}%`)
    )
  );
}

function fact(label: string, value: string): HTMLElement {
  return h('div', { class: 'fact' }, h('div', { class: 'label' }, label), h('div', { class: 'v' }, value));
}

function onlySeverity(s: RuleSeverity): boolean {
  return state.severities.size === 1 && state.severities.has(s);
}

function toggleOnlySeverity(s: RuleSeverity): void {
  state.severities = onlySeverity(s) ? new Set(SEVERITIES) : new Set([s]);
  state.tab = 'findings';
  render();
}

function tabs(): HTMLElement {
  const result = state.result!;
  const tab = (id: Tab, label: string, count?: number) =>
    h(
      'button',
      { class: `tab${state.tab === id ? ' active' : ''}`, role: 'tab', 'aria-selected': state.tab === id ? 'true' : 'false', onclick: () => { state.tab = id; render(); } },
      label,
      count === undefined ? null : h('span', { class: 'count' }, String(count))
    );
  return h(
    'nav',
    { class: 'tabs', role: 'tablist' },
    tab('findings', 'Findings', result.findings.length),
    tab('rules', 'Rules', result.rules.length),
    tab('modules', 'Module status', result.modules.filter((m) => m.type === 'user' && m.overall === 'incomplete').length || undefined),
    tab('libraries', 'Java libraries', libraryTabCount(result)),
    tab('upgrades', 'Upgrades', upgradesTabCount(result))
  );
}

function tabBody(result: SecurityAnalysisResult): HTMLElement {
  if (state.tab === 'rules') return rulesView(result);
  if (state.tab === 'modules') return modulesView(result);
  if (state.tab === 'libraries') return librariesView(result);
  if (state.tab === 'upgrades') return upgradesView(result);
  return findingsView(result);
}

/** The one-paragraph explanation at the top of each tab. */
function tabIntro(text: string): HTMLElement {
  return h('p', { class: 'muted small tab-intro' }, text);
}

/** Shown where risks can be accepted, when the decisions file exists but cannot be read. */
function riskFileWarning(): HTMLElement | null {
  return state.acceptedRisks.error ? h('p', { class: 'error-text small' }, state.acceptedRisks.error) : null;
}

// ---------------------------------------------------------------------- findings

function visibleFindings(result: SecurityAnalysisResult): Finding[] {
  const q = state.query.trim().toLowerCase();
  return result.findings.filter((f) => {
    if (!state.severities.has(f.severity)) return false;
    if (state.ruleFilter && f.ruleId !== state.ruleFilter) return false;
    if (!q) return true;
    return [f.ruleId, f.ruleTitle, f.artifact, f.observation, f.module ?? ''].some((s) => s.toLowerCase().includes(q));
  });
}

/**
 * The Rule filter: every rule that has findings in this run, grouped by area like the Rules tab,
 * with its finding count. A rule chosen before a re-run that no longer has findings is dropped.
 */
function ruleFilterSelect(result: SecurityAnalysisResult, onChange: () => void): HTMLSelectElement {
  const withFindings = result.rules.filter((r) => r.findingCount > 0);
  if (state.ruleFilter && !withFindings.some((r) => r.id === state.ruleFilter)) state.ruleFilter = '';
  const groups = new Map<string, RuleOutcome[]>();
  for (const r of withFindings) groups.set(r.subcategory, [...(groups.get(r.subcategory) ?? []), r]);
  const select = h(
    'select',
    { class: 'rule-filter', 'aria-label': 'Show findings of one rule', title: 'Show findings of one rule' },
    h('option', { value: '' }, `All rules (${withFindings.length})`),
    [...groups].map(([group, rules]) =>
      h('optgroup', { label: group }, rules.map((r) => h('option', { value: r.id }, `${r.id} · ${r.name} (${r.findingCount})`)))
    )
  ) as HTMLSelectElement;
  select.value = state.ruleFilter;
  select.addEventListener('change', () => {
    state.ruleFilter = select.value;
    onChange();
  });
  return select;
}

function findingsView(result: SecurityAnalysisResult): HTMLElement {
  const list = h('div', { class: 'finding-list' });
  const summary = h('p', { class: 'muted small filter-summary', 'aria-live': 'polite' });
  const renderList = () => {
    clear(list);
    const visible = visibleFindings(result);
    summary.textContent =
      result.findings.length === 0 ? '' : visible.length === result.findings.length
        ? `Showing all ${result.findings.length} findings`
        : `Showing ${visible.length} of ${result.findings.length} findings`;
    if (result.findings.length === 0) {
      append(list, [h('div', { class: 'all-clear' }, checkIcon(), h('div', {}, h('strong', {}, 'No security findings.'), ' Every rule that could run passed.'))]);
      return;
    }
    if (visible.length === 0) {
      append(list, [h('p', { class: 'muted center' }, 'No findings match the current filters.')]);
      return;
    }
    for (const f of visible) list.appendChild(findingCard(f, result));
  };

  const search = h('input', {
    type: 'search',
    class: 'search',
    placeholder: 'Filter findings…',
    value: state.query,
    'aria-label': 'Filter findings',
  });
  search.addEventListener('input', () => {
    state.query = search.value;
    renderList();
  });

  const toolbar = h('div', { class: 'toolbar' }, search, ruleFilterSelect(result, renderList));

  renderList();
  return h(
    'section',
    { class: 'panel' },
    tabIntro(
      'Security problems found in the app. Each finding names the rule it breaks and what was found; open it for why it matters, how to fix it, the evidence, and a button to open the document in Studio Pro. “Review” marks findings that need a person’s judgement or sit in a Marketplace module (shown one severity lower). Click a severity tile above to filter.'
    ),
    toolbar,
    summary,
    list
  );
}

function findingCard(f: Finding, result: SecurityAnalysisResult): HTMLElement {
  const open = state.expanded.has(f.id);
  const unitId = unitForFinding(f, result.units);
  const marketplace = f.module !== undefined && result.moduleTypes[f.module] === 'marketplace';

  const card = h(
    'article',
    { class: `finding sev-${f.severity.toLowerCase()}${open ? ' open' : ''}` },
    h(
      'button',
      {
        class: 'finding-head',
        'aria-expanded': open ? 'true' : 'false',
        onclick: () => {
          if (state.expanded.has(f.id)) state.expanded.delete(f.id);
          else state.expanded.add(f.id);
          card.replaceWith(findingCard(f, result));
        },
      },
      h('span', { class: `sev-badge sev-${f.severity.toLowerCase()}` }, f.severity),
      h(
        'span',
        { class: 'finding-title' },
        h('span', { class: 'rule' }, f.ruleTitle),
        h('span', { class: 'artifact' }, f.artifact)
      ),
      h(
        'span',
        { class: 'meta' },
        f.status === 'WARNING' ? h('span', { class: 'tag warn' }, 'Review') : null,
        marketplace ? h('span', { class: 'tag' }, 'Marketplace') : null,
        h('span', { class: 'rule-id' }, f.ruleId),
        chevronIcon()
      )
    ),
    h('p', { class: 'observation' }, f.observation),
    open
      ? h(
          'div',
          { class: 'details' },
          detail('Why it matters', f.whyItMatters),
          detail('Recommendation', f.recommendation),
          detail('Expected practice', f.expectedPractice),
          evidence(f, unitId),
          h(
            'div',
            { class: 'detail-foot' },
            unitId && inStudioPro
              ? h('button', { class: 'btn small', onclick: () => openInStudioPro(unitId, entityForFinding(f, result.entityNames)) }, 'Open in Studio Pro')
              : null
          )
        )
      : null
  );
  return card;
}

function detail(label: string, text: string): HTMLElement {
  return h('div', { class: 'detail' }, h('div', { class: 'label' }, label), h('div', {}, text));
}

function evidence(f: Finding, unitId: string | undefined): HTMLElement | null {
  const entries = Object.entries(f.evidence.details ?? {}).filter(
    ([k, v]) => v !== undefined && v !== null && k !== 'unitPath' && !(Array.isArray(v) && v.length === 0)
  );
  if (entries.length === 0) return null;
  return h(
    'div',
    { class: 'detail' },
    h('div', { class: 'label' }, 'Evidence'),
    h(
      'dl',
      { class: 'evidence' },
      h('dt', {}, 'artifact'),
      h('dd', {}, f.evidence.artifactPath),
      entries.flatMap(([k, v]) => [h('dt', {}, humanise(k)), h('dd', {}, evidenceValue(v, unitId))])
    )
  );
}

/**
 * Evidence laid out for reading: a list puts each item on its own line, and an item with fields
 * (activity, member, expression, problem …) shows each field on its own labelled line.
 */
function evidenceValue(value: unknown, unitId?: string): HTMLElement | string {
  if (Array.isArray(value)) {
    if (value.length === 1) return evidenceValue(value[0], unitId);
    return h('ol', { class: 'evidence-list' }, value.map((item) => h('li', {}, evidenceValue(item, unitId))));
  }
  if (value && typeof value === 'object') {
    const fields = value as Record<string, unknown>;
    // An item naming a microflow activity gets a button that opens the microflow with it selected.
    const activityId = typeof fields.activityId === 'string' ? fields.activityId : undefined;
    const showActivity =
      activityId && unitId && inStudioPro
        ? h(
            'button',
            {
              class: 'btn small evidence-open',
              title: 'Open the microflow in Studio Pro with this activity selected',
              onclick: () => openInStudioPro(unitId, undefined, activityId),
            },
            'Show activity'
          )
        : null;
    return h(
      'div',
      { class: 'evidence-item' },
      Object.entries(fields)
        .filter(([k, v]) => k !== 'activityId' && v !== undefined && v !== null && v !== '')
        .map(([k, v]) =>
          h(
            'div',
            { class: 'evidence-field' },
            h('span', { class: 'evidence-key' }, humanise(k)),
            k === 'member' && showActivity ? h('span', { class: 'evidence-with-action' }, h('span', {}, evidenceValue(v, unitId)), showActivity) : h('span', {}, evidenceValue(v, unitId))
          )
        )
    );
  }
  return String(value);
}

function humanise(key: string): string {
  return key.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
}


// ---------------------------------------------------------------------- rules

const STATUS_LABEL: Record<RuleOutcome['status'], string> = {
  PASSED: 'Passed',
  FAILED: 'Failed',
  WARNING: 'Review',
  NOT_APPLICABLE: 'Not applicable',
  NOT_VERIFIED: 'Not verified',
  DISABLED: 'Off',
};

function rulesView(result: SecurityAnalysisResult): HTMLElement {
  const groups = new Map<string, RuleOutcome[]>();
  for (const rule of result.rules) {
    const list = groups.get(rule.subcategory) ?? [];
    list.push(rule);
    groups.set(rule.subcategory, list);
  }
  return h(
    'section',
    { class: 'panel' },
    tabIntro(
      'Every security rule the analyzer checks, grouped by area, with its result for this app. Click a rule to see exactly what it checks, when it reports and what it leaves alone. Results: Passed, Failed, Review (needs judgement), Not applicable (the app has nothing to check, with the reason), Not verified (a setting the rule needs could not be read from this app, so it is not counted as a pass) or Off (advisory rules, not run).'
    ),
    [...groups].map(([group, rules]) =>
      h(
        'div',
        { class: 'rule-group' },
        h('h3', {}, group),
        rules.map((r) => ruleRow(r))
      )
    )
  );
}

/** One rule: a clickable summary line that expands to what exactly the rule validates. */
function ruleRow(r: RuleOutcome): HTMLElement {
  const key = `rule:${r.id}`;
  const open = state.expanded.has(key);
  const row = h(
    'div',
    { class: `rule-item st-${r.status.toLowerCase()}${open ? ' open' : ''}` },
    h(
      'button',
      {
        class: 'rule-row',
        'aria-expanded': open ? 'true' : 'false',
        title: open ? 'Hide what this rule checks' : 'Show what this rule checks',
        onclick: () => {
          if (state.expanded.has(key)) state.expanded.delete(key);
          else state.expanded.add(key);
          row.replaceWith(ruleRow(r));
        },
      },
      h('span', { class: 'rule-status' }, statusIcon(r.status), STATUS_LABEL[r.status]),
      h(
        'span',
        { class: 'rule-main' },
        h('span', { class: 'rule-name' }, h('span', { class: 'rule-id' }, r.id), ' ', r.name),
        // The status reason stays visible: it explains the result, not the rule.
        r.reason ? h('span', { class: 'muted small rule-reason' }, r.reason) : null
      ),
      h('span', { class: `sev-badge sev-${r.severity.toLowerCase()}` }, r.severity),
      h('span', { class: 'rule-count' }, r.findingCount > 0 ? String(r.findingCount) : ''),
      chevronIcon()
    ),
    open ? ruleDetails(r) : null
  );
  return row;
}

function ruleDetails(r: RuleOutcome): HTMLElement {
  const list = (items: string[]) => h('ul', { class: 'rule-list' }, items.map((i) => h('li', {}, i)));
  const c = r.checks;
  return h(
    'div',
    { class: 'details rule-details' },
    detail('Rule', r.description),
    c ? h('div', { class: 'detail' }, h('div', { class: 'label' }, 'What it checks in this app'), h('div', {}, c.reads)) : null,
    c && c.flagged.length > 0 ? h('div', { class: 'detail' }, h('div', { class: 'label' }, 'Reported when'), list(c.flagged)) : null,
    c && c.notFlagged.length > 0 ? h('div', { class: 'detail' }, h('div', { class: 'label' }, 'Not reported'), list(c.notFlagged)) : null,
    detail('Why it matters', r.whyItMatters),
    detail('How to fix', r.recommendation),
    r.findingCount > 0
      ? h(
          'div',
          { class: 'detail-foot' },
          h('span', {}),
          h(
            'button',
            {
              class: 'btn small',
              onclick: () => {
                // Open the Findings tab on this rule alone, clearing filters that could hide its findings.
                state.ruleFilter = r.id;
                state.query = '';
                state.severities = new Set(SEVERITIES);
                state.tab = 'findings';
                render();
              },
            },
            `Show ${r.findingCount} finding${r.findingCount === 1 ? '' : 's'}`
          )
        )
      : null
  );
}

// ---------------------------------------------------------------------- module status

const STATE_LABEL: Record<AccessState, string> = {
  complete: 'Complete',
  incomplete: 'Incomplete',
  review: 'Review',
  empty: 'None',
};

const SECTION_LABEL: Record<ModuleSection, string> = {
  entities: 'Entity access',
  pages: 'Page access',
  microflows: 'Microflow access',
  nanoflows: 'Nanoflow access',
  roles: 'Module roles',
};

function stateBadge(st: AccessState): HTMLElement {
  return h('span', { class: `state state-${st}` }, STATE_LABEL[st]);
}

function modulesView(result: SecurityAnalysisResult): HTMLElement {
  const own = result.modules.filter((m) => m.type === 'user');
  const market = result.modules.filter((m) => m.type !== 'user');
  const incomplete = own.filter((m) => m.overall === 'incomplete').length;
  const review = own.filter((m) => m.overall === 'review').length;
  const legend: [AccessState, string][] = [
    ['complete', 'every item has access set'],
    ['incomplete', 'something has no access set'],
    ['review', 'set, but open to the anonymous role or bypassing entity access'],
  ];

  return h(
    'section',
    { class: 'panel modules' },
    tabIntro(
      'How complete each module’s security is, and why: entity access (rules per role), page, microflow and nanoflow access (allowed roles), what the anonymous role can reach, and which user roles hold each module role. Click a tile to see the items behind it; Open goes to the item in Studio Pro.'
    ),
    h(
      'div',
      { class: 'modules-intro' },
      h(
        'p',
        {},
        own.length === 0
          ? 'This app has no modules of its own.'
          : `${own.length} module${own.length === 1 ? '' : 's'} of your own: ${incomplete} incomplete, ${review} to review, ${own.length - incomplete - review} complete.`
      ),
      h('div', { class: 'legend' }, legend.map(([s, text]) => h('span', {}, stateBadge(s), ' ', text)))
    ),
    own.map((m) => moduleCard(m, result)),
    market.length > 0
      ? h(
          'div',
          { class: 'market-group' },
          h(
            'button',
            {
              class: 'btn ghost small',
              onclick: () => {
                state.showMarketplace = !state.showMarketplace;
                render();
              },
            },
            `${state.showMarketplace ? 'Hide' : 'Show'} Marketplace modules (${market.length})`
          ),
          state.showMarketplace ? market.map((m) => moduleCard(m, result)) : null
        )
      : null,
    h(
      'p',
      { class: 'muted small' },
      "REST, OData and data set access are not read by this version and are not shown. Complete / Incomplete here is this analyzer's check, explained on each item; Studio Pro's App Security dialog remains the authority on its own status."
    )
  );
}

type FlowSectionKey = 'entities' | 'pages' | 'microflows' | 'nanoflows';

function moduleCard(m: ModuleStatus, result: SecurityAnalysisResult): HTMLElement {
  const open = state.openModules.get(m.name);
  const toggle = (section?: ModuleSection) => {
    if (section === undefined && open) state.openModules.delete(m.name);
    else state.openModules.set(m.name, section ?? open ?? firstProblem(m));
    render();
  };

  const tile = (section: FlowSectionKey, label: string) =>
    h(
      'button',
      {
        class: `tile tile-${m[section].state}${open === section ? ' active' : ''}`,
        title: `Show ${label.toLowerCase()} details`,
        onclick: () => toggle(section),
      },
      h('span', { class: 'tile-label' }, label),
      stateBadge(m[section].state),
      h('span', { class: 'tile-summary' }, m[section].summary)
    );

  const anon = m.anonymous;
  const parts: string[] = [];
  if (anon.entities) parts.push(`${anon.entities} entit${anon.entities === 1 ? 'y' : 'ies'}`);
  if (anon.pages) parts.push(`${anon.pages} page${anon.pages === 1 ? '' : 's'}`);
  if (anon.microflows) parts.push(`${anon.microflows} microflow${anon.microflows === 1 ? '' : 's'}`);
  if (anon.nanoflows) parts.push(`${anon.nanoflows} nanoflow${anon.nanoflows === 1 ? '' : 's'}`);
  const anonState: AccessState = anon.total > 0 ? 'review' : 'complete';

  return h(
    'article',
    { class: `module-card overall-${m.overall}${open ? ' open' : ''}` },
    h(
      'button',
      { class: 'module-head', 'aria-expanded': open ? 'true' : 'false', onclick: () => toggle() },
      h('span', { class: 'module-name' }, m.name),
      h('span', { class: 'tag' }, m.type === 'user' ? 'Your module' : 'Marketplace'),
      h(
        'span',
        { class: 'module-findings' },
        m.findings.total === 0
          ? h('span', { class: 'muted small' }, 'no findings')
          : (['Critical', 'High', 'Medium', 'Low'] as const)
              .filter((s) => m.findings[s] > 0)
              .map((s) => h('span', { class: `sev-badge sev-${s.toLowerCase()}` }, `${m.findings[s]} ${s}`))
      ),
      stateBadge(m.overall),
      chevronIcon()
    ),
    h(
      'div',
      { class: 'tiles' },
      tile('entities', 'Entity access'),
      tile('pages', 'Page access'),
      tile('microflows', 'Microflow access'),
      tile('nanoflows', 'Nanoflow access'),
      h(
        'div',
        { class: `tile tile-${anonState} static` },
        h('span', { class: 'tile-label' }, 'Anonymous exposure'),
        stateBadge(anonState),
        h('span', { class: 'tile-summary' }, parts.length > 0 ? parts.join(' · ') : 'Nothing reachable')
      )
    ),
    open ? moduleDetail(m, open, result) : null
  );
}

function firstProblem(m: ModuleStatus): ModuleSection {
  const order: FlowSectionKey[] = ['entities', 'pages', 'microflows', 'nanoflows'];
  return (
    order.find((s) => m[s].state === 'incomplete') ?? order.find((s) => m[s].state === 'review') ?? 'entities'
  );
}

function moduleDetail(m: ModuleStatus, section: ModuleSection, result: SecurityAnalysisResult): HTMLElement {
  const sections: ModuleSection[] = ['entities', 'pages', 'microflows', 'nanoflows', 'roles'];
  const count = (s: ModuleSection) => (s === 'roles' ? m.roles.length : m[s].rows.length);
  const anonymousRoles = new Set(result.diagnostics.guestModuleRoles);

  const openButton = (qualifiedName: string, isEntity = false) => {
    const unitId = result.units[qualifiedName];
    return unitId && inStudioPro
      ? h('button', { class: 'btn small', onclick: () => openInStudioPro(unitId, isEntity ? qualifiedName : undefined), title: isEntity ? 'Open the domain model with this entity selected' : undefined }, 'Open')
      : null;
  };
  const roleChips = (roles: string[]) =>
    roles.length === 0
      ? h('span', { class: 'muted small' }, 'none')
      : roles.map((r) => h('span', { class: `chip${anonymousRoles.has(r) ? ' chip-anon' : ''}` }, r));
  const rowIcon = (st: string) =>
    statusIcon(
      st === 'ok' ? 'PASSED' : st === 'no-rules' || st === 'no-roles' ? 'FAILED' : st === 'internal' ? 'NOT_APPLICABLE' : 'WARNING'
    );
  const row = (st: string, title: (Node | string | null)[], lines: (Node | null)[], qualifiedName: string, isEntity = false) =>
    h(
      'div',
      { class: `detail-row st-${st}` },
      h('span', { class: 'row-icon' }, rowIcon(st)),
      h('div', { class: 'row-main' }, h('div', { class: 'row-title' }, title), ...lines),
      openButton(qualifiedName, isEntity)
    );
  const callerChip = (qualifiedName: string, kind: 'microflow' | 'nanoflow') => {
    const unitId = result.units[qualifiedName];
    const label = kind === 'nanoflow' ? `${qualifiedName} (nanoflow)` : qualifiedName;
    return unitId && inStudioPro
      ? h('button', { class: 'chip chip-link', title: `Open ${qualifiedName}`, onclick: () => openInStudioPro(unitId) }, label)
      : h('span', { class: 'chip' }, label);
  };
  const anonTag = (on: boolean, text = 'anonymous') => (on ? h('span', { class: 'tag tag-anon' }, text) : null);

  let rows: HTMLElement[];
  let empty: string;
  if (section === 'entities') {
    empty = 'This module has no entities.';
    rows = m.entities.rows.map((r) =>
      row(
        r.state,
        [h('span', { class: 'mono' }, r.name), r.persistable ? null : h('span', { class: 'tag' }, 'non-persistable'), anonTag(r.anonymous)],
        [
          r.grants.length > 0
            ? h(
                'div',
                { class: 'grants' },
                r.grants.map((g) => h('span', { class: `chip${g.anonymous ? ' chip-anon' : ''}` }, h('strong', {}, g.role), ` — ${g.rights}`))
              )
            : null,
          h('div', { class: 'muted small' }, r.note),
        ],
        r.qualifiedName,
        true
      )
    );
  } else if (section === 'pages') {
    empty = 'This module has no pages.';
    rows = m.pages.rows.map((r) =>
      row(
        r.state,
        [h('span', { class: 'mono' }, r.name), anonTag(r.anonymous)],
        [h('div', { class: 'grants' }, roleChips(r.roles)), h('div', { class: 'muted small' }, r.note)],
        r.qualifiedName
      )
    );
  } else if (section === 'roles') {
    empty = 'This module declares no module roles.';
    rows = m.roles.map((r) => {
      const st = r.grantedTo.length === 0 ? 'internal' : r.anonymous ? 'anonymous' : 'ok';
      return row(
        st,
        [h('span', { class: 'mono' }, r.name), anonTag(r.anonymous, 'held by anonymous')],
        [
          h('div', { class: 'grants' }, h('span', { class: 'muted small' }, 'Granted to user roles:'), roleChips(r.grantedTo)),
          r.grantedTo.length === 0 ? h('div', { class: 'muted small' }, 'Not granted to any user role, so nobody holds it.') : null,
        ],
        r.qualifiedName
      );
    });
  } else {
    empty = `This module has no ${section}.`;
    rows = m[section].rows.map((r) =>
      row(
        r.state,
        [
          h('span', { class: 'mono' }, r.name),
          anonTag(r.anonymous),
          r.appliesEntityAccess === false ? h('span', { class: 'tag warn' }, 'no entity access') : null,
          r.calledBy && r.calledBy.length > 0
            ? h('span', { class: 'tag tag-sub' }, `sub-${section === 'microflows' ? 'microflow' : 'nanoflow'} · ${r.calledBy.length} caller${r.calledBy.length === 1 ? '' : 's'}`)
            : null,
        ],
        [
          r.roles.length > 0 ? h('div', { class: 'grants' }, roleChips(r.roles)) : null,
          r.calledBy && r.calledBy.length > 0
            ? h(
                'div',
                { class: 'grants' },
                h('span', { class: 'muted small' }, 'Called by:'),
                r.calledBy.map((c) => callerChip(c.qualifiedName, c.kind))
              )
            : null,
          h('div', { class: 'muted small' }, r.note),
        ],
        r.qualifiedName
      )
    );
  }

  return h(
    'div',
    { class: 'module-detail' },
    h(
      'div',
      { class: 'segmented', role: 'tablist' },
      sections.map((s) =>
        h(
          'button',
          {
            class: `seg${s === section ? ' active' : ''}`,
            role: 'tab',
            'aria-selected': s === section ? 'true' : 'false',
            onclick: () => {
              state.openModules.set(m.name, s);
              render();
            },
          },
          SECTION_LABEL[s],
          h('span', { class: 'count' }, String(count(s)))
        )
      )
    ),
    rows.length === 0 ? h('p', { class: 'muted small' }, empty) : h('div', { class: 'detail-list' }, rows)
  );
}

// ---------------------------------------------------------------------- java libraries

type LibraryStatus =
  | { kind: 'not-checked' }
  | { kind: 'cannot-check'; reason: string }
  | { kind: 'clean' }
  | { kind: 'accepted'; accepted: AcceptedVulnerability[] }
  | {
      kind: 'vulnerable';
      vulns: LibraryVulnerability[];
      worst: LibraryVulnerability['severity'];
      accepted: AcceptedVulnerability[];
      overdue: AcceptedVulnerability[];
    };

type LibraryReport = VulnerabilityReport & AcceptanceView;

/**
 * The last OSV.dev answer applied to the current inventory, or undefined before the first check.
 * `byLibrary` holds only the advisories still open: accepted ones (within their review date) are
 * moved to `accepted`, and lapsed acceptances stay open and are listed in `overdue` as well.
 */
function vulnerabilityReport(result: SecurityAnalysisResult): LibraryReport | undefined {
  if (!state.osv) return undefined;
  const report = applyOsvResult(result.javaLibraries, state.osv);
  const view: AcceptanceView = { accepted: {}, overdue: {} };
  for (const [key, list] of Object.entries(report.byLibrary)) {
    const split = splitByAcceptance(list, state.acceptedRisks.risks, 'library', key);
    report.byLibrary[key] = split.open;
    if (split.accepted.length > 0) view.accepted[key] = split.accepted;
    if (split.overdue.length > 0) view.overdue[key] = split.overdue;
  }
  return { ...report, ...view };
}

function libraryStatus(lib: JavaLibrary, report: LibraryReport | undefined): LibraryStatus {
  const checkable = isCheckable(lib.coordinates) || lib.bundled.some((b) => isCheckable(b));
  if (!checkable) {
    return {
      kind: 'cannot-check',
      reason: lib.unreadable
        ? 'The jar could not be opened.'
        : lib.coordinates?.group
          ? 'Its version could not be determined.'
          : 'It carries no Maven coordinates (no pom.properties), so it cannot be looked up by name.',
    };
  }
  if (!report) return { kind: 'not-checked' };
  const vulns = report.byLibrary[lib.key];
  if (vulns === undefined) return { kind: 'not-checked' };
  const accepted = report.accepted[lib.key] ?? [];
  if (vulns.length === 0) return accepted.length > 0 ? { kind: 'accepted', accepted } : { kind: 'clean' };
  return { kind: 'vulnerable', vulns, worst: vulns[0]!.severity, accepted, overdue: report.overdue[lib.key] ?? [] };
}

function libraryTabCount(result: SecurityAnalysisResult): number | undefined {
  const report = vulnerabilityReport(result);
  if (report) {
    const vulnerable = result.javaLibraries.libraries.filter((l) => (report.byLibrary[l.key]?.length ?? 0) > 0).length;
    return vulnerable || undefined;
  }
  return result.javaLibraries.libraries.length || undefined;
}

/**
 * A horizontal progress bar with what the check is doing right now, shown inside the tab whose check
 * is running. In Studio Pro a check is two steps (re-read the app, then ask the service); in the
 * browser stand-in there is nothing to re-read, so it is one.
 */
function taskProgress(step: number, message: string, total = 2): HTMLElement {
  // Outside Studio Pro there is no re-read, so the steps after it are numbered one lower.
  const steps = inStudioPro ? total : total - 1;
  const label = steps > 1 ? `Step ${inStudioPro ? step : step - 1} of ${steps} · ${message}` : message;
  return h(
    'div',
    { class: 'task-progress', role: 'status', 'aria-live': 'polite' },
    h('div', { class: 'progress', role: 'progressbar', 'aria-label': message }, h('div', { class: 'bar' })),
    h('span', { class: 'small' }, label)
  );
}

/**
 * Re-read the app (so files added since the last run are seen), then run `check` on the new result.
 * Outside Studio Pro there is nothing to re-read, so the check runs on what is loaded.
 */
function rereadThen(
  tab: 'libraries' | 'upgrades',
  check: (result: SecurityAnalysisResult) => void,
  current: SecurityAnalysisResult
): void {
  if (!inStudioPro) {
    check(current);
    return;
  }
  if (state.phase === 'reading' || state.phase === 'analyzing') return;
  state.afterRead = check;
  state.recheck = tab;
  if (tab === 'libraries') state.vulnPhase = 'idle';
  else state.wvPhase = state.wvPhase === 'error' ? 'idle' : state.wvPhase;
  state.phase = 'reading';
  state.error = '';
  render();
  send('RunAnalysis');
}

function checkVulnerabilities(result: SecurityAnalysisResult): void {
  const packages = packagesToCheck(result.javaLibraries);
  if (packages.length === 0) {
    showToast('None of the libraries carries Maven coordinates that can be looked up.');
    return;
  }
  if (!inStudioPro) {
    showToast('The vulnerability check needs Studio Pro: the pane asks OSV.dev through the extension host.');
    return;
  }
  state.vulnPhase = 'checking';
  state.vulnError = '';
  state.advice = { phase: 'idle', error: '', targets: [], candidates: {}, byLibrary: {} };
  render();
  send('CheckVulnerabilities', { packages });
}

// ---------------------------------------------------------------------- safe versions

/**
 * Step 3 of the library check: for every library with open advisories, find the release to move
 * to. Two calls to the host — the release lists, then the few candidate jars — and the choice is
 * made here by version-advice.ts. A failure leaves the advisories' minimum in the steps.
 */
function startVersionAdvice(result: SecurityAnalysisResult): void {
  const report = vulnerabilityReport(result);
  const targets = report ? upgradeTargets(result.javaLibraries.libraries, report) : [];
  state.advice = { phase: 'idle', error: '', targets, candidates: {}, byLibrary: {} };
  if (targets.length === 0 || !inStudioPro) return;
  state.advice.phase = 'versions';
  send('MavenVersions', { libraries: [...new Set(targets.map((t) => `${t.group}:${t.artifact}`))] });
}

function onVersionAdvice(data: { ok: boolean; stage: 'versions' | 'inspect'; json?: string; error?: string }): void {
  const advice = state.advice;
  const result = state.result;
  if (!result || advice.phase === 'idle' || advice.phase === 'done') return;
  if (!data.ok || !data.json) {
    advice.phase = 'error';
    advice.error = data.error ?? 'Maven Central could not be checked.';
    render();
    return;
  }
  try {
    if (data.stage === 'versions') {
      const lists = JSON.parse(data.json) as Record<string, string[] | { error: string }>;
      const wanted: { group: string; artifact: string; version: string }[] = [];
      for (const t of advice.targets) {
        const list = lists[`${t.group}:${t.artifact}`];
        if (!list || !Array.isArray(list)) {
          advice.candidates[t.libKey] = { candidates: [], error: list && !Array.isArray(list) ? list.error : 'no release list was returned' };
          continue;
        }
        const picked = candidateVersions(t, list);
        advice.candidates[t.libKey] = picked;
        for (const version of picked.candidates) wanted.push({ group: t.group, artifact: t.artifact, version });
      }
      if (wanted.length === 0) {
        finishVersionAdvice(result, { jars: {}, osv: {} });
        return;
      }
      advice.phase = 'inspecting';
      render();
      send('InspectCandidates', { candidates: wanted });
      return;
    }
    finishVersionAdvice(result, JSON.parse(data.json) as { jars: Record<string, CandidateFacts['jars'][string]>; osv: Record<string, string[]> });
  } catch (err) {
    advice.phase = 'error';
    advice.error = `The answer from Maven Central could not be read: ${(err as Error).message}`;
    render();
  }
}

function finishVersionAdvice(
  result: SecurityAnalysisResult,
  answer: { jars: Record<string, CandidateFacts['jars'][string]>; osv: Record<string, string[]> }
): void {
  const advice = state.advice;
  const java = appJavaVersion(result.app.javaVersion, result.upgrades.mendixVersion ?? result.app.studioProVersion);
  for (const t of advice.targets) {
    const picked = advice.candidates[t.libKey];
    if (!picked) continue;
    if (picked.error) {
      advice.byLibrary[t.libKey] = { minimum: t.minimum, rejected: [], note: `Maven Central's release list could not be read: ${picked.error}.` };
      continue;
    }
    const facts: CandidateFacts = { osv: {}, jars: {} };
    for (const version of picked.candidates) {
      const key = `${t.group}:${t.artifact}@${version}`;
      if (answer.osv[key]) facts.osv[version] = answer.osv[key]!;
      if (answer.jars[key]) facts.jars[version] = answer.jars[key]!;
    }
    advice.byLibrary[t.libKey] = chooseVersion(t, picked.candidates, facts, java, picked.newerMajor);
  }
  advice.phase = 'done';
  render();
}

function librariesView(result: SecurityAnalysisResult): HTMLElement {
  const inventory = result.javaLibraries;
  if (!inventory.scanned) {
    return h(
      'section',
      { class: 'panel' },
      h('p', { class: 'muted' }, 'The Java libraries could not be scanned.'),
      inventory.notes.map((n) => h('p', { class: 'muted small' }, n))
    );
  }

  const report = vulnerabilityReport(result);
  const libs = inventory.libraries;
  const statuses = new Map(libs.map((l) => [l.key, libraryStatus(l, report)]));
  const market = libs.filter((l) => l.origin === 'marketplace');
  const custom = libs.filter((l) => l.origin === 'custom');
  const vulnerable = libs.filter((l) => statuses.get(l.key)!.kind === 'vulnerable');
  const allVulns = vulnerable.flatMap((l) => (statuses.get(l.key) as { vulns: LibraryVulnerability[] }).vulns);
  const bySeverity = (s: string) => allVulns.filter((v) => v.severity === s).length;
  const cannotCheck = libs.filter((l) => statuses.get(l.key)!.kind === 'cannot-check').length;

  const list = h('div', { class: 'lib-sections' });
  const renderList = () => {
    clear(list);
    const q = state.libQuery.trim().toLowerCase();
    const visible = (group: JavaLibrary[]) =>
      group.filter((l) => {
        if (!matchesFilter(l, statuses.get(l.key)!, state.libFilter)) return false;
        if (!q) return true;
        return [l.fileName, gaOf(l.coordinates) ?? '', l.coordinates?.version ?? '', ...l.requiredBy.map((r) => r.module)].some((s) =>
          s.toLowerCase().includes(q)
        );
      });
    const section = (title: string, hint: string, group: JavaLibrary[]) => {
      const shown = sortLibraries(visible(group), statuses);
      // A card filter that leaves a section empty hides the section rather than listing "none".
      const byStatus = state.libFilter === 'vulnerable' || state.libFilter === 'critical-high' || state.libFilter === 'unchecked' || state.libFilter === 'accepted';
      if (byStatus && shown.length === 0) return null;
      return h(
        'div',
        { class: 'lib-section' },
        h('h3', {}, `${title} (${group.length})`),
        h('p', { class: 'muted small' }, hint),
        shown.length === 0
          ? h('p', { class: 'muted small' }, group.length === 0 ? 'None.' : 'None match the current filters.')
          : h('div', { class: 'finding-list' }, shown.map((l) => libraryCard(l, statuses.get(l.key)!)))
      );
    };
    const f = state.libFilter;
    const marketHint = 'Needed by Marketplace modules. Their versions are chosen by the module: fix them by updating the module, not the jar.';
    const customHint = 'Declared by your own modules, added to userlib by hand, or left behind by a removed module. Your team owns these versions.';
    const parts = [
      f === 'all' || f === 'duplicates' ? duplicatesSection(inventory.duplicates, libs, statuses) : null,
      f !== 'duplicates' && f !== 'custom' ? section('Marketplace libraries', marketHint, market) : null,
      f !== 'duplicates' && f !== 'marketplace' ? section('Custom libraries', customHint, custom) : null,
    ].filter((p): p is HTMLElement => p !== null);
    append(list, parts.length > 0 ? parts : [h('p', { class: 'muted center' }, `No ${LIBRARY_FILTER_LABEL[f].toLowerCase()}.`)]);
  };

  const search = h('input', { type: 'search', class: 'search', placeholder: 'Filter libraries…', value: state.libQuery, 'aria-label': 'Filter libraries' });
  search.addEventListener('input', () => {
    state.libQuery = search.value;
    renderList();
  });
  // A filter that needs the vulnerability check is meaningless without one.
  if (!report && (state.libFilter === 'vulnerable' || state.libFilter === 'critical-high' || state.libFilter === 'accepted')) state.libFilter = 'all';

  const checking = state.vulnPhase === 'checking';
  const reading = state.recheck === 'libraries';
  const suggesting = state.advice.phase === 'versions' || state.advice.phase === 'inspecting';
  const busy = checking || reading || suggesting;
  const packages = packagesToCheck(inventory).length;
  const checkBar = h(
    'div',
    { class: `check-bar${state.vulnPhase === 'error' ? ' failed' : ''}` },
    h(
      'div',
      { class: 'check-text' },
      h(
        'strong',
        {},
        busy
          ? 'Checking the Java libraries…'
          : report
            ? vulnerable.length === 0
              ? 'No known vulnerabilities'
              : `${vulnerable.length} vulnerable librar${vulnerable.length === 1 ? 'y' : 'ies'} · ${allVulns.length} advisor${allVulns.length === 1 ? 'y' : 'ies'}`
            : 'Vulnerabilities not checked yet'
      ),
      h(
        'span',
        { class: 'muted small' },
        state.vulnPhase === 'error'
          ? state.vulnError
          : report
            ? `Checked against ${report.source} at ${new Date(report.checkedAt).toLocaleTimeString()}. Absence of an advisory is not proof of safety.`
            : `Looks up ${packages} Maven package${packages === 1 ? '' : 's'} in OSV.dev, the open vulnerability database. Only names and versions are sent (e.g. org.apache.commons:commons-text 1.10.0) — nothing from the app model.`
      )
    ),
    h(
      'button',
      {
        class: 'btn primary',
        title: 'Re-reads userlib and vendorlib, then checks every library against OSV.dev',
        onclick: () => rereadThen('libraries', checkVulnerabilities, result),
        disabled: busy || packages === 0,
      },
      busy ? spinner() : shieldIcon(),
      reading ? 'Reading…' : checking || suggesting ? 'Checking…' : report ? 'Check again' : 'Check for vulnerabilities'
    ),
    reading
      ? taskProgress(1, 'Reading the jars in userlib and vendorlib…', 3)
      : checking
        ? taskProgress(2, `Checking ${packages} librar${packages === 1 ? 'y' : 'ies'} against OSV.dev…`, 3)
        : suggesting
          ? taskProgress(
              3,
              `Finding a safe version on Maven Central for ${state.advice.targets.length} vulnerable librar${state.advice.targets.length === 1 ? 'y' : 'ies'}${state.advice.phase === 'inspecting' ? ' (checking candidate releases)' : ''}…`,
              3
            )
          : null
  );

  const card = (filter: LibraryFilter, label: string, value: string | number, cls = '', needsCheck = false) => {
    const disabled = needsCheck && !report;
    const active = state.libFilter === filter;
    return h(
      'button',
      {
        class: `fact kpi ${cls}${active ? ' active' : ''}`,
        disabled,
        'aria-pressed': active ? 'true' : 'false',
        title: disabled ? 'Run the vulnerability check first' : active && filter !== 'all' ? 'Show all libraries' : `Show ${LIBRARY_FILTER_LABEL[filter].toLowerCase()}`,
        onclick: () => {
          state.libFilter = active ? 'all' : filter;
          render();
        },
      },
      h('div', { class: 'label' }, label),
      h('div', { class: 'v' }, String(value))
    );
  };

  renderList();
  return h(
    'section',
    { class: 'panel libraries' },
    tabIntro(
      'Every .jar in userlib and vendorlib, split into Marketplace libraries (chosen by a Marketplace module) and custom libraries (your team’s), with duplicate libraries and known vulnerabilities from OSV.dev. Click a card to filter. Open a library for why it is in the app, the fix, Open folder, and to accept a reviewed risk.'
    ),
    riskFileWarning(),
    checkBar,
    h(
      'div',
      { class: 'facts lib-facts' },
      card('all', 'Libraries', libs.length),
      card('marketplace', 'Marketplace', market.length),
      card('custom', 'Custom', custom.length),
      card('vulnerable', 'Vulnerable', report ? vulnerable.length : '—', report && vulnerable.length > 0 ? 'bad' : '', true),
      card(
        'critical-high',
        'Critical / High',
        report ? `${bySeverity('Critical')} / ${bySeverity('High')}` : '—',
        report && bySeverity('Critical') + bySeverity('High') > 0 ? 'bad' : '',
        true
      ),
      card('duplicates', 'Duplicates', inventory.duplicates.length, inventory.duplicates.length > 0 ? 'bad' : ''),
      card('accepted', 'Accepted risks', report ? Object.values(report.accepted).reduce((n, l) => n + l.length, 0) : '—', '', true),
      card('unchecked', 'Cannot be checked', cannotCheck)
    ),
    h(
      'div',
      { class: 'toolbar' },
      search,
      state.libFilter !== 'all'
        ? h(
            'span',
            { class: 'filter-pill' },
            `Showing: ${LIBRARY_FILTER_LABEL[state.libFilter]}`,
            h('button', { class: 'btn ghost small', onclick: () => { state.libFilter = 'all'; render(); } }, 'Show all')
          )
        : null
    ),
    list,
    inventory.notes.length > 0 ? h('div', { class: 'lib-notes' }, inventory.notes.map((n) => h('p', { class: 'muted small' }, n))) : null
  );
}

const LIBRARY_FILTER_LABEL: Record<LibraryFilter, string> = {
  all: 'All libraries',
  marketplace: 'Marketplace libraries',
  custom: 'Custom libraries',
  vulnerable: 'Vulnerable libraries',
  'critical-high': 'Libraries with Critical or High vulnerabilities',
  duplicates: 'Duplicate libraries',
  accepted: 'Libraries with accepted risks',
  unchecked: 'Libraries that cannot be checked',
};

function matchesFilter(lib: JavaLibrary, status: LibraryStatus, filter: LibraryFilter): boolean {
  switch (filter) {
    case 'vulnerable':
      return status.kind === 'vulnerable';
    case 'critical-high':
      return status.kind === 'vulnerable' && status.vulns.some((v) => v.severity === 'Critical' || v.severity === 'High');
    case 'unchecked':
      return status.kind === 'cannot-check';
    case 'duplicates':
      return lib.duplicateOf !== undefined;
    case 'accepted':
      return status.kind === 'accepted' || (status.kind === 'vulnerable' && status.accepted.length > 0);
    default:
      return true; // all, marketplace, custom: the section already selects
  }
}

/** Shows the jar selected in Windows Explorer, like Studio Pro's "Show App Directory in Explorer". */
function openFolderButton(lib: JavaLibrary, compact = false): HTMLElement | null {
  if (!inStudioPro) return null;
  return h(
    'button',
    {
      class: `btn small${compact ? ' ghost' : ''}`,
      title: `Show ${lib.folder}\\${lib.fileName} in Windows Explorer`,
      onclick: (event: Event) => {
        event.stopPropagation();
        send('OpenLibraryFolder', { folder: lib.folder, fileName: lib.fileName });
      },
    },
    folderIcon(),
    'Open folder'
  );
}

/** Libraries present more than once, matched by name regardless of version. */
function duplicatesSection(groups: DuplicateGroup[], libs: JavaLibrary[], statuses: Map<string, LibraryStatus>): HTMLElement {
  const byKey = new Map(libs.map((l) => [l.key, l]));
  return h(
    'div',
    { class: 'lib-section' },
    h('h3', {}, `Duplicate libraries (${groups.length})`),
    h(
      'p',
      { class: 'muted small' },
      'The same library present more than once, matched by name whatever the version (commons-io-2.3.4.jar and commons-io-3.4.5.jar are duplicates). Only one copy is loaded at run time, so decide which version the app uses.'
    ),
    groups.length === 0
      ? h('div', { class: 'all-clear small-clear' }, checkIcon(), h('div', {}, 'No duplicate libraries: every library is present once.'))
      : h(
          'div',
          { class: 'finding-list' },
          groups.map((g) => {
            const members = g.libraries.map((k) => byKey.get(k)).filter((l): l is JavaLibrary => Boolean(l));
            return h(
              'article',
              { class: 'finding dup-group sev-medium' },
              h(
                'div',
                { class: 'dup-head' },
                h('span', { class: 'sev-badge sev-medium' }, g.kind === 'versions' ? `${g.versions.length} versions` : `${members.length} copies`),
                h('span', { class: 'finding-title' }, h('span', { class: 'rule' }, g.name), h('span', { class: 'artifact' }, g.groups.join(', ') || 'no Maven group')),
                g.groups.length > 1 ? h('span', { class: 'tag warn', title: 'Different Maven groups' }, 'different publishers') : null
              ),
              h(
                'div',
                { class: 'dup-copies' },
                members.map((l) => {
                  const st = statuses.get(l.key);
                  return h(
                    'div',
                    { class: 'dup-copy' },
                    h('span', { class: 'mono dup-version' }, l.coordinates?.version ?? 'unknown version'),
                    g.kind === 'versions' && g.newest !== undefined && l.coordinates?.version === g.newest ? h('span', { class: 'tag tag-sub' }, 'newest') : null,
                    h('span', { class: 'mono small' }, `${l.folder}/${l.fileName}`),
                    h('span', { class: 'tag' }, l.origin === 'marketplace' ? 'Marketplace' : 'Custom'),
                    h('span', { class: 'muted small' }, l.requiredBy.length > 0 ? l.requiredBy.map((r) => r.module).join(', ') : 'no module claims it'),
                    st?.kind === 'vulnerable'
                      ? h('span', { class: `sev-badge sev-${st.worst.toLowerCase()}` }, `${st.vulns.length} vulnerabilit${st.vulns.length === 1 ? 'y' : 'ies'}`)
                      : null,
                    h('span', { class: 'dup-open' }, openFolderButton(l, true))
                  );
                })
              ),
              h('div', { class: 'vuln-fix dup-advice' }, h('strong', {}, 'Decide: '), duplicateAdvice(g, libs))
            );
          })
        )
  );
}

const STATUS_ORDER: Record<LibraryStatus['kind'], number> = { vulnerable: 0, 'not-checked': 1, 'cannot-check': 2, accepted: 3, clean: 4 };
const VULN_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };

function sortLibraries(list: JavaLibrary[], statuses: Map<string, LibraryStatus>): JavaLibrary[] {
  return [...list].sort((a, b) => {
    const sa = statuses.get(a.key)!;
    const sb = statuses.get(b.key)!;
    if (sa.kind !== sb.kind) return STATUS_ORDER[sa.kind] - STATUS_ORDER[sb.kind];
    if (sa.kind === 'vulnerable' && sb.kind === 'vulnerable' && sa.worst !== sb.worst) return VULN_RANK[sa.worst]! - VULN_RANK[sb.worst]!;
    return a.fileName.localeCompare(b.fileName, undefined, { sensitivity: 'base' });
  });
}

function libraryCard(lib: JavaLibrary, status: LibraryStatus): HTMLElement {
  const open = state.openLibraries.has(lib.key);
  const sevClass = status.kind === 'vulnerable' ? `sev-${status.worst.toLowerCase()}` : status.kind === 'clean' ? 'lib-clean' : '';
  const name = lib.coordinates?.artifact ?? lib.fileName;
  const version = lib.coordinates?.version;

  const badge =
    status.kind === 'vulnerable'
      ? h('span', { class: `sev-badge sev-${status.worst.toLowerCase()}` }, `${status.vulns.length} ${status.vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'}`)
      : status.kind === 'clean'
        ? h('span', { class: 'state state-complete' }, 'No known vulnerabilities')
        : status.kind === 'accepted'
          ? h('span', { class: 'state state-review', title: 'Every advisory has been reviewed and accepted' }, 'Accepted risk')
          : status.kind === 'cannot-check'
          ? h('span', { class: 'state state-empty', title: status.reason }, 'Cannot be checked')
          : h('span', { class: 'state state-empty' }, 'Not checked');

  const moduleChip = (r: JavaLibrary['requiredBy'][number]) =>
    h(
      'span',
      { class: `chip${r.moduleType === 'missing' ? ' chip-anon' : ''}`, title: r.direct ? 'Declared by this module' : `Through ${r.via}` },
      r.module,
      r.moduleType === 'marketplace' ? ' · Marketplace' : r.moduleType === 'missing' ? ' · not in app' : '',
      r.direct ? '' : ' · transitive'
    );

  const card = h(
    'article',
    { class: `finding lib ${sevClass}${open ? ' open' : ''}` },
    h(
      'button',
      {
        class: 'finding-head',
        'aria-expanded': open ? 'true' : 'false',
        onclick: () => {
          if (state.openLibraries.has(lib.key)) state.openLibraries.delete(lib.key);
          else state.openLibraries.add(lib.key);
          card.replaceWith(libraryCard(lib, status));
        },
      },
      badge,
      h(
        'span',
        { class: 'finding-title' },
        h('span', { class: 'rule' }, name, version ? h('span', { class: 'lib-version' }, ` ${version}`) : null),
        h('span', { class: 'artifact' }, `${gaOf(lib.coordinates) ?? 'no Maven coordinates'} · ${lib.folder}/${lib.fileName}`)
      ),
      h(
        'span',
        { class: 'meta' },
        lib.duplicateOf ? h('span', { class: 'tag warn', title: `Also present: ${lib.otherVersions.join(', ') || 'the same version'}` }, 'duplicate') : null,
        lib.bundled.length > 0 ? h('span', { class: 'tag', title: 'Other libraries are copied inside this jar' }, `bundles ${lib.bundled.length}`) : null,
        h('span', { class: 'tag' }, lib.folder),
        chevronIcon()
      )
    ),
    h('div', { class: 'observation lib-origin' }, lib.requiredBy.length > 0 ? lib.requiredBy.map(moduleChip) : h('span', { class: 'muted small' }, lib.originReason)),
    open ? libraryDetail(lib, status) : null
  );
  return card;
}

function libraryDetail(lib: JavaLibrary, status: LibraryStatus): HTMLElement {
  const identified: Record<string, string> = {
    sbom: 'the vendorlib SBOM written by Studio Pro',
    pom: 'the pom.properties inside the jar',
    manifest: 'the jar manifest',
    'file name': 'the file name only (no Maven metadata in the jar)',
    unknown: 'nothing — the jar carries no identifying metadata',
  };
  const size = lib.sizeBytes >= 1024 * 1024 ? `${(lib.sizeBytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(lib.sizeBytes / 1024))} KB`;

  return h(
    'div',
    { class: 'details' },
    detail('Why it is here', lib.originReason),
    status.kind === 'vulnerable'
      ? h(
          'div',
          { class: 'detail' },
          h('div', { class: 'label' }, 'Known vulnerabilities'),
          h(
            'div',
            { class: 'detail-list' },
            status.vulns.map((v) => vulnerabilityRow(lib, v, status.overdue.find((o) => o.vulnerability.id === v.id)?.risk))
          )
        )
      : status.kind === 'cannot-check'
        ? detail('Vulnerabilities', `Cannot be checked: ${status.reason} Identify it by hand, or replace it with the same library from Maven Central and declare it as a Java dependency.`)
        : status.kind === 'clean'
          ? detail('Vulnerabilities', 'OSV.dev lists no advisory for this version.')
          : null,
    status.kind === 'vulnerable' ? howToResolve(lib, status.vulns) : null,
    status.kind === 'accepted' || status.kind === 'vulnerable' ? acceptedSection('library', lib.key, status.accepted) : null,
    lib.duplicateOf
      ? detail(
          'Duplicate',
          lib.otherVersions.length > 0
            ? `This library is also present in version ${lib.otherVersions.join(', ')}. See Duplicate libraries at the top of this tab to choose which version to keep.`
            : 'Another copy of this exact version is present. See Duplicate libraries at the top of this tab.'
        )
      : null,
    lib.bundled.length > 0
      ? detail('Bundled inside', lib.bundled.map((b) => `${gaOf(b) ?? b.artifact} ${b.version ?? ''}`.trim()).join(', '))
      : null,
    h(
      'dl',
      { class: 'evidence' },
      h('dt', {}, 'file'),
      h('dd', {}, `${lib.folder}/${lib.fileName} (${size})`),
      h('dt', {}, 'identified from'),
      h('dd', {}, identified[lib.identifiedBy] ?? lib.identifiedBy),
      lib.nestedJars ? [h('dt', {}, 'nested jars'), h('dd', {}, `${lib.nestedJars} jar(s) packed inside, not inspected`)] : null
    ),
    inStudioPro ? h('div', { class: 'detail-foot' }, h('span', { class: 'muted small' }, `${lib.folder}\\${lib.fileName}`), openFolderButton(lib)) : null
  );
}

/**
 * The version to move to and the steps to get there, for one vulnerable library. The version comes
 * from the safe-version lookup when it has finished, otherwise from the advisories' minimum.
 */
function howToResolve(lib: JavaLibrary, vulns: LibraryVulnerability[]): HTMLElement {
  const advice = state.advice.byLibrary[lib.key];
  const lookingUp = state.advice.phase === 'versions' || state.advice.phase === 'inspecting';
  const ownFixes = vulns.filter((v) => !v.bundled && v.fixedIn).map((v) => v.fixedIn!);
  const minimum = ownFixes.sort((a, b) => compareVersions(b, a))[0];
  const plan = resolutionPlan(lib, vulns, advice, minimum);
  const java = state.result ? appJavaVersion(state.result.app.javaVersion, state.result.upgrades.mendixVersion ?? state.result.app.studioProVersion) : undefined;
  const name = lib.coordinates?.artifact ?? lib.fileName;

  const versionLine = (): HTMLElement | null => {
    if (advice?.suggested) {
      return h(
        'p',
        { class: 'resolve-version' },
        'Use ',
        h('strong', {}, `${name} ${advice.suggested}`),
        ` — the newest ${name} release in the same major version that fixes ${vulns.length === 1 ? 'this advisory' : `all ${vulns.length} advisories`} here, has no known advisories of its own`,
        advice.suggestedJava !== undefined ? `, and is compiled for Java ${advice.suggestedJava}${java !== undefined ? ` (this app runs Java ${java})` : ''}` : '',
        '.',
        advice.minimum && advice.minimum !== advice.suggested ? ` Minimum fix: ${advice.minimum}.` : ''
      );
    }
    if (lookingUp) return h('p', { class: 'muted small' }, spinner(), ' Finding a safe version on Maven Central…');
    const why = advice?.note ?? (state.advice.phase === 'error' ? state.advice.error : undefined);
    if (!plan.versionText) return null;
    return h('p', { class: 'resolve-version' }, 'Use ', h('strong', {}, `${name} ${plan.versionText}`), '.', why ? h('span', { class: 'muted small' }, ` ${why}`) : null);
  };

  return h(
    'div',
    { class: 'detail resolve' },
    h('div', { class: 'label' }, 'How to resolve'),
    versionLine(),
    advice?.newerMajor
      ? h('p', { class: 'muted small' }, `${name} ${advice.newerMajor} (a newer major version) exists but is not suggested: a major version can change the library's API and break the module's code.`)
      : null,
    plan.steps.length > 0 ? h('ol', { class: 'resolve-steps' }, plan.steps.map((s) => h('li', {}, s))) : null,
    plan.notes.map((n) => h('p', { class: 'muted small' }, n)),
    advice && advice.rejected.length > 0
      ? h(
          'details',
          { class: 'resolve-rejected' },
          h('summary', { class: 'muted small' }, `Releases passed over (${advice.rejected.length})`),
          h('ul', { class: 'small' }, advice.rejected.map((r) => h('li', {}, `${name} ${r.version} ${r.reason}`)))
        )
      : null,
    inStudioPro && (plan.openSettings.length > 0 || plan.maven)
      ? h(
          'div',
          { class: 'resolve-actions' },
          plan.openSettings.map((o) =>
            h(
              'button',
              { class: 'btn small primary', title: `Opens ${o.module}'s module settings, with its Java Dependencies`, onclick: () => openInStudioPro(o.unitId) },
              `Open ${o.module} settings in Studio Pro`
            )
          ),
          plan.maven
            ? h(
                'button',
                { class: 'btn small', onclick: () => send('OpenMavenCentral', { ...plan.maven }) },
                plan.maven.version ? `Open ${name} ${plan.maven.version} on Maven Central` : `Open ${name} on Maven Central`
              )
            : null
        )
      : null
  );
}

function vulnerabilityRow(lib: JavaLibrary, v: LibraryVulnerability, overdue?: AcceptedRisk): HTMLElement {
  return h(
    'div',
    { class: 'vuln-row' },
    h(
      'div',
      { class: 'vuln-head' },
      h('span', { class: `sev-badge sev-${v.severity.toLowerCase()}` }, v.score !== undefined ? `${v.severity} ${v.score.toFixed(1)}` : v.severity),
      inStudioPro
        ? h('button', { class: 'chip chip-link mono', title: 'Open the advisory on osv.dev', onclick: () => send('OpenAdvisory', { id: v.id }) }, v.id)
        : h('span', { class: 'chip mono' }, v.id),
      v.cves.map((c) => h('span', { class: 'chip mono' }, c)),
      v.bundled ? h('span', { class: 'tag warn' }, `in bundled ${v.package}`) : null
    ),
    h('div', { class: 'vuln-summary' }, v.summary),
    h(
      'div',
      { class: 'muted small' },
      `Affects ${v.package} ${v.version}`,
      v.fixedIn ? ` · fixed in ${v.fixedIn}` : ' · no fixed release listed',
      v.published ? ` · published ${new Date(v.published).toLocaleDateString()}` : '',
      v.cwes.length > 0 ? ` · ${v.cwes.join(', ')}` : ''
    ),
    riskControls('library', lib.key, v, overdue)
  );
}

// ---------------------------------------------------------------------- upgrades

type UpgradeFilter = 'all' | 'modules' | 'widgets' | 'updates' | 'vulnerable' | 'accepted' | 'current' | 'unknown';

const UPGRADE_FILTER_LABEL: Record<UpgradeFilter, string> = {
  all: 'Everything',
  modules: 'Marketplace modules',
  widgets: 'Widgets',
  updates: 'Items that need an update',
  vulnerable: 'Widgets with known vulnerabilities',
  accepted: 'Widgets with accepted risks',
  current: 'Items that are up to date',
  unknown: 'Items that could not be assessed',
};

const UPGRADE_STATUS: Record<UpgradeStatus, { label: string; cls: string }> = {
  'up-to-date': { label: 'Up to date', cls: 'state state-complete' },
  'update-available': { label: 'Update available', cls: 'sev-badge sev-medium' },
  'update-recommended': { label: 'Update recommended', cls: 'sev-badge sev-high' },
  incompatible: { label: 'Incompatible', cls: 'sev-badge sev-critical' },
  'no-compatible': { label: 'No compatible version', cls: 'sev-badge sev-critical' },
  'not-found': { label: 'Not on Marketplace', cls: 'state state-empty' },
  'not-checked': { label: 'Not checked', cls: 'state state-empty' },
};

/** Every verdict that means "this item should change": all of them count as an update. */
const UPDATE_STATUSES = new Set<UpgradeStatus>(['update-available', 'update-recommended', 'incompatible', 'no-compatible']);

type WidgetReport = WidgetVulnerabilityReport & AcceptanceView;

/** Like {@link vulnerabilityReport}: `byWidget` holds only open advisories; accepted ones move aside. */
function widgetVulnerabilities(result: SecurityAnalysisResult): WidgetReport | undefined {
  if (!state.widgetOsv) return undefined;
  const report = applyWidgetOsv(result.upgrades, state.widgetOsv);
  const view: AcceptanceView = { accepted: {}, overdue: {} };
  for (const w of result.upgrades.widgets) {
    const list = report.byWidget[w.key];
    if (!list || !w.fileName) continue;
    const split = splitByAcceptance(list, state.acceptedRisks.risks, 'widget', w.fileName);
    report.byWidget[w.key] = split.open;
    if (split.accepted.length > 0) view.accepted[w.key] = split.accepted;
    if (split.overdue.length > 0) view.overdue[w.key] = split.overdue;
  }
  return { ...report, ...view };
}

function needsUpdate(item: MarketplaceItem, a: ItemAssessment, wv: WidgetReport | undefined): boolean {
  return UPDATE_STATUSES.has(a.status) || (wv?.byWidget[item.key]?.length ?? 0) > 0;
}

function checkWidgetVulnerabilities(result: SecurityAnalysisResult): void {
  const packages = widgetPackagesToCheck(result.upgrades);
  if (packages.length === 0) {
    showToast('None of the widgets lists bundled libraries that can be looked up.');
    return;
  }
  if (!inStudioPro) {
    showToast('The vulnerability check needs Studio Pro: the pane asks OSV.dev through the extension host.');
    return;
  }
  state.wvPhase = 'checking';
  state.wvError = '';
  render();
  send('CheckVulnerabilities', { packages, purpose: 'widgets' });
}

function onWidgetVulnerabilityResult(data: { ok: boolean; json?: string; error?: string }): void {
  if (data.ok && data.json) {
    try {
      state.widgetOsv = JSON.parse(data.json) as OsvCheckResult;
      state.wvPhase = 'idle';
    } catch (err) {
      state.wvPhase = 'error';
      state.wvError = `The answer from OSV.dev could not be read: ${(err as Error).message}`;
    }
  } else {
    state.wvPhase = 'error';
    state.wvError = data.error ?? 'The vulnerability check failed.';
  }
  render();
}

/** The token typed for the check in progress; kept only until the host has answered. */
let pendingToken = '';

/** Versions are always judged against the Mendix version of the app the extension is running in. */
function upgradeTarget(result: SecurityAnalysisResult): string | undefined {
  return result.upgrades.mendixVersion;
}

function upgradeAssessments(result: SecurityAnalysisResult): Map<string, ItemAssessment> {
  const inventory = result.upgrades;
  const target = upgradeTarget(result);
  const answer = state.marketplace;
  const out = new Map<string, ItemAssessment>();
  for (const m of inventory.modules) {
    out.set(m.key, assessItem(m, m.contentId ? answer?.versions[String(m.contentId)] : undefined, target));
  }
  for (const w of inventory.widgets) {
    const contentId = w.bundledWith ? undefined : state.widgetMatches[w.key];
    const own = assessItem(
      { ...w, contentId },
      contentId ? answer?.versions[String(contentId)] : undefined,
      target
    );
    // Before the catalog has been read, an unmatched standalone widget is "not checked", not "not found".
    const unmatched = !w.bundledWith && contentId === undefined && !answer?.catalog && !state.catalogRead;
    out.set(w.key, assessWidget(w, unmatched ? { status: 'not-checked', note: 'Matched to the Marketplace by name when you check.' } : own, w.bundledWith ? out.get(`module:${w.bundledWith}`) : undefined));
  }
  return out;
}

function upgradesTabCount(result: SecurityAnalysisResult): number | undefined {
  if (!state.marketplace && !state.widgetOsv) return undefined;
  const a = upgradeAssessments(result);
  const wv = widgetVulnerabilities(result);
  const items = [...result.upgrades.modules, ...result.upgrades.widgets];
  return items.filter((i) => needsUpdate(i, a.get(i.key)!, wv)).length || undefined;
}

function checkMarketplace(result: SecurityAnalysisResult, typedToken: string, remember: boolean): void {
  if (!inStudioPro) {
    showToast('The Marketplace check needs Studio Pro: the host reads the Marketplace on the pane’s behalf.');
    return;
  }
  const inventory = result.upgrades;
  pendingToken = typedToken.trim();
  state.mpPhase = 'checking';
  state.mpError = '';
  render();
  const needCatalog = inventory.widgets.some((w) => !w.bundledWith) && !state.catalogRead;
  send('CheckMarketplace', { token: pendingToken || undefined, remember, contentIds: contentIdsToCheck(inventory, state.widgetMatches), catalog: needCatalog });
}

function onMarketplaceResult(data: { ok: boolean; json?: string; error?: string; needsToken?: boolean; tokenSource?: string }): void {
  if (!data.ok || !data.json) {
    pendingToken = '';
    state.mpPhase = 'error';
    state.mpError = data.error ?? 'The Marketplace could not be read.';
    if (data.needsToken) state.tokenSource = 'None';
    render();
    return;
  }
  const answer = JSON.parse(data.json) as MarketplaceAnswer;
  if (data.tokenSource) state.tokenSource = data.tokenSource as typeof state.tokenSource;
  const merged: MarketplaceAnswer = {
    checkedAt: answer.checkedAt,
    versions: { ...(state.marketplace?.versions ?? {}), ...answer.versions },
    failures: { ...(state.marketplace?.failures ?? {}), ...(answer.failures ?? {}) },
  };
  state.marketplace = merged;
  const result = state.result;
  if (answer.catalog && result) {
    state.catalogRead = true;
    state.widgetMatches = matchWidgets(result.upgrades, answer.catalog);
    const missing = Object.values(state.widgetMatches).filter((id) => merged.versions[String(id)] === undefined);
    if (missing.length > 0) {
      // Second round: the version lists of the widgets just matched.
      send('CheckMarketplace', { token: pendingToken || undefined, remember: false, contentIds: [...new Set(missing)], catalog: false });
      render();
      return;
    }
  }
  pendingToken = '';
  state.mpPhase = 'idle';
  render();
}

function upgradesView(result: SecurityAnalysisResult): HTMLElement {
  const inventory = result.upgrades;
  const target = upgradeTarget(result);
  const assessments = upgradeAssessments(result);
  const items = [...inventory.modules, ...inventory.widgets];
  const count = (pred: (a: ItemAssessment) => boolean) => items.filter((i) => pred(assessments.get(i.key)!)).length;
  const checked = state.marketplace !== undefined;
  const wv = widgetVulnerabilities(result);

  const matches = (item: MarketplaceItem): boolean => {
    const a = assessments.get(item.key)!;
    switch (state.upFilter) {
      case 'modules':
        return item.kind === 'module';
      case 'widgets':
        return item.kind === 'widget';
      case 'updates':
        return needsUpdate(item, a, wv);
      case 'vulnerable':
        return (wv?.byWidget[item.key]?.length ?? 0) > 0;
      case 'accepted':
        return (wv?.accepted[item.key]?.length ?? 0) > 0;
      case 'current':
        return a.status === 'up-to-date';
      case 'unknown':
        return a.status === 'not-found' || a.status === 'not-checked';
      default:
        return true;
    }
  };

  // ---- connection
  const tokenInput = h('input', { type: 'password', class: 'search', placeholder: 'Mendix Personal Access Token', autocomplete: 'off', 'aria-label': 'Mendix Personal Access Token' });
  const rememberBox = h('input', { type: 'checkbox' });
  const checking = state.mpPhase === 'checking';
  const hasToken = state.tokenSource !== 'None';

  // One bar, one button: the Marketplace compatibility check and the widget vulnerability check
  // run together. The vulnerability check needs no token, so it runs even when there is none.
  const wvChecking = state.wvPhase === 'checking';
  const rereading = state.recheck === 'upgrades';
  const anyChecking = checking || wvChecking || rereading;
  const widgetCount = inventory.widgets.length;
  // What is running right now, for the progress line: both checks can run at once.
  const running = [
    checking ? `checking ${inventory.modules.length + inventory.widgets.length} modules and widgets against the Marketplace` : '',
    wvChecking ? `checking the libraries bundled into ${widgetCount} widget${widgetCount === 1 ? '' : 's'} against OSV.dev` : '',
  ].filter(Boolean);
  const progress = rereading
    ? taskProgress(1, 'Reading the Marketplace modules and the widgets folder…')
    : running.length > 0
      ? taskProgress(2, `${running.join(', and ').replace(/^./, (c) => c.toUpperCase())}…`)
      : null;
  const vulnerableCount = inventory.widgets.filter((w) => (wv?.byWidget[w.key]?.length ?? 0) > 0).length;
  const advisoryCount = new Set(inventory.widgets.flatMap((w) => (wv?.byWidget[w.key] ?? []).map((v) => v.id))).size;
  const tokenText = hasToken
    ? `Using ${state.tokenSource === 'Remembered' ? 'the token remembered on this computer' : state.tokenSource === 'Environment' ? 'the MENDIX_PAT environment variable' : 'the token you entered'}.`
    : 'Version compatibility needs a Mendix Personal Access Token (user-settings.mendix.com ▸ Developer Settings ▸ Personal Access Tokens, with the Marketplace content read scope).';
  const statusLine = (label: string, value: string, failed: boolean) =>
    h('div', { class: `check-line${failed ? ' failed-line' : ''}` }, h('strong', {}, label), ' ', h('span', {}, value));

  const connect = h(
    'div',
    { class: `check-bar${state.mpPhase === 'error' || state.wvPhase === 'error' ? ' failed' : ''}` },
    h(
      'div',
      { class: 'check-text' },
      statusLine(
        'Compatibility:',
        checking
          ? 'reading the Marketplace…'
          : state.mpPhase === 'error'
            ? state.mpError
            : checked
              ? `checked against the Marketplace at ${new Date(state.marketplace!.checkedAt).toLocaleTimeString()}.`
              : hasToken
                ? 'not checked yet.'
                : 'not checked — enter a token below to include it.',
        state.mpPhase === 'error'
      ),
      statusLine(
        'Widget vulnerabilities:',
        wvChecking
          ? 'checking bundled libraries on OSV.dev…'
          : state.wvPhase === 'error'
            ? state.wvError
            : wv
              ? vulnerableCount === 0
                ? `none known (checked at ${new Date(wv.checkedAt).toLocaleTimeString()}).`
                : `${vulnerableCount} vulnerable widget${vulnerableCount === 1 ? '' : 's'} · ${advisoryCount} advisor${advisoryCount === 1 ? 'y' : 'ies'} (checked at ${new Date(wv.checkedAt).toLocaleTimeString()}).`
              : 'not checked yet.',
        state.wvPhase === 'error'
      ),
      h(
        'span',
        { class: 'muted small' },
        `${tokenText} Only Marketplace content ids and library names with versions are sent — nothing from the app model. The suggested versions are for the Mendix version above.`
      ),
      !hasToken || state.mpPhase === 'error'
        ? h(
            'div',
            { class: 'token-row' },
            tokenInput,
            h('label', { class: 'toggle', title: 'Encrypted for your Windows account (DPAPI) under %LOCALAPPDATA%' }, rememberBox, 'Remember on this computer')
          )
        : state.tokenSource === 'Remembered'
          ? h('button', { class: 'btn ghost small', onclick: () => send('ForgetMarketplaceToken') }, 'Forget the remembered token')
          : null
    ),
    h(
      'button',
      {
        class: 'btn primary',
        disabled: anyChecking || items.length === 0,
        title: 'Re-reads the modules and the widgets folder, then runs the checks',
        onclick: () => {
          const typed = tokenInput.value;
          const remember = rememberBox.checked;
          tokenInput.value = '';
          // Re-read first so widgets and modules added since the last run are checked too.
          rereadThen('upgrades', (fresh) => {
            // Compatibility runs when a token is available or typed; the vulnerability check always runs.
            if (hasToken || typed.trim()) checkMarketplace(fresh, typed, remember);
            if (widgetPackagesToCheck(fresh.upgrades).length > 0) checkWidgetVulnerabilities(fresh);
            if (!hasToken && !typed.trim()) showToast('Checking widget vulnerabilities only: enter a Mendix Personal Access Token to include version compatibility.');
          }, result);
        },
      },
      anyChecking ? spinner() : shieldIcon(),
      rereading ? 'Reading…' : anyChecking ? 'Checking…' : checked || wv ? 'Check again' : 'Run checks'
    ),
    progress
  );

  const planner = h(
    'div',
    { class: 'planner' },
    h('div', {}, h('div', { class: 'label' }, 'App Mendix version'), h('div', { class: 'v' }, inventory.mendixVersion ?? 'unknown')),
    h(
      'div',
      { class: 'planner-target' },
      h(
        'span',
        { class: 'muted small' },
        target
          ? `Read from this app. Every module and widget below is judged against Mendix ${target}: the version to use is the newest one that supports it.`
          : 'The app’s Mendix version could not be read, so versions cannot be judged for compatibility.'
      )
    )
  );

  const card = (filter: UpgradeFilter, label: string, value: string | number, cls = '', needsCheck = false, available = checked) => {
    const disabled = needsCheck && !available;
    const active = state.upFilter === filter;
    return h(
      'button',
      {
        class: `fact kpi ${cls}${active ? ' active' : ''}`,
        disabled,
        'aria-pressed': active ? 'true' : 'false',
        title: disabled ? 'Check the Marketplace first' : active && filter !== 'all' ? 'Show everything' : `Show ${UPGRADE_FILTER_LABEL[filter].toLowerCase()}`,
        onclick: () => {
          state.upFilter = active ? 'all' : filter;
          render();
        },
      },
      h('div', { class: 'label' }, label),
      h('div', { class: 'v' }, String(value))
    );
  };
  const updates = items.filter((i) => needsUpdate(i, assessments.get(i.key)!, wv)).length;
  const vulnerableWidgets = inventory.widgets.filter((w) => (wv?.byWidget[w.key]?.length ?? 0) > 0).length;

  const search = h('input', { type: 'search', class: 'search', placeholder: 'Filter modules and widgets…', value: state.upQuery, 'aria-label': 'Filter modules and widgets' });
  const list = h('div', { class: 'lib-sections' });
  const renderList = () => {
    clear(list);
    const q = state.upQuery.trim().toLowerCase();
    const visible = (group: MarketplaceItem[]) =>
      group
        .filter((i) => matches(i) && (!q || [i.name, i.fileName ?? '', i.bundledWith ?? '', i.installedVersion ?? ''].some((s) => s.toLowerCase().includes(q))))
        .sort(
          (a, b) =>
            Number((wv?.byWidget[b.key]?.length ?? 0) > 0) - Number((wv?.byWidget[a.key]?.length ?? 0) > 0) ||
            Number((b.usedIn?.length ?? 1) > 0) - Number((a.usedIn?.length ?? 1) > 0) ||
            STATUS_RANK[assessments.get(a.key)!.status] - STATUS_RANK[assessments.get(b.key)!.status] ||
            a.name.localeCompare(b.name)
        );
    const itemCard = (i: MarketplaceItem) => upgradeCard(i, assessments.get(i.key)!, target, wv?.byWidget[i.key], wv?.accepted[i.key], wv?.overdue[i.key]);
    // Widgets that ship inside a module cannot be updated on their own: one group per module.
    const bundleGroup = (moduleName: string, members: MarketplaceItem[]) => {
      const open = state.openBundles.has(moduleName) || q.length > 0;
      const moduleItem = inventory.modules.find((m) => m.name === moduleName);
      const moduleNote = moduleItem ? assessments.get(moduleItem.key)?.note : undefined;
      const withAdvisories = members.filter((m) => (wv?.byWidget[m.key]?.length ?? 0) > 0).length;
      const usageKnown = members.every((m) => m.usedIn !== undefined);
      const placed = members.filter((m) => (m.usedIn?.length ?? 0) > 0).length;
      const version = members[0]?.moduleVersion;
      const el: HTMLElement = h(
        'article',
        { class: `finding lib bundle${withAdvisories > 0 ? ' sev-high' : ''}${open ? ' open' : ''}` },
        h(
          'button',
          {
            class: 'finding-head',
            'aria-expanded': open ? 'true' : 'false',
            onclick: () => {
              if (state.openBundles.has(moduleName)) state.openBundles.delete(moduleName);
              else state.openBundles.add(moduleName);
              renderList();
            },
          },
          withAdvisories > 0
            ? h('span', { class: 'sev-badge sev-high' }, `${withAdvisories} with advisories`)
            : h('span', { class: 'state state-empty' }, 'Bundled'),
          h(
            'span',
            { class: 'finding-title' },
            h('span', { class: 'rule' }, `Widgets shipped with ${moduleName}`, h('span', { class: 'lib-version' }, version ? ` ${version}` : '')),
            h(
              'span',
              { class: 'artifact' },
              `${members.length} widget${members.length === 1 ? '' : 's'}${usageKnown ? ` · ${placed} placed in the app, ${members.length - placed} not used` : ''}`
            )
          ),
          h('span', { class: 'meta' }, chevronIcon())
        ),
        h(
          'p',
          { class: 'observation' },
          `These widgets are part of the ${moduleName} module and are not on the Marketplace on their own: they change only when ${moduleName} is updated to another release.${moduleNote ? ` ${moduleNote}` : ''}`
        ),
        open ? h('div', { class: 'details bundle-members' }, h('div', { class: 'finding-list' }, members.map(itemCard))) : null
      );
      return el;
    };
    // Widgets whose ids share a namespace: one family card, read from the packages themselves.
    const familyGroup = (family: string, members: MarketplaceItem[]) => {
      const key = `family:${family}`;
      const open = state.openBundles.has(key) || q.length > 0;
      const withAdvisories = members.filter((m) => (wv?.byWidget[m.key]?.length ?? 0) > 0).length;
      const usageKnown = members.every((m) => m.usedIn !== undefined);
      const placed = members.filter((m) => (m.usedIn?.length ?? 0) > 0).length;
      const notOnOwn = members.filter((m) => assessments.get(m.key)?.status === 'not-found').length;
      return h(
        'article',
        { class: `finding lib bundle${withAdvisories > 0 ? ' sev-high' : ''}${open ? ' open' : ''}` },
        h(
          'button',
          {
            class: 'finding-head',
            'aria-expanded': open ? 'true' : 'false',
            onclick: () => {
              if (state.openBundles.has(key)) state.openBundles.delete(key);
              else state.openBundles.add(key);
              renderList();
            },
          },
          withAdvisories > 0
            ? h('span', { class: 'sev-badge sev-high' }, `${withAdvisories} with advisories`)
            : h('span', { class: 'state state-empty' }, 'Family'),
          h(
            'span',
            { class: 'finding-title' },
            h('span', { class: 'rule' }, 'Widget family ', h('span', { class: 'mono' }, family)),
            h(
              'span',
              { class: 'artifact' },
              `${members.length} widgets${usageKnown ? ` · ${placed} placed in the app, ${members.length - placed} not used` : ''}${notOnOwn > 0 ? ` · ${notOnOwn} not on the Marketplace on their own` : ''}`
            )
          ),
          h('span', { class: 'meta' }, chevronIcon())
        ),
        h(
          'p',
          { class: 'observation' },
          `Widgets whose ids share the namespace ${family}. Each is checked on its own. A widget the Marketplace does not list on its own was probably installed by a Marketplace module: updating that module is what updates it.`
        ),
        open ? h('div', { class: 'details bundle-members' }, h('div', { class: 'finding-list' }, members.map(itemCard))) : null
      );
    };
    const section = (title: string, hint: string, group: MarketplaceItem[]) => {
      const shown = visible(group);
      if (shown.length === 0 && state.upFilter !== 'all') return null;
      const bundles = new Map<string, MarketplaceItem[]>();
      for (const i of shown) if (i.bundledWith) bundles.set(i.bundledWith, [...(bundles.get(i.bundledWith) ?? []), i]);
      // Families count across the whole widgets folder, so a filter showing one member still groups it.
      const familySize = new Map<string, number>();
      for (const i of group) if (!i.bundledWith && i.family) familySize.set(i.family, (familySize.get(i.family) ?? 0) + 1);
      const families = new Map<string, MarketplaceItem[]>();
      const standalone: MarketplaceItem[] = [];
      for (const i of shown) {
        if (i.bundledWith) continue;
        if (i.family && (familySize.get(i.family) ?? 0) > 1) families.set(i.family, [...(families.get(i.family) ?? []), i]);
        else standalone.push(i);
      }
      return h(
        'div',
        { class: 'lib-section' },
        h('h3', {}, `${title} (${group.length})`),
        h('p', { class: 'muted small' }, hint),
        shown.length === 0
          ? h('p', { class: 'muted small' }, group.length === 0 ? 'None.' : 'None match the filter.')
          : h(
              'div',
              { class: 'finding-list' },
              [...bundles].sort(([x], [y]) => x.localeCompare(y)).map(([name, members]) => bundleGroup(name, members)),
              [...families].sort(([x], [y]) => x.localeCompare(y)).map(([name, members]) => familyGroup(name, members)),
              standalone.map(itemCard)
            )
      );
    };
    const parts = [
      state.upFilter !== 'widgets'
        ? section('Marketplace modules', 'Modules installed from the Marketplace, identified by the content id the model records.', inventory.modules)
        : null,
      state.upFilter !== 'modules'
        ? section(
            'Widgets',
            'Widget packages in the widgets folder. A widget with the same name and version as a Marketplace module is shown with that module; widgets whose ids share a namespace are shown as one family. Each is matched to the Marketplace by name; one the Marketplace does not list on its own was probably installed by a module, and updating that module updates it.',
            inventory.widgets
          )
        : null,
    ].filter((p): p is HTMLDivElement => p !== null);
    append(list, parts.length > 0 ? parts : [h('p', { class: 'muted center' }, `No ${UPGRADE_FILTER_LABEL[state.upFilter].toLowerCase()}.`)]);
  };
  search.addEventListener('input', () => {
    state.upQuery = search.value;
    renderList();
  });
  renderList();

  return h(
    'section',
    { class: 'panel libraries upgrades' },
    tabIntro(
      'The Marketplace modules and widgets in the app: the version of each that suits this app’s Mendix version, and known vulnerabilities in the libraries bundled into widgets. Run checks reads the Marketplace (needs a Personal Access Token) and OSV.dev in one go. Click a card to filter; open an item for the version to use, its advisories, and to accept a reviewed risk.'
    ),
    riskFileWarning(),
    planner,
    connect,
    h(
      'div',
      { class: 'facts lib-facts' },
      card('all', 'Everything', items.length),
      card('modules', 'Marketplace modules', inventory.modules.length),
      card('widgets', 'Widgets', inventory.widgets.length),
      card('updates', 'Updates available', checked || wv ? updates : '—', (checked || wv) && updates > 0 ? 'warn' : '', true, checked || wv !== undefined),
      card('vulnerable', 'Vulnerable widgets', wv ? vulnerableWidgets : '—', wv && vulnerableWidgets > 0 ? 'bad' : '', true, wv !== undefined),
      card('accepted', 'Accepted risks', wv ? Object.values(wv.accepted).reduce((n, l) => n + l.length, 0) : '—', '', true, wv !== undefined),
      card('current', 'Up to date', checked ? count((a) => a.status === 'up-to-date') : '—', '', true),
      card('unknown', 'Not assessed', count((a) => a.status === 'not-found' || a.status === 'not-checked'))
    ),
    h(
      'div',
      { class: 'toolbar' },
      search,
      state.upFilter !== 'all'
        ? h('span', { class: 'filter-pill' }, `Showing: ${UPGRADE_FILTER_LABEL[state.upFilter]}`, h('button', { class: 'btn ghost small', onclick: () => { state.upFilter = 'all'; render(); } }, 'Show all'))
        : null
    ),
    list,
    inventory.notes.length > 0 ? h('div', { class: 'lib-notes' }, inventory.notes.map((n) => h('p', { class: 'muted small' }, n))) : null,
    h(
      'p',
      { class: 'muted small' },
      'The Marketplace publishes a minimum Mendix version for each release but no maximum, so "update recommended" marks versions built for an older major Mendix line. Read the release notes before updating, and update in a branch: Marketplace updates replace the module, including any local changes.'
    )
  );
}

/** Advisories found only in indirect libraries: shown for completeness, not counted. */
function indirectVulnerabilities(list: LibraryVulnerability[] | undefined): HTMLElement | null {
  if (!list || list.length === 0) return null;
  const libs = new Set(list.map((v) => v.package)).size;
  return h(
    'details',
    { class: 'detail indirect' },
    h(
      'summary',
      { class: 'label' },
      `${list.length} advisor${list.length === 1 ? 'y' : 'ies'} in ${libs} indirect librar${libs === 1 ? 'y' : 'ies'} — not counted`
    ),
    h(
      'p',
      { class: 'muted small' },
      "These libraries are pulled in by the widget's own dependencies, which for native widgets include its build tools (bundlers, compilers, linters). Most never run in the app; review the ones that do."
    ),
    h('div', { class: 'detail-list' }, list.map((v) => widgetVulnerabilityRow(v)))
  );
}

function widgetVulnerabilityRow(v: LibraryVulnerability, risk?: { target: string; overdue?: AcceptedRisk }): HTMLElement {
  return h(
    'div',
    { class: 'vuln-row' },
    h(
      'div',
      { class: 'vuln-head' },
      h('span', { class: `sev-badge sev-${v.severity.toLowerCase()}` }, v.score !== undefined ? `${v.severity} ${v.score.toFixed(1)}` : v.severity),
      inStudioPro
        ? h('button', { class: 'chip chip-link mono', title: 'Open the advisory on osv.dev', onclick: () => send('OpenAdvisory', { id: v.id }) }, v.id)
        : h('span', { class: 'chip mono' }, v.id),
      v.cves.map((c) => h('span', { class: 'chip mono' }, c))
    ),
    h('div', { class: 'vuln-summary' }, v.summary),
    h('div', { class: 'muted small' }, `In bundled ${v.package} ${v.version}`, v.fixedIn ? ` · fixed in ${v.package} ${v.fixedIn}` : ' · no fixed release listed', v.published ? ` · published ${new Date(v.published).toLocaleDateString()}` : ''),
    risk ? riskControls('widget', risk.target, v, risk.overdue) : null
  );
}

// ---------------------------------------------------------------------- accepted risks

/**
 * "Accept risk…" on an open advisory, with the form inline: a reason (required) and a review-by
 * date. A lapsed acceptance shows why it counts again and offers to accept it anew.
 */
function riskControls(scope: RiskScope, target: string, v: LibraryVulnerability, overdue?: AcceptedRisk): HTMLElement {
  const identity = { scope, target, advisoryId: v.id, package: v.package, version: v.version };
  const key = riskKey(identity);
  if (state.riskForm !== key) {
    return h(
      'div',
      { class: 'risk-actions' },
      overdue
        ? h('span', { class: 'tag warn', title: overdue.reason }, `Accepted until ${overdue.reviewBy} by ${acceptedByText(overdue).who} — review overdue, counts again`)
        : null,
      h(
        'button',
        {
          class: 'btn ghost small',
          title: 'Record that this advisory has been reviewed and the risk is accepted for now',
          onclick: () => {
            state.riskForm = key;
            state.riskError = '';
            state.riskDraft = { reason: overdue?.reason ?? '', reviewBy: addDays(todayIso(), DEFAULT_REVIEW_DAYS) };
            render();
          },
        },
        overdue ? 'Review and accept again…' : 'Accept risk…'
      )
    );
  }

  const reason = h('textarea', {
    class: 'risk-reason',
    rows: 3,
    placeholder: 'Why is this acceptable for now? e.g. "The chart data comes from our own model; no attacker-controlled template or path reaches lodash. Revisit when we move to Mendix 11.12."',
    'aria-label': 'Reason for accepting the risk',
  });
  reason.value = state.riskDraft.reason;
  reason.addEventListener('input', () => (state.riskDraft.reason = reason.value));
  const reviewBy = h('input', { type: 'date', class: 'search risk-date', min: addDays(todayIso(), 1), max: addDays(todayIso(), MAX_REVIEW_DAYS), 'aria-label': 'Review-by date' });
  reviewBy.value = state.riskDraft.reviewBy;
  reviewBy.addEventListener('change', () => (state.riskDraft.reviewBy = reviewBy.value));

  const save = () => {
    const proposed: AcceptedRisk = { ...identity, reason: reason.value.trim(), reviewBy: reviewBy.value };
    const problem = validateRisk(proposed);
    if (problem) {
      state.riskError = problem;
      render();
      return;
    }
    if (inStudioPro) {
      send('AcceptRisk', { risk: proposed });
      return;
    }
    // Development mode: no app folder to write to; keep it for this session only.
    state.acceptedRisks = {
      ...state.acceptedRisks,
      risks: [...state.acceptedRisks.risks.filter((r) => riskKey(r) !== key), { ...proposed, acceptedBy: 'you (not saved — development mode)', acceptedAt: new Date().toISOString() }],
    };
    state.riskForm = '';
    render();
  };

  return h(
    'div',
    { class: 'risk-form' },
    h('div', { class: 'label' }, `Accept ${v.id} in ${v.package} ${v.version}`),
    h(
      'p',
      { class: 'muted small' },
      `The advisory stops counting until the review-by date, then counts again. The decision covers this library version only, is saved in the app folder (${state.acceptedRisks.path ?? '.security-analyzer/accepted-risks.json'}) with your Windows user name, and should be committed with the app.`
    ),
    reason,
    h('div', { class: 'risk-row' }, h('label', { class: 'label' }, 'Review by'), reviewBy, h('span', { class: 'muted small' }, `at most ${MAX_REVIEW_DAYS} days ahead`)),
    state.riskError ? h('p', { class: 'error-text small' }, state.riskError) : null,
    h(
      'div',
      { class: 'risk-row' },
      h('button', { class: 'btn primary small', onclick: save }, 'Accept risk'),
      h('button', { class: 'btn ghost small', onclick: () => { state.riskForm = ''; state.riskError = ''; render(); } }, 'Cancel')
    )
  );
}

/** Advisories accepted for this library or widget: shown with the decision, not counted. */
function acceptedSection(scope: RiskScope, target: string, list: AcceptedVulnerability[]): HTMLElement | null {
  if (list.length === 0) return null;
  return h(
    'div',
    { class: 'detail' },
    h('div', { class: 'label' }, `Accepted risks (${list.length}) — not counted`),
    h(
      'div',
      { class: 'detail-list' },
      list.map(({ vulnerability: v, risk }) =>
        h(
          'div',
          { class: 'vuln-row accepted-row' },
          h(
            'div',
            { class: 'vuln-head' },
            h('span', { class: 'state state-review' }, 'Accepted'),
            h('span', { class: `sev-badge sev-${v.severity.toLowerCase()}` }, v.score !== undefined ? `${v.severity} ${v.score.toFixed(1)}` : v.severity),
            inStudioPro
              ? h('button', { class: 'chip chip-link mono', title: 'Open the advisory on osv.dev', onclick: () => send('OpenAdvisory', { id: v.id }) }, v.id)
              : h('span', { class: 'chip mono' }, v.id),
            h('span', { class: 'muted small' }, `${v.package} ${v.version}`)
          ),
          h('div', { class: 'vuln-summary' }, v.summary),
          h('div', { class: 'risk-reason-text' }, h('strong', {}, 'Reason: '), risk.reason),
          h(
            'div',
            { class: 'muted small' },
            'Accepted by ',
            h('strong', {}, acceptedByText(risk).who),
            `${risk.acceptedAt ? ` on ${new Date(risk.acceptedAt).toLocaleDateString()}` : ''} · review by ${risk.reviewBy}`,
            acceptedByText(risk).detail ? ` · ${acceptedByText(risk).detail}` : ''
          ),
          h(
            'div',
            { class: 'risk-actions' },
            h(
              'button',
              {
                class: 'btn ghost small',
                title: 'Remove the decision; the advisory counts again',
                onclick: () => {
                  if (!window.confirm(`Revoke the accepted risk for ${v.id}? It will count as open again.`)) return;
                  const which = { scope, target, advisoryId: risk.advisoryId, package: risk.package, version: risk.version };
                  if (inStudioPro) send('RevokeRisk', { risk: which });
                  else {
                    state.acceptedRisks = { ...state.acceptedRisks, risks: state.acceptedRisks.risks.filter((r) => riskKey(r) !== riskKey(which)) };
                    render();
                  }
                },
              },
              'Revoke'
            )
          )
        )
      )
    )
  );
}

const STATUS_RANK: Record<UpgradeStatus, number> = {
  incompatible: 0,
  'no-compatible': 1,
  'update-recommended': 2,
  'update-available': 3,
  'not-checked': 4,
  'not-found': 5,
  'up-to-date': 6,
};

function upgradeCard(
  item: MarketplaceItem,
  a: ItemAssessment,
  target: string | undefined,
  vulns: LibraryVulnerability[] | undefined,
  accepted: AcceptedVulnerability[] = [],
  overdue: AcceptedVulnerability[] = []
): HTMLElement {
  const open = state.openUpgrades.has(item.key);
  const status = UPGRADE_STATUS[a.status];
  // Each card filter shows what it is for: "Accepted risks" only the accepted advisories,
  // "Vulnerable widgets" only the open ones, "Updates available" the version to move to.
  // "Everything" and the inventory filters show the whole item.
  const view = state.upFilter;
  const showAccepted = view === 'accepted' || view === 'all';
  const showVulns = view !== 'accepted' && view !== 'updates';
  const vulnerable = view !== 'accepted' && (vulns?.length ?? 0) > 0;
  accepted = showAccepted ? accepted : [];
  const statusClass =
    a.status === 'incompatible' || a.status === 'no-compatible' ? 'sev-critical' : a.status === 'update-recommended' ? 'sev-high' : a.status === 'update-available' ? 'sev-medium' : a.status === 'up-to-date' ? 'lib-clean' : '';
  const sevClass = vulnerable ? `sev-${vulns![0]!.severity.toLowerCase()}` : statusClass;
  const contentId = item.kind === 'widget' && !item.bundledWith ? state.widgetMatches[item.key] : item.contentId;
  const version = (v: MarketplaceVersion | undefined) =>
    v ? `${v.versionNumber}${v.minSupportedMendixVersion ? ` · needs Mendix ${v.minSupportedMendixVersion}` : ''}${v.publicationDate ? ` · ${new Date(v.publicationDate).toLocaleDateString()}` : ''}` : '—';

  const el = h(
    'article',
    { class: `finding lib ${sevClass}${open ? ' open' : ''}` },
    h(
      'button',
      {
        class: 'finding-head',
        'aria-expanded': open ? 'true' : 'false',
        onclick: () => {
          if (state.openUpgrades.has(item.key)) state.openUpgrades.delete(item.key);
          else state.openUpgrades.add(item.key);
          el.replaceWith(upgradeCard(item, a, target, vulns, accepted, overdue));
        },
      },
      view === 'accepted' && accepted.length > 0
        ? h('span', { class: 'state state-review', title: 'Advisories reviewed and accepted for this widget' }, `${accepted.length} accepted risk${accepted.length === 1 ? '' : 's'}`)
        : vulnerable
          ? h('span', { class: `sev-badge sev-${vulns![0]!.severity.toLowerCase()}` }, `${vulns!.length} ${vulns!.length === 1 ? 'vulnerability' : 'vulnerabilities'}`)
          : accepted.length > 0
            ? h('span', { class: 'state state-review', title: 'Every advisory has been reviewed and accepted' }, 'Accepted risk')
            : h('span', { class: status.cls }, status.label),
      h(
        'span',
        { class: 'finding-title' },
        h('span', { class: 'rule' }, item.name, h('span', { class: 'lib-version' }, ` ${item.installedVersion ?? 'version unknown'}`)),
        h(
          'span',
          { class: 'artifact' },
          item.kind === 'module'
            ? `module${item.contentId ? ` · Marketplace ${item.contentId}` : ''}${item.isThemeModule ? ' · theme module' : ''}`
            : `widgets/${item.fileName}${item.bundledWith ? ` · ships with ${item.bundledWith}` : ''}`
        )
      ),
      h(
        'span',
        { class: 'meta' },
        a.recommended && isNewer(a.recommended.versionNumber, item.bundledWith ? item.moduleVersion : item.installedVersion)
          ? h('span', { class: 'tag tag-sub', title: item.bundledWith ? `${item.bundledWith} version to move to` : 'Version to move to' }, `→ ${item.bundledWith ? `${item.bundledWith} ` : ''}${a.recommended.versionNumber}`)
          : null,
        item.kind === 'widget' && item.usedIn !== undefined
          ? item.usedIn.length > 0
            ? h('span', { class: 'tag', title: 'Pages, snippets and layouts that place this widget' }, `Used on ${item.usedIn.length}`)
            : h('span', { class: 'tag', title: 'No page, snippet or layout places this widget' }, 'Not used')
          : null,
        item.platforms.map((p) => h('span', { class: 'tag' }, p)),
        chevronIcon()
      )
    ),
    h(
      'p',
      { class: 'observation' },
      view === 'accepted'
        ? `${accepted.length} advisor${accepted.length === 1 ? 'y has' : 'ies have'} been reviewed and accepted for this version; they do not count until the review date.`
        : vulnerable
          ? `${widgetSecurityAdvice(item, vulns!, a, target)}${item.usedIn?.length === 0 ? ' The app places this widget on no page, snippet or layout, so its code does not run in the app — a lower concern than a widget in use.' : ''}`
          : a.note
    ),
    open
      ? h(
          'div',
          { class: 'details' },
          vulnerable && !showVulns
            ? detail(
                'Known vulnerabilities',
                `${vulns!.length} open advisor${vulns!.length === 1 ? 'y' : 'ies'} in the bundled libraries — open the "Vulnerable widgets" card to see them and accept or resolve each.`
              )
            : null,
          vulnerable && showVulns
            ? h(
                'div',
                { class: 'detail' },
                h('div', { class: 'label' }, 'Known vulnerabilities in bundled libraries'),
                h(
                  'div',
                  { class: 'detail-list' },
                  vulns!.map((v) => widgetVulnerabilityRow(v, item.fileName ? { target: item.fileName, overdue: overdue.find((o) => o.vulnerability.id === v.id)?.risk } : undefined))
                )
              )
            : null,
          item.fileName && accepted.length > 0 ? acceptedSection('widget', item.fileName, accepted) : null,
          vulnerable && view !== 'updates' ? detail('Version status', a.note) : null,
          showVulns ? indirectVulnerabilities(state.widgetOsv ? applyWidgetOsv(state.result!.upgrades, state.widgetOsv).indirectByWidget[item.key] : undefined) : null,
          item.usedIn && item.usedIn.length > 0
            ? h(
                'details',
                { class: 'detail bundled' },
                h('summary', { class: 'label' }, `Used in (${item.usedIn.length})`),
                h('ul', { class: 'bundled-list mono' }, item.usedIn.map((d) => h('li', {}, h('span', {}, d))))
              )
            : null,
          item.dependencies.length > 0
            ? h(
                // Collapsed by default: a widget can bundle hundreds of libraries.
                'details',
                { class: 'detail bundled' },
                h('summary', { class: 'label' }, `Bundled libraries (${item.dependencies.length})`),
                h(
                  'ul',
                  { class: 'bundled-list mono' },
                  [...item.dependencies]
                    .sort((x, y) => x.name.localeCompare(y.name))
                    .map((d) => h('li', {}, h('span', {}, d.name), h('span', { class: 'muted' }, d.version)))
                )
              )
            : null,
          h(
            'dl',
            { class: 'evidence' },
            h('dt', {}, 'installed'),
            h('dd', {}, item.installedVersion ? `${item.installedVersion}${a.installed?.minSupportedMendixVersion ? ` · built for Mendix ${a.installed.minSupportedMendixVersion}` : ''}` : 'unknown'),
            h('dt', {}, `for Mendix ${target ?? '—'}`),
            h('dd', {}, version(a.recommended)),
            h('dt', {}, 'latest published'),
            h('dd', {}, version(a.latest)),
            item.kind === 'widget' && item.widgetIds.length > 0 ? [h('dt', {}, 'widget ids'), h('dd', {}, item.widgetIds.join(', '))] : null
          ),
          inStudioPro
            ? h(
                'div',
                { class: 'detail-foot' },
                h(
                  'span',
                  { class: 'muted small' },
                  item.bundledWith
                      ? `Update ${item.bundledWith} from the Marketplace to update this widget.`
                      : contentId
                        ? 'Update it from the Marketplace in Studio Pro.'
                        : ''
                ),
                h(
                  'span',
                  { class: 'foot-actions' },
                  item.fileName
                    ? h('button', { class: 'btn small ghost', onclick: () => send('OpenLibraryFolder', { folder: 'widgets', fileName: item.fileName }) }, folderIcon(), 'Open folder')
                    : null,
                  contentId ? h('button', { class: 'btn small', onclick: () => send('OpenMarketplacePage', { contentId }) }, 'Open on Marketplace') : null
                )
              )
            : null
        )
      : null
  );
  return el;
}

// ====================================================================== icons

function svg(path: string, cls = 'icon'): SVGSVGElement {
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  el.setAttribute('viewBox', '0 0 24 24');
  el.setAttribute('class', cls);
  el.setAttribute('aria-hidden', 'true');
  el.innerHTML = path; // static markup defined in this file, never model data
  return el;
}

function shieldIcon(): SVGSVGElement {
  return svg('<path d="M12 2.5 4.5 5.3v6.1c0 4.6 3.2 8.8 7.5 10.1 4.3-1.3 7.5-5.5 7.5-10.1V5.3L12 2.5Z" fill="currentColor" opacity=".15"/><path d="M12 2.5 4.5 5.3v6.1c0 4.6 3.2 8.8 7.5 10.1 4.3-1.3 7.5-5.5 7.5-10.1V5.3L12 2.5Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="m8.8 12.2 2.2 2.2 4.4-4.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>', 'icon shield');
}
function playIcon(): SVGSVGElement {
  return svg('<path d="M8 5.5v13l10.5-6.5L8 5.5Z" fill="currentColor"/>');
}
function checkIcon(): SVGSVGElement {
  return svg('<circle cx="12" cy="12" r="9.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m7.8 12.3 2.8 2.8 5.6-5.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>', 'icon check');
}
function folderIcon(): SVGSVGElement {
  return svg('<path d="M3.5 7.5A1.5 1.5 0 0 1 5 6h4l2 2h8a1.5 1.5 0 0 1 1.5 1.5v8A1.5 1.5 0 0 1 19 19H5a1.5 1.5 0 0 1-1.5-1.5v-10Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>');
}
function chevronIcon(): SVGSVGElement {
  return svg('<path d="m7 10 5 5 5-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>', 'icon chevron');
}
function spinner(): HTMLElement {
  return h('span', { class: 'spinner', 'aria-hidden': 'true' });
}
function statusIcon(status: RuleOutcome['status']): SVGSVGElement {
  switch (status) {
    case 'PASSED':
      return svg('<circle cx="12" cy="12" r="8" fill="currentColor"/><path d="m8.6 12.2 2.3 2.3 4.6-4.8" fill="none" stroke="var(--bg)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>');
    case 'FAILED':
      return svg('<circle cx="12" cy="12" r="8" fill="currentColor"/><path d="m9.2 9.2 5.6 5.6m0-5.6-5.6 5.6" stroke="var(--bg)" stroke-width="2" stroke-linecap="round"/>');
    case 'WARNING':
      return svg('<path d="M12 4 3.5 19h17L12 4Z" fill="currentColor"/><path d="M12 10v4m0 2.6v.1" stroke="var(--bg)" stroke-width="2" stroke-linecap="round"/>');
    default:
      return svg('<circle cx="12" cy="12" r="7.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M8.5 12h7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>');
  }
}

// ====================================================================== start

connect();
render();
send('MarketplaceTokenStatus');

// Development convenience: `index.html?snapshot=<url>` analyses a snapshot file directly.
const snapshotUrl = new URLSearchParams(location.search).get('snapshot');
if (!inStudioPro && snapshotUrl) {
  fetch(snapshotUrl)
    .then((r) => r.json())
    .then((s: ModelSnapshot) => analyze(s))
    .catch((err) => {
      state.phase = 'error';
      state.error = `Could not load ${snapshotUrl}: ${(err as Error).message}`;
      render();
    });
}
