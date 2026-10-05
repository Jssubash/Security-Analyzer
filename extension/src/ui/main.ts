/**
 * The Security Analyzer pane.
 *
 * Flow: the user presses Run → the pane asks the host for a model snapshot → the host reads
 * the open app through Studio Pro's model API and posts it back → the pane runs the SEC-*
 * catalogue locally and renders the result. Nothing leaves the machine.
 */

import { analyzeSnapshot, entityForFinding, securityCatalogue, unitForFinding } from '../analyze.js';
import type { RuleOutcome, SecurityAnalysisResult } from '../analyze.js';
import { applyOsvResult, duplicateAdvice, gaOf, isCheckable, packagesToCheck, remediation } from '../java-libraries.js';
import type { DuplicateGroup, JavaLibrary, LibraryVulnerability, OsvCheckResult, VulnerabilityReport } from '../java-libraries.js';
import { PLANNING_TARGETS, applyWidgetOsv, assessItem, assessWidget, contentIdsToCheck, isMendixVersion, matchWidgets, normaliseMendixVersion, widgetPackagesToCheck, widgetSecurityAdvice } from '../marketplace.js';
import type { ItemAssessment, MarketplaceAnswer, MarketplaceItem, MarketplaceVersion, UpgradeStatus, WidgetVulnerabilityReport } from '../marketplace.js';
import type { AccessState, ModuleStatus } from '../module-status.js';
import { DEFAULT_REVIEW_DAYS, MAX_REVIEW_DAYS, MIN_REASON_LENGTH, addDays, riskKey, splitByAcceptance, today as todayIso, validateRisk } from '../accepted-risks.js';
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
const ADVISORY_RULES = ['SEC-008', 'SEC-009'];

const state = {
  phase: 'idle' as Phase,
  error: '',
  snapshot: undefined as ModelSnapshot | undefined,
  result: undefined as SecurityAnalysisResult | undefined,
  tab: 'findings' as Tab,
  severities: new Set<RuleSeverity>(SEVERITIES),
  showWarnings: true,
  onlyOwnModules: false,
  includeAdvisory: false,
  query: '',
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
  upgradeTarget: '',
  marketplace: undefined as MarketplaceAnswer | undefined,
  widgetMatches: {} as Record<string, number>,
  catalogRead: false,
  mpPhase: 'idle' as 'idle' | 'checking' | 'error',
  mpError: '',
  tokenSource: 'None' as 'None' | 'Typed' | 'Remembered' | 'Environment',
  upFilter: 'all' as UpgradeFilter,
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
      const enabledRules = Object.fromEntries(ADVISORY_RULES.map((id) => [id, state.includeAdvisory]));
      state.result = analyzeSnapshot(snapshot, { enabledRules });
      state.phase = 'done';
      state.expanded.clear();
      const failures = state.result.findings.filter((f) => f.status === 'FAIL').length;
      send('AnalysisComplete', { failures, findings: state.result.findings.length });
    } catch (err) {
      state.phase = 'error';
      state.error = `The analysis failed: ${(err as Error)?.message ?? String(err)}`;
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
      if (msg.data.ok) break;
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
function openInStudioPro(unitId: string, entity?: string): void {
  send('OpenUnit', entity ? { unitId, entity } : { unitId });
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
  const busy = state.phase === 'reading' || state.phase === 'analyzing';
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
        { class: 'btn primary', onclick: run, disabled: busy },
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
    if (!state.showWarnings && f.status === 'WARNING') return false;
    if (state.onlyOwnModules && f.module && result.moduleTypes[f.module] !== 'user') return false;
    if (!q) return true;
    return [f.ruleId, f.ruleTitle, f.artifact, f.observation, f.module ?? ''].some((s) => s.toLowerCase().includes(q));
  });
}

function findingsView(result: SecurityAnalysisResult): HTMLElement {
  const list = h('div', { class: 'finding-list' });
  const renderList = () => {
    clear(list);
    const visible = visibleFindings(result);
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

  const toggle = (label: string, checked: boolean, onChange: (v: boolean) => void, title?: string) => {
    const box = h('input', { type: 'checkbox', checked });
    box.addEventListener('change', () => onChange(box.checked));
    return h('label', { class: 'toggle', title }, box, label);
  };

  const toolbar = h(
    'div',
    { class: 'toolbar' },
    search,
    toggle('Warnings', state.showWarnings, (v) => { state.showWarnings = v; renderList(); }, 'Include findings that need review rather than a fix'),
    toggle('Only my modules', state.onlyOwnModules, (v) => { state.onlyOwnModules = v; renderList(); }, 'Hide findings in Marketplace modules'),
    toggle('Advisory checks', state.includeAdvisory, (v) => {
      state.includeAdvisory = v;
      if (state.snapshot) analyze(state.snapshot);
    }, 'Also run SEC-008 (PII encryption) and SEC-009 (rate limiting), which are off by default')
  );

  renderList();
  return h(
    'section',
    { class: 'panel' },
    tabIntro(
      'Security problems found in the app. Each finding names the rule it breaks and what was found; open it for why it matters, how to fix it, the evidence, and a button to open the document in Studio Pro. “Review” marks findings that need a person’s judgement or sit in a Marketplace module (shown one severity lower). Click a severity tile above to filter.'
    ),
    toolbar,
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
          evidence(f),
          h(
            'div',
            { class: 'detail-foot' },
            h('span', { class: 'muted' }, `Confidence: ${f.confidence} · Source: ${f.sourceSkill}${f.sourceSection ? ` › ${f.sourceSection}` : ''}`),
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

function evidence(f: Finding): HTMLElement | null {
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
      entries.flatMap(([k, v]) => [h('dt', {}, humanise(k)), h('dd', {}, formatValue(v))])
    )
  );
}

function humanise(key: string): string {
  return key.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
}

function formatValue(value: unknown): string {
  if (Array.isArray(value)) return value.map(formatValue).join(', ');
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${humanise(k)}: ${formatValue(v)}`)
      .join('; ');
  }
  return String(value);
}

// ---------------------------------------------------------------------- rules

const STATUS_LABEL: Record<RuleOutcome['status'], string> = {
  PASSED: 'Passed',
  FAILED: 'Failed',
  WARNING: 'Review',
  NOT_APPLICABLE: 'Not applicable',
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
      'Every security rule the analyzer checks, grouped by area, with its result for this app: Passed, Failed, Review (needs judgement), Not applicable (the app has nothing to check, with the reason) or Off (advisory rules, enabled from the Findings tab).'
    ),
    [...groups].map(([group, rules]) =>
      h(
        'div',
        { class: 'rule-group' },
        h('h3', {}, group),
        rules.map((r) =>
          h(
            'div',
            { class: `rule-row st-${r.status.toLowerCase()}` },
            h('span', { class: 'rule-status' }, statusIcon(r.status), STATUS_LABEL[r.status]),
            h(
              'div',
              { class: 'rule-main' },
              h('div', {}, h('span', { class: 'rule-id' }, r.id), ' ', r.name),
              h('div', { class: 'muted small' }, r.reason ?? r.description)
            ),
            h('span', { class: `sev-badge sev-${r.severity.toLowerCase()}` }, r.severity),
            h('span', { class: 'rule-count' }, r.findingCount > 0 ? String(r.findingCount) : '')
          )
        )
      )
    )
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
  render();
  send('CheckVulnerabilities', { packages });
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
        checking
          ? 'Checking OSV.dev…'
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
      { class: 'btn primary', onclick: () => checkVulnerabilities(result), disabled: checking || packages === 0 },
      checking ? spinner() : shieldIcon(),
      checking ? 'Checking…' : report ? 'Check again' : 'Check for vulnerabilities'
    )
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
    h('div', { class: 'vuln-fix' }, h('strong', {}, 'Fix: '), remediation(lib, v)),
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

function upgradeTarget(result: SecurityAnalysisResult): string | undefined {
  const typed = state.upgradeTarget.trim();
  return typed && isMendixVersion(typed) ? normaliseMendixVersion(typed) : result.upgrades.mendixVersion;
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

  // ---- planner and connection
  const targetInput = h('input', {
    type: 'text',
    class: 'search version-input',
    value: state.upgradeTarget,
    placeholder: inventory.mendixVersion ?? 'e.g. 10.24.0',
    list: 'mendix-versions',
    'aria-label': 'Mendix version to plan for',
  });
  targetInput.addEventListener('change', () => {
    state.upgradeTarget = targetInput.value;
    render();
  });
  const versions = h('datalist', { id: 'mendix-versions' }, PLANNING_TARGETS.map((v) => h('option', { value: v })));
  const badTarget = state.upgradeTarget.trim() !== '' && !isMendixVersion(state.upgradeTarget);

  const tokenInput = h('input', { type: 'password', class: 'search', placeholder: 'Mendix Personal Access Token', autocomplete: 'off', 'aria-label': 'Mendix Personal Access Token' });
  const rememberBox = h('input', { type: 'checkbox' });
  const checking = state.mpPhase === 'checking';
  const hasToken = state.tokenSource !== 'None';

  // One bar, one button: the Marketplace compatibility check and the widget vulnerability check
  // run together. The vulnerability check needs no token, so it runs even when there is none.
  const wvChecking = state.wvPhase === 'checking';
  const anyChecking = checking || wvChecking;
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
        onclick: () => {
          const typed = tokenInput.value;
          // Compatibility runs when a token is available or typed; the vulnerability check always runs.
          if (hasToken || typed.trim()) checkMarketplace(result, typed, rememberBox.checked);
          if (widgetPackagesToCheck(inventory).length > 0) checkWidgetVulnerabilities(result);
          if (!hasToken && !typed.trim()) showToast('Checking widget vulnerabilities only: enter a Mendix Personal Access Token to include version compatibility.');
          tokenInput.value = '';
        },
      },
      anyChecking ? spinner() : shieldIcon(),
      anyChecking ? 'Checking…' : checked || wv ? 'Check again' : 'Run checks'
    )
  );

  const planner = h(
    'div',
    { class: 'planner' },
    h('div', {}, h('div', { class: 'label' }, 'App Mendix version'), h('div', { class: 'v' }, inventory.mendixVersion ?? 'unknown')),
    h(
      'div',
      { class: 'planner-target' },
      h('label', { class: 'label' }, 'Plan for Mendix version'),
      h('div', { class: 'planner-row' }, targetInput, versions, state.upgradeTarget ? h('button', { class: 'btn ghost small', onclick: () => { state.upgradeTarget = ''; render(); } }, 'Use the app’s version') : null),
      h(
        'span',
        { class: badTarget ? 'error-text small' : 'muted small' },
        badTarget
          ? 'Enter a version such as 10.24.0.'
          : `Showing the versions to use on Mendix ${target ?? '—'}. Enter the version you are upgrading to (e.g. 10.24.0 or 11.6.0) to plan the upgrade before you make it.`
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
            STATUS_RANK[assessments.get(a.key)!.status] - STATUS_RANK[assessments.get(b.key)!.status] ||
            a.name.localeCompare(b.name)
        );
    const section = (title: string, hint: string, group: MarketplaceItem[]) => {
      const shown = visible(group);
      if (shown.length === 0 && state.upFilter !== 'all') return null;
      return h(
        'div',
        { class: 'lib-section' },
        h('h3', {}, `${title} (${group.length})`),
        h('p', { class: 'muted small' }, hint),
        shown.length === 0 ? h('p', { class: 'muted small' }, group.length === 0 ? 'None.' : 'None match the filter.') : h('div', { class: 'finding-list' }, shown.map((i) => upgradeCard(i, assessments.get(i.key)!, target, wv?.byWidget[i.key], wv?.accepted[i.key], wv?.overdue[i.key])))
      );
    };
    const parts = [
      state.upFilter !== 'widgets'
        ? section('Marketplace modules', 'Modules installed from the Marketplace, identified by the content id the model records.', inventory.modules)
        : null,
      state.upFilter !== 'modules'
        ? section(
            'Widgets',
            'Widget packages in the widgets folder. Widgets that ship inside a module (Data Widgets, Native Mobile Resources, …) are updated by updating that module; the rest are matched to the Marketplace by name.',
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
      'The Marketplace modules and widgets in the app: the version of each that suits the app’s Mendix version (or the version you plan to move to), and known vulnerabilities in the libraries bundled into widgets. Run checks reads the Marketplace (needs a Personal Access Token) and OSV.dev in one go. Click a card to filter; open an item for the version to use, its advisories, and to accept a reviewed risk.'
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
        ? h('span', { class: 'tag warn', title: overdue.reason }, `Accepted until ${overdue.reviewBy} by ${overdue.acceptedBy ?? 'someone'} — review overdue, counts again`)
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
            `Accepted by ${risk.acceptedBy ?? 'unknown'}${risk.acceptedAt ? ` on ${new Date(risk.acceptedAt).toLocaleDateString()}` : ''} · review by ${risk.reviewBy}`
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
  const vulnerable = (vulns?.length ?? 0) > 0;
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
      vulnerable
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
        a.recommended && a.recommended.versionNumber !== (item.bundledWith ? item.moduleVersion : item.installedVersion)
          ? h('span', { class: 'tag tag-sub', title: item.bundledWith ? `${item.bundledWith} version to move to` : 'Version to move to' }, `→ ${item.bundledWith ? `${item.bundledWith} ` : ''}${a.recommended.versionNumber}`)
          : null,
        item.platforms.map((p) => h('span', { class: 'tag' }, p)),
        chevronIcon()
      )
    ),
    h('p', { class: 'observation' }, vulnerable ? widgetSecurityAdvice(item, vulns!, a, target) : a.note),
    open
      ? h(
          'div',
          { class: 'details' },
          vulnerable
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
          vulnerable ? detail('Version status', a.note) : null,
          indirectVulnerabilities(state.widgetOsv ? applyWidgetOsv(state.result!.upgrades, state.widgetOsv).indirectByWidget[item.key] : undefined),
          item.dependencies.length > 0
            ? detail('Bundled libraries', item.dependencies.map((d) => `${d.name} ${d.version}`).join(', '))
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
                h('span', { class: 'muted small' }, item.bundledWith ? `Update ${item.bundledWith} from the Marketplace to update this widget.` : contentId ? 'Update it from the Marketplace in Studio Pro.' : ''),
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
