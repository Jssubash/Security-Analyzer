/**
 * The Security Analyzer pane.
 *
 * Flow: the user presses Run → the pane asks the host for a model snapshot → the host reads
 * the open app through Studio Pro's model API and posts it back → the pane runs the SEC-*
 * catalogue locally and renders the result. Nothing leaves the machine.
 */

import { analyzeSnapshot, entityForFinding, securityCatalogue, unitForFinding } from '../analyze.js';
import type { RuleOutcome, SecurityAnalysisResult } from '../analyze.js';
import type { AccessState, ModuleStatus } from '../module-status.js';
import type { ModelSnapshot } from '../snapshot/types.js';
import type { Finding, RuleSeverity } from '@mendix-analyzer/rule-engine';

import { append, clear, h } from './dom.js';
import { connect, inStudioPro, onHostMessage, send } from './host.js';
import { buildHtmlReport, buildJsonReport, reportFileStem } from './report.js';

type Phase = 'idle' | 'reading' | 'analyzing' | 'done' | 'error';
type Tab = 'findings' | 'rules' | 'modules';
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
};

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
  const content = kind === 'html' ? buildHtmlReport(result) : buildJsonReport(result);
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
    tab('modules', 'Module status', result.modules.filter((m) => m.type === 'user' && m.overall === 'incomplete').length || undefined)
  );
}

function tabBody(result: SecurityAnalysisResult): HTMLElement {
  if (state.tab === 'rules') return rulesView(result);
  if (state.tab === 'modules') return modulesView(result);
  return findingsView(result);
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
  return h('section', { class: 'panel' }, toolbar, list);
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
