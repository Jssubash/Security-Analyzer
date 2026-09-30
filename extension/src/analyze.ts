/**
 * Run the `SEC-*` catalogue against a model snapshot.
 *
 * The rules, engine and scorer are the governance analyzer's own packages, unchanged — the
 * extension only swaps the input (Studio Pro's live model instead of an uploaded archive), so
 * a finding in the pane means exactly what the same finding means in the web dashboard.
 */

import type { FactCoverage, ModuleType } from '@mendix-analyzer/application-ir';
import { RuleEngine, RuleRegistry } from '@mendix-analyzer/rule-engine';
import type { Finding, Rule, RuleSeverity } from '@mendix-analyzer/rule-engine';
import { securityRules } from '@mendix-analyzer/rules';
import { ScoringEngine } from '@mendix-analyzer/scoring';
import type { ScoreReport } from '@mendix-analyzer/scoring';

import { buildModuleStatus } from './module-status.js';
import type { ModuleStatus } from './module-status.js';
import { buildIrFromSnapshot } from './snapshot/build-ir.js';
import type { ReadDiagnostics, UnitLocator } from './snapshot/build-ir.js';
import type { ModelSnapshot } from './snapshot/types.js';

export type RuleOutcomeStatus = 'PASSED' | 'FAILED' | 'WARNING' | 'NOT_APPLICABLE' | 'DISABLED';

export interface RuleOutcome {
  id: string;
  name: string;
  description: string;
  subcategory: string;
  severity: RuleSeverity;
  status: RuleOutcomeStatus;
  findingCount: number;
  /** Why the rule did not run, for NOT_APPLICABLE and DISABLED. */
  reason?: string;
}

export interface AnalysisOptions {
  /** Per-rule overrides of the catalogue's `enabled` flag, e.g. `{ 'SEC-008': true }`. */
  enabledRules?: Record<string, boolean>;
}

export interface SecurityAnalysisResult {
  app: { name: string; studioProVersion?: string; directory?: string };
  analyzedAt: string;
  durationMs: number;
  score: ScoreReport;
  /** The Security category score, or `null` when it could not be assessed. */
  securityScore: number | null;
  findings: Finding[];
  rules: RuleOutcome[];
  coverage: FactCoverage;
  units: UnitLocator;
  /** What the snapshot contained, for the Coverage tab's troubleshooting section. */
  diagnostics: ReadDiagnostics;
  /** Each module's origin, so the pane can separate the team's own modules from marketplace ones. */
  moduleTypes: Record<string, ModuleType>;
  /** Qualified names of every entity, so "Open in Studio Pro" can select the entity itself. */
  entityNames: string[];
  /** Per-module security status, for the Module status tab. */
  modules: ModuleStatus[];
  inventory: {
    modules: number;
    userModules: number;
    entities: number;
    pages: number;
    microflows: number;
    userRoles: number;
    moduleRoles: number;
    javaActions: number;
  };
}

const SEVERITY_ORDER: Record<RuleSeverity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
};

export function securityCatalogue(options: AnalysisOptions = {}): Rule[] {
  return securityRules.map((rule) => {
    const override = options.enabledRules?.[rule.id];
    return override === undefined ? rule : { ...rule, enabled: override };
  });
}

export function analyzeSnapshot(
  snapshot: ModelSnapshot,
  options: AnalysisOptions = {},
  now: () => number = () => Date.now()
): SecurityAnalysisResult {
  const started = now();
  const { ir, units, diagnostics, nanoflows, flowReferences } = buildIrFromSnapshot(snapshot);

  const catalogue = securityCatalogue(options);
  const registry = new RuleRegistry();
  registry.registerMany(catalogue);
  const summary = new RuleEngine(registry).evaluate(ir);
  const score = new ScoringEngine().calculateScores(summary, ir.coverage);

  const findings = summary.findings
    .filter((f) => f.status === 'FAIL' || f.status === 'WARNING')
    .sort(
      (a, b) =>
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        (a.status === b.status ? 0 : a.status === 'FAIL' ? -1 : 1) ||
        a.ruleId.localeCompare(b.ruleId) ||
        a.id.localeCompare(b.id)
    );

  const skipped = new Map(summary.skippedRules.map((s) => [s.ruleId, s.reason]));
  const rules: RuleOutcome[] = catalogue.map((rule) => {
    const own = findings.filter((f) => f.ruleId === rule.id);
    let status: RuleOutcomeStatus;
    let reason: string | undefined;
    if (!rule.enabled) {
      status = 'DISABLED';
      reason = 'advisory rule, off by default';
    } else if (skipped.has(rule.id)) {
      status = 'NOT_APPLICABLE';
      reason = skipped.get(rule.id);
    } else if (own.some((f) => f.status === 'FAIL')) {
      status = 'FAILED';
    } else if (own.length > 0) {
      status = 'WARNING';
    } else {
      status = 'PASSED';
    }
    return {
      id: rule.id,
      name: rule.name,
      description: rule.description,
      subcategory: rule.subcategory,
      severity: rule.severity,
      status,
      findingCount: own.length,
      reason,
    };
  });

  const unassessed = score.unassessedCategories.find((c) => c.category === 'Security');
  const moduleList = Object.values(ir.modules);

  return {
    app: {
      name: snapshot.app.name,
      studioProVersion: snapshot.app.studioProVersion,
      directory: snapshot.app.directory,
    },
    analyzedAt: new Date(started).toISOString(),
    durationMs: Math.max(0, now() - started),
    score,
    securityScore: unassessed ? null : (score.categoryScores['Security'] ?? null),
    findings,
    rules,
    coverage: ir.coverage,
    units,
    diagnostics,
    moduleTypes: Object.fromEntries(moduleList.map((m) => [m.name, m.type])),
    entityNames: Object.keys(ir.entities),
    modules: buildModuleStatus(ir, nanoflows, findings, flowReferences),
    inventory: {
      modules: moduleList.length,
      userModules: moduleList.filter((m) => m.type === 'user').length,
      entities: Object.keys(ir.entities).length,
      pages: Object.keys(ir.pages).length,
      microflows: Object.keys(ir.microflows).length,
      userRoles: ir.security.userRoles.length,
      moduleRoles: ir.security.moduleRoles.length,
      javaActions: ir.customCode.javaActions.length,
    },
  };
}

/**
 * The Studio Pro unit a finding points at, for "Open in Studio Pro".
 *
 * Findings name artifacts logically (`AppSecurity.UserRoles.Anonymous`,
 * `MyFirstModule.RequestForm.Email`); this walks up the dotted path until it reaches a name the
 * snapshot recorded a unit for — a member resolves to its entity's domain model.
 */
/**
 * The entity a finding is about, if any — the finding's own entity, or the entity owning the
 * attribute or access rule it names — so the domain model opens with that entity selected.
 */
export function entityForFinding(finding: Finding, entityNames: readonly string[]): string | undefined {
  const known = new Set(entityNames);
  const segments = finding.evidence.artifactPath.split('.');
  for (let n = segments.length; n >= 2; n--) {
    const candidate = segments.slice(0, n).join('.');
    if (known.has(candidate)) return candidate;
  }
  return undefined;
}

export function unitForFinding(finding: Finding, units: UnitLocator): string | undefined {
  const path = finding.evidence.artifactPath;
  if (path.startsWith('AppSecurity')) return units['AppSecurity'];
  const segments = path.split('.');
  for (let n = segments.length; n >= 2; n--) {
    const id = units[segments.slice(0, n).join('.')];
    if (id) return id;
  }
  return undefined;
}
