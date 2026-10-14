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

import { buildJavaLibraryReport } from './java-libraries.js';
import type { JavaLibraryReport } from './java-libraries.js';
import { buildUpgradeInventory } from './marketplace.js';
import type { UpgradeInventory } from './marketplace.js';
import { buildModuleStatus } from './module-status.js';
import { RULE_CHECKS } from './rule-checks.js';
import type { RuleCheck } from './rule-checks.js';
import type { ModuleStatus } from './module-status.js';
import { buildIrFromSnapshot } from './snapshot/build-ir.js';
import type { ReadDiagnostics, UnitLocator, UnreadFact } from './snapshot/build-ir.js';
import type { ModelSnapshot } from './snapshot/types.js';

/**
 * `NOT_VERIFIED`: the rule ran, found nothing, but a value it depends on could not be read from
 * the open app — so "nothing found" is not a pass. Excluded from the score like NOT_APPLICABLE.
 */
export type RuleOutcomeStatus = 'PASSED' | 'FAILED' | 'WARNING' | 'NOT_APPLICABLE' | 'NOT_VERIFIED' | 'DISABLED';

export interface RuleOutcome {
  id: string;
  name: string;
  description: string;
  subcategory: string;
  severity: RuleSeverity;
  status: RuleOutcomeStatus;
  findingCount: number;
  /** Why the rule did not run or could not conclude, for NOT_APPLICABLE, NOT_VERIFIED and DISABLED. */
  reason?: string;
  /** What the rule validates, shown when its row is expanded. */
  checks?: RuleCheck;
  whyItMatters: string;
  recommendation: string;
}

export interface AnalysisOptions {
  /** Per-rule overrides of the catalogue's `enabled` flag, e.g. `{ 'SEC-008': true }`. */
  enabledRules?: Record<string, boolean>;
}

export interface SecurityAnalysisResult {
  app: { name: string; studioProVersion?: string; directory?: string; javaVersion?: string };
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
  /** The jars in userlib and vendorlib, split into Marketplace and custom, for the Java libraries tab. */
  javaLibraries: JavaLibraryReport;
  /** Marketplace modules and widgets with their installed versions, for the Upgrades tab. */
  upgrades: UpgradeInventory;
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

/**
 * The individual values each rule reads, beyond the fact groups it declares in `requires`.
 *
 * The engine skips a rule only when a whole group is unreadable. Inside a readable group a single
 * value can still be missing — a flag Studio Pro did not expose, a role list that came back empty —
 * and a rule that then finds nothing has not checked anything. Every rule that passes is meant to
 * have looked at this app's own model; this map is what enforces it.
 */
export const RULE_INPUTS: Record<string, readonly UnreadFact[]> = {
  'SEC-002': ['securityLevel'],
  'SEC-011': ['checkSecurity'],
  'SEC-012': ['enableDemoUsers'],
  'SEC-013': ['demoUserPasswords'],
  'SEC-014': ['adminPassword', 'passwordPolicy'],
  'SEC-015': ['passwordPolicy'],
  'SEC-016': ['strictPageUrlCheck'],
  'SEC-006': ['enableGuestAccess', 'guestUserRole', 'userRoleModuleRoles'],
  'SEC-017': ['enableGuestAccess', 'guestUserRole', 'userRoleModuleRoles'],
  'SEC-018': ['enableGuestAccess', 'guestUserRole', 'userRoleModuleRoles'],
  'SEC-009': ['enableGuestAccess', 'guestUserRole', 'userRoleModuleRoles'],
  'SEC-003': ['enableGuestAccess', 'guestUserRole', 'userRoleModuleRoles', 'accessRuleRoles'],
  'SEC-020': ['enableGuestAccess', 'guestUserRole', 'userRoleModuleRoles', 'accessRuleRoles'],
  'SEC-029': ['enableGuestAccess', 'guestUserRole', 'userRoleModuleRoles', 'accessRuleRoles'],
  'SEC-022': ['entityOwner', 'accessRuleRoles'],
  'SEC-EE-003': ['accessRuleRoles'],
  'SEC-005': ['attributeTypes'],
  'SEC-008': ['attributeTypes'],
  'SEC-023': ['userRoleCheckSecurity'],
  'SEC-024': ['userRoleManageAllRoles'],
  'SEC-025': ['userRoleModuleRoles'],
  'SEC-028': ['applyEntityAccess', 'enableGuestAccess', 'guestUserRole'],
  'SEC-MF-001': ['applyEntityAccess'],
  'SEC-MF-002': ['enableGuestAccess', 'guestUserRole', 'userRoleModuleRoles'],
  'SEC-MF-003': ['applyEntityAccess'],
};

/** Why a rule that found nothing has not verified anything, or `undefined` when it has. */
export function unverifiedReason(ruleId: string, diagnostics: ReadDiagnostics): string | undefined {
  const missing = (RULE_INPUTS[ruleId] ?? [])
    .map((fact) => diagnostics.unreadFacts[fact])
    .filter((d): d is string => d !== undefined);
  if (missing.length === 0) return undefined;
  return `not verified: ${missing.join('; ')} could not be read from the open app, so finding nothing here is not a pass`;
}

/**
 * Wrap a rule so that, when it finds nothing while one of its inputs was unreadable, it reports a
 * NOT_APPLICABLE finding instead. The engine then leaves it out of the score rather than counting
 * a pass. SEC-002 is the one rule whose IR value is defaulted when unread (the level becomes
 * CheckNothing), so its findings are dropped too: they would describe a level nobody read.
 */
function guarded(rule: Rule, diagnostics: ReadDiagnostics): Rule {
  const reason = unverifiedReason(rule.id, diagnostics);
  if (!reason) return rule;
  return {
    ...rule,
    evaluate: (ir) => {
      const findings = rule.id === 'SEC-002' ? [] : rule.evaluate(ir);
      if (findings.some((f) => f.status === 'FAIL' || f.status === 'WARNING')) return findings;
      return [
        {
          id: `${rule.id}-not-verified`,
          ruleId: rule.id,
          ruleTitle: rule.name,
          category: rule.category,
          severity: rule.severity,
          status: 'NOT_APPLICABLE',
          artifact: 'Model read',
          observation: reason,
          whyItMatters: rule.whyItMatters,
          expectedPractice: rule.expectedPractice,
          recommendation: 'Re-run the analysis; if this persists, send the diagnostic snapshot so the read can be fixed.',
          confidence: 'High',
          evidence: { artifactPath: '', objectName: rule.id, objectType: 'Rule', details: { unverified: true } },
          sourceSkill: rule.sourceSkill,
          sourceSection: rule.sourceSection,
        },
      ];
    },
  };
}

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
  registry.registerMany(catalogue.map((rule) => guarded(rule, diagnostics)));
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
  const unverified = new Map(
    summary.findings.filter((f) => f.status === 'NOT_APPLICABLE' && f.evidence.details['unverified'] === true).map((f) => [f.ruleId, f.observation])
  );
  const rules: RuleOutcome[] = catalogue.map((rule) => {
    const own = findings.filter((f) => f.ruleId === rule.id);
    let status: RuleOutcomeStatus;
    let reason: string | undefined;
    if (!rule.enabled) {
      status = 'DISABLED';
      reason = 'advisory rule, off by default';
    } else if (skipped.has(rule.id)) {
      status = 'NOT_APPLICABLE';
      reason =
        rule.requires.includes('publishedServices') && diagnostics.publishedRestServices === 0
          ? 'nothing to check: the app publishes no REST services'
          : skipped.get(rule.id);
    } else if (unverified.has(rule.id)) {
      status = 'NOT_VERIFIED';
      reason = unverified.get(rule.id);
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
      checks: RULE_CHECKS[rule.id],
      whyItMatters: rule.whyItMatters,
      recommendation: rule.recommendation,
    };
  });

  const unassessed = score.unassessedCategories.find((c) => c.category === 'Security');
  const moduleList = Object.values(ir.modules);
  const moduleTypes = Object.fromEntries(moduleList.map((m) => [m.name, m.type]));

  return {
    app: {
      name: snapshot.app.name,
      studioProVersion: snapshot.app.studioProVersion,
      directory: snapshot.app.directory,
      javaVersion: snapshot.app.javaVersion,
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
    moduleTypes,
    entityNames: Object.keys(ir.entities),
    modules: buildModuleStatus(ir, nanoflows, findings, flowReferences),
    javaLibraries: buildJavaLibraryReport(snapshot, moduleTypes),
    upgrades: buildUpgradeInventory(snapshot),
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
 * `Module.Entity.Attribute`); this walks up the dotted path until it reaches a name the
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
