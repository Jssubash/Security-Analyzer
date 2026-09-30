import { ApplicationIR, factsAvailable, missingFacts } from '@mendix-analyzer/application-ir';
import { RuleRegistry } from './registry.js';
import {
  CategoryTally,
  Finding,
  RuleCategory,
  RuleEvaluationSummary,
  RuleSeverity,
  SkippedRule,
} from './types.js';

const CATEGORIES: readonly RuleCategory[] = [
  'Security',
  'Architecture',
  'Performance',
  'Data',
  'Logic',
  'UI',
  'Integration',
  'Operations',
  'Maintainability',
];

export class RuleEngine {
  private registry: RuleRegistry;

  constructor(registry?: RuleRegistry) {
    this.registry = registry || new RuleRegistry();
  }

  public getRegistry(): RuleRegistry {
    return this.registry;
  }

  public evaluate(ir: ApplicationIR): RuleEvaluationSummary {
    const enabledRules = this.registry.getEnabled();
    const allFindings: Finding[] = [];
    const skippedRules: SkippedRule[] = [];

    const categoryBreakdown = {} as Record<RuleCategory, CategoryTally>;
    for (const category of CATEGORIES) {
      categoryBreakdown[category] = {
        rulesPassed: 0,
        rulesViolated: 0,
        rulesNotApplicable: 0,
        findingsFailed: 0,
        findingsWarning: 0,
      };
    }

    const severityBreakdown: Record<RuleSeverity, number> = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Informational: 0,
    };

    let totalPassed = 0;
    let totalFailed = 0;
    let totalWarnings = 0;
    let totalNotApplicable = 0;
    let totalEvaluated = 0;

    // Coverage may be absent on an IR produced by an older parser build. Treat that as
    // "everything readable" so such an IR still evaluates, rather than skipping every rule.
    const coverage = ir.coverage;

    for (const rule of enabledRules) {
      const tally = categoryBreakdown[rule.category];
      const required = rule.requires ?? [];

      if (coverage && required.length > 0 && !factsAvailable(coverage, required)) {
        const missing = missingFacts(coverage, required);
        totalNotApplicable++;
        if (tally) tally.rulesNotApplicable++;
        skippedRules.push({
          ruleId: rule.id,
          ruleTitle: rule.name,
          category: rule.category,
          missingFacts: missing,
          reason: `not evaluated: the analyzer could not read ${missing.join(', ')}`,
        });
        continue;
      }

      let findings: Finding[];
      try {
        findings = rule.evaluate(ir);
      } catch (err: any) {
        // A rule that threw proves nothing about the application. It is excluded from the
        // denominator so that a buggy rule can neither raise nor lower the score.
        totalNotApplicable++;
        if (tally) tally.rulesNotApplicable++;
        skippedRules.push({
          ruleId: rule.id,
          ruleTitle: rule.name,
          category: rule.category,
          missingFacts: [],
          reason: `rule threw during evaluation: ${err?.message || 'Unknown error'}`,
        });
        allFindings.push(ruleErrorFinding(rule, err));
        continue;
      }

      const failed = findings.filter((f) => f.status === 'FAIL');
      const warned = findings.filter((f) => f.status === 'WARNING');
      allFindings.push(...findings);

      for (const f of [...failed, ...warned]) severityBreakdown[f.severity]++;
      totalFailed += failed.length;
      totalWarnings += warned.length;
      if (tally) {
        tally.findingsFailed += failed.length;
        tally.findingsWarning += warned.length;
      }

      if (failed.length === 0 && warned.length === 0) {
        if (findings.some((f) => f.status === 'NOT_APPLICABLE')) {
          // The rule decided at runtime it had nothing to judge (e.g. the app publishes
          // no services). That is neither a pass nor a penalty.
          totalNotApplicable++;
          if (tally) tally.rulesNotApplicable++;
        } else {
          // The rule looked and found nothing. Only now is that a pass.
          totalEvaluated++;
          totalPassed++;
          if (tally) tally.rulesPassed++;
        }
      } else {
        totalEvaluated++;
        if (tally) tally.rulesViolated++;
      }
    }

    return {
      totalRulesEvaluated: totalEvaluated,
      totalPassed,
      totalFailed,
      totalWarnings,
      totalNotApplicable,
      findings: allFindings,
      categoryBreakdown,
      severityBreakdown,
      skippedRules,
    };
  }
}

function ruleErrorFinding(
  rule: { id: string; name: string; category: RuleCategory; expectedPractice: string; sourceSkill: string },
  err: any
): Finding {
  return {
    id: `${rule.id}-error`,
    ruleId: rule.id,
    ruleTitle: rule.name,
    category: rule.category,
    severity: 'Informational',
    status: 'NOT_APPLICABLE',
    artifact: 'RuleEngine',
    observation: `Rule failed to execute: ${err?.message || 'Unknown error'}`,
    whyItMatters:
      'This rule produced no verdict, so the application is unassessed on this control.',
    expectedPractice: rule.expectedPractice,
    recommendation: 'Report this as an analyzer defect, then re-run the analysis.',
    confidence: 'Low',
    evidence: {
      artifactPath: 'RuleEngine',
      objectName: rule.id,
      objectType: 'Rule',
      details: { error: err?.message },
    },
    sourceSkill: rule.sourceSkill,
  };
}
