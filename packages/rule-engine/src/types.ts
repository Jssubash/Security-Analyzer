import { ApplicationIR, FactKey } from '@mendix-analyzer/application-ir';

export type RuleCategory =
  | 'Security'
  | 'Architecture'
  | 'Performance'
  | 'Data'
  | 'Logic'
  | 'UI'
  | 'Integration'
  | 'Operations'
  | 'Maintainability';

export type RuleSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type RuleStatus = 'PASS' | 'FAIL' | 'WARNING' | 'NOT_APPLICABLE' | 'ACCEPTED_EXCEPTION';

export interface Evidence {
  artifactPath: string; // e.g. "Administration.Account"
  objectName: string;   // e.g. "Account"
  objectType: string;   // e.g. "Entity", "Microflow", "Activity", "Endpoint"
  details: Record<string, any>;
  snippet?: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  ruleTitle: string;
  category: RuleCategory;
  severity: RuleSeverity;
  status: RuleStatus;
  module?: string;
  artifact: string;
  observation: string;
  whyItMatters: string;
  expectedPractice: string;
  recommendation: string;
  confidence: 'High' | 'Medium' | 'Low';
  evidence: Evidence;
  sourceSkill: string;
  sourceSection?: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  subcategory: string;
  severity: RuleSeverity;
  sourceSkill: string;
  sourceSection?: string;
  expectedPractice: string;
  recommendation: string;
  whyItMatters: string;
  confidence: 'High' | 'Medium' | 'Low';
  enabled: boolean;
  /**
   * The IR facts this rule needs in order to reach any conclusion.
   *
   * If any of them is NOT_ANALYZABLE the engine records the rule as NOT_APPLICABLE and
   * never calls `evaluate`. This is what stops "the parser could not read the security
   * model" from being scored as "the security model is fine": a rule that cannot look is
   * excluded from the denominator instead of counted as a pass.
   *
   * A rule that genuinely needs nothing (a metadata check) may use `[]`.
   */
  requires: readonly FactKey[];
  evaluate: (ir: ApplicationIR) => Finding[];
}

/** A rule that could not be evaluated, and the facts that were missing. */
export interface SkippedRule {
  ruleId: string;
  ruleTitle: string;
  category: RuleCategory;
  missingFacts: FactKey[];
  reason: string;
}

export interface RuleEvaluationSummary {
  /**
   * Rules that actually ran. Excludes those skipped for missing facts, so this is a
   * denominator that means something.
   */
  totalRulesEvaluated: number;
  totalPassed: number;
  totalFailed: number;
  totalWarnings: number;
  totalNotApplicable: number;
  findings: Finding[];
  categoryBreakdown: Record<RuleCategory, CategoryTally>;
  severityBreakdown: Record<RuleSeverity, number>;
  /** Rules skipped because the model could not be read well enough to judge them. */
  skippedRules: SkippedRule[];
}

/**
 * Per-category outcomes.
 *
 * Rule counts and finding counts are kept apart on purpose. Scoring must divide a
 * category's penalty by the number of *rules* that ran, not by the number of findings
 * they produced — otherwise a rule that reports ten violations enlarges its own
 * denominator and each additional violation lowers the penalty per rule.
 */
export interface CategoryTally {
  /** Rules that ran and found nothing. */
  rulesPassed: number;
  /** Rules that ran and produced at least one FAIL or WARNING. */
  rulesViolated: number;
  /** Rules not evaluated: missing facts, a runtime NOT_APPLICABLE, or a rule error. */
  rulesNotApplicable: number;
  /** Individual FAIL findings. */
  findingsFailed: number;
  /** Individual WARNING findings. */
  findingsWarning: number;
}
