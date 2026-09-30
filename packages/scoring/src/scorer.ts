import type { FactCoverage, FactKey } from '@mendix-analyzer/application-ir';
import {
  CategoryTally,
  Finding,
  RuleCategory,
  RuleEvaluationSummary,
  RuleSeverity,
} from '@mendix-analyzer/rule-engine';

export interface ScoreReport {
  overallScore: number; // 0 - 100
  riskRating: 'A' | 'B' | 'C' | 'D' | 'F';
  /**
   * Scores for categories that were actually assessed.
   *
   * A category with no rule outcomes is omitted rather than reported as 100. Showing a
   * perfect score for a category the analyzer could not read is the single most misleading
   * thing this tool could do, because it is indistinguishable from a genuinely clean result.
   */
  categoryScores: Record<string, number>;
  /** Categories deliberately left unscored, with the reason. */
  unassessedCategories: { category: string; reason: string }[];
  /**
   * Share of the catalogue that could actually be evaluated, 0 - 100.
   *
   * This belongs next to `categoryScores['Compliance']` wherever it is shown. A run that
   * could evaluate 40 % of its rules and passed 90 % of those is not a 90 % result, and
   * the compliance figure alone cannot tell the two apart (§4.2).
   */
  coveragePercentage: number;
  /**
   * Set when a fact some category cannot be scored without was unreadable.
   *
   * `overallScore` is still a number when this is true — it is the penalty per rule that
   * *ran* — but it is then a score for a partial assessment and must never be shown on its
   * own. Removing the reference project's `Security$ProjectSecurity` unit takes the overall
   * score from 79 to 100 precisely because the rules that were failing could no longer run,
   * so this flag, not the number, is what tells a reader the two are not comparable.
   */
  assessmentIsIncomplete: boolean;
  severityCounts: Record<RuleSeverity, number>;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  passedCount: number;
  /** Rules that could not be evaluated. A high number means the score is weakly grounded. */
  notApplicableCount: number;
  /** Facts the parser could not read, surfaced next to the score that depends on them. */
  coverageNotes: string[];
  topRisks: Finding[];
}

const SEVERITY_WEIGHTS: Record<RuleSeverity, number> = {
  Critical: 25,
  High: 10,
  Medium: 4,
  Low: 1,
  Informational: 0,
};

/**
 * Which facts each category's score depends on.
 *
 * If every fact backing a category is unreadable, that category is not scored at all.
 */
/**
 * Facts without which a category cannot be scored at all, even when its other facts were read.
 *
 * This is separate from `CATEGORY_FACTS` because "all the facts were unreadable" is too weak a
 * test. With no `Security$ProjectSecurity` unit the reference project still has readable module
 * roles, access rules and pages, so nine Security rules run and pass and the category scores
 * 100 — higher than the 65 it scores when the security model *is* readable. An analyzer that
 * rewards an unreadable model is the §2.1 defect, and §4.2 calls for the score to be suppressed
 * rather than computed from whichever rules happened to survive.
 */
const CATEGORY_CRITICAL_FACTS: Partial<Record<RuleCategory, readonly FactKey[]>> = {
  Security: ['projectSecurity'],
};

const CATEGORY_FACTS: Partial<Record<RuleCategory, readonly FactKey[]>> = {
  Security: ['projectSecurity', 'moduleRoles', 'entityAccessRules', 'pageAccess'],
  Logic: ['microflows'],
  Performance: ['microflows'],
  Data: ['entityAccessRules', 'attributeTypes'],
  Integration: ['publishedServices'],
  Operations: ['constants'],
};

export class ScoringEngine {
  /**
   * @param coverage what the parser managed to read. Omitting it scores every category
   *   that has outcomes, which is only correct for an IR whose provenance is already known.
   */
  public calculateScores(summary: RuleEvaluationSummary, coverage?: FactCoverage): ScoreReport {
    const categoryPenalties: Record<string, number> = {};
    let totalWeightedPenalty = 0;

    for (const finding of summary.findings) {
      if (finding.status !== 'FAIL' && finding.status !== 'WARNING') continue;
      const factor = finding.status === 'WARNING' ? 0.5 : 1.0;
      const penalty = SEVERITY_WEIGHTS[finding.severity] * factor;
      categoryPenalties[finding.category] = (categoryPenalties[finding.category] ?? 0) + penalty;
      totalWeightedPenalty += penalty;
    }

    const categoryScores: Record<string, number> = {};
    const unassessedCategories: { category: string; reason: string }[] = [];
    const missingCriticalFacts = new Set<FactKey>();

    for (const [category, tally] of Object.entries(summary.categoryBreakdown) as [
      RuleCategory,
      CategoryTally,
    ][]) {
      // Divide by the rules that ran, never by the findings they produced.
      const rulesRun = tally.rulesPassed + tally.rulesViolated;

      // Checked before the "nothing ran" case, because naming the unreadable fact tells the
      // reader why nothing ran.
      const missingCritical = unreadableFacts(CATEGORY_CRITICAL_FACTS[category], coverage);
      if (missingCritical.length > 0 && rulesRun + tally.rulesNotApplicable > 0) {
        for (const fact of missingCritical) missingCriticalFacts.add(fact);
        unassessedCategories.push({
          category,
          reason: `${missingCritical.join(', ')} could not be read, so the rules that did run are not a representative sample`,
        });
        continue;
      }

      if (rulesRun === 0) {
        if (tally.rulesNotApplicable > 0) {
          unassessedCategories.push({
            category,
            reason: `${tally.rulesNotApplicable} rule(s) could not be evaluated and none ran`,
          });
        }
        continue;
      }

      const unreadable = unreadableFacts(CATEGORY_FACTS[category], coverage);
      if (unreadable.length > 0 && unreadable.length === (CATEGORY_FACTS[category]?.length ?? 0)) {
        unassessedCategories.push({
          category,
          reason: `none of the facts this category depends on could be read (${unreadable.join(', ')})`,
        });
        continue;
      }

      const scaledPenalty = ((categoryPenalties[category] ?? 0) / rulesRun) * 4;
      categoryScores[category] = clampScore(100 - scaledPenalty);
    }

    // Compliance is the share of rules that ran and passed. Rules excluded for missing
    // facts are absent from both numerator and denominator, so an unreadable model moves
    // this toward "unknown" rather than toward 100.
    //
    // Unless something a category cannot be scored without was unreadable, in which case
    // there is no compliance figure at all. Dropping the failing rules out of the ratio
    // *raises* it — the reference project reports 64 % with its security model readable and
    // 90 % with that one unit removed — and §9.5 requires that a less readable project never
    // produce a higher compliance score. The only number that cannot be read as an
    // improvement is no number.
    if (missingCriticalFacts.size > 0) {
      unassessedCategories.push({
        category: 'Compliance',
        reason: `${[...missingCriticalFacts].join(', ')} could not be read, so the share of rules that passed does not describe this project`,
      });
    } else if (summary.totalRulesEvaluated > 0) {
      categoryScores['Compliance'] = Math.round(
        (summary.totalPassed / summary.totalRulesEvaluated) * 100
      );
    } else {
      unassessedCategories.push({
        category: 'Compliance',
        reason: 'no rule could be evaluated against this model',
      });
    }

    const rulesConsidered = summary.totalRulesEvaluated + summary.totalNotApplicable;
    const coveragePercentage =
      rulesConsidered > 0 ? Math.round((summary.totalRulesEvaluated / rulesConsidered) * 100) : 0;

    const overallScore =
      summary.totalRulesEvaluated > 0
        ? clampScore(100 - (totalWeightedPenalty / summary.totalRulesEvaluated) * 3.5)
        : 0;

    const riskRating = rate(overallScore, summary.severityBreakdown.Critical);

    const topRisks = [...summary.findings]
      .filter((f) => f.status === 'FAIL')
      .sort((a, b) => SEVERITY_WEIGHTS[b.severity] - SEVERITY_WEIGHTS[a.severity])
      .slice(0, 5);

    return {
      overallScore,
      riskRating,
      categoryScores,
      unassessedCategories,
      coveragePercentage,
      assessmentIsIncomplete: missingCriticalFacts.size > 0,
      severityCounts: summary.severityBreakdown,
      totalFindings: summary.findings.length,
      criticalCount: summary.severityBreakdown.Critical,
      highCount: summary.severityBreakdown.High,
      mediumCount: summary.severityBreakdown.Medium,
      lowCount: summary.severityBreakdown.Low,
      passedCount: summary.totalPassed,
      notApplicableCount: summary.totalNotApplicable,
      coverageNotes: coverage ? [...coverage.notes] : [],
      topRisks,
    };
  }
}

function unreadableFacts(
  facts: readonly FactKey[] | undefined,
  coverage: FactCoverage | undefined
): FactKey[] {
  if (!coverage || !facts) return [];
  return facts.filter((f) => coverage[f] === 'NOT_ANALYZABLE');
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function rate(overallScore: number, criticalCount: number): ScoreReport['riskRating'] {
  if (overallScore < 50 || criticalCount >= 3) return 'F';
  if (overallScore < 65 || criticalCount >= 1) return 'D';
  if (overallScore < 75) return 'C';
  if (overallScore < 88) return 'B';
  return 'A';
}
