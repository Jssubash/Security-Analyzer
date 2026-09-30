import { Rule, Finding } from '@mendix-analyzer/rule-engine';

export const performanceRules: Rule[] = [
  {
    id: 'PERF-001',
    name: 'Database Retrieve Inside Loop',
    description: 'Retrieving objects from the database inside a loop causes severe N+1 query performance degradation.',
    category: 'Performance',
    subcategory: 'Microflow Efficiency',
    severity: 'High',
    sourceSkill: 'write-microflows.md',
    sourceSection: 'Loops and Retrievals',
    expectedPractice: 'Retrieve objects in batch before the loop, or retrieve by association.',
    recommendation: 'Move the retrieve activity before the loop and filter in memory, or use association traversal.',
    whyItMatters: 'If the loop iterates 1,000 times, it executes 1,000 separate SQL queries, saturating database connections.',
    confidence: 'High',
    enabled: true,
    /** retrieves inside loops are activity-level facts. */
    requires: ['microflowActivities'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, mf] of Object.entries(ir.microflows)) {
        if (mf.retrievesInsideLoops.length > 0) {
          findings.push({
            id: `PERF-001-${mf.name}`,
            ruleId: 'PERF-001',
            ruleTitle: 'Database Retrieve Inside Loop',
            category: 'Performance',
            severity: 'High',
            status: 'FAIL',
            module: mf.module,
            artifact: `Microflow: ${mf.name}`,
            observation: `Microflow "${mf.name}" executes ${mf.retrievesInsideLoops.length} database retrieve(s) inside a loop.`,
            whyItMatters: 'Causes classic N+1 database roundtrips, causing CPU spikes and blocking database pools under load.',
            expectedPractice: 'Batch retrieve all required data before entering the loop.',
            recommendation: `Refactor "${mf.name}" to retrieve objects prior to the loop and match them in-memory.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${mf.module}.${mf.name}`,
              objectName: mf.name,
              objectType: 'Microflow',
              details: {
                loopRetrievesCount: mf.retrievesInsideLoops.length,
                activities: mf.retrievesInsideLoops.map((a) => a.name),
              },
            },
            sourceSkill: 'write-microflows.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'PERF-002',
    name: 'Database Commit Inside Loop',
    description: 'Committing objects inside a loop creates separate database transactions per iteration.',
    category: 'Performance',
    subcategory: 'Transaction Hygiene',
    severity: 'High',
    sourceSkill: 'write-microflows.md',
    sourceSection: 'Commits and Batching',
    expectedPractice: 'Collect modified objects into a list and execute a single batch Commit outside the loop.',
    recommendation: 'Change the Commit activity inside the loop to Change Object without commit, add to a list, and commit the list after the loop.',
    whyItMatters: 'Individual commits write disk transaction logs and acquire row locks on each loop cycle.',
    confidence: 'High',
    enabled: true,
    /** commits inside loops are activity-level facts. */
    requires: ['microflowActivities'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, mf] of Object.entries(ir.microflows)) {
        if (mf.commitsInsideLoops.length > 0) {
          findings.push({
            id: `PERF-002-${mf.name}`,
            ruleId: 'PERF-002',
            ruleTitle: 'Database Commit Inside Loop',
            category: 'Performance',
            severity: 'High',
            status: 'FAIL',
            module: mf.module,
            artifact: `Microflow: ${mf.name}`,
            observation: `Microflow "${mf.name}" commits objects inside a loop.`,
            whyItMatters: 'Forces the database to open and commit separate transactions for every item, multiplying I/O latency.',
            expectedPractice: 'Accumulate modified items in a list and commit once after the loop.',
            recommendation: `Remove commit from the loop in "${mf.name}" and use a batch commit activity.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${mf.module}.${mf.name}`,
              objectName: mf.name,
              objectType: 'Microflow',
              details: { loopCommitsCount: mf.commitsInsideLoops.length },
            },
            sourceSkill: 'write-microflows.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'PERF-003',
    name: 'Consumed REST Service Missing Timeout',
    description: 'External REST integrations must have timeouts configured to avoid hung threads.',
    category: 'Performance',
    subcategory: 'Integration Performance',
    severity: 'Medium',
    sourceSkill: 'rest-client.md',
    sourceSection: 'Call REST Service Configuration',
    expectedPractice: 'Always configure a reasonable timeout (e.g. 10–30 seconds) on consumed REST services.',
    recommendation: 'Specify a timeout in the Call REST activity or Consumed REST Service settings.',
    whyItMatters: 'If a remote service becomes unresponsive, Mendix request handler threads hang, causing runtime exhaustion.',
    confidence: 'High',
    enabled: true,
    /** consumed service timeouts are part of the unread integration model. */
    requires: ['publishedServices'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const consumed of ir.integrations.consumedRestServices) {
        if (!consumed.isTimeoutConfigured) {
          findings.push({
            id: `PERF-003-${consumed.name}`,
            ruleId: 'PERF-003',
            ruleTitle: 'Consumed REST Service Missing Timeout',
            category: 'Performance',
            severity: 'Medium',
            status: 'WARNING',
            module: consumed.module,
            artifact: `Consumed REST: ${consumed.name}`,
            observation: `Consumed REST service "${consumed.name}" does not have an explicit timeout configured.`,
            whyItMatters: 'Network stalls or slow upstream services will cause Mendix worker threads to wait indefinitely.',
            expectedPractice: 'Set explicit request timeouts on all external REST integrations.',
            recommendation: `Configure a timeout (e.g. 15000 ms) for "${consumed.name}".`,
            confidence: 'High',
            evidence: {
              artifactPath: `${consumed.module}.${consumed.name}`,
              objectName: consumed.name,
              objectType: 'ConsumedRestService',
              details: { baseUrl: consumed.baseUrl },
            },
            sourceSkill: 'rest-client.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'PERF-004',
    name: 'High Cyclomatic Complexity Microflow',
    description: 'Microflows with cyclomatic complexity > 15 are error-prone, hard to maintain, and indicate unoptimized logic.',
    category: 'Performance',
    subcategory: 'Logic Complexity',
    severity: 'Medium',
    sourceSkill: 'write-microflows.md',
    sourceSection: 'Microflow Complexity Guidelines',
    expectedPractice: 'Keep cyclomatic complexity <= 10, decomposing complex branches into sub-microflows.',
    recommendation: 'Extract nested decision trees and loops into dedicated sub-microflows.',
    whyItMatters: 'High complexity leads to unmaintainable code, difficult debugging, and hidden performance traps.',
    confidence: 'High',
    enabled: true,
    /** unbounded retrieves are activity-level facts. */
    requires: ['microflowActivities'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, mf] of Object.entries(ir.microflows)) {
        if (mf.cyclomaticComplexity > 15) {
          findings.push({
            id: `PERF-004-${mf.name}`,
            ruleId: 'PERF-004',
            ruleTitle: 'High Cyclomatic Complexity Microflow',
            category: 'Performance',
            severity: 'Medium',
            status: 'WARNING',
            module: mf.module,
            artifact: `Microflow: ${mf.name}`,
            observation: `Microflow "${mf.name}" has a cyclomatic complexity of ${mf.cyclomaticComplexity} (threshold: 15).`,
            whyItMatters: 'Complex decision trees multiply test cases and are prone to logic errors.',
            expectedPractice: 'Refactor complex microflows into modular sub-microflows with complexity <= 10.',
            recommendation: `Decompose "${mf.name}" into sub-microflows.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${mf.module}.${mf.name}`,
              objectName: mf.name,
              objectType: 'Microflow',
              details: { complexity: mf.cyclomaticComplexity, activitiesCount: mf.activities.length },
            },
            sourceSkill: 'write-microflows.md',
          });
        }
      }
      return findings;
    },
  },
];
