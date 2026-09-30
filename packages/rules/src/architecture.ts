import { Rule, Finding } from '@mendix-analyzer/rule-engine';

export const architectureRules: Rule[] = [
  {
    id: 'ARC-001',
    name: 'Circular Module Dependency Detected',
    description: 'Modules must not depend on each other in cycles (A -> B -> A).',
    category: 'Architecture',
    subcategory: 'Modularity',
    severity: 'High',
    sourceSkill: 'graph-analysis.md',
    sourceSection: 'Circular Dependencies',
    expectedPractice: 'Maintain a directed acyclic graph (DAG) across modules with clear architectural layering.',
    recommendation: 'Break the cycle by moving shared entities, interfaces, or microflows into a common core/foundation module.',
    whyItMatters: 'Cycles prevent modular updates, cause tight coupling, and make independent module deployment impossible.',
    confidence: 'High',
    enabled: true,
    /** the module dependency graph is derived from the domain model, which is read for every project. */
    requires: [],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      const cycles = ir.dependencyGraph.cycles;

      for (let i = 0; i < cycles.length; i++) {
        const cycle = cycles[i];
        const cycleStr = cycle.join(' -> ');
        findings.push({
          id: `ARC-001-Cycle-${i}`,
          ruleId: 'ARC-001',
          ruleTitle: 'Circular Module Dependency Detected',
          category: 'Architecture',
          severity: 'High',
          status: 'FAIL',
          artifact: `Module Dependency Cycle: ${cycleStr}`,
          observation: `A circular dependency was detected between modules: ${cycleStr}.`,
          whyItMatters: 'Tight circular coupling leads to cascading ripple effects when modifying data models or logic.',
          expectedPractice: 'Structure modules in layers: Feature -> Business Core -> Foundation, without upward or circular links.',
          recommendation: `Extract shared elements between "${cycle[0]}" and "${cycle[1]}" into a dedicated base module.`,
          confidence: 'High',
          evidence: {
            artifactPath: 'Architecture.DependencyGraph',
            objectName: 'ModuleCycle',
            objectType: 'DependencyCycle',
            details: { cyclePath: cycle },
          },
          sourceSkill: 'graph-analysis.md',
        });
      }
      return findings;
    },
  },
  {
    id: 'ARC-002',
    name: 'God Module Architectural Anti-Pattern',
    description: 'A single module contains an excessive proportion (> 35%) of all application entities and microflows.',
    category: 'Architecture',
    subcategory: 'Cohesion and Coupling',
    severity: 'Medium',
    sourceSkill: 'graph-analysis.md',
    sourceSection: 'Centrality and God Nodes',
    expectedPractice: 'Distribute business capabilities across domain-specific bounded contexts.',
    recommendation: 'Decompose the oversized module into distinct functional modules.',
    whyItMatters: 'Monolithic modules become unmaintainable bottlenecks where merge conflicts and regressions thrive.',
    confidence: 'High',
    enabled: true,
    /** entity counts per module come from the module inventory. */
    requires: [],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const godMod of ir.dependencyGraph.godModules) {
        const mod = ir.modules[godMod];
        if (mod) {
          findings.push({
            id: `ARC-002-${godMod}`,
            ruleId: 'ARC-002',
            ruleTitle: 'God Module Architectural Anti-Pattern',
            category: 'Architecture',
            severity: 'Medium',
            status: 'WARNING',
            module: godMod,
            artifact: `Module: ${godMod}`,
            observation: `Module "${godMod}" contains ${mod.entities.length} entities and ${mod.microflows.length} microflows, exceeding balanced architecture thresholds.`,
            whyItMatters: 'Concentrating too much logic in a single module violates separation of concerns.',
            expectedPractice: 'Organize features into cohesive bounded modules.',
            recommendation: `Split "${godMod}" into smaller domain modules according to business functions.`,
            confidence: 'High',
            evidence: {
              artifactPath: godMod,
              objectName: godMod,
              objectType: 'Module',
              details: { entitiesCount: mod.entities.length, microflowsCount: mod.microflows.length },
            },
            sourceSkill: 'graph-analysis.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'ARC-003',
    name: 'Foundation Module Depends on Feature Module',
    description: 'Core/System/Common modules must never have upward dependencies on high-level feature modules.',
    category: 'Architecture',
    subcategory: 'Layering Hygiene',
    severity: 'High',
    sourceSkill: 'graph-analysis.md',
    sourceSection: 'Layer Analysis and Upward Dependencies',
    expectedPractice: 'Dependencies must flow strictly downwards from Feature -> Core -> Foundation.',
    recommendation: 'Invert the dependency using interfaces, events, or extract the required logic into the lower module.',
    whyItMatters: 'Upward dependencies break foundational reusability and make base modules fragile.',
    confidence: 'High',
    enabled: true,
    /** the module inventory is always read. */
    requires: [],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      const baseModules = ['system', 'communitycommons', 'administration', 'atlas_core'];

      for (const [modName, mod] of Object.entries(ir.modules)) {
        if (baseModules.includes(modName.toLowerCase())) {
          for (const dep of mod.dependencies) {
            if (!baseModules.includes(dep.toLowerCase())) {
              findings.push({
                id: `ARC-003-${modName}-${dep}`,
                ruleId: 'ARC-003',
                ruleTitle: 'Foundation Module Depends on Feature Module',
                category: 'Architecture',
                severity: 'High',
                status: 'FAIL',
                module: modName,
                artifact: `Module: ${modName}`,
                observation: `Base/Foundation module "${modName}" depends upward on feature module "${dep}".`,
                whyItMatters: 'Base modules should be completely agnostic of consumer features.',
                expectedPractice: 'Ensure lower-level modules have zero dependencies on upper feature modules.',
                recommendation: `Remove dependency from "${modName}" to "${dep}".`,
                confidence: 'High',
                evidence: {
                  artifactPath: `${modName}->${dep}`,
                  objectName: modName,
                  objectType: 'ModuleDependency',
                  details: { source: modName, forbiddenTarget: dep },
                },
                sourceSkill: 'graph-analysis.md',
              });
            }
          }
        }
      }
      return findings;
    },
  },
];
