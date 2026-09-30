import { Rule, Finding } from '@mendix-analyzer/rule-engine';

export const maintainabilityRules: Rule[] = [
  {
    id: 'MNT-001',
    name: 'Entity Naming Convention Violation',
    description: 'Entities should be named in PascalCase without underscores or special characters.',
    category: 'Maintainability',
    subcategory: 'Naming Conventions',
    severity: 'Low',
    sourceSkill: 'write-lint-rules.md',
    sourceSection: 'Domain Model Naming Rules',
    expectedPractice: 'Use PascalCase for entity names (e.g. CustomerOrder, not customer_order).',
    recommendation: 'Rename entity to PascalCase standard.',
    whyItMatters: 'Consistent naming ensures clean generated Java/TypeScript proxies and team maintainability.',
    confidence: 'High',
    enabled: true,
    /** entity documentation is read with the domain model. */
    requires: [],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      const pascalCaseRegex = /^[A-Z][a-zA-Z0-9]+$/;

      for (const [key, entity] of Object.entries(ir.entities)) {
        const mod = ir.modules[entity.module];
        const isExcluded = entity.module.toLowerCase() === 'system' || (mod && (mod.isSystem || mod.isMarketplace));
        if (!pascalCaseRegex.test(entity.name) && !isExcluded) {
          findings.push({
            id: `MNT-001-${entity.name}`,
            ruleId: 'MNT-001',
            ruleTitle: 'Entity Naming Convention Violation',
            category: 'Maintainability',
            severity: 'Low',
            status: 'WARNING',
            module: entity.module,
            artifact: `Entity: ${entity.name}`,
            observation: `Entity "${entity.name}" does not adhere to PascalCase naming conventions.`,
            whyItMatters: 'Inconsistent naming creates confusing proxy class names and violates corporate standards.',
            expectedPractice: 'Follow PascalCase conventions for domain entities.',
            recommendation: `Rename "${entity.name}" to follow PascalCase.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${entity.module}.${entity.name}`,
              objectName: entity.name,
              objectType: 'Entity',
              details: { entityName: entity.name },
            },
            sourceSkill: 'write-lint-rules.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'MNT-002',
    name: 'Microflow Naming Convention Violation',
    description: 'Microflows must start with a standardized prefix indicating their purpose (ACT_, SUB_, DS_, BCo_).',
    category: 'Maintainability',
    subcategory: 'Naming Conventions',
    severity: 'Low',
    sourceSkill: 'write-lint-rules.md',
    sourceSection: 'Microflow Naming Rules',
    expectedPractice: 'Prefix microflows with: ACT_ (action), SUB_ (sub-flow), DS_ (data source), BCo_ (before commit), etc.',
    recommendation: 'Add the standard prefix to the microflow name.',
    whyItMatters: 'Standard prefixes immediately signal to developers the trigger context and lifecycle role of the flow.',
    confidence: 'High',
    enabled: true,
    /** microflow documentation is read from the microflow documents. */
    requires: ['microflows'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      const standardPrefixes = ['ACT_', 'SUB_', 'DS_', 'BCo_', 'ACo_', 'BDe_', 'ADe_', 'IVK_', 'OCh_', 'VAL_', 'SF_'];

      for (const [key, mf] of Object.entries(ir.microflows)) {
        const mod = ir.modules[mf.module];
        const isExcluded = mf.module.toLowerCase() === 'system' || (mod && (mod.isSystem || mod.isMarketplace));
        const hasPrefix = standardPrefixes.some((p) => mf.name.startsWith(p));
        if (!hasPrefix && !isExcluded) {
          findings.push({
            id: `MNT-002-${mf.name}`,
            ruleId: 'MNT-002',
            ruleTitle: 'Microflow Naming Convention Violation',
            category: 'Maintainability',
            severity: 'Low',
            status: 'WARNING',
            module: mf.module,
            artifact: `Microflow: ${mf.name}`,
            observation: `Microflow "${mf.name}" does not start with a recognized Mendix prefix (${standardPrefixes.slice(0, 4).join(', ')}, etc.).`,
            whyItMatters: 'Without prefixes, developers cannot tell if a flow is a button action, data source, or event handler.',
            expectedPractice: 'Apply standard Mendix community naming prefixes.',
            recommendation: `Rename "${mf.name}" using an appropriate prefix like ACT_ or SUB_.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${mf.module}.${mf.name}`,
              objectName: mf.name,
              objectType: 'Microflow',
              details: { name: mf.name },
            },
            sourceSkill: 'write-lint-rules.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'MNT-003',
    name: 'Heavy Vendor Library Dependency Footprint',
    description: 'A large number of external JAR files (> 25) increases deployment size and vulnerability exposure.',
    category: 'Maintainability',
    subcategory: 'Dependency Governance',
    severity: 'Medium',
    sourceSkill: 'java-dependencies.md',
    sourceSection: 'Managing Vendor Libraries',
    expectedPractice: 'Audit userlib/vendorlib and prune unused or redundant third-party libraries.',
    recommendation: 'Review vendorlib dependencies and remove superseded or duplicate JAR versions.',
    whyItMatters: 'Excess JAR dependencies slow build times and introduce potential CVE vulnerabilities into the runtime.',
    confidence: 'High',
    enabled: true,
    /** vendor jars are counted on disk, not in the model. */
    requires: [],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      const jarCount = ir.customCode.vendorJars.length;
      if (jarCount > 25) {
        findings.push({
          id: 'MNT-003-VendorJars',
          ruleId: 'MNT-003',
          ruleTitle: 'Heavy Vendor Library Dependency Footprint',
          category: 'Maintainability',
          severity: 'Medium',
          status: 'WARNING',
          artifact: 'vendorlib',
          observation: `Project includes ${jarCount} external JAR files in vendorlib.`,
          whyItMatters: 'Accumulated legacy JARs risk version conflicts, increase deployment artifact size, and carry security risks.',
          expectedPractice: 'Keep vendor libraries lean and run automated dependency vulnerability scans.',
          recommendation: 'Audit vendorlib and remove unnecessary libraries.',
          confidence: 'High',
          evidence: {
            artifactPath: 'vendorlib',
            objectName: 'vendorlib',
            objectType: 'Folder',
            details: { jarCount, sampleJars: ir.customCode.vendorJars.slice(0, 5).map((j) => j.name) },
          },
          sourceSkill: 'java-dependencies.md',
        });
      }
      return findings;
    },
  },
];
