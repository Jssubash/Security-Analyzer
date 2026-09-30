import { Rule, Finding } from '@mendix-analyzer/rule-engine';

export const dataRules: Rule[] = [
  {
    id: 'DAT-001',
    name: 'Missing Index on Association Foreign Key',
    description: 'Associations frequently queried or joined should have database indexes defined.',
    category: 'Data',
    subcategory: 'Indexing',
    severity: 'Medium',
    sourceSkill: 'mdl-entities.md',
    sourceSection: 'Indexes and Performance',
    expectedPractice: 'Define indexes on entity foreign key attributes and heavily traversed associations.',
    recommendation: 'Add an index on the association in the Entity Properties -> Indexes tab.',
    whyItMatters: 'Unindexed foreign key lookups cause full table scans in relational databases as data volume grows.',
    confidence: 'Medium',
    enabled: true,
    /** association delete behaviour is read with the domain model. */
    requires: [],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const assoc of ir.associations) {
        const parentEntity = ir.entities[assoc.parentEntity];
        const parentMod = parentEntity ? ir.modules[parentEntity.module] : undefined;
        const isExcluded = !parentEntity || parentEntity.module.toLowerCase() === 'system' || (parentMod && (parentMod.isSystem || parentMod.isMarketplace));
        if (parentEntity && parentEntity.persistenceType === 'persistable' && !isExcluded) {
          const hasIndex = parentEntity.indexes.some((idx: { attributes: string[] }) => idx.attributes.includes(assoc.name));
          if (!hasIndex && parentEntity.attributes.length > 5) {
            findings.push({
              id: `DAT-001-${assoc.name}`,
              ruleId: 'DAT-001',
              ruleTitle: 'Missing Index on Association Foreign Key',
              category: 'Data',
              severity: 'Medium',
              status: 'WARNING',
              module: assoc.module,
              artifact: `Association: ${assoc.name}`,
              observation: `Association "${assoc.name}" between "${assoc.parentEntity}" and "${assoc.childEntity}" has no index.`,
              whyItMatters: 'Retrieving associated records will perform table scans without an index.',
              expectedPractice: 'Index high-frequency reference associations.',
              recommendation: `Add an index for association "${assoc.name}" on entity "${parent.name}".`,
              confidence: 'Medium',
              evidence: {
                artifactPath: `${assoc.module}.${assoc.name}`,
                objectName: assoc.name,
                objectType: 'Association',
                details: { parent: assoc.parentEntity, child: assoc.childEntity, type: assoc.type },
              },
              sourceSkill: 'mdl-entities.md',
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'DAT-002',
    name: 'Dangerous Cascading Delete Behavior',
    description: 'DeleteBoth cascading delete behavior can cause unintentional bulk data loss.',
    category: 'Data',
    subcategory: 'Delete Behavior',
    severity: 'High',
    sourceSkill: 'mdl-entities.md',
    sourceSection: 'Association Delete Behavior',
    expectedPractice: 'Use DeleteChildOnly or DeleteNever with explicit business microflows rather than DeleteBoth.',
    recommendation: 'Review association delete behavior and change from DeleteBoth to DeleteParentOnly or DeleteNever.',
    whyItMatters: 'Deleting an object can unintentionally delete parent or child records across the entire database.',
    confidence: 'High',
    enabled: true,
    /** association types are read with the domain model. */
    requires: [],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const assoc of ir.associations) {
        if (assoc.deleteBehavior === 'DeleteBoth') {
          findings.push({
            id: `DAT-002-${assoc.name}`,
            ruleId: 'DAT-002',
            ruleTitle: 'Dangerous Cascading Delete Behavior',
            category: 'Data',
            severity: 'High',
            status: 'FAIL',
            module: assoc.module,
            artifact: `Association: ${assoc.name}`,
            observation: `Association "${assoc.name}" is configured with "DeleteBoth" cascading delete.`,
            whyItMatters: 'Deleting an entity instance on either side will wipe out associated records in the other table.',
            expectedPractice: 'Avoid bidirectional cascading deletes on enterprise data models.',
            recommendation: `Configure delete behavior on "${assoc.name}" to prevent cascading deletions.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${assoc.module}.${assoc.name}`,
              objectName: assoc.name,
              objectType: 'Association',
              details: { deleteBehavior: assoc.deleteBehavior },
            },
            sourceSkill: 'mdl-entities.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'DAT-003',
    name: 'Deep Generalization Hierarchy',
    description: 'Entity inheritance depth should not exceed 2 levels.',
    category: 'Data',
    subcategory: 'Domain Modeling',
    severity: 'Medium',
    sourceSkill: 'generate-domain-model.md',
    sourceSection: 'Inheritance and Generalization',
    expectedPractice: 'Keep entity generalization hierarchies shallow (<= 2 levels) or use composition (1-1 association).',
    recommendation: 'Refactor deep generalization into 1-1 associations or composition.',
    whyItMatters: 'Mendix queries on deeply nested generalizations generate multi-table SQL joins that degrade database performance.',
    confidence: 'High',
    enabled: true,
    /** generalization chains are read with the domain model. */
    requires: [],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, entity] of Object.entries(ir.entities)) {
        if (entity.module.toLowerCase() === 'system') continue;
        let depth = 0;
        let curr: string | undefined = entity.generalization;
        while (curr && depth < 10) {
          depth++;
          curr = ir.entities[curr]?.generalization;
        }

        if (depth > 2) {
          findings.push({
            id: `DAT-003-${entity.name}`,
            ruleId: 'DAT-003',
            ruleTitle: 'Deep Generalization Hierarchy',
            category: 'Data',
            severity: 'Medium',
            status: 'WARNING',
            module: entity.module,
            artifact: `Entity: ${entity.name}`,
            observation: `Entity "${entity.name}" has an inheritance depth of ${depth} levels.`,
            whyItMatters: 'Deep inheritance creates excessive SQL joins across multiple tables on every retrieve.',
            expectedPractice: 'Limit generalization depth to a maximum of 2 levels.',
            recommendation: `Refactor "${entity.name}" to use association-based composition instead of deep inheritance.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${entity.module}.${entity.name}`,
              objectName: entity.name,
              objectType: 'Entity',
              details: { depth, rootGeneralization: entity.generalization },
            },
            sourceSkill: 'generate-domain-model.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'DAT-004',
    name: 'Excessive Entity Attribute Count',
    description: 'Entities with more than 30 attributes indicate poor domain modularization.',
    category: 'Data',
    subcategory: 'Domain Design',
    severity: 'Low',
    sourceSkill: 'mdl-entities.md',
    sourceSection: 'Entity Design Principles',
    expectedPractice: 'Decompose wide entities into normalized child entities or 1-1 sub-entities.',
    recommendation: 'Break down large entities into focused logical entities connected via 1-1 references.',
    whyItMatters: 'Wide tables increase row size, memory footprint, and network payload during data transfers.',
    confidence: 'High',
    enabled: true,
    /** the rule counts attributes, so it needs the attribute list to be readable. */
    requires: ['attributeTypes'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, entity] of Object.entries(ir.entities)) {
        if (entity.module.toLowerCase() === 'system') continue;
        if (entity.attributes.length > 30) {
          findings.push({
            id: `DAT-004-${entity.name}`,
            ruleId: 'DAT-004',
            ruleTitle: 'Excessive Entity Attribute Count',
            category: 'Data',
            severity: 'Low',
            status: 'WARNING',
            module: entity.module,
            artifact: `Entity: ${entity.name}`,
            observation: `Entity "${entity.name}" has ${entity.attributes.length} attributes (threshold: 30).`,
            whyItMatters: 'Large entities cause wide database rows and slow down data serialization.',
            expectedPractice: 'Normalize entities with more than 30 fields into related sub-entities.',
            recommendation: `Split "${entity.name}" into smaller domain concepts using associations.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${entity.module}.${entity.name}`,
              objectName: entity.name,
              objectType: 'Entity',
              details: { attributeCount: entity.attributes.length },
            },
            sourceSkill: 'mdl-entities.md',
          });
        }
      }
      return findings;
    },
  },
];
