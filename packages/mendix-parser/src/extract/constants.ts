/**
 * Extract `Constants$Constant` units.
 *
 * Constants matter to Phase 1 for one reason: they are where hardcoded secrets end up. A
 * constant named `ApiKey` with a non-empty default is a credential committed to the model,
 * and one that is additionally `ExposedToClient` has been published to every browser that
 * loads the app.
 *
 * Module attribution is the correction here. The old extractor guessed the owning module,
 * which is how the fixture's only constant — `FeedbackModule.LocalStorageKey`, a marketplace
 * module's browser storage key — came to be reported against the user's own code.
 *
 * SECURITY — a secret-shaped value is classified, then dropped. `defaultValue` is retained
 * only for constants the classifier judges non-sensitive, because the IR is written to
 * `data/runs/*.json` and embedded in reports.
 */

import type { OperationsModel } from '@mendix-analyzer/application-ir';
import { classifySensitivity, isPlaceholderValue } from '@mendix-analyzer/application-ir';

import { elementType, str, subDoc, bool } from '../bson/accessors.js';
import type { ModelGraph } from '../model/model-graph.js';
import { analyzed } from './types.js';
import type { Extraction } from './types.js';

const CONSTANT_TYPE = 'Constants$Constant';

/** A constant, with its value redacted when the name says it holds a secret. */
export interface ConstantFact {
  name: string;
  module: string;
  qualifiedName: string;
  dataType: string;
  hasDefaultValue: boolean;
  /** Present only when the constant is not secret-shaped. */
  defaultValue?: string;
  isExposedToClient: boolean;
  /** Whether the name indicates a credential. */
  isSecretShaped: boolean;
  /** The classifier term that matched, for the evidence trail. */
  sensitivityTerm?: string;
  /** Whether the default looks like a real value rather than `changeme` or empty. */
  hasRealValue: boolean;
  /** Whether the owning module is the team's own code. */
  isUserModule: boolean;
  provenance: { unitPath: string };
}

export interface ConstantsExtraction {
  constants: Extraction<ConstantFact[]>;
  /** Shaped for `ApplicationIR.operations`. */
  operations: OperationsModel;
}

export function extractConstants(graph: ModelGraph): ConstantsExtraction {
  const refs = graph.units.refsOfType(CONSTANT_TYPE);
  const facts: ConstantFact[] = [];
  const notes: string[] = [];

  for (const { tree, ref } of graph.units.unitsOfType(CONSTANT_TYPE)) {
    const name = str(tree, 'Name');
    const owner = graph.moduleOf(ref);
    if (!name) {
      notes.push(`an unnamed constant in ${ref.unitPath} was skipped`);
      continue;
    }
    if (!owner) {
      // Without the owning module there is no way to tell the team's own credential from a
      // marketplace module's configuration key, which is the distinction that decides
      // whether this is actionable.
      notes.push(`the module owning constant ${name} could not be resolved; it was skipped`);
      continue;
    }

    const sensitivity = classifySensitivity(name);
    const rawValue = str(tree, 'DefaultValue');
    const isSecretShaped = sensitivity.kind === 'secret';

    facts.push({
      name,
      module: owner.name,
      qualifiedName: `${owner.name}.${name}`,
      dataType: dataTypeOf(tree),
      hasDefaultValue: rawValue !== undefined && rawValue.length > 0,
      defaultValue: isSecretShaped ? undefined : rawValue || undefined,
      isExposedToClient: bool(tree, 'ExposedToClient') ?? false,
      isSecretShaped,
      sensitivityTerm: sensitivity.matchedTerm,
      hasRealValue: !isPlaceholderValue(rawValue),
      isUserModule: owner.origin === 'user',
      provenance: { unitPath: ref.unitPath },
    });
  }

  const operations: OperationsModel = {
    constants: facts.map((f) => ({
      name: f.name,
      module: f.module,
      dataType: f.dataType,
      hasDefaultValue: f.hasDefaultValue,
      defaultValue: f.defaultValue,
      isExposedToClient: f.isExposedToClient,
    })),
    // Scheduled events are not extracted in Phase 1; an empty array here is reported
    // through coverage rather than implying the project defines none.
    scheduledEvents: [],
  };

  if (refs.length === 0) {
    // No constant units at all is a readable, meaningful answer: there are no constants,
    // so constant-based rules correctly pass rather than being skipped.
    return { constants: analyzed([], notes), operations };
  }

  return { constants: analyzed(facts, notes), operations };
}

function dataTypeOf(tree: Parameters<typeof subDoc>[0]): string {
  const discriminator = elementType(subDoc(tree, 'Type')) ?? '';
  const match = /^DataTypes\$(.+)Type$/.exec(discriminator);
  return match ? match[1] : 'Unknown';
}

/** Constants that hold a real, secret-shaped value. */
export function hardcodedSecrets(constants: ConstantFact[]): ConstantFact[] {
  return constants.filter((c) => c.isSecretShaped && c.hasDefaultValue && c.hasRealValue);
}
