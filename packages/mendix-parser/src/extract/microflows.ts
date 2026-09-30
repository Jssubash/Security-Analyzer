/**
 * Extract the security-relevant facts from `Microflows$Microflow` and
 * `Microflows$Nanoflow` units.
 *
 * Phase 1 deliberately reads only what the security rules need — `AllowedModuleRoles` and
 * `ApplyEntityAccess` — and reports `microflows` coverage as PARTIAL. The activity graph
 * (retrieves inside loops, commits, error handling) is what the Performance and Logic
 * analyzers need, and inventing it here would repeat the mistake this rewrite exists to
 * correct: the old parser reported `cyclomaticComplexity: 2` and `activitiesCount: 4` for
 * every nanoflow because it was counting JavaScript source files, not reading the model.
 *
 * That the count was wrong is worth stating plainly: the old parser reported 0 microflows
 * and 73 nanoflows for a project that contains 17 microflows and 15 nanoflows.
 */

import type { Microflow, Nanoflow } from '@mendix-analyzer/application-ir';

import { bool, elementId, str, strArray, subDoc } from '../bson/accessors.js';
import type { ModelGraph } from '../model/model-graph.js';
import { notAnalyzable } from './types.js';
import type { Extraction } from './types.js';

const MICROFLOW_TYPE = 'Microflows$Microflow';
const NANOFLOW_TYPE = 'Microflows$Nanoflow';

const ACTIVITIES_NOT_READ =
  'microflow activities are not extracted in Phase 1: allowed roles and entity-access ' +
  'settings are read, but rules about retrieves, commits, loops or error handling cannot ' +
  'be evaluated from this IR';

export interface FlowExtraction {
  microflows: Extraction<Record<string, Microflow>>;
  nanoflows: Extraction<Record<string, Nanoflow>>;
}

export function extractFlows(graph: ModelGraph): FlowExtraction {
  const microflowRefs = graph.units.refsOfType(MICROFLOW_TYPE);
  const notes: string[] = [];

  const microflows: Record<string, Microflow> = {};
  for (const { tree, ref } of graph.units.unitsOfType(MICROFLOW_TYPE)) {
    const name = str(tree, 'Name');
    const owner = graph.moduleOf(ref);
    if (!name || !owner) {
      notes.push(`the microflow in ${ref.unitPath} could not be attributed to a module`);
      continue;
    }
    const qualifiedName = `${owner.name}.${name}`;
    microflows[qualifiedName] = {
      name,
      module: owner.name,
      qualifiedName,
      returnType: returnTypeOf(tree),
      parameters: [],
      activities: [],
      cyclomaticComplexity: 0,
      hasErrorHandling: false,
      callsMicroflows: [],
      callsJavaActions: [],
      retrievesInsideLoops: [],
      commitsInsideLoops: [],
      deletesInsideLoops: [],
      // A microflow exposed as a web-service operation is recorded on the service, not
      // here, so this stays false until the published-services extractor exists.
      isExposedAsService: false,
      allowedRoles: strArray(tree, 'AllowedModuleRoles'),
      appliesEntityAccess: bool(tree, 'ApplyEntityAccess'),
      returnEntity: returnEntityOf(tree),
      documentation: str(tree, 'Documentation') || undefined,
      provenance: { unitPath: ref.unitPath, elementId: elementId(tree) },
    };
  }

  const nanoflows: Record<string, Nanoflow> = {};
  for (const { tree, ref } of graph.units.unitsOfType(NANOFLOW_TYPE)) {
    const name = str(tree, 'Name');
    const owner = graph.moduleOf(ref);
    if (!name || !owner) {
      notes.push(`the nanoflow in ${ref.unitPath} could not be attributed to a module`);
      continue;
    }
    const qualifiedName = `${owner.name}.${name}`;
    nanoflows[qualifiedName] = {
      name,
      module: owner.name,
      qualifiedName,
      returnType: returnTypeOf(tree),
      parameters: [],
      activities: [],
      callsJavaScriptActions: [],
      cyclomaticComplexity: 0,
      returnEntity: returnEntityOf(tree),
      documentation: str(tree, 'Documentation') || undefined,
    };
  }

  if (microflowRefs.length === 0) {
    return {
      microflows: notAnalyzable({}, `no ${MICROFLOW_TYPE} unit was found`),
      nanoflows: { value: nanoflows, analyzability: 'PARTIAL', notes: [ACTIVITIES_NOT_READ] },
    };
  }

  return {
    // PARTIAL, never ANALYZED: the roles and entity-access flags are complete, but a rule
    // that needs the activity graph must not read this as a full microflow model.
    microflows: {
      value: microflows,
      analyzability: 'PARTIAL',
      notes: [ACTIVITIES_NOT_READ, ...notes],
    },
    nanoflows: { value: nanoflows, analyzability: 'PARTIAL', notes: [ACTIVITIES_NOT_READ] },
  };
}

/** The entity an object- or list-returning flow returns; a page data source resolves through it. */
function returnEntityOf(tree: Parameters<typeof subDoc>[0]): string | undefined {
  return str(subDoc(tree, 'MicroflowReturnType'), 'Entity') || undefined;
}

function returnTypeOf(tree: Parameters<typeof subDoc>[0]): string {
  const returnType = subDoc(tree, 'MicroflowReturnType');
  if (!returnType) return 'Void';
  const discriminator = str(returnType, '$Type') ?? '';
  const match = /^DataTypes\$(.+)Type$/.exec(discriminator);
  return match ? match[1] : 'Void';
}
