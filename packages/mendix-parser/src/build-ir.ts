/**
 * Assemble the Application IR from the model.
 *
 * This is the file that replaces `ir-builder.ts`. The old builder's job was to make the IR
 * *look* complete: it fabricated an access rule per entity with a hardcoded
 * `[Owner = $currentUser]` constraint, a three-widget array for every page, a
 * `<Module>_Overview` page per module, and a Retrieve activity for every microflow so the
 * performance rules would have something to read. Every one of those was indistinguishable,
 * downstream, from a fact — which is how a project with two plaintext demo credentials and
 * an anonymous role holding Atlas administrator rights scored 78/100.
 *
 * The rule here is the inverse: assemble only what an extractor actually read, and record
 * what could not be read in `coverage` so the engine can skip the rules that depend on it.
 * An empty collection in this IR means "the model contains none", never "we did not look" —
 * the second case is what `coverage` is for.
 */

import { basename } from 'node:path';

import type {
  Analyzability,
  ApplicationIR,
  ApplicationMetadata,
  DependencyGraph,
  Entity,
  FactCoverage,
  GraphEdge,
  GraphNode,
  IntegrationModel,
  Module,
  Page,
} from '@mendix-analyzer/application-ir';
import { resolveDataEntities } from '@mendix-analyzer/application-ir';

import { extractConstants } from './extract/constants.js';
import { extractDomainModel } from './extract/domain-model.js';
import { extractCustomCode } from './extract/filesystem.js';
import { extractFlows } from './extract/microflows.js';
import { extractPages, extractSnippetReferences } from './extract/pages.js';
import type { ReferenceMap } from './extract/pages.js';
import { extractNavigation, extractProject, navigationHomePages } from './extract/project.js';
import type { ModuleContents } from './extract/project.js';
import { extractSecurity } from './extract/security.js';
import type { Extraction } from './extract/types.js';
import { ModelGraph } from './model/model-graph.js';

/** Archive-level facts the extractor knows and the model does not. */
export interface ArchiveFacts {
  sha256?: string;
  extractedSizeBytes?: number;
  fileCount?: number;
}

export interface BuildIrResult {
  ir: ApplicationIR;
  /** Everything the extractors could not read, in the order it was discovered. */
  notes: string[];
}

/**
 * Phase 1 has no published-services extractor, so integration facts are unreadable rather
 * than absent. Reporting them as empty would make SEC-004 ("published service without
 * authentication") pass for every project, which is the exact failure mode this rewrite
 * exists to remove: a rule that cannot fail is worse than a missing rule, because it
 * contributes a perfect score.
 */
const SERVICES_NOT_EXTRACTED =
  'published and consumed services are not extracted in Phase 1, so no conclusion was ' +
  'drawn about service authentication';

const EMPTY_INTEGRATIONS: IntegrationModel = {
  publishedRestServices: [],
  consumedRestServices: [],
  publishedODataServices: [],
};

export function buildApplicationIr(
  projectRoot: string,
  mprPath: string,
  archive: ArchiveFacts = {}
): BuildIrResult {
  const graph = ModelGraph.build(projectRoot, mprPath);

  const { security, moduleRoles } = extractSecurity(graph);
  const domain = extractDomainModel(graph);
  // Navigation is read before the pages so a page can know it is a navigation home page,
  // which is what keeps SEC-018 from reporting every public app's own front door.
  const navigation = extractNavigation(graph);
  const pageReferences: ReferenceMap = new Map();
  const pages = extractPages(graph, security.value, navigationHomePages(navigation.value), pageReferences);
  const flows = extractFlows(graph);
  resolvePageData(pages.value, pageReferences, extractSnippetReferences(graph), domain.entities.value, flows);
  const { constants, operations } = extractConstants(graph);
  const customCode = extractCustomCode(projectRoot, graph);
  const project = extractProject(
    graph,
    moduleContentsOf(domain.entities.value, flows, pages.value),
    navigation
  );

  const notes = [
    ...diagnosticNotes(graph),
    ...security.notes,
    ...domain.entities.notes,
    ...domain.attributeTypes.notes,
    ...domain.accessRules.notes,
    ...pages.notes,
    ...flows.microflows.notes,
    ...constants.notes,
    ...customCode.notes,
    ...project.modules.notes,
    ...project.navigation.notes,
    SERVICES_NOT_EXTRACTED,
  ];

  const coverage: FactCoverage = {
    projectSecurity: security.analyzability,
    moduleRoles: moduleRoles.analyzability,
    entityAccessRules: domain.accessRules.analyzability,
    attributeTypes: domain.attributeTypes.analyzability,
    pageAccess: pages.analyzability,
    publishedServices: 'NOT_ANALYZABLE',
    microflows: flows.microflows.analyzability,
    // No activity is read in Phase 1 (see `extract/microflows.ts`), so every rule that counts
    // retrieves, commits or loops is skipped rather than allowed to pass on an empty array.
    microflowActivities: 'NOT_ANALYZABLE',
    modelReferences: 'NOT_ANALYZABLE',
    constants: constants.analyzability,
    // `extract/constants.ts` returns an empty `scheduledEvents` array by design; this is what
    // stops that emptiness being read as "the project schedules nothing".
    scheduledEvents: 'NOT_ANALYZABLE',
    notes,
  };

  const modules = project.modules.value;
  const entities = domain.entities.value;

  const metadata: ApplicationMetadata = {
    name: basename(mprPath, '.mpr'),
    mendixVersion: project.mendixVersion,
    javaVersion: project.javaVersion,
    applicationType: project.applicationType,
    // POSIX-normalised so a path in a report does not differ between the machine that ran
    // the analysis and the one reading it.
    primaryMprPath: mprPath.replace(/\\/g, '/'),
    archiveSha256: archive.sha256,
    extractedSizeBytes: archive.extractedSizeBytes,
    fileCount: archive.fileCount,
    totalModules: Object.keys(modules).length,
    totalEntities: Object.keys(entities).length,
    totalMicroflows: Object.keys(flows.microflows.value).length,
    totalNanoflows: Object.keys(flows.nanoflows.value).length,
    totalPages: Object.keys(pages.value).length,
  };

  const ir: ApplicationIR = {
    metadata,
    coverage,
    modules,
    entities,
    associations: domain.associations.value,
    microflows: flows.microflows.value,
    nanoflows: flows.nanoflows.value,
    pages: pages.value,
    security: security.value,
    integrations: EMPTY_INTEGRATIONS,
    customCode: customCode.value,
    operations,
    dependencyGraph: buildDependencyGraph(modules, entities, domain.associations.value),
    generatedAt: new Date().toISOString(),
  };

  return { ir, notes };
}

/**
 * Fill in each page's `dataEntities` from what the page, its snippets and its data-source flows
 * refer to. Runs after flows are extracted because a microflow data source resolves through the
 * microflow's return type.
 */
function resolvePageData(
  pages: Record<string, Page>,
  pageReferences: ReferenceMap,
  snippetReferences: ReferenceMap,
  entities: Record<string, Entity>,
  flows: ReturnType<typeof extractFlows>
): void {
  const flowReturnEntities = new Map<string, string | undefined>();
  for (const f of Object.values(flows.microflows.value)) flowReturnEntities.set(f.qualifiedName, f.returnEntity);
  for (const f of Object.values(flows.nanoflows.value)) flowReturnEntities.set(f.qualifiedName, f.returnEntity);
  const context = { entities: new Set(Object.keys(entities)), flowReturnEntities, snippetReferences };
  for (const page of Object.values(pages)) {
    const references = pageReferences.get(page.qualifiedName);
    if (references) page.dataEntities = resolveDataEntities(references, context);
  }
}

/**
 * Group document names by owning module.
 *
 * Each extractor already resolved ownership through containment, so this is a regrouping of
 * facts rather than a second attribution pass — which matters, because two different answers
 * to "which module owns this page?" is how findings end up filed against the wrong team.
 */
function moduleContentsOf(
  entities: Record<string, Entity>,
  flows: ReturnType<typeof extractFlows>,
  pages: Record<string, { module: string; name: string }>
): ModuleContents {
  const contents: ModuleContents = {
    entities: new Map(),
    microflows: new Map(),
    nanoflows: new Map(),
    pages: new Map(),
  };

  const add = (target: Map<string, string[]>, module: string, name: string): void => {
    const list = target.get(module);
    if (list) list.push(name);
    else target.set(module, [name]);
  };

  for (const entity of Object.values(entities)) add(contents.entities, entity.module, entity.name);
  for (const flow of Object.values(flows.microflows.value)) {
    add(contents.microflows, flow.module, flow.name);
  }
  for (const flow of Object.values(flows.nanoflows.value)) {
    add(contents.nanoflows, flow.module, flow.name);
  }
  for (const page of Object.values(pages)) add(contents.pages, page.module, page.name);

  return contents;
}

/**
 * Module dependencies derived from the model: a cross-module association or a cross-module
 * generalization is a dependency that exists in the domain model and can be pointed at.
 *
 * The old builder added `System` as a dependency of every module on the grounds that all
 * Mendix modules use it, then detected cycles in the result. A dependency nobody wrote is
 * not an architecture finding, so nothing is added here that the model does not state.
 */
function buildDependencyGraph(
  modules: Record<string, Module>,
  entities: Record<string, Entity>,
  associations: ApplicationIR['associations']
): DependencyGraph {
  const dependencies = new Map<string, Set<string>>();
  for (const name of Object.keys(modules)) dependencies.set(name, new Set());

  const link = (from: string | undefined, to: string | undefined): void => {
    if (!from || !to || from === to) return;
    dependencies.get(from)?.add(to);
  };

  for (const association of associations) {
    link(moduleOf(association.parentEntity), moduleOf(association.childEntity));
    link(moduleOf(association.childEntity), moduleOf(association.parentEntity));
  }
  for (const entity of Object.values(entities)) {
    if (entity.generalization) link(entity.module, moduleOf(entity.generalization));
  }

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  for (const [name, deps] of dependencies) {
    nodes.push({
      id: name,
      label: name,
      type: 'module',
      module: name,
      outDegree: deps.size,
    });
    for (const dep of deps) {
      edges.push({ id: `${name}->${dep}`, source: name, target: dep, type: 'depends_on' });
    }
  }
  for (const node of nodes) {
    node.inDegree = edges.filter((e) => e.target === node.id).length;
    node.degree = (node.outDegree ?? 0) + node.inDegree;
  }

  for (const module of Object.values(modules)) {
    module.dependencies = [...(dependencies.get(module.name) ?? [])].sort();
  }

  return {
    nodes,
    edges,
    cycles: findCycles(dependencies),
    godModules: findGodModules(modules),
  };
}

function moduleOf(qualifiedName: string): string | undefined {
  const dot = qualifiedName.indexOf('.');
  return dot > 0 ? qualifiedName.slice(0, dot) : undefined;
}

/**
 * Cycles in the module dependency graph, each reported once.
 *
 * A cycle is keyed by its sorted member set so that the same loop found from two different
 * entry points is not reported twice — the old detector pushed one cycle per traversal that
 * reached it, which inflated the count with duplicates of a single problem.
 */
function findCycles(dependencies: Map<string, Set<string>>): string[][] {
  const cycles: string[][] = [];
  const seenKeys = new Set<string>();
  const visited = new Set<string>();
  const onStack = new Set<string>();

  const visit = (node: string, path: string[]): void => {
    visited.add(node);
    onStack.add(node);
    path.push(node);

    for (const next of dependencies.get(node) ?? []) {
      if (onStack.has(next)) {
        const start = path.indexOf(next);
        if (start >= 0) {
          const cycle = path.slice(start);
          const key = [...cycle].sort().join('|');
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            cycles.push([...cycle, next]);
          }
        }
      } else if (!visited.has(next)) {
        visit(next, path);
      }
    }

    onStack.delete(node);
    path.pop();
  };

  for (const node of dependencies.keys()) {
    if (!visited.has(node)) visit(node, []);
  }
  return cycles;
}

/** Modules holding a disproportionate share of the domain model. */
function findGodModules(modules: Record<string, Module>): string[] {
  const candidates = Object.values(modules).filter((m) => !m.isSystem && !m.isMarketplace);
  const total = candidates.reduce((sum, m) => sum + m.entities.length, 0);
  // Below a handful of entities the ratio says nothing: a two-entity project would report
  // its only module as a god module.
  if (total < 10) return [];
  return candidates.filter((m) => m.entities.length / total > 0.35).map((m) => m.name);
}

function diagnosticNotes(graph: ModelGraph): string[] {
  const diagnostics = graph.diagnosticsReport;
  const notes: string[] = [];

  if (diagnostics.containmentError) {
    notes.push(
      `the .mpr containment tree could not be read (${diagnostics.containmentError}), so no ` +
        'document could be attributed to its module'
    );
  }
  if (diagnostics.unitParseFailures.length > 0) {
    notes.push(
      `${diagnostics.unitParseFailures.length} model unit(s) could not be parsed: ` +
        diagnostics.unitParseFailures
          .slice(0, 5)
          .map((f) => `${f.unitPath} (${f.reason})`)
          .join('; ')
    );
  }
  if (diagnostics.unitsWithoutModule.length > 0) {
    notes.push(
      `${diagnostics.unitsWithoutModule.length} model unit(s) could not be attributed to a module`
    );
  }
  if (diagnostics.unitsMissingContainment.length > 0) {
    notes.push(
      `${diagnostics.unitsMissingContainment.length} model unit(s) have no containment record ` +
        'in the .mpr'
    );
  }
  return notes;
}

/** Re-exported so callers can reason about an extraction without importing the internals. */
export type { Extraction, Analyzability };
