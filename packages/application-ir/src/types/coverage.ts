/**
 * How much of the model the parser actually managed to read.
 *
 * Design §22 requires that a fact the analyzer cannot establish be "marked
 * NOT_ANALYZABLE rather than guessed". Without somewhere to record that, an unreadable
 * model is indistinguishable from a clean one — a rule that finds nothing because it
 * could not look reports the same empty result as a rule that looked and found nothing.
 * Every rule declares the facts it depends on (`Rule.requires`), and the engine refuses
 * to draw a conclusion from a fact that was never read.
 */

/**
 * - `ANALYZED`     — the fact was read from the model and is complete.
 * - `PARTIAL`      — some of it was read; findings are real but absence proves nothing.
 * - `NOT_ANALYZABLE` — it could not be read at all; no conclusion may be drawn either way.
 */
export type Analyzability = 'ANALYZED' | 'PARTIAL' | 'NOT_ANALYZABLE';

/** The fact groups Phase 1 rules depend on. */
export interface FactCoverage {
  /** `Security$ProjectSecurity`: security level, guest access, password policy, demo users. */
  projectSecurity: Analyzability;
  /** `Security$ModuleSecurity` module roles, and the user-role → module-role mapping. */
  moduleRoles: Analyzability;
  /** `DomainModels$AccessRule` with member access and XPath constraints. */
  entityAccessRules: Analyzability;
  /** Real attribute types, needed before an attribute can be called sensitive. */
  attributeTypes: Analyzability;
  /** `Forms$Page.AllowedModuleRoles`, and anonymous reachability derived from it. */
  pageAccess: Analyzability;
  /** Published REST/OData services and their authentication settings. */
  publishedServices: Analyzability;
  /** Microflow and nanoflow documents: names, allowed module roles, entity-access flags. */
  microflows: Analyzability;
  /**
   * The activity graph inside a flow: retrieves, commits, loops, error handling.
   *
   * Separate from `microflows` because the two are read independently and a rule that needs
   * one does not need the other. SEC-028 reads a microflow's `ApplyEntityAccess` and needs no
   * activity; PERF-001 counts retrieves inside loops and is worthless without them. Folding
   * both into one key would let the performance rules pass vacuously on an IR that never
   * opened a single activity — a project with a retrieve in every loop would score full marks
   * on performance.
   */
  microflowActivities: Analyzability;
  /** Where each microflow is referenced across the whole model (pages, navigation, flows, events, services). */
  modelReferences: Analyzability;
  /** `Constants$Constant` names, values and `ExposedToClient`. */
  constants: Analyzability;
  /** Scheduled events and their intervals and enabled flags. */
  scheduledEvents: Analyzability;
  /** Human-readable reasons for any PARTIAL or NOT_ANALYZABLE entry above. */
  notes: string[];
}

/** The fact groups a rule can declare a dependency on. */
export type FactKey = keyof Omit<FactCoverage, 'notes'>;

export const FACT_KEYS: readonly FactKey[] = [
  'projectSecurity',
  'moduleRoles',
  'entityAccessRules',
  'attributeTypes',
  'pageAccess',
  'publishedServices',
  'microflows',
  'microflowActivities',
  'modelReferences',
  'constants',
  'scheduledEvents',
];

/**
 * A coverage record with every fact unread.
 *
 * This is the correct starting point: the parser marks a fact `ANALYZED` only after it
 * has read it, so a parser path that forgets to report fails closed.
 */
export function emptyFactCoverage(): FactCoverage {
  return {
    projectSecurity: 'NOT_ANALYZABLE',
    moduleRoles: 'NOT_ANALYZABLE',
    entityAccessRules: 'NOT_ANALYZABLE',
    attributeTypes: 'NOT_ANALYZABLE',
    pageAccess: 'NOT_ANALYZABLE',
    publishedServices: 'NOT_ANALYZABLE',
    microflows: 'NOT_ANALYZABLE',
    microflowActivities: 'NOT_ANALYZABLE',
    modelReferences: 'NOT_ANALYZABLE',
    constants: 'NOT_ANALYZABLE',
    scheduledEvents: 'NOT_ANALYZABLE',
    notes: [],
  };
}

/**
 * Whether every listed fact was read well enough to conclude from.
 *
 * `PARTIAL` counts as analyzable: the rule may report what it did find. It must not treat
 * absence as proof of compliance, which is why a partial fact is surfaced in the coverage
 * notes shown alongside the score.
 */
export function factsAvailable(coverage: FactCoverage, required: readonly FactKey[]): boolean {
  return required.every((key) => coverage[key] !== 'NOT_ANALYZABLE');
}

/** The listed facts that could not be read, for explaining a NOT_APPLICABLE result. */
export function missingFacts(
  coverage: FactCoverage,
  required: readonly FactKey[]
): FactKey[] {
  return required.filter((key) => coverage[key] === 'NOT_ANALYZABLE');
}
