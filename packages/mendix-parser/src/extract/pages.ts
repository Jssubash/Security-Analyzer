/**
 * Extract pages from `Forms$Page` units.
 *
 * The security-relevant fact is `AllowedModuleRoles`: an array of qualified `Module.Role`
 * names. Anonymous reachability is then *computed* by intersecting that with the module
 * roles the guest user role actually holds. The old parser fabricated pages that do not
 * exist (`ir-builder.ts:180-186` synthesised a `<Module>_Overview` page per module with
 * `totalWidgets: 16`) and hardcoded `isAccessibleAnonymously: false` for all of them, which
 * is why SEC-005 could report on pages nobody had written.
 */

import type { Page, SecurityModel, Widget } from '@mendix-analyzer/application-ir';
import { looksQualified } from '@mendix-analyzer/application-ir';

import { elementId, elementType, str, strArray, subDoc } from '../bson/accessors.js';
import type { BsonDocument } from '../bson/reader.js';
import type { ModelGraph } from '../model/model-graph.js';
import { analyzed, notAnalyzable } from './types.js';
import type { Extraction } from './types.js';

const PAGE_TYPE = 'Forms$Page';

/**
 * Widgets are recorded in `Widgets` arrays at many depths, so the count is a walk rather
 * than a single property read. Only the count and the top-level widget kinds are kept: a
 * full widget inventory for a 3 MB page would dominate the IR without informing any
 * Phase 1 rule.
 */
const MAX_WIDGETS_RETAINED = 200;

/** Page or snippet qualified name → the qualified names its tree refers to. */
export type ReferenceMap = Map<string, string[]>;

export function extractPages(
  graph: ModelGraph,
  security: SecurityModel,
  /** Qualified names of pages a navigation profile opens on; see `Page.isNavigationHomePage`. */
  homePages: ReadonlySet<string> = new Set(),
  /** Filled with each page's references, for resolving `Page.dataEntities` once flows are read. */
  references: ReferenceMap = new Map()
): Extraction<Record<string, Page>> {
  const refs = graph.units.refsOfType(PAGE_TYPE);
  if (refs.length === 0) {
    // A project can legitimately have no pages (a pure integration app), but then no
    // page-access conclusion can be drawn either, so this is not ANALYZED.
    return notAnalyzable({}, `no ${PAGE_TYPE} unit was found, so page access was not assessed`);
  }

  const guestModuleRoles = guestRolesOf(security);
  const notes: string[] = [];
  if (!guestModuleRoles) {
    notes.push(
      'the guest user role could not be identified, so anonymous page reachability was not computed'
    );
  }

  const pages: Record<string, Page> = {};

  for (const { tree, ref } of graph.units.unitsOfType(PAGE_TYPE)) {
    const name = str(tree, 'Name');
    const owner = graph.moduleOf(ref);
    if (!name || !owner) {
      notes.push(`the page in ${ref.unitPath} could not be attributed to a module and was skipped`);
      continue;
    }

    const allowedRoles = strArray(tree, 'AllowedModuleRoles');
    const { total, widgets } = collectWidgets(tree);

    const qualifiedName = `${owner.name}.${name}`;
    references.set(qualifiedName, treeReferences(tree));
    pages[qualifiedName] = {
      name,
      module: owner.name,
      qualifiedName,
      layout: str(subDoc(tree, 'FormCall'), 'Form') || undefined,
      totalWidgets: total,
      widgets,
      allowedRoles,
      // Only a role the guest actually holds makes a page anonymously reachable. When the
      // guest role is unknown this stays `false` and the note above explains why, so a
      // rule reading it is not silently told "no page is public".
      isAccessibleAnonymously: guestModuleRoles
        ? allowedRoles.some((role) => guestModuleRoles.has(role))
        : false,
      isNavigationHomePage: homePages.has(qualifiedName),
      navigationPath: str(tree, 'Url') || undefined,
      documentation: str(tree, 'Documentation') || undefined,
      provenance: { unitPath: ref.unitPath, elementId: elementId(tree) },
    };
  }

  return analyzed(pages, notes);
}

/**
 * Snippets and the names they refer to. A page that embeds a snippet uses whatever the snippet
 * uses, so page data is resolved through these.
 */
export function extractSnippetReferences(graph: ModelGraph): ReferenceMap {
  const references: ReferenceMap = new Map();
  for (const { tree, ref } of graph.units.unitsOfType('Forms$Snippet')) {
    const name = str(tree, 'Name');
    const owner = graph.moduleOf(ref);
    if (!name || !owner) continue;
    references.set(`${owner.name}.${name}`, treeReferences(tree));
  }
  return references;
}

/** Every string in the tree shaped like a qualified model name, de-duplicated. */
export function treeReferences(tree: BsonDocument): string[] {
  const found = new Set<string>();
  const visit = (value: unknown): void => {
    if (typeof value === 'string') {
      if (looksQualified(value)) found.add(value);
    } else if (Array.isArray(value)) {
      for (const item of value) visit(item);
    } else if (value && typeof value === 'object' && !(value instanceof Uint8Array)) {
      for (const v of Object.values(value)) visit(v);
    }
  };
  visit(tree);
  return [...found];
}

/**
 * The qualified module roles held by the guest user role.
 *
 * Returns `undefined` when guest access is configured but the role cannot be found, and an
 * empty set when guest access is switched off — the two are different, and conflating them
 * would make every page look either public or private.
 */
function guestRolesOf(security: SecurityModel): Set<string> | undefined {
  if (security.anonymousUserEnabled === false) return new Set();

  const guestName = security.anonymousRole;
  const guest = guestName
    ? security.userRoles.find((r) => r.name === guestName)
    : security.userRoles.find((r) => r.isAnonymous);
  if (!guest) return undefined;

  return new Set(guest.moduleRoles.map((m) => `${m.module}.${m.role}`));
}

function collectWidgets(tree: BsonDocument): { total: number; widgets: Widget[] } {
  const widgets: Widget[] = [];
  let total = 0;

  const visit = (doc: BsonDocument): void => {
    for (const key of Object.keys(doc)) {
      const value = doc[key];
      if (Array.isArray(value)) {
        for (const item of value) {
          if (!item || typeof item !== 'object' || Array.isArray(item) || item instanceof Uint8Array) {
            continue;
          }
          if (key === 'Widgets') {
            total++;
            if (widgets.length < MAX_WIDGETS_RETAINED) widgets.push(toWidget(item));
          }
          visit(item);
        }
      } else if (value && typeof value === 'object' && !(value instanceof Uint8Array)) {
        visit(value);
      }
    }
  };

  visit(tree);
  return { total, widgets };
}

function toWidget(doc: BsonDocument): Widget {
  const type = elementType(doc) ?? 'Unknown';
  return {
    id: elementId(doc) ?? '',
    // `Forms$ActionButton` reads better as `ActionButton` in a report.
    type: type.includes('$') ? type.slice(type.indexOf('$') + 1) : type,
    name: str(doc, 'Name') || undefined,
    dataSource: dataSourceOf(doc),
    actionName: elementType(subDoc(doc, 'Action')),
  };
}

function dataSourceOf(doc: BsonDocument): string | undefined {
  const dataSource = subDoc(doc, 'DataSource');
  if (!dataSource) return undefined;
  return (
    str(dataSource, 'Entity') ??
    str(dataSource, 'EntityRef') ??
    str(dataSource, 'Microflow') ??
    elementType(dataSource)
  );
}

/** Pages that are reachable without authenticating. */
export function anonymouslyReachablePages(pages: Record<string, Page>): Page[] {
  return Object.values(pages).filter((p) => p.isAccessibleAnonymously);
}

/** Pages with no allowed module roles at all: unreachable by any authenticated user. */
export function pagesWithoutRoles(pages: Record<string, Page>): Page[] {
  return Object.values(pages).filter((p) => p.allowedRoles.length === 0);
}
