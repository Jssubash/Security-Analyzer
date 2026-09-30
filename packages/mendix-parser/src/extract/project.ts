/**
 * Extract project-level facts: the Mendix version, the module inventory, and navigation.
 *
 * The version is the one correction here that changes every other answer. The old parser
 * guessed it from directory names and `.mpr` file size, so a rule that says "this setting
 * only exists from 9.6" had nothing trustworthy to test. `_MetaData._ProductVersion` in the
 * `.mpr` is what Studio Pro itself writes, so it is read from there and reported as unknown
 * when absent rather than defaulted to a plausible-looking number.
 *
 * Module classification is likewise a model fact (`FromAppStore`), which is what lets the
 * rules distinguish a finding the team can fix from one inside a marketplace module.
 */

import type { Module, ProjectType } from '@mendix-analyzer/application-ir';

import { str, subDoc, walkDocuments, elementType } from '../bson/accessors.js';
import type { ModelGraph } from '../model/model-graph.js';
import { analyzed } from './types.js';
import type { Extraction } from './types.js';

const NAVIGATION_TYPE = 'Navigation$NavigationDocument';
const SETTINGS_TYPE = 'Settings$ProjectSettings';

/** A navigation profile, and the page it opens on. */
export interface NavigationProfile {
  name: string;
  /** `Responsive`, `Tablet`, `Phone`, `NativePhone`, … */
  kind?: string;
  /** Qualified page name, when the home page is a page rather than a microflow. */
  homePage?: string;
  /** Qualified microflow name, when the home "page" is a microflow. */
  homeMicroflow?: string;
}

export interface ProjectExtraction {
  /** From `_MetaData._ProductVersion`; `'unknown'` when the `.mpr` could not be read. */
  mendixVersion: string;
  /** From `Settings$ModelSettings.JavaMajorVersion`. */
  javaVersion?: string;
  applicationType: ProjectType;
  modules: Extraction<Record<string, Module>>;
  navigation: Extraction<NavigationProfile[]>;
}

/** The document lists a module owns, so `Module` can be filled without a second walk. */
export interface ModuleContents {
  entities: Map<string, string[]>;
  microflows: Map<string, string[]>;
  nanoflows: Map<string, string[]>;
  pages: Map<string, string[]>;
}

/** The qualified names of every page a navigation profile opens on. */
export function navigationHomePages(profiles: readonly NavigationProfile[]): Set<string> {
  return new Set(profiles.map((p) => p.homePage).filter((p): p is string => !!p));
}

export function extractProject(
  graph: ModelGraph,
  contents: ModuleContents,
  navigation: Extraction<NavigationProfile[]>
): ProjectExtraction {
  const notes: string[] = [];
  const version = graph.mprMetadata.productVersion;
  if (!version) {
    notes.push(
      'the Mendix product version could not be read from the .mpr metadata, so version-' +
        'dependent conclusions were not drawn'
    );
  }

  const modules: Record<string, Module> = {};
  for (const info of graph.modules) {
    modules[info.name] = {
      name: info.name,
      type: info.origin,
      isSystem: info.origin === 'system',
      isMarketplace: info.origin === 'marketplace',
      entities: contents.entities.get(info.name) ?? [],
      microflows: contents.microflows.get(info.name) ?? [],
      nanoflows: contents.nanoflows.get(info.name) ?? [],
      pages: contents.pages.get(info.name) ?? [],
      // Cross-module dependencies need the microflow call graph and page references, which
      // Phase 1 does not read. An empty list here is honest: it is not a claim that the
      // module depends on nothing, and no Phase 1 rule reads it.
      dependencies: [],
    };
  }
  if (Object.keys(modules).length === 0) {
    notes.push('no Projects$ModuleImpl unit was found, so the module inventory is empty');
  }

  return {
    mendixVersion: version ?? 'unknown',
    javaVersion: javaVersionOf(graph),
    applicationType: applicationTypeOf(navigation.value),
    modules: analyzed(modules, notes),
    navigation,
  };
}

export function extractNavigation(graph: ModelGraph): Extraction<NavigationProfile[]> {
  const unit = graph.units.soleUnitOfType(NAVIGATION_TYPE);
  if (!unit) {
    return analyzed([], [`no ${NAVIGATION_TYPE} unit was found, so no home page was identified`]);
  }

  const profiles: NavigationProfile[] = [];
  for (const doc of walkDocuments(unit.tree)) {
    if (elementType(doc) !== 'Navigation$NavigationProfile') continue;
    const home = subDoc(doc, 'HomePage');
    profiles.push({
      name: str(doc, 'Name') ?? str(doc, 'Kind') ?? 'Unnamed',
      kind: str(doc, 'Kind'),
      homePage: str(home, 'Page') || undefined,
      homeMicroflow: str(home, 'Microflow') || undefined,
    });
  }

  return analyzed(profiles);
}

/**
 * `JavaMajorVersion` lives on `Settings$ModelSettings`, nested inside the project settings
 * unit's `Settings` array rather than at its top level, so it is found by walking.
 */
function javaVersionOf(graph: ModelGraph): string | undefined {
  const unit = graph.units.soleUnitOfType(SETTINGS_TYPE);
  if (!unit) return undefined;
  for (const doc of walkDocuments(unit.tree)) {
    if (elementType(doc) !== 'Settings$ModelSettings') continue;
    return str(doc, 'JavaMajorVersion') || undefined;
  }
  return undefined;
}

/**
 * Infer the application type from the navigation profiles that exist.
 *
 * A native profile means the project ships a native mobile app; otherwise it is a web app.
 * This is a weaker fact than the rest of this file and no security rule depends on it.
 */
function applicationTypeOf(profiles: NavigationProfile[]): ProjectType {
  const kinds = profiles.map((p) => (p.kind ?? '').toLowerCase());
  if (kinds.some((k) => k.includes('native'))) return 'native';
  if (kinds.some((k) => k.includes('progressive') || k.includes('pwa'))) return 'pwa';
  return 'web';
}
