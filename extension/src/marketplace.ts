/**
 * The Upgrades tab: which Marketplace modules and widgets the app uses, and which version of each
 * suits the app's Mendix version — or a version the team is about to move to.
 *
 * What the model records:
 *
 * - A Marketplace **module** carries its content id (`AppStorePackageId`, e.g. 170 for Community
 *   Commons) and the version installed (`AppStoreVersion`). That identifies it exactly.
 * - A **widget** package (`widgets/*.mpk`) carries only its own name and version. Many widgets
 *   are not installed on their own at all but ship inside a module — the Data Widgets module
 *   brings the Datagrid family, Native Mobile Resources brings every native widget — and are
 *   updated by updating that module. The rest are matched to the Marketplace catalog by name.
 *
 * What the Marketplace says (Content API, needs a Personal Access Token): every published version
 * of an item and the minimum Mendix version it supports. There is no maximum, so "the newest
 * version whose minimum is at or below the target" is the version to use, and a version built for
 * an older major Mendix line is called out for review when the app moves to a newer one.
 */

import type { ModelSnapshot } from './snapshot/types.js';
import { compareVersions, toVulnerability } from './java-libraries.js';
import type { LibraryVulnerability, OsvCheckResult } from './java-libraries.js';

export type ItemKind = 'module' | 'widget';

export interface MarketplaceItem {
  /** `module:<name>` or `widget:<fileName>`. */
  key: string;
  kind: ItemKind;
  name: string;
  installedVersion?: string;
  /** Marketplace content id: recorded for modules, matched for widgets. */
  contentId?: number;
  /** How the content id was found. */
  identifiedBy: 'recorded' | 'catalog' | 'bundled' | 'none';
  /** For a widget shipped inside a module: that module's name. */
  bundledWith?: string;
  /** For a widget shipped inside a module: the module's installed version, which is what updates. */
  moduleVersion?: string;
  /**
   * Widgets: the namespace its widget ids share (`vendor.widget.native.barchart.BarChart` →
   * `vendor.widget.native`). Widgets with the same namespace are shown as one family.
   */
  family?: string;
  isThemeModule?: boolean;
  /** Widget packages: the widget ids inside, and the platforms they target. */
  widgetIds: string[];
  platforms: string[];
  fileName?: string;
  /**
   * Widgets: the npm libraries listed in the package. `transitive` ones are pulled in by another
   * dependency — for native widgets that includes the whole build toolchain — so they are reported
   * separately and do not count towards a widget being vulnerable.
   */
  dependencies: { name: string; version: string; transitive?: boolean }[];
  /**
   * Widgets: the pages, snippets and layouts that place any of its widget ids. Empty when the app
   * places none of them; `undefined` when the snapshot does not say (an older host).
   */
  usedIn?: string[];
}

export interface UpgradeInventory {
  /** The app's Mendix version, `major.minor.patch`, from the Studio Pro hosting it. */
  mendixVersion?: string;
  modules: MarketplaceItem[];
  widgets: MarketplaceItem[];
  /** False when the snapshot came from a host that predates this tab. */
  scanned: boolean;
  notes: string[];
}

const normalise = (s: string | null | undefined) => (s ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');

export function mendixVersionOf(snapshot: ModelSnapshot): string | undefined {
  const raw = snapshot.app.studioProVersion;
  const m = raw ? /^(\d+)\.(\d+)\.(\d+)/.exec(raw) : null;
  return m ? `${m[1]}.${m[2]}.${m[3]}` : undefined;
}

export function buildUpgradeInventory(snapshot: ModelSnapshot): UpgradeInventory {
  const notes: string[] = [];
  const modules: MarketplaceItem[] = snapshot.modules
    .filter((m) => m.fromAppStore)
    .map((m) => ({
      key: `module:${m.name}`,
      kind: 'module' as const,
      name: m.name,
      installedVersion: m.appStoreVersion ?? undefined,
      contentId: m.appStorePackageId ?? undefined,
      identifiedBy: m.appStorePackageId ? ('recorded' as const) : ('none' as const),
      isThemeModule: m.isThemeModule ?? undefined,
      widgetIds: [],
      platforms: [],
      dependencies: [],
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const hasRecordedVersions = snapshot.modules.some((m) => m.appStorePackageId !== undefined);
  if (modules.length > 0 && !hasRecordedVersions) {
    notes.push('This snapshot does not include Marketplace content ids (it was taken by an older version of the extension). Run the analysis again.');
  }

  const byName = new Map(modules.map((m) => [normalise(m.name), m]));
  // Widget ids are matched without case: a package's XML and the page model spell them alike in
  // practice, but nothing requires it.
  const usage = snapshot.widgetUsage
    ? new Map(Object.entries(snapshot.widgetUsage).map(([id, docs]) => [id.toLowerCase(), docs]))
    : undefined;
  const widgets: MarketplaceItem[] = (snapshot.widgets?.packages ?? []).map((p) => {
    const ids = (p.widgets ?? []).map((w) => w.id);
    const usedIn = usage ? [...new Set(ids.flatMap((id) => usage.get(id.toLowerCase()) ?? []))].sort() : undefined;
    const platforms = [...new Set((p.widgets ?? []).map((w) => w.supportedPlatform || 'Web'))];
    const item: MarketplaceItem = {
      key: `widget:${p.fileName}`,
      kind: 'widget',
      name: p.widgets?.[0]?.name || p.name || p.fileName.replace(/\.mpk$/i, ''),
      installedVersion: p.version ?? undefined,
      identifiedBy: 'none',
      widgetIds: ids,
      platforms,
      fileName: p.fileName,
      dependencies: p.dependencies ?? [],
      usedIn,
      family: widgetFamily(ids),
    };
    const owner = bundlingModule(p.name ?? undefined, p.version ?? undefined, ids, byName);
    if (owner) {
      item.bundledWith = owner.name;
      item.moduleVersion = owner.installedVersion;
      item.contentId = owner.contentId;
      item.identifiedBy = 'bundled';
    }
    return item;
  });
  widgets.sort((a, b) => a.name.localeCompare(b.name));

  if (!snapshot.widgets) notes.push('This snapshot has no widget inventory (it was taken by an older version of the extension).');
  return {
    mendixVersion: mendixVersionOf(snapshot),
    modules,
    widgets,
    scanned: snapshot.widgets?.scanned ?? false,
    notes,
  };
}

/** The installed module a widget package ships with, if it is one of a module's own widgets. */
/**
 * The namespace a package's widget ids share: the id without its widget name and, when it repeats
 * that name, the package segment (`vendor.widget.native.barchart.BarChart` → `vendor.widget.native`).
 * Read from the package itself, so it works for any vendor's widgets.
 */
function widgetFamily(ids: string[]): string | undefined {
  const spaces = ids.map((id) => {
    const parts = id.split('.');
    const name = parts.pop() ?? '';
    if (parts.length > 0 && parts[parts.length - 1]!.toLowerCase() === name.toLowerCase()) parts.pop();
    return parts.join('.');
  });
  const first = spaces[0];
  return first && spaces.every((s) => s === first) ? first : undefined;
}

/**
 * The module that installed a widget, when the model shows it: a Marketplace module of the same
 * name at the same version (module X 2.2.1 → widget X 2.2.1). Mendix records no other link between
 * a module and the widget packages its import wrote, so nothing else is assumed.
 */
function bundlingModule(
  packageName: string | undefined,
  version: string | undefined,
  _ids: string[],
  modules: Map<string, MarketplaceItem>
): MarketplaceItem | undefined {
  const same = modules.get(normalise(packageName));
  if (same && version && same.installedVersion === version) return same;
  return undefined;
}

// ====================================================================== Marketplace answers

export interface MarketplaceVersion {
  versionNumber: string;
  minSupportedMendixVersion?: string;
  publicationDate?: string;
}

export interface CatalogEntry {
  contentId: number;
  name?: string;
  type?: string;
  publisher?: string;
  supportCategory?: string;
  latestVersion?: string;
  latestMinMendix?: string;
}

export interface MarketplaceAnswer {
  checkedAt: string;
  versions: Record<string, MarketplaceVersion[]>;
  failures?: Record<string, string>;
  catalog?: CatalogEntry[];
}

/** Content ids the host should fetch version lists for. */
export function contentIdsToCheck(inventory: UpgradeInventory, widgetMatches: Record<string, number> = {}): number[] {
  const ids = new Set<number>();
  for (const m of inventory.modules) if (m.contentId) ids.add(m.contentId);
  for (const id of Object.values(widgetMatches)) ids.add(id);
  return [...ids].sort((a, b) => a - b);
}

/**
 * Widgets that ship on their own, matched to catalog widgets by name. A name that matches more
 * than one entry is left unmatched rather than guessed.
 */
export function matchWidgets(inventory: UpgradeInventory, catalog: CatalogEntry[]): Record<string, number> {
  const widgets = catalog.filter((c) => /widget/i.test(c.type ?? ''));
  const index = new Map<string, CatalogEntry[]>();
  for (const c of widgets) {
    const key = normalise(c.name);
    if (key) index.set(key, [...(index.get(key) ?? []), c]);
  }
  const matches: Record<string, number> = {};
  for (const w of inventory.widgets) {
    if (w.bundledWith) continue;
    const names = [w.name, w.fileName?.replace(/\.mpk$/i, '').split('.').pop(), ...w.widgetIds.map((id) => id.split('.').pop())];
    let candidates: CatalogEntry[] = [];
    for (const n of names) {
      candidates = index.get(normalise(n)) ?? [];
      if (candidates.length > 0) break;
    }
    if (candidates.length === 1) matches[w.key] = candidates[0]!.contentId;
  }
  return matches;
}

// ====================================================================== assessment

export type UpgradeStatus =
  | 'up-to-date'
  | 'update-available'
  | 'update-recommended'
  | 'incompatible'
  | 'no-compatible'
  | 'not-found'
  | 'not-checked';

export interface ItemAssessment {
  status: UpgradeStatus;
  /** The newest version that supports the target Mendix version. */
  recommended?: MarketplaceVersion;
  /** The newest version published, whatever it needs. */
  latest?: MarketplaceVersion;
  /** The installed version as the Marketplace lists it, if it still does. */
  installed?: MarketplaceVersion;
  /** In a sentence, what this means. */
  note: string;
}

const majorOf = (v: string | undefined) => (v ? Number(v.split('.')[0]) : NaN);

/** At or below: `minSupportedMendixVersion` 10.24.0 suits a 10.24.3 app. */
const supports = (v: MarketplaceVersion, target: string) => !v.minSupportedMendixVersion || compareVersions(v.minSupportedMendixVersion, target) <= 0;

/** What is known about a widget the Marketplace does not list under its own name. */
const NOT_ON_ITS_OWN =
  'Not on the Marketplace on its own: probably installed by a Marketplace module (update the module that installed it to update this widget), or a custom or private widget (check it with its author).';

export function assessItem(item: MarketplaceItem, versions: MarketplaceVersion[] | undefined, target: string | undefined): ItemAssessment {
  if (!item.contentId) {
    return {
      status: 'not-found',
      note:
        item.kind === 'module'
          ? 'The model records no Marketplace content id for this module (installed by hand, or by a very old Studio Pro).'
          : NOT_ON_ITS_OWN,
    };
  }
  if (!versions) return { status: 'not-checked', note: 'Not checked against the Marketplace yet.' };
  if (versions.length === 0) {
    return { status: 'not-found', note: 'The Marketplace lists no versions for this item (it may be private or withdrawn).' };
  }
  if (!target) return { status: 'not-checked', note: 'The Mendix version of the app is unknown.' };

  const sorted = [...versions].sort((a, b) => compareVersions(b.versionNumber, a.versionNumber));
  const latest = sorted[0];
  // A widget matched by name whose every Marketplace release is older than the installed one, and
  // none equal to it, is a different item that happens to share the name.
  if (
    item.kind === 'widget' &&
    item.installedVersion &&
    latest &&
    !sorted.some((v) => v.versionNumber === item.installedVersion) &&
    compareVersions(latest.versionNumber, item.installedVersion) < 0
  ) {
    return {
      status: 'not-found',
      note: `The Marketplace item with this name stops at ${latest.versionNumber}, below the installed ${item.installedVersion}, so it is a different item. ${NOT_ON_ITS_OWN}`,
    };
  }
  const recommended = sorted.find((v) => supports(v, target));
  const installed = item.installedVersion ? sorted.find((v) => v.versionNumber === item.installedVersion) : undefined;
  const needs = (v: MarketplaceVersion | undefined) => (v?.minSupportedMendixVersion ? ` (needs Mendix ${v.minSupportedMendixVersion})` : '');
  const newerThanRecommended =
    latest && recommended && latest.versionNumber !== recommended.versionNumber ? ` Version ${latest.versionNumber} is newer but needs Mendix ${latest.minSupportedMendixVersion}.` : '';

  // A history that stops short of the installed version is incomplete, not proof that nothing fits:
  // the installed version is running on this app, so something older than every listed version exists.
  const oldest = sorted[sorted.length - 1];
  const historyIncomplete =
    item.installedVersion !== undefined && !installed && oldest !== undefined && compareVersions(item.installedVersion, oldest.versionNumber) < 0;
  if (!recommended && historyIncomplete) {
    return {
      status: 'not-checked',
      latest,
      note: `The Marketplace returned only part of the version history (back to ${oldest.versionNumber}), which does not reach the installed ${item.installedVersion}. Check again; if this persists, look the item up on the Marketplace.`,
    };
  }
  if (!recommended) {
    return {
      status: 'no-compatible',
      latest,
      installed,
      note: `No published version supports Mendix ${target}; the oldest needs ${sorted[sorted.length - 1]?.minSupportedMendixVersion ?? 'a newer version'}.`,
    };
  }
  if (installed && !supports(installed, target)) {
    return {
      status: 'incompatible',
      recommended,
      latest,
      installed,
      note: `The installed ${installed.versionNumber} needs Mendix ${installed.minSupportedMendixVersion}, newer than ${target}. Use ${recommended.versionNumber}${needs(recommended)}, or move the app to Mendix ${installed.minSupportedMendixVersion} or later.`,
    };
  }
  const current = item.installedVersion;
  const behind = current ? compareVersions(recommended.versionNumber, current) > 0 : true;
  const builtForOlderLine =
    installed?.minSupportedMendixVersion !== undefined &&
    majorOf(installed.minSupportedMendixVersion) < majorOf(target) &&
    majorOf(recommended.minSupportedMendixVersion) === majorOf(target);

  if (behind && builtForOlderLine) {
    return {
      status: 'update-recommended',
      recommended,
      latest,
      installed,
      note: `The installed ${current} was built for Mendix ${installed!.minSupportedMendixVersion}. For Mendix ${target}, move to ${recommended.versionNumber}, built for Mendix ${recommended.minSupportedMendixVersion}.${newerThanRecommended}`,
    };
  }
  if (behind) {
    return {
      status: 'update-available',
      recommended,
      latest,
      installed,
      note: `${recommended.versionNumber}${needs(recommended)} is the newest version for Mendix ${target}${current ? `; ${current} is installed` : ''}.${newerThanRecommended}`,
    };
  }
  const unlisted = current && !installed ? ` The installed ${current} is no longer listed on the Marketplace.` : '';
  return {
    status: 'up-to-date',
    recommended,
    latest,
    installed,
    note: `${current ?? recommended.versionNumber} is the newest version for Mendix ${target}.${newerThanRecommended}${unlisted}`,
  };
}

/** A widget shipped inside a module follows that module's verdict. */
export function assessWidget(widget: MarketplaceItem, own: ItemAssessment, owner: ItemAssessment | undefined): ItemAssessment {
  if (!widget.bundledWith) return own;
  if (!owner || owner.status === 'not-checked') {
    return { status: 'not-checked', note: `Ships with the ${widget.bundledWith} module; it is updated by updating that module.` };
  }
  return {
    ...owner,
    note: `Ships with the ${widget.bundledWith} module and is updated with it. ${owner.note}`,
  };
}


export function isMendixVersion(value: string): boolean {
  return /^\d+\.\d+(\.\d+)?$/.test(value.trim());
}

export function normaliseMendixVersion(value: string): string {
  const parts = value.trim().split('.');
  while (parts.length < 3) parts.push('0');
  return parts.slice(0, 3).join('.');
}

// ====================================================================== widget vulnerabilities

/**
 * The npm libraries bundled into the app's widgets, once each. Mendix's own internal helper
 * packages (`@mendix/piw-*`, `@mendix/widget-plugin-*`, the build tools) are not published to npm,
 * so they are left out rather than looked up and silently found clean.
 */
export function widgetPackagesToCheck(inventory: UpgradeInventory): { name: string; version: string; ecosystem: 'npm' }[] {
  const seen = new Set<string>();
  const out: { name: string; version: string; ecosystem: 'npm' }[] = [];
  for (const w of inventory.widgets) {
    for (const d of w.dependencies) {
      if (isInternalMendixPackage(d.name)) continue;
      const key = `${d.name}@${d.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name: d.name, version: d.version, ecosystem: 'npm' });
    }
  }
  return out;
}

export function isInternalMendixPackage(name: string): boolean {
  return /^@mendix\/(piw-|widget-plugin-|pluggable-widgets-tools|shared-)/.test(name);
}

export interface WidgetVulnerabilityReport {
  checkedAt: string;
  /** Widget key → vulnerabilities in its direct libraries, worst first; [] when checked and clean. */
  byWidget: Record<string, LibraryVulnerability[]>;
  /** Widget key → vulnerabilities only in indirect libraries (may be build-time only); not counted. */
  indirectByWidget: Record<string, LibraryVulnerability[]>;
  /** Widgets that list no bundled libraries, so there was nothing to look up. */
  unchecked: string[];
}

const SEVERITY_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };

export function applyWidgetOsv(inventory: UpgradeInventory, osv: OsvCheckResult): WidgetVulnerabilityReport {
  const answers = new Map(osv.results.map((r) => [`${r.name}@${r.version}`, r.ids]));
  const byWidget: Record<string, LibraryVulnerability[]> = {};
  const indirectByWidget: Record<string, LibraryVulnerability[]> = {};
  const unchecked: string[] = [];
  const sort = (list: LibraryVulnerability[]) =>
    list.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) || (b.score ?? 0) - (a.score ?? 0) || a.id.localeCompare(b.id));
  for (const w of inventory.widgets) {
    const deps = w.dependencies.filter((d) => !isInternalMendixPackage(d.name));
    if (deps.length === 0 || !deps.some((d) => answers.has(`${d.name}@${d.version}`))) {
      unchecked.push(w.key);
      continue;
    }
    const direct = new Map<string, LibraryVulnerability>();
    const indirect = new Map<string, LibraryVulnerability>();
    for (const d of deps) {
      for (const id of answers.get(`${d.name}@${d.version}`) ?? []) {
        const advisory = osv.vulns[id];
        if (!advisory) continue;
        const into = d.transitive ? indirect : direct;
        if (!into.has(id)) into.set(id, toVulnerability(advisory, d.name, d.version, true));
      }
    }
    for (const id of direct.keys()) indirect.delete(id);
    byWidget[w.key] = sort([...direct.values()]);
    if (indirect.size > 0) indirectByWidget[w.key] = sort([...indirect.values()]);
  }
  return { checkedAt: osv.checkedAt, byWidget, indirectByWidget, unchecked };
}

/**
 * The secure version to move to, for the Mendix version the app runs on (or the planned one).
 * The fix for a library bundled into a widget is a widget release that bundles a fixed copy: the
 * newest Marketplace release for the target Mendix version is the candidate, and its release notes
 * confirm the library version, since the Marketplace does not publish bundled-library lists.
 */
export function widgetSecurityAdvice(
  widget: MarketplaceItem,
  vulns: LibraryVulnerability[],
  assessment: ItemAssessment,
  target: string | undefined
): string {
  const libs = [...new Set(vulns.map((v) => `${v.package} ${v.version}${v.fixedIn ? ` (fixed in ${v.fixedIn})` : ''}`))].join(', ');
  const forTarget = target ? `Mendix ${target}` : 'this Mendix version';
  const owner = widget.bundledWith ? `the ${widget.bundledWith} module` : widget.name;
  const rec = assessment.recommended;
  const latest = assessment.latest;
  const confirm = 'Confirm in its release notes that it ships the fixed library version.';


  if (assessment.status === 'not-checked' || assessment.status === 'not-found' || !rec) {
    return `The vulnerable code is in ${libs}, bundled into this widget. ${
      assessment.status === 'not-found'
        ? 'The widget is not on the Marketplace on its own. If a Marketplace module installed it, a newer release of that module is the fix; otherwise ask its author for a release with a fixed copy, or replace the widget. Delete the package if the app does not use it.'
        : 'Check the Marketplace (above) to find the release to move to for ' + forTarget + '.'
    }`;
  }
  // A bundled widget is updated through its module, so its module's version is the one to compare.
  const current = widget.bundledWith ? widget.moduleVersion : widget.installedVersion;
  const installedLabel = widget.bundledWith ? `${widget.bundledWith} ${current ?? ''}`.trim() : `${widget.name} ${current ?? ''}`.trim();
  if (current && compareVersions(rec.versionNumber, current) > 0) {
    return `Update ${owner} to ${rec.versionNumber}, the newest release for ${forTarget}, which may bundle a fixed copy of ${libs}. ${confirm}`;
  }
  if (latest && compareVersions(latest.versionNumber, rec.versionNumber) > 0) {
    return `The installed ${installedLabel} is already the newest release for ${forTarget}, and it still bundles ${libs}. Updating from the Marketplace will not change it. ${latest.versionNumber} is newer but needs Mendix ${latest.minSupportedMendixVersion}: plan that Mendix upgrade (and check that release's bundled libraries), or assess whether the vulnerable code path is reachable in this app.`;
  }
  return `No release of ${owner} ships a newer copy yet (the installed ${installedLabel} is the latest). Track the advisory, and assess whether the vulnerable code path is reachable in this app until a fixed release is published.`;
}
