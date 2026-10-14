/**
 * The Java libraries tab: which jars the app ships, which module needs each one, and whether a
 * Marketplace module or the team's own code is responsible for it.
 *
 * Where jars come from in a Mendix app:
 *
 * - `vendorlib/` — managed dependencies (Studio Pro 10.3+). A module declares Maven coordinates in
 *   its settings (`Projects$ModuleSettings.JarDependencies`); Studio Pro resolves them, with their
 *   transitive dependencies, into `vendorlib/` and writes a CycloneDX SBOM recording the graph.
 *   Walking that graph from each module's declarations says which module pulled in which jar.
 * - `userlib/` — jars placed by hand or by modules that predate managed dependencies. Such a
 *   module marks each jar it needs with an empty `<jar>.<Module>.RequiredLib` file.
 *
 * A jar is **Marketplace** when a Marketplace module needs it — the team does not choose its
 * version, the module does — and **custom** otherwise: declared by the team's own module, dropped
 * into `userlib/` by hand, or left behind by a module that is gone.
 */

import type { ModuleType } from '@mendix-analyzer/application-ir';

import { bool, children, isKind, str } from './snapshot/accessors.js';
import type { JarFileFacts, JavaLibrariesSnapshot, ModelSnapshot } from './snapshot/types.js';

export interface MavenCoordinates {
  group?: string;
  artifact: string;
  version?: string;
}

export type IdentifiedBy = 'sbom' | 'pom' | 'manifest' | 'file name' | 'unknown';
export type LibraryOrigin = 'marketplace' | 'custom';

export interface LibraryRequirement {
  module: string;
  /** `missing` when the module named by a marker is no longer in the app. */
  moduleType: ModuleType | 'missing';
  /** Declared by the module itself, rather than reached through another library. */
  direct: boolean;
  /** For a transitive dependency: the `group:artifact` the module declared that brought it in. */
  via?: string;
  /** The module's Settings unit, which holds its Java Dependencies — what "Open in Studio Pro" opens. */
  settingsUnitId?: string;
  /** The version in the module's Java Dependencies row: of this library when direct, of `via` otherwise. */
  declaredVersion?: string;
  /** The exclusions on that row, as `group:artifact`, which must survive a version change. */
  exclusions?: string[];
}

export interface JavaLibrary {
  /** `folder/fileName`, unique within the app. */
  key: string;
  folder: 'userlib' | 'vendorlib';
  fileName: string;
  sizeBytes: number;
  coordinates?: MavenCoordinates;
  identifiedBy: IdentifiedBy;
  /** Libraries shaded (copied) inside this jar, from their own pom.properties. */
  bundled: MavenCoordinates[];
  requiredBy: LibraryRequirement[];
  origin: LibraryOrigin;
  /** Why the library is in its group, in a sentence. */
  originReason: string;
  /** Versions of the other copies of this library (same name) in the app; see `duplicates`. */
  otherVersions: string[];
  /** The duplicate group this jar belongs to, by {@link DuplicateGroup.name}, if any. */
  duplicateOf?: string;
  nestedJars?: number;
  unreadable?: string;
}

/**
 * Two or more jars of the same library. They are matched by **name** — the Maven artifact id, or
 * the file name without its version — never by version: `commons-io-2.3.4.jar` and
 * `commons-io-3.4.5.jar` are the same library, and only one copy is loaded at run time, so the
 * team has to choose which version the app uses.
 */
export interface DuplicateGroup {
  /** The library name the copies share, e.g. `commons-io`. */
  name: string;
  /** Library keys (`folder/fileName`), newest version first. */
  libraries: string[];
  /** Distinct versions present, newest first. */
  versions: string[];
  /** The newest version present, when versions are known. */
  newest?: string;
  /** `versions`: different versions; `copies`: the same version more than once. */
  kind: 'versions' | 'copies';
  /** Maven groups seen. More than one means different publishers — confirm they are the same library. */
  groups: string[];
  /** Copies owned by a Marketplace module, whose version the team does not choose. */
  marketplaceCopies: string[];
}

export interface JavaLibraryReport {
  /** False when the host predates this tab or could not find the app directory. */
  scanned: boolean;
  libraries: JavaLibrary[];
  /** Libraries present more than once, by name. */
  duplicates: DuplicateGroup[];
  notes: string[];
}

export function gaOf(c: MavenCoordinates | undefined): string | undefined {
  return c?.group ? `${c.group}:${c.artifact}` : undefined;
}

/** Whether OSV can be asked about this exact library: it needs group, artifact and version. */
export function isCheckable(c: MavenCoordinates | undefined): c is Required<MavenCoordinates> {
  return Boolean(c?.group && c.artifact && c.version);
}

// ====================================================================== inventory

interface DeclaredDependency {
  module: string;
  group: string;
  artifact: string;
  version?: string;
  settingsUnitId?: string;
  exclusions: string[];
}

/** The parts of a declaration a requirement carries, so the UI can name the row to edit. */
function rowFacts(dep: DeclaredDependency): Pick<LibraryRequirement, 'settingsUnitId' | 'declaredVersion' | 'exclusions'> {
  return { settingsUnitId: dep.settingsUnitId, declaredVersion: dep.version, exclusions: dep.exclusions };
}

export function buildJavaLibraryReport(
  snapshot: ModelSnapshot,
  moduleTypes: Record<string, ModuleType>
): JavaLibraryReport {
  const facts: JavaLibrariesSnapshot | undefined = snapshot.javaLibraries;
  if (!facts) {
    return {
      scanned: false,
      libraries: [],
      duplicates: [],
      notes: ['This snapshot has no Java library inventory (it was taken by an older version of the extension).'],
    };
  }
  if (!facts.scanned) {
    return { scanned: false, libraries: [], duplicates: [], notes: ['The app directory could not be determined, so userlib and vendorlib were not scanned.'] };
  }

  const declared = declaredDependencies(snapshot);
  const sbom = facts.sbom;
  const components = (sbom?.components ?? []).filter((c) => c.ref && c.name);
  const byRef = new Map(components.map((c) => [c.ref!, c]));
  const reach = reachFromDeclarations(declared, sbom, moduleTypes);
  const notes: string[] = [];

  const libraries: JavaLibrary[] = facts.jars.map((jar) => {
    const { coordinates, identifiedBy, sbomRef } = identify(jar, components);
    const bundled = bundledLibraries(jar, coordinates);

    let requiredBy: LibraryRequirement[] = [];
    if (jar.folder === 'vendorlib') {
      if (sbomRef) requiredBy = reach.get(sbomRef) ?? [];
      // Without an SBOM only direct declarations can be matched, by coordinates.
      if (!sbom && coordinates) {
        requiredBy = declared
          .filter((d) => d.group === coordinates.group && d.artifact === coordinates.artifact)
          .map((d) => ({ module: d.module, moduleType: moduleTypes[d.module] ?? 'missing', direct: true, ...rowFacts(d) }));
      }
    } else {
      requiredBy = facts.requiredLibMarkers
        .filter((m) => m.jarFileName.toLowerCase() === jar.fileName.toLowerCase())
        .map((m) => ({ module: m.module, moduleType: moduleTypes[m.module] ?? 'missing', direct: true }));
    }
    requiredBy = dedupeRequirements(requiredBy);
    const { origin, reason } = classify(jar, requiredBy, Boolean(sbom));

    return {
      key: `${jar.folder}/${jar.fileName}`,
      folder: jar.folder,
      fileName: jar.fileName,
      sizeBytes: jar.sizeBytes,
      coordinates,
      identifiedBy,
      bundled,
      requiredBy,
      origin,
      originReason: reason,
      otherVersions: [],
      nestedJars: jar.nestedJars,
      unreadable: jar.unreadable,
    };
  });

  const duplicates = findDuplicates(libraries);

  if (facts.jars.some((j) => j.folder === 'vendorlib') && !sbom) {
    notes.push('vendorlib/vendorlib-sbom.json was not found, so transitive dependencies could not be traced to a module.');
  }
  for (const d of declared) {
    if (sbom && ![...byRef.values()].some((c) => c.group === d.group && c.name === d.artifact)) {
      notes.push(`${d.module} declares ${d.group}:${d.artifact}${d.version ? ` ${d.version}` : ''}, which is not in vendorlib — synchronise the app's dependencies (App ▸ Synchronize Dependencies) and run again.`);
    }
  }

  libraries.sort((a, b) => a.fileName.localeCompare(b.fileName, undefined, { sensitivity: 'base' }));
  return { scanned: true, libraries, duplicates, notes };
}

/** The name two copies of a library share: artifact id, or the file name without its version. */
export function libraryName(lib: Pick<JavaLibrary, 'coordinates' | 'fileName'>): string {
  const name = lib.coordinates?.artifact ?? parseFileName(lib.fileName)?.artifact ?? lib.fileName;
  return name.trim().toLowerCase().replace(/[\s_]+/g, '-');
}

/**
 * Groups jars by library name, ignoring version, folder and publisher. Sets `otherVersions` and
 * `duplicateOf` on each member.
 */
function findDuplicates(libraries: JavaLibrary[]): DuplicateGroup[] {
  const byName = new Map<string, JavaLibrary[]>();
  for (const lib of libraries) {
    const name = libraryName(lib);
    byName.set(name, [...(byName.get(name) ?? []), lib]);
  }
  const groups: DuplicateGroup[] = [];
  for (const [name, members] of byName) {
    if (members.length < 2) continue;
    const newestFirst = [...members].sort(
      (a, b) => compareVersions(b.coordinates?.version ?? '', a.coordinates?.version ?? '') || a.key.localeCompare(b.key)
    );
    const versions = [...new Set(newestFirst.map((l) => l.coordinates?.version).filter((v): v is string => Boolean(v)))];
    for (const lib of members) {
      lib.duplicateOf = name;
      lib.otherVersions = [...new Set(members.filter((m) => m !== lib).map((m) => m.coordinates?.version ?? 'unknown version'))]
        .filter((v) => v !== lib.coordinates?.version)
        .sort(compareVersions);
    }
    groups.push({
      name: members.find((m) => m.coordinates?.artifact)?.coordinates?.artifact ?? name,
      libraries: newestFirst.map((l) => l.key),
      versions,
      newest: versions[0],
      kind: versions.length > 1 ? 'versions' : 'copies',
      groups: [...new Set(members.map((m) => m.coordinates?.group).filter((g): g is string => Boolean(g)))].sort(),
      marketplaceCopies: members.filter((m) => m.origin === 'marketplace').map((m) => m.key),
    });
  }
  return groups.sort((a, b) => a.name.localeCompare(b.name));
}

/** What to do about a duplicate, given who owns each copy. */
export function duplicateAdvice(group: DuplicateGroup, libraries: JavaLibrary[]): string {
  const members = group.libraries.map((k) => libraries.find((l) => l.key === k)).filter((l): l is JavaLibrary => Boolean(l));
  const market = members.filter((l) => l.origin === 'marketplace');
  const custom = members.filter((l) => l.origin === 'custom');
  const label = (l: JavaLibrary) => `${l.folder}/${l.fileName}`;
  const publishers =
    group.groups.length > 1
      ? ` The copies come from different publishers (${group.groups.join(', ')}): confirm they are the same library before removing one.`
      : '';
  if (group.kind === 'copies') {
    return `The same version is present ${members.length} times (${members.map(label).join(', ')}). Keep one copy and delete the others.${publishers}`;
  }
  const head = `Only one version is loaded at run time, and which one is not defined, so the app can behave differently between deployments. Decide which version the app uses — the newest present is ${group.newest ?? 'unknown'} — and remove the others.`;
  if (market.length > 0 && custom.length > 0) {
    return `${head} ${market.map(label).join(', ')} ${market.length === 1 ? 'is' : 'are'} owned by a Marketplace module and will come back if deleted, so the usual fix is to remove the custom ${custom.length === 1 ? 'copy' : 'copies'} (${custom.map(label).join(', ')}), or update the Marketplace module if your code needs a newer version.${publishers}`;
  }
  if (market.length === members.length) {
    const modules = [...new Set(market.flatMap((l) => l.requiredBy.map((r) => r.module)))];
    return `${head} All copies are owned by Marketplace modules (${modules.join(', ')}): update the module that ships the older version rather than deleting a jar.${publishers}`;
  }
  return `${head} For a jar in userlib, delete the file (and its .RequiredLib marker); for one in vendorlib, change or remove the Java dependency in the module's settings and synchronise the dependencies.${publishers}`;
}

/** Each module's `JarDependencies`, from its `Projects$ModuleSettings` unit. */
function declaredDependencies(snapshot: ModelSnapshot): DeclaredDependency[] {
  const out: DeclaredDependency[] = [];
  for (const module of snapshot.modules) {
    for (const unit of module.units) {
      if (!isKind(unit, 'ModuleSettings')) continue;
      for (const dep of children(unit, 'jarDependencies', 'JarDependencies')) {
        if (bool(dep, 'isIncluded', 'IsIncluded') === false) continue;
        const group = str(dep, 'groupId', 'GroupId');
        const artifact = str(dep, 'artifactId', 'ArtifactId');
        if (!group || !artifact) continue;
        const exclusions = children(dep, 'exclusions', 'Exclusions')
          .map((x) => [str(x, 'groupId', 'GroupId'), str(x, 'artifactId', 'ArtifactId')].filter(Boolean).join(':'))
          .filter((x) => x.length > 0);
        out.push({ module: module.name, group, artifact, version: str(dep, 'version', 'Version'), settingsUnitId: unit.$ID, exclusions });
      }
    }
  }
  return out;
}

/** For every SBOM component, which modules reach it, and through which declared dependency. */
function reachFromDeclarations(
  declared: DeclaredDependency[],
  sbom: JavaLibrariesSnapshot['sbom'],
  moduleTypes: Record<string, ModuleType>
): Map<string, LibraryRequirement[]> {
  const reach = new Map<string, LibraryRequirement[]>();
  if (!sbom) return reach;
  const edges = new Map<string, string[]>();
  for (const d of sbom.dependencies) {
    if (d.ref) edges.set(d.ref, d.dependsOn.filter((x): x is string => typeof x === 'string'));
  }
  for (const dep of declared) {
    const roots = sbom.components.filter((c) => c.ref && c.group === dep.group && c.name === dep.artifact).map((c) => c.ref!);
    const via = `${dep.group}:${dep.artifact}`;
    const seen = new Set<string>();
    const queue = [...roots];
    while (queue.length > 0) {
      const ref = queue.shift()!;
      if (seen.has(ref)) continue;
      seen.add(ref);
      const list = reach.get(ref) ?? [];
      const direct = roots.includes(ref);
      list.push({ module: dep.module, moduleType: moduleTypes[dep.module] ?? 'missing', direct, via: direct ? undefined : via, ...rowFacts(dep) });
      reach.set(ref, list);
      queue.push(...(edges.get(ref) ?? []));
    }
  }
  return reach;
}

function dedupeRequirements(list: LibraryRequirement[]): LibraryRequirement[] {
  const byModule = new Map<string, LibraryRequirement>();
  for (const r of list) {
    const existing = byModule.get(r.module);
    // A module that declares the library directly and also reaches it transitively: direct wins.
    if (!existing || (r.direct && !existing.direct)) byModule.set(r.module, r);
  }
  return [...byModule.values()].sort((a, b) => a.module.localeCompare(b.module));
}

function identify(
  jar: JarFileFacts,
  components: NonNullable<JavaLibrariesSnapshot['sbom']>['components']
): { coordinates?: MavenCoordinates; identifiedBy: IdentifiedBy; sbomRef?: string } {
  if (jar.folder === 'vendorlib') {
    const component =
      (jar.sha256 && components.find((c) => c.sha256?.toLowerCase() === jar.sha256)) ||
      components.find((c) => `${c.name}-${c.version}.jar` === jar.fileName);
    if (component?.name) {
      return {
        coordinates: { group: component.group, artifact: component.name, version: component.version },
        identifiedBy: 'sbom',
        sbomRef: component.ref,
      };
    }
  }

  const own = ownPom(jar);
  if (own) return { coordinates: { group: own.groupId, artifact: own.artifactId, version: own.version }, identifiedBy: 'pom' };

  const fromName = parseFileName(jar.fileName);
  const manifest = jar.manifest ?? {};
  const manifestVersion = manifest['Bundle-Version'] ?? manifest['Implementation-Version'];
  const vendorId = manifest['Implementation-Vendor-Id'];
  if (vendorId && fromName) {
    return { coordinates: { group: vendorId, artifact: fromName.artifact, version: fromName.version ?? manifestVersion }, identifiedBy: 'manifest' };
  }
  if (fromName) return { coordinates: { artifact: fromName.artifact, version: fromName.version ?? manifestVersion }, identifiedBy: 'file name' };
  return { identifiedBy: 'unknown' };
}

/** The jar's own pom.properties, as opposed to those of libraries shaded into it. */
function ownPom(jar: JarFileFacts) {
  const poms = (jar.pomProperties ?? []).filter((p) => p.artifactId);
  const name = jar.fileName.toLowerCase();
  return (
    poms.find((p) => p.version && name.startsWith(`${p.artifactId}-${p.version}`.toLowerCase())) ??
    poms.find((p) => name.startsWith(`${p.artifactId}-`.toLowerCase()) || name === `${p.artifactId}.jar`.toLowerCase()) ??
    (poms.length === 1 ? poms[0] : undefined)
  );
}

function bundledLibraries(jar: JarFileFacts, own: MavenCoordinates | undefined): MavenCoordinates[] {
  const seen = new Set<string>();
  const out: MavenCoordinates[] = [];
  for (const p of jar.pomProperties ?? []) {
    if (own && p.artifactId === own.artifact && (!own.group || p.groupId === own.group)) continue;
    const key = `${p.groupId}:${p.artifactId}:${p.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ group: p.groupId, artifact: p.artifactId, version: p.version });
  }
  return out;
}

/** `commons-text-1.10.0.jar` → `{ artifact: 'commons-text', version: '1.10.0' }`. */
export function parseFileName(fileName: string): { artifact: string; version?: string } | undefined {
  const stem = fileName.replace(/\.jar$/i, '');
  if (!stem) return undefined;
  // `commons-io-2.11.0`, and the occasional `commons_io_2.11.0` or `commons-io 2.11.0`.
  const m = /^(.+?)[-_ ](\d[\w.+-]*)$/.exec(stem);
  return m ? { artifact: m[1]!, version: m[2] } : { artifact: stem };
}

function classify(
  jar: JarFileFacts,
  requiredBy: LibraryRequirement[],
  hasSbom: boolean
): { origin: LibraryOrigin; reason: string } {
  const names = (list: LibraryRequirement[]) => list.map((r) => r.module).join(', ');
  const market = requiredBy.filter((r) => r.moduleType === 'marketplace' || r.moduleType === 'system');
  const own = requiredBy.filter((r) => r.moduleType === 'user');
  const gone = requiredBy.filter((r) => r.moduleType === 'missing');

  if (market.length > 0) {
    const also = own.length > 0 ? ` Also used by your module${own.length === 1 ? '' : 's'} ${names(own)}.` : '';
    const how = market.every((r) => r.direct) ? 'Required by' : 'Pulled in for';
    return { origin: 'marketplace', reason: `${how} Marketplace module${market.length === 1 ? '' : 's'} ${names(market)}.${also}` };
  }
  if (own.length > 0) {
    const direct = own.filter((r) => r.direct);
    if (direct.length > 0) {
      return { origin: 'custom', reason: `Declared by your module${direct.length === 1 ? '' : 's'} ${names(direct)}.` };
    }
    const via = [...new Set(own.map((r) => r.via).filter(Boolean))].join(', ');
    return { origin: 'custom', reason: `A dependency of ${via}, declared by your module${own.length === 1 ? '' : 's'} ${names(own)}.` };
  }
  if (gone.length > 0) {
    return {
      origin: 'custom',
      reason: `Claimed by ${names(gone)}, which ${gone.length === 1 ? 'is' : 'are'} no longer in the app — probably left behind when the module was removed.`,
    };
  }
  if (jar.folder === 'userlib') {
    return { origin: 'custom', reason: 'Added to userlib by hand: no module claims it with a .RequiredLib marker.' };
  }
  return {
    origin: 'custom',
    reason: hasSbom
      ? "In vendorlib but not reached from any module's Java dependencies."
      : "In vendorlib, but without the SBOM it could not be traced to a module's Java dependencies.",
  };
}

// ====================================================================== vulnerabilities

export type VulnerabilitySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown';

/** An OSV advisory as the host trims it (see OsvClient.cs). */
export interface OsvAdvisory {
  id: string;
  modified?: string;
  published?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  databaseSeverity?: string;
  cwes?: string[];
  affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { type?: string; events?: Record<string, string>[] }[] }[];
  references?: string[];
}

export interface OsvCheckResult {
  source: string;
  checkedAt: string;
  results: { name: string; version: string; ecosystem?: string; ids: string[] }[];
  vulns: Record<string, OsvAdvisory>;
}

export interface LibraryVulnerability {
  id: string;
  cves: string[];
  summary: string;
  details?: string;
  severity: VulnerabilitySeverity;
  /** CVSS v3 base score, when the advisory carries a v3 vector. */
  score?: number;
  published?: string;
  /** `group:artifact` the advisory is about — the library itself, or one bundled inside it. */
  package: string;
  version: string;
  /** True when the vulnerable code is shaded inside the jar rather than being the jar itself. */
  bundled: boolean;
  /** The lowest release that fixes it and is newer than the version in use. */
  fixedIn?: string;
  cwes: string[];
}

export interface VulnerabilityReport {
  source: string;
  checkedAt: string;
  /** Library key → its vulnerabilities, worst first. Libraries that were checked and are clean map to []. */
  byLibrary: Record<string, LibraryVulnerability[]>;
  /** Library keys that could not be checked (no Maven group or version). */
  unchecked: string[];
}

/** The Maven packages to look up: each library's own coordinates and those bundled inside it. */
export function packagesToCheck(report: JavaLibraryReport): { name: string; version: string }[] {
  const seen = new Set<string>();
  const out: { name: string; version: string }[] = [];
  for (const lib of report.libraries) {
    for (const c of [lib.coordinates, ...lib.bundled]) {
      if (!isCheckable(c)) continue;
      const key = `${c.group}:${c.artifact}@${c.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name: `${c.group}:${c.artifact}`, version: c.version });
    }
  }
  return out;
}

const SEVERITY_RANK: Record<VulnerabilitySeverity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };

export function applyOsvResult(report: JavaLibraryReport, osv: OsvCheckResult): VulnerabilityReport {
  const answers = new Map(osv.results.map((r) => [`${r.name}@${r.version}`, r.ids]));
  const byLibrary: Record<string, LibraryVulnerability[]> = {};
  const unchecked: string[] = [];

  for (const lib of report.libraries) {
    const targets: { c: Required<MavenCoordinates>; bundled: boolean }[] = [];
    if (isCheckable(lib.coordinates)) targets.push({ c: lib.coordinates, bundled: false });
    for (const b of lib.bundled) if (isCheckable(b)) targets.push({ c: b, bundled: true });
    if (targets.length === 0) {
      unchecked.push(lib.key);
      continue;
    }
    const found = new Map<string, LibraryVulnerability>();
    let answered = false;
    let answeredAny = false;
    for (const { c, bundled } of targets) {
      const name = `${c.group}:${c.artifact}`;
      const ids = answers.get(`${name}@${c.version}`);
      // Not in this check's answers: the library appeared after the check ran (the analysis was
      // run again), so it is unchecked — not clean.
      if (!ids) continue;
      answeredAny = true;
      if (!bundled) answered = true;
      for (const id of ids) {
        const advisory = osv.vulns[id];
        if (!advisory || found.has(id)) continue;
        found.set(id, toVulnerability(advisory, name, c.version, bundled));
      }
    }
    const hasOwn = targets.some((t) => !t.bundled);
    if (hasOwn ? !answered : !answeredAny) {
      unchecked.push(lib.key);
      continue;
    }
    byLibrary[lib.key] = [...found.values()].sort(
      (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || (b.score ?? 0) - (a.score ?? 0) || a.id.localeCompare(b.id)
    );
  }
  return { source: osv.source, checkedAt: osv.checkedAt, byLibrary, unchecked };
}

/** One OSV advisory as it affects `pkg` at `version`; shared with the widget check (marketplace.ts). */
export function toVulnerability(a: OsvAdvisory, pkg: string, version: string, bundled: boolean): LibraryVulnerability {
  const v3 = a.severity?.find((s) => s.type === 'CVSS_V3')?.score;
  const score = v3 ? cvss3BaseScore(v3) : undefined;
  return {
    id: a.id,
    cves: (a.aliases ?? []).filter((x) => x.startsWith('CVE-')),
    summary: a.summary || firstSentence(a.details) || 'No summary published.',
    details: a.details,
    severity: severityOf(a.databaseSeverity, score),
    score,
    published: a.published,
    package: pkg,
    version,
    bundled,
    fixedIn: lowestFixAbove(a, pkg, version),
    cwes: a.cwes ?? [],
  };
}

function firstSentence(text: string | undefined): string | undefined {
  if (!text) return undefined;
  const line = text.split(/\n/).find((l) => l.trim().length > 0)?.trim() ?? '';
  return line.length > 200 ? `${line.slice(0, 197)}…` : line;
}

export function severityOf(databaseSeverity: string | undefined, score: number | undefined): VulnerabilitySeverity {
  switch ((databaseSeverity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'Critical';
    case 'HIGH':
      return 'High';
    case 'MODERATE':
    case 'MEDIUM':
      return 'Medium';
    case 'LOW':
      return 'Low';
  }
  if (score === undefined) return 'Unknown';
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return score > 0 ? 'Low' : 'Unknown';
}

function lowestFixAbove(a: OsvAdvisory, pkg: string, version: string): string | undefined {
  const fixes: string[] = [];
  for (const affected of a.affected ?? []) {
    if (affected.package?.name !== pkg) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixes.push(event.fixed);
      }
    }
  }
  return fixes.filter((f) => compareVersions(f, version) > 0).sort(compareVersions)[0];
}

/**
 * Maven-style version order, sufficient for choosing an upgrade: numeric segments compare as
 * numbers, a release sorts after its qualifiers (`2.0-rc1` < `2.0`), and other text compares
 * alphabetically.
 */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.split(/[.\-_+]/).filter((p) => p.length > 0);
  const pa = parts(a);
  const pb = parts(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return /^\d+$/.test(y!) ? (Number(y) === 0 ? 0 : -1) : 1;
    if (y === undefined) return /^\d+$/.test(x) ? (Number(x) === 0 ? 0 : 1) : -1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (nx !== ny) {
      return nx ? 1 : -1;
    } else {
      const d = x.toLowerCase().localeCompare(y.toLowerCase());
      if (d !== 0) return d;
    }
  }
  return 0;
}

/** CVSS v3.0/v3.1 base score from a vector such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. */
export function cvss3BaseScore(vector: string): number | undefined {
  const m: Record<string, string> = {};
  for (const part of vector.split('/')) {
    const [k, v] = part.split(':');
    if (k && v) m[k] = v;
  }
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV ?? ''];
  const AC = { L: 0.77, H: 0.44 }[m.AC ?? ''];
  const UI = { N: 0.85, R: 0.62 }[m.UI ?? ''];
  const changed = m.S === 'C';
  const PR = changed ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR ?? ''] : { N: 0.85, L: 0.62, H: 0.27 }[m.PR ?? ''];
  const cia = (x: string | undefined) => ({ H: 0.56, L: 0.22, N: 0 })[x ?? ''];
  const C = cia(m.C);
  const I = cia(m.I);
  const A = cia(m.A);
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined) || (m.S !== 'U' && m.S !== 'C')) return undefined;
  const iss = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  if (impact <= 0) return 0;
  const roundUp = (x: number) => {
    const i = Math.round(x * 100000);
    return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
  };
  return roundUp(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

/** What to do about a vulnerable library, given where it comes from. */
export function remediation(lib: JavaLibrary, v: LibraryVulnerability): string {
  const target = v.fixedIn ? `${v.fixedIn} or later` : 'a fixed release (none is published yet — watch the advisory)';
  const artifact = v.package.split(':')[1] ?? v.package;
  if (v.bundled) {
    return `${artifact} ${v.version} is bundled inside ${lib.fileName}, so the fix has to come from a new release of ${lib.coordinates?.artifact ?? lib.fileName} that bundles ${artifact} ${target}.`;
  }
  if (lib.origin === 'marketplace') {
    const modules = lib.requiredBy.filter((r) => r.moduleType === 'marketplace' || r.moduleType === 'system').map((r) => r.module);
    return `Update ${modules.join(', ')} from the Marketplace to a version that ships ${artifact} ${target}. Do not replace the jar by hand: the module's own dependency declaration puts it back, and an untested upgrade can break the module.`;
  }
  const direct = lib.requiredBy.filter((r) => r.moduleType === 'user' && r.direct).map((r) => r.module);
  if (lib.folder === 'vendorlib' && direct.length > 0) {
    return `In ${direct.join(', ')} ▸ Settings ▸ Java Dependencies, raise ${v.package} to ${target}, then synchronise the app's dependencies.`;
  }
  const transitive = lib.requiredBy.filter((r) => r.moduleType === 'user' && !r.direct);
  if (lib.folder === 'vendorlib' && transitive.length > 0) {
    const via = [...new Set(transitive.map((r) => r.via))].join(', ');
    return `${v.package} comes in through ${via}. Upgrade ${via} in ${transitive.map((r) => r.module).join(', ')} ▸ Settings ▸ Java Dependencies to a release that uses ${artifact} ${target}, or declare ${v.package} ${target} there directly to override it.`;
  }
  if (lib.folder === 'userlib') {
    return `Replace userlib/${lib.fileName} with ${artifact} ${target} and delete the old jar (and any .RequiredLib marker for it). Better still, declare it as a Java dependency in a module's settings so Studio Pro manages the version.`;
  }
  return `Upgrade ${v.package} to ${target}.`;
}
