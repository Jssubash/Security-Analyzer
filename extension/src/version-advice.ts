/**
 * "How to resolve" for a vulnerable Java library: which version to move to, and the steps to get
 * there in Studio Pro.
 *
 * The version is chosen from Maven Central's release list, newest first, among releases that
 *
 *   - are stable and of the same flavour as the installed one (`32.0.1-jre` stays `-jre`),
 *   - stay in the installed major version, so the module's code keeps compiling,
 *   - are at or above every advisory's fixed version,
 *   - have no known advisory of their own (OSV.dev),
 *   - were compiled for a Java version the app runs (read from the jar's class files), and
 *   - when the problem was a library bundled inside the jar, bundle a fixed version of it or none.
 *
 * Everything here is pure: the host fetches the release list and inspects candidate jars, and this
 * module decides. The minimum fixed version from the advisories is always reported too, so the
 * steps still make sense when Maven Central could not be reached.
 */

import type { JavaLibrary, LibraryRequirement, LibraryVulnerability, VulnerabilityReport } from './java-libraries.js';
import { compareVersions, gaOf, isCheckable } from './java-libraries.js';

/** One library that needs a new version, and what that version has to fix. */
export interface UpgradeTarget {
  libKey: string;
  group: string;
  artifact: string;
  current: string;
  /** The highest of the advisories' fixed versions for the library itself. */
  minimum?: string;
  /** Advisories on the library itself that list no fixed release. */
  unfixed: string[];
  /** Libraries bundled inside the jar that are vulnerable, and the version they must reach. */
  bundled: { group: string; artifact: string; version: string; minimum?: string }[];
}

/** What the host found out about one candidate jar on Maven Central. */
export interface CandidateJarFacts {
  /** Highest class-file major version in the jar (52 = Java 8, 65 = Java 21); undefined when it has no classes. */
  classMajor?: number;
  /** Libraries whose pom.properties are inside the jar, its own included. */
  poms: { group?: string; artifact: string; version?: string }[];
  error?: string;
}

export interface CandidateFacts {
  /** Version → OSV advisory ids for that exact release (absent: not checked). */
  osv: Record<string, string[]>;
  /** Version → what is inside the jar. */
  jars: Record<string, CandidateJarFacts>;
}

export interface VersionAdvice {
  /** The release to move to, when one passed every check. */
  suggested?: string;
  /** The Java version that release was compiled for. */
  suggestedJava?: number;
  /** The advisories' minimum, always given. */
  minimum?: string;
  /** Releases looked at and why each was passed over, newest first. */
  rejected: { version: string; reason: string }[];
  /** A newer major version exists; it is not suggested because it may change the library's API. */
  newerMajor?: string;
  /** Why no suggestion could be made (Maven Central unreachable, nothing newer, …). */
  note?: string;
}

const UNSTABLE = /(alpha|beta|\brc\d*|[-.]rc|\bcr\d*|[-.]m\d+|milestone|preview|snapshot|[-.]ea\b|[-.]dev|incubat)/i;

/** `32.0.1-jre` → `{ numbers: [32, 0, 1], suffix: '-jre' }`. */
export function splitVersion(version: string): { numbers: number[]; suffix: string } {
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(version.trim());
  if (!m) return { numbers: [], suffix: version };
  return { numbers: m[1]!.split('.').map(Number), suffix: m[2]!.toLowerCase() };
}

export function isStableRelease(version: string): boolean {
  return !UNSTABLE.test(version) && splitVersion(version).numbers.length > 0;
}

/** The libraries in a vulnerability report that need a new version, one per jar. */
export function upgradeTargets(libraries: JavaLibrary[], report: VulnerabilityReport): UpgradeTarget[] {
  const out: UpgradeTarget[] = [];
  for (const lib of libraries) {
    const vulns = report.byLibrary[lib.key] ?? [];
    if (vulns.length === 0 || !isCheckable(lib.coordinates)) continue;
    const own = vulns.filter((v) => !v.bundled);
    const bundled = new Map<string, UpgradeTarget['bundled'][number]>();
    for (const v of vulns.filter((x) => x.bundled)) {
      const [group = '', artifact = ''] = v.package.split(':');
      const entry = bundled.get(v.package) ?? { group, artifact, version: v.version };
      entry.minimum = maxVersion(entry.minimum, v.fixedIn);
      bundled.set(v.package, entry);
    }
    out.push({
      libKey: lib.key,
      group: lib.coordinates.group,
      artifact: lib.coordinates.artifact,
      current: lib.coordinates.version,
      minimum: own.reduce<string | undefined>((m, v) => maxVersion(m, v.fixedIn), undefined),
      unfixed: own.filter((v) => !v.fixedIn).map((v) => v.id),
      bundled: [...bundled.values()],
    });
  }
  return out;
}

function maxVersion(a: string | undefined, b: string | undefined): string | undefined {
  if (!a) return b;
  if (!b) return a;
  return compareVersions(a, b) >= 0 ? a : b;
}

/**
 * The releases worth inspecting, newest first: stable, same flavour, same major version, newer than
 * the installed one and at or above the advisories' minimum. `limit` caps the jars the host downloads.
 */
export function candidateVersions(
  target: Pick<UpgradeTarget, 'current' | 'minimum'>,
  versions: string[],
  limit = 5
): { candidates: string[]; newerMajor?: string } {
  const current = splitVersion(target.current);
  const major = current.numbers[0];
  const stable = versions.filter((v) => isStableRelease(v) && splitVersion(v).suffix === current.suffix);
  const newer = stable.filter((v) => compareVersions(v, target.current) > 0);
  const sameMajor = newer.filter((v) => splitVersion(v).numbers[0] === major);
  const candidates = sameMajor
    .filter((v) => !target.minimum || compareVersions(v, target.minimum) >= 0)
    .sort((a, b) => compareVersions(b, a))
    .slice(0, limit);
  const newerMajor = newer.filter((v) => (splitVersion(v).numbers[0] ?? 0) > (major ?? 0)).sort((a, b) => compareVersions(b, a))[0];
  return { candidates, newerMajor };
}

/** Java feature version from a class-file major version: 52 → 8, 65 → 21. */
export function javaOfClassMajor(major: number | undefined): number | undefined {
  return major !== undefined && major >= 45 ? major - 44 : undefined;
}

/**
 * The app's Java version: `Java21` from the app's runtime settings. When it could not be read,
 * Mendix 11 is taken as Java 21 (its minimum); for older apps it stays unknown and the Java check
 * is skipped rather than guessed.
 */
export function appJavaVersion(setting: string | undefined, mendixVersion: string | undefined): number | undefined {
  const m = /(\d+)/.exec(setting ?? '');
  if (m) return Number(m[1]);
  const major = Number(/^(\d+)/.exec(mendixVersion ?? '')?.[1]);
  return major >= 11 ? 21 : undefined;
}

/** The first candidate that passes every check. */
export function chooseVersion(
  target: UpgradeTarget,
  candidates: string[],
  facts: CandidateFacts,
  appJava: number | undefined,
  newerMajor?: string
): VersionAdvice {
  const rejected: VersionAdvice['rejected'] = [];
  for (const version of candidates) {
    const jar = facts.jars[version];
    const ids = facts.osv[version];
    if (!jar || jar.error) {
      rejected.push({ version, reason: `could not be inspected${jar?.error ? `: ${jar.error}` : ''}` });
      continue;
    }
    if (!ids) {
      rejected.push({ version, reason: 'was not checked on OSV.dev' });
      continue;
    }
    if (ids.length > 0) {
      rejected.push({ version, reason: `has its own known advisor${ids.length === 1 ? 'y' : 'ies'} (${ids.join(', ')})` });
      continue;
    }
    const java = javaOfClassMajor(jar.classMajor);
    if (appJava !== undefined && java !== undefined && java > appJava) {
      rejected.push({ version, reason: `needs Java ${java}; this app runs Java ${appJava}` });
      continue;
    }
    const stillBundled = target.bundled
      .map((b) => ({ b, inside: jar.poms.find((p) => p.artifact === b.artifact && (!p.group || p.group === b.group)) }))
      .find(({ b, inside }) => inside && (!b.minimum || !inside.version || compareVersions(inside.version, b.minimum) < 0));
    if (stillBundled) {
      rejected.push({ version, reason: `still bundles ${stillBundled.b.artifact} ${stillBundled.inside!.version ?? ''}`.trim() });
      continue;
    }
    return { suggested: version, suggestedJava: java, minimum: target.minimum, rejected, newerMajor };
  }
  return {
    minimum: target.minimum,
    rejected,
    newerMajor,
    note:
      candidates.length === 0
        ? `Maven Central has no newer stable ${target.artifact} ${splitVersion(target.current).numbers[0] ?? ''}.x release${target.minimum ? ` at or above ${target.minimum}` : ''}.`
        : `None of the ${candidates.length} newest ${target.artifact} release${candidates.length === 1 ? '' : 's'} passed every check.`,
  };
}

// ====================================================================== steps

export interface ResolutionPlan {
  /** The version the steps use: the suggestion, or "<minimum> or later". */
  versionText?: string;
  steps: string[];
  notes: string[];
  /** Settings dialogs to offer to open, one per module. */
  openSettings: { module: string; unitId: string }[];
  /** Maven Central page of the version to move to (or of the library, when no single version is known). */
  maven?: { group: string; artifact: string; version?: string };
}

/** What must stay as it is on the row: "Group ID and Artifact ID", plus any exclusions. */
function keep(r: LibraryRequirement): string {
  const list = r.exclusions ?? [];
  return list.length === 0
    ? 'Group ID and Artifact ID'
    : `Group ID, Artifact ID and its ${list.length} exclusion${list.length === 1 ? '' : 's'} (${list.join(', ')})`;
}

/** Step-by-step instructions for one vulnerable library. */
export function resolutionPlan(
  lib: JavaLibrary,
  vulns: LibraryVulnerability[],
  advice: VersionAdvice | undefined,
  minimumIfNoAdvice?: string
): ResolutionPlan {
  const c = lib.coordinates;
  const artifact = c?.artifact ?? lib.fileName;
  const onlyBundled = vulns.every((v) => v.bundled);
  // The advisories' minimum is a version of the library itself; when every advisory is about a
  // library bundled inside the jar, it says nothing about which release of the jar to use.
  const minimum = onlyBundled ? undefined : (advice?.minimum ?? minimumIfNoAdvice);
  const version = advice?.suggested;
  const bundledFix = vulns.filter((v) => v.bundled && v.fixedIn).map((v) => `${v.package.split(':')[1] ?? v.package} ${v.fixedIn}`);
  const versionText =
    version ??
    (minimum
      ? `${minimum} or later`
      : onlyBundled && bundledFix.length > 0
        ? `a newer release that bundles ${[...new Set(bundledFix)].join(', ')} or later (or none at all)`
        : undefined);
  const openSettings: ResolutionPlan['openSettings'] = [];
  const notes: string[] = [];
  const steps: string[] = [];

  if (!versionText) {
    return {
      steps: [],
      notes: [
        `No fixed release of ${onlyBundled ? 'the bundled library' : artifact} is published yet. Record the decision with Accept risk… and a review date, and watch the advisory for a fix.`,
      ],
      openSettings,
    };
  }

  if (onlyBundled) {
    notes.push(
      version
        ? `The vulnerable code is bundled inside ${lib.fileName}; ${artifact} ${version} bundles a fixed version of it, or none.`
        : `The vulnerable code is bundled inside ${lib.fileName}, so ${artifact} itself has to move to ${versionText}. Find that release in ${artifact}'s release notes on Maven Central.`
    );
  }
  const newFile = version ?? minimum;

  if (lib.folder === 'vendorlib') {
    const direct = lib.requiredBy.filter((r) => r.direct && r.moduleType !== 'missing');
    const transitive = lib.requiredBy.filter((r) => !r.direct && r.moduleType !== 'missing');
    const testModules = [...new Set(lib.requiredBy.map((r) => r.module))];
    for (const r of [...direct, ...transitive]) {
      if (r.settingsUnitId && !openSettings.some((o) => o.module === r.module)) openSettings.push({ module: r.module, unitId: r.settingsUnitId });
    }

    if (direct.length > 0) {
      const modules = direct.map((r) => r.module).join(' and ');
      steps.push(`Open ${modules} ▸ Settings ▸ Java Dependencies (use the button below).`);
      for (const r of direct) {
        steps.push(
          `${direct.length > 1 ? `In ${r.module}: s` : 'S'}elect the row ${gaOf(c) ?? artifact}${r.declaredVersion ? ` ${r.declaredVersion}` : ''}, click Edit, set Version to ${versionText}, and leave ${keep(r)} unchanged.`
        );
      }
    } else if (transitive.length > 0) {
      const r = transitive[0]!;
      steps.push(`Open ${r.module} ▸ Settings ▸ Java Dependencies (use the button below). ${artifact} is not listed there: it comes in through ${r.via}.`);
      steps.push(
        `Click New and add Group ID ${c?.group ?? ''}, Artifact ID ${artifact}, Version ${versionText}. Studio Pro uses the highest declared version, so this replaces ${c?.version ?? 'the current version'}.`
      );
    } else {
      steps.push(`No module's Java Dependencies lists ${artifact}. Declare it in one of your modules: Settings ▸ Java Dependencies ▸ New, Group ID ${c?.group ?? ''}, Artifact ID ${artifact}, Version ${versionText}.`);
    }
    steps.push(
      `Click OK in both dialogs. Studio Pro updates vendorlib: ${lib.fileName} is replaced by ${newFile ? `${artifact}-${newFile}.jar` : 'the new release'} (both appear in the Changes pane). If not, synchronise the app's dependencies.`
    );
    steps.push(
      `Test the features that use ${testModules.join(', ')} — run the app locally and exercise them end to end. ${
        lib.origin === 'marketplace' ? `The module was released and tested with ${artifact} ${c?.version ?? 'the old version'}, not the new release.` : ''
      }`.trim()
    );
    steps.push('Click Check again here to confirm the advisories are gone, then commit.');
    if (direct.some((r) => r.moduleType === 'marketplace' || r.moduleType === 'system')) {
      notes.push(
        `This edits a Marketplace module's settings: updating ${direct.filter((r) => r.moduleType !== 'user').map((r) => r.module).join(', ')} from the Marketplace later puts back the version its new release declares. Check again after every module update.`
      );
    }
  } else {
    const markers = lib.requiredBy.filter((r) => r.moduleType !== 'missing');
    const newJar = newFile ? `${artifact}-${newFile}.jar` : `the new ${artifact} jar`;
    steps.push(`Download ${newJar} from Maven Central (use the button below).`);
    steps.push(`Copy it into the app's userlib folder (Open folder), and delete userlib\\${lib.fileName}.`);
    if (markers.length > 0) {
      steps.push(
        `Rename the marker file${markers.length === 1 ? '' : 's'} ${markers.map((r) => `${lib.fileName}.${r.module}.RequiredLib`).join(', ')} to ${markers.map((r) => `${newJar}.${r.module}.RequiredLib`).join(', ')}, so the module keeps claiming the jar.`
      );
    }
    steps.push(
      `Run the app locally: the Java actions must still compile. Then test the features that use ${markers.length > 0 ? markers.map((r) => r.module).join(', ') : 'this library'}.`
    );
    steps.push('Click Check again here to confirm the advisories are gone, then commit.');
    if (markers.some((r) => r.moduleType === 'marketplace')) {
      notes.push('A Marketplace module put this jar in userlib; updating the module may put the old jar back. Check again after every module update.');
    }
    notes.push('Better still, declare the library in a module\'s Settings ▸ Java Dependencies and delete the userlib jar: Studio Pro then manages its version in vendorlib.');
  }

  return {
    versionText,
    steps,
    notes,
    openSettings,
    maven: c?.group ? { group: c.group, artifact, version: newFile } : undefined,
  };
}
