/**
 * The contract between the Studio Pro host (C#) and the analyzer running in the pane.
 *
 * The host walks Studio Pro's untyped model API and serialises the units the security rules
 * need into this shape. It deliberately does no interpretation: every property is copied under
 * the name the model gave it, so the mapping from model to IR lives in one place
 * (`build-ir.ts`), where it can be tested without Studio Pro.
 *
 * Property names differ by source. Studio Pro's untyped API uses metamodel names
 * (`enableGuestAccess`, `allowedRoles`); the `.mxunit` storage format uses storage names
 * (`EnableGuestAccess`, `AllowedModuleRoles`). Readers must go through `accessors.ts`, which
 * matches case-insensitively and accepts both spellings.
 */

export const SNAPSHOT_SCHEMA_VERSION = 1;

/**
 * A secret the host was not willing to hand over.
 *
 * Passwords are reduced to the features the weakness check needs before they leave the host,
 * so the plaintext never reaches the web view, an exported report, or a support dump.
 */
export interface RedactedSecret {
  $redacted: true;
  length: number;
  hasDigit: boolean;
  hasLower: boolean;
  hasUpper: boolean;
  hasSymbol: boolean;
}

export type SnapshotValue =
  | string
  | number
  | boolean
  | null
  | RedactedSecret
  | SnapshotNode
  | SnapshotValue[];

/** One model element or unit, with its properties copied verbatim. */
export interface SnapshotNode {
  $Type: string;
  $ID?: string;
  /** `IModelStructure.Name` where the model defines one. */
  $Name?: string;
  /** `IModelStructure.QualifiedName` where the element can be referred to by name. */
  $QualifiedName?: string;
  [property: string]: SnapshotValue | undefined;
}

export interface SnapshotModule {
  name: string;
  /** `Projects$Module.FromAppStore`, when readable. */
  fromAppStore?: boolean;
  /** The Marketplace content id the module was installed from (e.g. 170 for Community Commons). */
  appStorePackageId?: number | null;
  /** The Marketplace version installed. */
  appStoreVersion?: string | null;
  appStoreVersionGuid?: string | null;
  isThemeModule?: boolean | null;
  unitId?: string;
  /** Units owned by the module: security, domain model, pages, microflows, constants, services. */
  units: SnapshotNode[];
}

export interface JavaSourceFile {
  /** Directory under `javasource/`, which is the module name in lower case. */
  moduleDirectory: string;
  fileName: string;
  /** Path relative to the app directory, with forward slashes. */
  relativePath: string;
  content: string;
}

/** Maven coordinates read from a jar's `META-INF/maven/<group>/<artifact>/pom.properties`. */
export interface PomProperties {
  groupId?: string;
  artifactId: string;
  version?: string;
  /** Entry path inside the jar. */
  path: string;
}

/** One `.jar` file under `userlib/` or `vendorlib/`. */
export interface JarFileFacts {
  folder: 'userlib' | 'vendorlib';
  fileName: string;
  sizeBytes: number;
  sha256?: string;
  /** Every pom.properties inside the jar: its own, and those of libraries shaded into it. */
  pomProperties?: PomProperties[];
  /** Identifying manifest attributes (Implementation-*, Bundle-*, Automatic-Module-Name). */
  manifest?: Record<string, string>;
  /** Jars packed inside this jar (fat jars), which are counted but not opened. */
  nestedJars?: number;
  /** Why the jar could not be opened, if it could not. */
  unreadable?: string;
}

/** `vendorlib/vendorlib-sbom.json` (CycloneDX), reduced to coordinates and the dependency graph. */
export interface VendorlibSbom {
  components: { ref?: string; group?: string; name?: string; version?: string; sha256?: string }[];
  dependencies: { ref?: string; dependsOn: (string | null)[] }[];
}

export interface JavaLibrariesSnapshot {
  /** False when the app directory was unknown, so nothing could be scanned. */
  scanned: boolean;
  jars: JarFileFacts[];
  /** `userlib/<jar>.<Module>.RequiredLib` marker files: which module needs which userlib jar. */
  requiredLibMarkers: { jarFileName: string; module: string }[];
  sbom?: VendorlibSbom;
}

/** One widget package (`widgets/*.mpk`). */
export interface WidgetPackageFacts {
  fileName: string;
  /** `<clientModule name>` from package.xml. */
  name?: string | null;
  /** `<clientModule version>` from package.xml. */
  version?: string | null;
  widgets?: { id: string; name?: string | null; pluginWidget?: boolean; supportedPlatform?: string | null }[];
  /** npm libraries bundled into the widget, from its dependencies.json / dependencies.txt. */
  dependencies?: { name: string; version: string; transitive?: boolean }[];
  unreadable?: string;
}

export interface WidgetsSnapshot {
  scanned: boolean;
  packages: WidgetPackageFacts[];
}

export interface ModelSnapshot {
  schemaVersion: number;
  /** Where the snapshot came from; `studio-pro` in production, `mprcontents` in tests. */
  source: 'studio-pro' | 'mprcontents';
  app: {
    name: string;
    directory?: string;
    /** Studio Pro version hosting the extension, e.g. `10.24.0.73019`. */
    studioProVersion?: string;
    /** The app's Java version from its runtime settings, e.g. `Java21`. Absent from older hosts. */
    javaVersion?: string;
  };
  /** Project-level units: `Security$ProjectSecurity`, `Navigation$NavigationDocument`. */
  projectUnits: SnapshotNode[];
  modules: SnapshotModule[];
  javaSources: JavaSourceFile[];
  /** The jars in `userlib/` and `vendorlib/`. Absent from hosts that predate the Java libraries tab. */
  javaLibraries?: JavaLibrariesSnapshot;
  /** The widget packages in `widgets/`. Absent from hosts that predate the Upgrades tab. */
  widgets?: WidgetsSnapshot;
  /** Accepted-risk decisions from `.security-analyzer/accepted-risks.json` in the app folder. */
  acceptedRisks?: import('../accepted-risks.js').AcceptedRisksFile;
  /** Anything the host could not read, in plain language. */
  notes: string[];
  /**
   * For every document that refers to a microflow: its name, kind and the microflows it refers to.
   * Covers all units — pages, layouts, navigation, flows, domain models (event handlers), scheduled
   * events, workflows, published services, project settings. Absent from hosts that predate it.
   */
  referenceIndex?: { referrer: string; kind: string; references: string[] }[];
  /**
   * Each pluggable widget id placed in the app, with the pages, snippets and layouts that place it.
   * Absent from hosts that predate it, which leaves widget usage unknown.
   */
  widgetUsage?: Record<string, string[]>;
  /** What the host saw, for troubleshooting a snapshot that reads less than expected. */
  diagnostics?: {
    /** Every unit type found under a module, with a count. */
    unitTypes?: Record<string, number>;
    /** `Owner$Type.property` → CLR type, for values the host had to read by name or text. */
    unexpectedValueTypes?: Record<string, string>;
  };
  capturedAt: string;
}
