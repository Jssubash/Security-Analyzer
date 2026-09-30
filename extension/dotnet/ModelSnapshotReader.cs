using System.Diagnostics;
using System.Text.Json.Nodes;
using Mendix.StudioPro.ExtensionsAPI.Model;
using Mendix.StudioPro.ExtensionsAPI.Model.UntypedModel;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Reads the open app through Studio Pro's untyped model API into a <c>ModelSnapshot</c>
/// (see <c>src/snapshot/types.ts</c>).
///
/// The reader copies; it does not interpret. Every property is written under the name the
/// model gives it, so the mapping from model to security facts lives in one place, the
/// TypeScript extractor, where it is tested against the reference project. The only
/// transformation here is secret redaction.
/// </summary>
internal sealed class ModelSnapshotReader
{
    /// <summary>
    /// Units owned by a module that the security rules read, by the local part of their type.
    /// Matching on the part after <c>$</c> tolerates the metamodel and storage spellings differing
    /// in the namespace: a page is <c>Forms$Page</c> on disk and <c>Pages$Page</c> in the metamodel.
    /// </summary>
    private static readonly HashSet<string> ModuleUnitKinds = new(StringComparer.Ordinal)
    {
        "ModuleSecurity",
        "DomainModel",
        "Page",
        "Microflow",
        "Constant",
        "PublishedRestService",
        "Snippet",
        "Nanoflow",
    };

    /// <summary>
    /// Units whose by-name references are collected into <c>$References</c>. The pane resolves
    /// them to the entities a page uses (directly, through snippets, and through data-source
    /// flows' return types) without the host shipping whole widget trees.
    /// </summary>
    private static readonly HashSet<string> ReferenceKinds = new(StringComparer.Ordinal)
    {
        "Page",
        "Snippet",
        // A flow's references include the microflows and nanoflows it calls, which is how the
        // pane finds where a flow is used as a sub-microflow or sub-nanoflow.
        "Microflow",
        "Nanoflow",
    };

    private const int MaxReferencesPerUnit = 5000;

    /// <summary>Project-level units.</summary>
    private static readonly string[] ProjectUnitTypes =
    {
        "Security$ProjectSecurity",
        "Navigation$NavigationDocument",
    };

    /// <summary>
    /// Units copied without nested elements. The rules need a page's allowed roles, not its widget
    /// tree, which can run to megabytes. Microflows are copied in full: the SEC-MF rules read their
    /// parameters, activities and sequence flows.
    /// </summary>
    private static readonly HashSet<string> ShallowKinds = new(StringComparer.Ordinal)
    {
        "Page",
        "Snippet",
        "Nanoflow",
    };

    /// <summary>Qualified names of every microflow, so the reference index keeps only those.</summary>
    private HashSet<string> microflowNames = new(StringComparer.Ordinal);

    /// <summary>Every unit that refers to a microflow: <c>{ referrer, kind, references }</c>.</summary>
    private readonly JsonArray referenceIndex = new();

    private const int MaxDepth = 48;
    private const int MaxJavaFileBytes = 512 * 1024;
    private const long MaxJavaTotalBytes = 16L * 1024 * 1024;

    private static readonly object Skip = new();

    private readonly List<string> notes = new();

    /// <summary>Every unit type seen under a module, with a count, for the Coverage tab.</summary>
    private readonly SortedDictionary<string, int> unitTypes = new(StringComparer.Ordinal);

    /// <summary>Values of a CLR type the reader does not map directly, by owner type and property.</summary>
    private readonly SortedDictionary<string, string> unexpectedValues = new(StringComparer.Ordinal);

    public JsonObject Read(IModel model, IModelRoot root)
    {
        var project = model.Root;
        microflowNames = new HashSet<string>(
            UnitsOfType(root, "Microflows$Microflow").Select(u => u.QualifiedName).OfType<string>(),
            StringComparer.Ordinal);

        var modules = new JsonArray();
        foreach (var module in UnitsOfType(root, "Projects$Module"))
        {
            modules.Add(ReadModule(module));
        }
        if (modules.Count == 0) notes.Add("no module could be read from the model");

        var projectUnits = new JsonArray();
        foreach (var type in ProjectUnitTypes)
        {
            foreach (var unit in UnitsOfType(root, type))
            {
                projectUnits.Add(Serialize(unit, shallow: false, depth: 0));
                IndexReferences(unit, References(unit), moduleName: null);
            }
        }
        // Project settings name the after-startup and before-shutdown microflows.
        foreach (var unit in UnitsOfType(root, "Settings$ProjectSettings"))
        {
            IndexReferences(unit, References(unit), moduleName: null);
        }

        var directory = SafeDirectory(project);

        return new JsonObject
        {
            ["schemaVersion"] = 1,
            ["source"] = "studio-pro",
            ["app"] = new JsonObject
            {
                ["name"] = project.Name,
                ["directory"] = directory,
                ["studioProVersion"] = StudioProVersion(),
            },
            ["projectUnits"] = projectUnits,
            ["modules"] = modules,
            ["javaSources"] = ReadJavaSources(directory),
            ["referenceIndex"] = referenceIndex,
            ["notes"] = new JsonArray(notes.Select(n => (JsonNode?)JsonValue.Create(n)).ToArray()),
            ["diagnostics"] = new JsonObject
            {
                ["unitTypes"] = new JsonObject(unitTypes.Select(kv => KeyValuePair.Create(kv.Key, (JsonNode?)JsonValue.Create(kv.Value)))),
                ["unexpectedValueTypes"] = new JsonObject(unexpectedValues.Select(kv => KeyValuePair.Create(kv.Key, (JsonNode?)JsonValue.Create(kv.Value)))),
            },
            ["capturedAt"] = DateTime.UtcNow.ToString("o"),
        };
    }

    private JsonObject ReadModule(IModelUnit module)
    {
        var name = module.Name ?? AsString(PropertyValue(module, "name")) ?? "(unnamed)";
        var units = new JsonArray();
        try
        {
            foreach (var unit in module.GetUnits())
            {
                var type = Normalise(unit.Type);
                unitTypes[type] = unitTypes.GetValueOrDefault(type) + 1;
                var kind = LocalName(type);
                // Every unit is scanned for microflow references — layouts, scheduled events,
                // workflows, entity event handlers, import mappings — so an "unused microflow"
                // conclusion covers the whole module, not just the documents the rules read.
                var references = References(unit);
                IndexReferences(unit, references, name);
                if (!ModuleUnitKinds.Contains(kind)) continue;
                var node = Serialize(unit, ShallowKinds.Contains(kind), depth: 0);
                if (ReferenceKinds.Contains(kind)) node["$References"] = references.DeepClone();
                units.Add(node);
            }
        }
        catch (Exception ex)
        {
            notes.Add($"the documents of module {name} could not be read: {ex.Message}");
        }

        return new JsonObject
        {
            ["name"] = name,
            ["fromAppStore"] = PropertyValue(module, "fromAppStore") is bool b ? b : null,
            ["unitId"] = module.ID.ToString(),
            ["units"] = units,
        };
    }

    /// <summary>
    /// Units of a type, tolerating the storage spelling (<c>…Impl</c>) as well as the metamodel one.
    /// </summary>
    private IEnumerable<IModelUnit> UnitsOfType(IModelRoot root, string type)
    {
        foreach (var candidate in new[] { type, type + "Impl" })
        {
            List<IModelUnit> found;
            try
            {
                found = root.GetUnitsOfType(candidate).ToList();
            }
            catch (Exception ex)
            {
                notes.Add($"units of type {candidate} could not be listed: {ex.Message}");
                continue;
            }
            if (found.Count > 0) return found;
        }
        return Array.Empty<IModelUnit>();
    }

    private JsonObject Serialize(IModelStructure structure, bool shallow, int depth)
    {
        var node = new JsonObject { ["$Type"] = structure.Type };
        if (structure.ID != Guid.Empty) node["$ID"] = structure.ID.ToString();
        if (structure.Name is { } name) node["$Name"] = name;
        if (structure.QualifiedName is { } qualifiedName) node["$QualifiedName"] = qualifiedName;

        IEnumerable<IModelProperty> properties;
        try
        {
            properties = structure.GetProperties().ToList();
        }
        catch (Exception ex)
        {
            notes.Add($"the properties of a {structure.Type} could not be read: {ex.Message}");
            return node;
        }

        foreach (var property in properties)
        {
            if (IsUnsupported(property.Type)) continue;
            try
            {
                if (property.IsList)
                {
                    var array = new JsonArray();
                    foreach (var item in property.GetValues() ?? (IReadOnlyList<object?>)Array.Empty<object?>())
                    {
                        var converted = Convert(structure.Type, property.Name, IsByName(property.Type), item, shallow, depth);
                        if (!ReferenceEquals(converted, Skip)) array.Add((JsonNode?)converted);
                    }
                    node[property.Name] = array;
                }
                else
                {
                    var converted = Convert(structure.Type, property.Name, IsByName(property.Type), property.Value, shallow, depth);
                    if (!ReferenceEquals(converted, Skip)) node[property.Name] = (JsonNode?)converted;
                }
            }
            catch (Exception ex)
            {
                notes.Add($"{structure.Type}.{property.Name} could not be read: {ex.Message}");
            }
        }
        return node;
    }

    /// <summary>
    /// Whether a property points at another element by name rather than containing it — a user
    /// role's module roles, an access rule's roles, the guest user role.
    /// </summary>
    private static bool IsByName(PropertyType type) =>
        type is PropertyType.ElementByName or PropertyType.ElementLocalByName;

    private object? Convert(string ownerType, string propertyName, bool byName, object? value, bool shallow, int depth)
    {
        switch (value)
        {
            case null:
                return null;
            case IModelStructure referenced when byName:
                // A reference must reach the snapshot as the qualified name every rule compares
                // against. Serialising the referenced element instead turns "Anonymous holds
                // MyFirstModule.Anonymous" into a nested object no rule recognises, and every
                // anonymous-access rule then passes for want of a role name.
                unexpectedValues.TryAdd($"{Normalise(ownerType)}.{propertyName}", "reference element, read by qualified name");
                return JsonValue.Create(referenced.QualifiedName ?? referenced.Name ?? "");
            case IModelStructure child:
                // A flow's return type is kept even in a shallow copy: a page's microflow or
                // nanoflow data source resolves to an entity through it.
                var keepReturnType = shallow && propertyName.EndsWith("ReturnType", StringComparison.OrdinalIgnoreCase);
                if ((shallow && !keepReturnType) || depth >= MaxDepth) return Skip;
                return Serialize(child, shallow: false, depth + 1);
            case string s:
                return SecretRedactor.IsSecretProperty(propertyName) ? SecretRedactor.Redact(s) : JsonValue.Create(s);
            case bool b:
                return JsonValue.Create(b);
            case int i:
                return JsonValue.Create(i);
            case long l:
                return JsonValue.Create(l);
            case double d:
                return double.IsFinite(d) ? JsonValue.Create(d) : null;
            case Guid g:
                return JsonValue.Create(g.ToString());
            case DateTime dt:
                return JsonValue.Create(dt.ToString("o"));
            case Enum e:
                return JsonValue.Create(e.ToString());
            case System.Collections.IEnumerable items:
                // A list delivered through Value rather than GetValues(); keep it rather than lose it.
                var array = new JsonArray();
                foreach (var item in items)
                {
                    var converted = Convert(ownerType, propertyName, byName, item, shallow, depth);
                    if (!ReferenceEquals(converted, Skip)) array.Add((JsonNode?)converted);
                }
                return array;
            default:
                return ByNameOrText(ownerType, propertyName, value);
        }
    }

    /// <summary>
    /// A value of a type the API documentation does not list. A reference object is read by its
    /// qualified name — the form every other reference arrives in — and anything else by its text,
    /// and the CLR type is recorded so a mismatch shows up in the Coverage tab instead of silently
    /// becoming an empty role list.
    /// </summary>
    private object? ByNameOrText(string ownerType, string propertyName, object value)
    {
        var clrType = value.GetType();
        unexpectedValues.TryAdd($"{Normalise(ownerType)}.{propertyName}", clrType.FullName ?? clrType.Name);
        foreach (var member in new[] { "QualifiedName", "FullName", "Name" })
        {
            if (clrType.GetProperty(member)?.GetValue(value) is string text && text.Length > 0) return JsonValue.Create(text);
        }
        var fallback = value.ToString();
        return fallback is null || fallback == clrType.FullName ? Skip : JsonValue.Create(fallback);
    }

    private static string LocalName(string type)
    {
        var dollar = type.IndexOf('$');
        return dollar >= 0 ? type[(dollar + 1)..] : type;
    }

    /// <summary>
    /// Every by-name reference anywhere in the unit's own contents — entity refs of data views and
    /// grids, page parameter types, attribute paths, snippet calls, data-source microflows — as a
    /// sorted, de-duplicated list of qualified names.
    /// </summary>
    private JsonArray References(IModelUnit unit)
    {
        var names = new SortedSet<string>(StringComparer.Ordinal);

        void Add(object? value)
        {
            var text = value switch
            {
                string s => s,
                IModelStructure referenced => referenced.QualifiedName ?? referenced.Name,
                _ => null,
            };
            if (!string.IsNullOrEmpty(text) && names.Count < MaxReferencesPerUnit) names.Add(text);
        }

        void Collect(IModelStructure structure)
        {
            IEnumerable<IModelProperty> properties;
            try
            {
                properties = structure.GetProperties().ToList();
            }
            catch
            {
                return;
            }
            foreach (var property in properties)
            {
                if (!IsByName(property.Type)) continue;
                try
                {
                    if (property.IsList)
                    {
                        foreach (var item in property.GetValues() ?? (IReadOnlyList<object?>)Array.Empty<object?>()) Add(item);
                    }
                    else
                    {
                        Add(property.Value);
                    }
                }
                catch
                {
                    // An unreadable reference only narrows what is known about the page.
                }
            }
        }

        try
        {
            Collect(unit);
            foreach (var element in unit.GetElements()) Collect(element);
        }
        catch (Exception ex)
        {
            notes.Add($"the references of {unit.QualifiedName ?? unit.Name ?? unit.Type} could not all be read: {ex.Message}");
        }
        return new JsonArray(names.Select(n => (JsonNode?)JsonValue.Create(n)).ToArray());
    }

    private void IndexReferences(IModelUnit unit, JsonArray references, string? moduleName)
    {
        var found = references
            .Select(r => r?.GetValue<string>())
            .Where(r => r is not null && microflowNames.Contains(r))
            .Select(r => (JsonNode?)JsonValue.Create(r))
            .ToArray();
        if (found.Length == 0) return;
        var kind = LocalName(Normalise(unit.Type));
        var referrer = unit.QualifiedName
            ?? (moduleName is not null && unit.Name is not null ? $"{moduleName}.{unit.Name}" : moduleName is not null ? $"{moduleName}.{kind}" : kind);
        referenceIndex.Add(new JsonObject
        {
            ["referrer"] = referrer,
            ["kind"] = kind,
            ["references"] = new JsonArray(found),
        });
    }

    private static bool IsUnsupported(PropertyType type) =>
        type is PropertyType.Blob or PropertyType.Location or PropertyType.Dimensions or PropertyType.Color;

    private static object? PropertyValue(IModelStructure structure, string name)
    {
        try
        {
            return structure.GetProperty(name)?.Value;
        }
        catch
        {
            return null;
        }
    }

    private static string? AsString(object? value) => value as string;

    private static string Normalise(string type) =>
        type.EndsWith("Impl", StringComparison.Ordinal) ? type[..^4] : type;

    private string? SafeDirectory(Mendix.StudioPro.ExtensionsAPI.Model.Projects.IProject project)
    {
        try
        {
            return project.DirectoryPath;
        }
        catch (Exception ex)
        {
            notes.Add($"the app directory could not be determined, so Java actions were not scanned: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Java action sources under <c>javasource/&lt;module&gt;/actions</c>, for the regex-sanitiser
    /// check (SEC-007). These are the app's own files on disk, read-only.
    /// </summary>
    private JsonArray ReadJavaSources(string? directory)
    {
        var files = new JsonArray();
        if (directory is null) return files;
        var javaRoot = Path.Combine(directory, "javasource");
        if (!Directory.Exists(javaRoot)) return files;

        long total = 0;
        foreach (var moduleDir in Directory.EnumerateDirectories(javaRoot))
        {
            var actions = Path.Combine(moduleDir, "actions");
            if (!Directory.Exists(actions)) continue;
            foreach (var file in Directory.EnumerateFiles(actions, "*.java"))
            {
                var info = new FileInfo(file);
                if (info.Length > MaxJavaFileBytes || total + info.Length > MaxJavaTotalBytes)
                {
                    notes.Add($"{Path.GetRelativePath(directory, file)} was too large to scan");
                    continue;
                }
                try
                {
                    var content = File.ReadAllText(file);
                    total += info.Length;
                    files.Add(new JsonObject
                    {
                        ["moduleDirectory"] = Path.GetFileName(moduleDir),
                        ["fileName"] = Path.GetFileName(file),
                        ["relativePath"] = Path.GetRelativePath(directory, file).Replace('\\', '/'),
                        ["content"] = content,
                    });
                }
                catch (Exception ex)
                {
                    notes.Add($"{Path.GetFileName(file)} could not be read: {ex.Message}");
                }
            }
        }
        return files;
    }

    private static string? StudioProVersion()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (exe is not null)
            {
                var version = FileVersionInfo.GetVersionInfo(exe).ProductVersion;
                if (!string.IsNullOrWhiteSpace(version)) return version.Split('+')[0];
            }
        }
        catch
        {
            // Fall through to the API assembly version.
        }
        return typeof(IModel).Assembly.GetName().Version?.ToString();
    }
}
