using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Inventories the Java libraries an app ships, for the Java libraries tab.
/// <para>
/// A Mendix app carries jars in two places. <c>vendorlib/</c> holds the libraries Studio Pro
/// downloads for the Java dependencies modules declare (10.3+, managed dependencies), together
/// with a CycloneDX SBOM, <c>vendorlib-sbom.json</c>, listing each one and what it depends on.
/// <c>userlib/</c> holds jars copied in by hand or by older Marketplace modules, which mark the
/// jars they need with an empty <c>&lt;jar&gt;.&lt;Module&gt;.RequiredLib</c> file beside them.
/// </para>
/// <para>
/// Like the model reader, this only collects facts: which jars exist, what Maven coordinates
/// they carry (<c>META-INF/maven/**/pom.properties</c>, including those of libraries shaded
/// inside them) and their manifest. Deciding which module needs a jar, and whether that makes it
/// Marketplace or custom code, is done in the pane (<c>java-libraries.ts</c>), where it is tested.
/// </para>
/// </summary>
internal static class JavaLibraryScanner
{
    private static readonly string[] Folders = { "userlib", "vendorlib" };

    /// <summary>Manifest attributes that identify a library; the rest of the manifest is not shipped.</summary>
    private static readonly string[] ManifestKeys =
    {
        "Implementation-Title", "Implementation-Version", "Implementation-Vendor", "Implementation-Vendor-Id",
        "Bundle-SymbolicName", "Bundle-Version", "Bundle-Name", "Automatic-Module-Name",
    };

    private const long MaxHashedBytes = 200L * 1024 * 1024;

    public static JsonObject Read(string? directory, List<string> notes)
    {
        var result = new JsonObject { ["scanned"] = directory is not null };
        var jars = new JsonArray();
        var markers = new JsonArray();
        result["jars"] = jars;
        result["requiredLibMarkers"] = markers;
        if (directory is null) return result;

        foreach (var folder in Folders)
        {
            var path = Path.Combine(directory, folder);
            if (!Directory.Exists(path)) continue;
            foreach (var file in Directory.EnumerateFiles(path).OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                var fileName = Path.GetFileName(file);
                if (fileName.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                {
                    jars.Add(ReadJar(file, folder, notes));
                }
                else if (folder == "userlib" && fileName.EndsWith(".RequiredLib", StringComparison.OrdinalIgnoreCase))
                {
                    // commons-io-2.11.0.jar.CommunityCommons.RequiredLib → (commons-io-2.11.0.jar, CommunityCommons)
                    var stem = fileName[..^".RequiredLib".Length];
                    var split = stem.LastIndexOf(".jar.", StringComparison.OrdinalIgnoreCase);
                    if (split <= 0) continue;
                    markers.Add(new JsonObject
                    {
                        ["jarFileName"] = stem[..(split + 4)],
                        ["module"] = stem[(split + 5)..],
                    });
                }
            }
        }

        var sbomPath = Path.Combine(directory, "vendorlib", "vendorlib-sbom.json");
        if (File.Exists(sbomPath))
        {
            try
            {
                result["sbom"] = ReadSbom(File.ReadAllText(sbomPath));
            }
            catch (Exception ex)
            {
                notes.Add($"vendorlib/vendorlib-sbom.json could not be read: {ex.Message}");
            }
        }
        return result;
    }

    private static JsonObject ReadJar(string file, string folder, List<string> notes)
    {
        var info = new FileInfo(file);
        var node = new JsonObject
        {
            ["folder"] = folder,
            ["fileName"] = info.Name,
            ["sizeBytes"] = info.Length,
        };

        try
        {
            if (info.Length <= MaxHashedBytes)
            {
                using var stream = File.OpenRead(file);
                node["sha256"] = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            }
        }
        catch (Exception ex)
        {
            notes.Add($"{folder}/{info.Name} could not be hashed: {ex.Message}");
        }

        try
        {
            using var zip = ZipFile.OpenRead(file);
            var poms = new JsonArray();
            var nestedJars = 0;
            foreach (var entry in zip.Entries)
            {
                var name = entry.FullName;
                if (name.StartsWith("META-INF/maven/", StringComparison.OrdinalIgnoreCase)
                    && name.EndsWith("/pom.properties", StringComparison.OrdinalIgnoreCase)
                    && entry.Length < 64 * 1024)
                {
                    var props = ParseProperties(ReadText(entry));
                    if (props.TryGetValue("artifactId", out var artifact))
                    {
                        poms.Add(new JsonObject
                        {
                            ["groupId"] = props.GetValueOrDefault("groupId"),
                            ["artifactId"] = artifact,
                            ["version"] = props.GetValueOrDefault("version"),
                            ["path"] = name,
                        });
                    }
                }
                else if (name.Equals("META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase) && entry.Length < 1024 * 1024)
                {
                    var manifest = ParseManifest(ReadText(entry));
                    var selected = new JsonObject();
                    foreach (var key in ManifestKeys)
                    {
                        if (manifest.TryGetValue(key, out var value)) selected[key] = value;
                    }
                    node["manifest"] = selected;
                }
                else if (name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                {
                    nestedJars++;
                }
            }
            node["pomProperties"] = poms;
            if (nestedJars > 0) node["nestedJars"] = nestedJars;
        }
        catch (Exception ex)
        {
            node["unreadable"] = ex.Message;
            notes.Add($"{folder}/{info.Name} could not be opened as a jar: {ex.Message}");
        }
        return node;
    }

    /// <summary>Keeps the SBOM's components (coordinates and SHA-256) and dependency graph.</summary>
    private static JsonObject ReadSbom(string json)
    {
        var doc = JsonNode.Parse(json) as JsonObject ?? new JsonObject();
        var components = new JsonArray();
        foreach (var c in doc["components"] as JsonArray ?? new JsonArray())
        {
            if (c is not JsonObject o) continue;
            string? sha256 = null;
            foreach (var hash in o["hashes"] as JsonArray ?? new JsonArray())
            {
                if (hash?["alg"]?.GetValue<string>() == "SHA-256") sha256 = hash["content"]?.GetValue<string>();
            }
            components.Add(new JsonObject
            {
                ["ref"] = Text(o["bom-ref"]) ?? Text(o["purl"]),
                ["group"] = Text(o["group"]),
                ["name"] = Text(o["name"]),
                ["version"] = Text(o["version"]),
                ["sha256"] = sha256,
            });
        }
        var dependencies = new JsonArray();
        foreach (var d in doc["dependencies"] as JsonArray ?? new JsonArray())
        {
            if (d is not JsonObject o) continue;
            dependencies.Add(new JsonObject
            {
                ["ref"] = Text(o["ref"]),
                ["dependsOn"] = new JsonArray((o["dependsOn"] as JsonArray ?? new JsonArray())
                    .Select(x => (JsonNode?)JsonValue.Create(Text(x))).ToArray()),
            });
        }
        return new JsonObject { ["components"] = components, ["dependencies"] = dependencies };
    }

    private static string? Text(JsonNode? node) =>
        node is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private static string ReadText(ZipArchiveEntry entry)
    {
        using var reader = new StreamReader(entry.Open());
        return reader.ReadToEnd();
    }

    private static Dictionary<string, string> ParseProperties(string text)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or '!') continue;
            var eq = line.IndexOfAny(new[] { '=', ':' });
            if (eq <= 0) continue;
            map[line[..eq].Trim()] = line[(eq + 1)..].Trim();
        }
        return map;
    }

    /// <summary>The manifest's main section; a line starting with a space continues the previous one.</summary>
    private static Dictionary<string, string> ParseManifest(string text)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? last = null;
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (raw.Length == 0) break; // end of the main section
            if (raw[0] == ' ' && last is not null)
            {
                map[last] += raw[1..];
                continue;
            }
            var colon = raw.IndexOf(':');
            if (colon <= 0) continue;
            last = raw[..colon].Trim();
            map[last] = raw[(colon + 1)..].Trim();
        }
        return map;
    }
}
