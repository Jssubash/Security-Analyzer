using System.IO.Compression;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Inventories the widget packages in <c>widgets/</c>, for the Upgrades tab.
/// <para>
/// A widget package (<c>.mpk</c>) is a zip whose <c>package.xml</c> names the package and its
/// version (<c>&lt;clientModule name version&gt;</c> — not the root <c>&lt;package version&gt;</c>,
/// which is the manifest schema and is 1.0 for every widget), and whose widget XML files give
/// each widget's id, display name and platform. Packages record no Marketplace content id, so
/// matching them to the Marketplace is left to the pane (<c>marketplace.ts</c>).
/// </para>
/// </summary>
internal static class WidgetScanner
{
    private static readonly Regex ClientModule = new("<clientModule\\b[^>]*>", RegexOptions.Compiled);
    private static readonly Regex Widget = new("<widget\\b[^>]*>", RegexOptions.Compiled);
    private static readonly Regex DisplayName = new("<name>\\s*([^<]*?)\\s*</name>", RegexOptions.Compiled);

    public static JsonObject Read(string? directory, List<string> notes)
    {
        var result = new JsonObject { ["scanned"] = directory is not null };
        var packages = new JsonArray();
        result["packages"] = packages;
        if (directory is null) return result;
        var folder = Path.Combine(directory, "widgets");
        if (!Directory.Exists(folder)) return result;

        foreach (var file in Directory.EnumerateFiles(folder, "*.mpk").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            var node = new JsonObject { ["fileName"] = Path.GetFileName(file) };
            try
            {
                using var zip = ZipFile.OpenRead(file);
                var packageXml = zip.GetEntry("package.xml");
                if (packageXml is not null)
                {
                    var tag = ClientModule.Match(Read(packageXml)).Value;
                    node["name"] = Attribute(tag, "name");
                    node["version"] = Attribute(tag, "version");
                }
                var widgets = new JsonArray();
                var dependencies = new SortedSet<(string Name, string Version, bool Transitive)>();
                var fromText = new SortedSet<(string Name, string Version, bool Transitive)>();
                foreach (var entry in zip.Entries)
                {
                    // The JavaScript libraries bundled into the widget, written by the widget build
                    // (rollup-plugin-license): dependencies.json, with dependencies.txt as a fallback.
                    if (entry.Name.Equals("dependencies.json", StringComparison.OrdinalIgnoreCase) && entry.Length < 4 * 1024 * 1024)
                    {
                        ReadDependenciesJson(Read(entry), dependencies);
                        continue;
                    }
                    if (entry.Name.Equals("dependencies.txt", StringComparison.OrdinalIgnoreCase) && entry.Length < 8 * 1024 * 1024)
                    {
                        ReadDependenciesText(Read(entry), fromText);
                        continue;
                    }
                    // Widget definitions sit at the package root; nested XML is translations, schemas, etc.
                    if (entry.FullName.Contains('/') || !entry.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)
                        || entry.FullName.Equals("package.xml", StringComparison.OrdinalIgnoreCase) || entry.Length > 2 * 1024 * 1024)
                    {
                        continue;
                    }
                    var xml = Read(entry);
                    var tag = Widget.Match(xml).Value;
                    var id = Attribute(tag, "id");
                    if (id is null) continue;
                    widgets.Add(new JsonObject
                    {
                        ["id"] = id,
                        ["name"] = DisplayName.Match(xml) is { Success: true } m ? m.Groups[1].Value : null,
                        ["pluginWidget"] = Attribute(tag, "pluginWidget") == "true",
                        ["supportedPlatform"] = Attribute(tag, "supportedPlatform"),
                    });
                }
                node["widgets"] = widgets;
                // dependencies.txt carries no direct/transitive flag: it is used only when there is no JSON.
                if (dependencies.Count == 0) dependencies.UnionWith(fromText);
                node["dependencies"] = new JsonArray(dependencies
                    .GroupBy(d => (d.Name, d.Version))
                    // Listed as direct anywhere in the package (several widgets share one) makes it direct.
                    .Select(g => (JsonNode?)new JsonObject { ["name"] = g.Key.Name, ["version"] = g.Key.Version, ["transitive"] = g.All(d => d.Transitive) })
                    .ToArray());
            }
            catch (Exception ex)
            {
                node["unreadable"] = ex.Message;
                notes.Add($"widgets/{Path.GetFileName(file)} could not be read: {ex.Message}");
            }
            packages.Add(node);
        }
        return result;
    }

    /// <summary>
    /// <c>[{"mobx":{"version":"6.12.3","transitive":false,...}}, ...]</c>. Native widgets flag each entry:
    /// <c>transitive: true</c> is pulled in by another dependency (including the widget build tools);
    /// web widgets list only what was bundled, with no flag, and those count as direct.
    /// </summary>
    private static void ReadDependenciesJson(string json, SortedSet<(string Name, string Version, bool Transitive)> into)
    {
        try
        {
            if (JsonNode.Parse(json) is not JsonArray list) return;
            foreach (var item in list.OfType<JsonObject>())
            {
                foreach (var (name, value) in item)
                {
                    var version = value?["version"] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
                    var transitive = value?["transitive"] is JsonValue t && t.TryGetValue<bool>(out var b) && b;
                    if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(version)) into.Add((name, version, transitive));
                }
            }
        }
        catch
        {
            // A malformed manifest leaves the text one to fill in.
        }
    }

    /// <summary>Blocks of <c>Name: x</c> / <c>Version: y</c> lines.</summary>
    private static void ReadDependenciesText(string text, SortedSet<(string Name, string Version, bool Transitive)> into)
    {
        string? name = null;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("Name:", StringComparison.Ordinal)) name = line[5..].Trim();
            else if (line.StartsWith("Version:", StringComparison.Ordinal) && name is not null)
            {
                var version = line[8..].Trim();
                if (name.Length > 0 && version.Length > 0) into.Add((name, version, false));
                name = null;
            }
        }
    }

    private static string Read(ZipArchiveEntry entry)
    {
        using var reader = new StreamReader(entry.Open());
        return reader.ReadToEnd();
    }

    private static string? Attribute(string tag, string name)
    {
        var m = Regex.Match(tag, $"\\s{Regex.Escape(name)}=\"([^\"]*)\"");
        return m.Success ? m.Groups[1].Value : null;
    }
}
