using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Looks Java libraries up in OSV.dev, the open vulnerability database that aggregates the GitHub
/// Advisory Database, NVD-linked advisories and others for the Maven ecosystem.
/// <para>
/// Only Maven coordinates leave the machine — <c>group:artifact</c> and a version, the same
/// information as a line of a public build file. No model data, file names or paths are sent. The
/// check runs only when the user presses the button in the Java libraries tab.
/// </para>
/// <para>
/// Advisories are cached under %LOCALAPPDATA%\Mendix Security Analyzer\osv-cache, keyed by id and
/// last-modified time, so a second check only downloads what changed.
/// </para>
/// </summary>
internal sealed class OsvClient
{
    private const string Api = "https://api.osv.dev/v1";
    private static readonly Regex SafeId = new("^[A-Za-z0-9._:-]{1,80}$", RegexOptions.Compiled);
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(45) };

    static OsvClient()
    {
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("MendixSecurityAnalyzer/1.0");
    }

    private readonly string cacheFolder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mendix Security Analyzer", "osv-cache");

    /// <summary>
    /// <paramref name="packages"/>: <c>[{ name, version, ecosystem? }]</c> — Maven (<c>group:artifact</c>,
    /// the default) for Java libraries, npm for the JavaScript libraries bundled into widgets.
    /// Returns <c>{ results: [{ name, version, ids: [] }], vulns: { id: advisory } }</c>.
    /// </summary>
    public async Task<JsonObject> CheckAsync(JsonArray packages, CancellationToken cancel)
    {
        var queries = packages
            .OfType<JsonObject>()
            .Select(p => (name: p["name"]?.GetValue<string>(), version: p["version"]?.GetValue<string>(),
                ecosystem: p["ecosystem"]?.GetValue<string>() is "npm" ? "npm" : "Maven"))
            .Where(p => !string.IsNullOrWhiteSpace(p.name) && !string.IsNullOrWhiteSpace(p.version))
            .Select(p => (name: p.name!, version: p.version!, p.ecosystem))
            .Distinct()
            .ToList();

        var results = new JsonArray();
        var wanted = new Dictionary<string, string?>(StringComparer.Ordinal); // id → modified
        for (var offset = 0; offset < queries.Count; offset += 500)
        {
            var batch = queries.Skip(offset).Take(500).ToList();
            var body = new JsonObject
            {
                ["queries"] = new JsonArray(batch.Select(q => (JsonNode?)new JsonObject
                {
                    ["package"] = new JsonObject { ["ecosystem"] = q.ecosystem, ["name"] = q.name },
                    ["version"] = q.version,
                }).ToArray()),
            };
            using var response = await Http.PostAsJsonAsync($"{Api}/querybatch", body, cancel);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancel);
            var answers = json?["results"] as JsonArray ?? new JsonArray();
            for (var i = 0; i < batch.Count; i++)
            {
                var ids = new JsonArray();
                foreach (var v in answers.ElementAtOrDefault(i)?["vulns"] as JsonArray ?? new JsonArray())
                {
                    var id = v?["id"]?.GetValue<string>();
                    if (id is null || !SafeId.IsMatch(id)) continue;
                    ids.Add(id);
                    wanted[id] = v?["modified"]?.GetValue<string>();
                }
                results.Add(new JsonObject { ["name"] = batch[i].name, ["version"] = batch[i].version, ["ecosystem"] = batch[i].ecosystem, ["ids"] = ids });
            }
        }

        var vulns = new JsonObject();
        using var gate = new SemaphoreSlim(6);
        var fetched = await Task.WhenAll(wanted.Select(async kv =>
        {
            await gate.WaitAsync(cancel);
            try
            {
                return (id: kv.Key, advisory: await AdvisoryAsync(kv.Key, kv.Value, cancel));
            }
            finally
            {
                gate.Release();
            }
        }));
        foreach (var (id, advisory) in fetched)
        {
            if (advisory is not null) vulns[id] = advisory;
        }

        return new JsonObject
        {
            ["source"] = "OSV.dev",
            ["checkedAt"] = DateTime.UtcNow.ToString("o"),
            ["results"] = results,
            ["vulns"] = vulns,
        };
    }

    private async Task<JsonObject?> AdvisoryAsync(string id, string? modified, CancellationToken cancel)
    {
        var cacheFile = Path.Combine(cacheFolder, id.Replace(':', '_') + ".json");
        try
        {
            if (File.Exists(cacheFile) && JsonNode.Parse(await File.ReadAllTextAsync(cacheFile, cancel)) is JsonObject cached
                && (modified is null || cached["modified"]?.GetValue<string>() == modified))
            {
                return cached;
            }
        }
        catch
        {
            // A damaged cache entry is simply fetched again.
        }

        using var response = await Http.GetAsync($"{Api}/vulns/{Uri.EscapeDataString(id)}", cancel);
        if (!response.IsSuccessStatusCode) return null;
        var full = await response.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancel);
        if (full is null) return null;
        var trimmed = Trim(full);
        try
        {
            Directory.CreateDirectory(cacheFolder);
            await File.WriteAllTextAsync(cacheFile, trimmed.ToJsonString(), cancel);
        }
        catch
        {
            // Caching is an optimisation only.
        }
        return trimmed;
    }

    /// <summary>
    /// Keeps what the pane shows. The per-package version lists in <c>affected</c> can run to
    /// thousands of entries and are dropped; the ranges (introduced / fixed) are kept.
    /// </summary>
    private static JsonObject Trim(JsonObject full)
    {
        string? Text(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
        var details = Text(full["details"]);
        if (details is { Length: > 1500 }) details = details[..1500] + "…";

        var affected = new JsonArray();
        foreach (var a in full["affected"] as JsonArray ?? new JsonArray())
        {
            if (a is not JsonObject o) continue;
            affected.Add(new JsonObject
            {
                ["package"] = o["package"]?.DeepClone(),
                ["ranges"] = o["ranges"]?.DeepClone(),
            });
        }
        var references = new JsonArray();
        foreach (var r in (full["references"] as JsonArray ?? new JsonArray()).Take(8))
        {
            if (Text(r?["url"]) is { } url && url.StartsWith("https://", StringComparison.Ordinal)) references.Add(url);
        }
        return new JsonObject
        {
            ["id"] = Text(full["id"]),
            ["modified"] = Text(full["modified"]),
            ["published"] = Text(full["published"]),
            ["summary"] = Text(full["summary"]),
            ["details"] = details,
            ["aliases"] = full["aliases"]?.DeepClone(),
            ["severity"] = full["severity"]?.DeepClone(),
            ["databaseSeverity"] = Text(full["database_specific"]?["severity"]),
            ["cwes"] = full["database_specific"]?["cwe_ids"]?.DeepClone(),
            ["affected"] = affected,
            ["references"] = references,
        };
    }

    /// <summary>The advisory's page on osv.dev, for an id that came back from OSV.</summary>
    public static Uri? AdvisoryPage(string? id) =>
        id is not null && SafeId.IsMatch(id) ? new Uri($"https://osv.dev/vulnerability/{Uri.EscapeDataString(id)}") : null;
}
