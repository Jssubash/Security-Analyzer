using System.IO.Compression;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Reads Maven Central for the "How to resolve" advice on a vulnerable Java library: which releases
/// exist, and for a few candidate releases, which Java version their classes were compiled for and
/// which libraries they bundle. The pane decides which release to suggest (src/version-advice.ts).
/// <para>
/// Only Maven coordinates leave the machine — the same group, artifact and version as a line of a
/// public build file. Candidate jars are read in memory and never written to disk; only the facts
/// taken from them are cached, under %LOCALAPPDATA%\Mendix Security Analyzer\maven-cache. A
/// release never changes on Maven Central, so those facts are kept; release lists are re-read
/// after 12 hours.
/// </para>
/// </summary>
internal sealed class MavenClient
{
    private const string Repository = "https://repo1.maven.org/maven2";
    private const long MaxJarBytes = 64L * 1024 * 1024;
    private static readonly TimeSpan VersionListLifetime = TimeSpan.FromHours(12);

    /// <summary>Maven group, artifact and version characters only, so nothing else reaches a URL or a file name.</summary>
    private static readonly Regex Safe = new("^[A-Za-z0-9._+-]{1,120}$", RegexOptions.Compiled);

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(60) };

    static MavenClient()
    {
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("MendixSecurityAnalyzer/1.0");
    }

    private readonly string cacheFolder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mendix Security Analyzer", "maven-cache");

    public static bool IsSafe(string? part) => part is not null && Safe.IsMatch(part);

    /// <summary>The page of one release on Maven Central's website, for "Open on Maven Central".</summary>
    public static Uri? ReleasePage(string? group, string? artifact, string? version) =>
        !IsSafe(group) || !IsSafe(artifact) ? null
            : string.IsNullOrEmpty(version) ? new Uri($"https://central.sonatype.com/artifact/{group}/{artifact}/versions")
            : IsSafe(version) ? new Uri($"https://central.sonatype.com/artifact/{group}/{artifact}/{version}")
            : null;

    /// <summary><c>["group:artifact", …]</c> → <c>{ "group:artifact": ["1.0", …] | { error } }</c>.</summary>
    public async Task<JsonObject> VersionsAsync(IEnumerable<string> libraries, CancellationToken cancel)
    {
        var result = new JsonObject();
        foreach (var ga in libraries.Distinct())
        {
            var parts = ga.Split(':');
            if (parts.Length != 2 || !IsSafe(parts[0]) || !IsSafe(parts[1])) continue;
            try
            {
                result[ga] = await VersionListAsync(parts[0], parts[1], cancel);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancel.IsCancellationRequested)
            {
                result[ga] = new JsonObject { ["error"] = Describe(ex) };
            }
        }
        return result;
    }

    private async Task<JsonArray> VersionListAsync(string group, string artifact, CancellationToken cancel)
    {
        var cacheFile = Path.Combine(cacheFolder, $"versions-{group}_{artifact}.json");
        if (File.Exists(cacheFile) && DateTime.UtcNow - File.GetLastWriteTimeUtc(cacheFile) < VersionListLifetime
            && JsonNode.Parse(await File.ReadAllTextAsync(cacheFile, cancel)) is JsonArray cached)
        {
            return cached;
        }
        var url = $"{Repository}/{group.Replace('.', '/')}/{artifact}/maven-metadata.xml";
        var xml = XDocument.Parse(await Http.GetStringAsync(url, cancel));
        var versions = new JsonArray(xml.Descendants("version").Select(v => (JsonNode?)JsonValue.Create(v.Value.Trim())).ToArray());
        Directory.CreateDirectory(cacheFolder);
        await File.WriteAllTextAsync(cacheFile, versions.ToJsonString(), cancel);
        return versions;
    }

    /// <summary>
    /// <c>[{ group, artifact, version }]</c> → <c>{ "group:artifact@version": { classMajor, poms: [{ group, artifact, version }] } | { error } }</c>.
    /// </summary>
    public async Task<JsonObject> InspectAsync(JsonArray candidates, CancellationToken cancel)
    {
        var wanted = candidates.OfType<JsonObject>()
            .Select(c => (group: c["group"]?.GetValue<string>(), artifact: c["artifact"]?.GetValue<string>(), version: c["version"]?.GetValue<string>()))
            .Where(c => IsSafe(c.group) && IsSafe(c.artifact) && IsSafe(c.version))
            .Distinct()
            .ToList();
        using var gate = new SemaphoreSlim(4);
        var inspected = await Task.WhenAll(wanted.Select(async c =>
        {
            await gate.WaitAsync(cancel);
            try
            {
                return (key: $"{c.group}:{c.artifact}@{c.version}", facts: await JarFactsAsync(c.group!, c.artifact!, c.version!, cancel));
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancel.IsCancellationRequested)
            {
                return (key: $"{c.group}:{c.artifact}@{c.version}", facts: (JsonNode)new JsonObject { ["error"] = Describe(ex) });
            }
            finally
            {
                gate.Release();
            }
        }));
        var result = new JsonObject();
        foreach (var (key, facts) in inspected) result[key] = facts;
        return result;
    }

    private async Task<JsonNode> JarFactsAsync(string group, string artifact, string version, CancellationToken cancel)
    {
        var cacheFile = Path.Combine(cacheFolder, $"jar-{group}_{artifact}_{version}.json");
        if (File.Exists(cacheFile))
        {
            try
            {
                if (JsonNode.Parse(await File.ReadAllTextAsync(cacheFile, cancel)) is JsonObject cached) return cached;
            }
            catch
            {
                // A damaged cache entry is simply read again.
            }
        }

        var url = $"{Repository}/{group.Replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar";
        using var response = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancel);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > MaxJarBytes) return new JsonObject { ["error"] = "the jar is too large to inspect" };
        using var buffer = new MemoryStream();
        await response.Content.CopyToAsync(buffer, cancel);
        if (buffer.Length > MaxJarBytes) return new JsonObject { ["error"] = "the jar is too large to inspect" };
        buffer.Position = 0;

        int? classMajor = null;
        var poms = new JsonArray();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Read))
        {
            var header = new byte[8];
            foreach (var entry in zip.Entries)
            {
                var name = entry.FullName;
                if (name.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    // Multi-release jars keep newer-Java variants under META-INF/versions/<n>/; the
                    // base classes are what an older Java runs, so only those set the requirement.
                    if (name.StartsWith("META-INF/", StringComparison.OrdinalIgnoreCase) || name.EndsWith("module-info.class", StringComparison.Ordinal)) continue;
                    using var stream = entry.Open();
                    if (await stream.ReadAtLeastAsync(header, 8, throwOnEndOfStream: false, cancel) < 8) continue;
                    if (header[0] != 0xCA || header[1] != 0xFE || header[2] != 0xBA || header[3] != 0xBE) continue;
                    var major = (header[6] << 8) | header[7];
                    if (classMajor is null || major > classMajor) classMajor = major;
                }
                else if (name.StartsWith("META-INF/maven/", StringComparison.OrdinalIgnoreCase) && name.EndsWith("/pom.properties", StringComparison.OrdinalIgnoreCase))
                {
                    using var reader = new StreamReader(entry.Open());
                    var properties = (await reader.ReadToEndAsync(cancel))
                        .Split('\n')
                        .Select(l => l.Trim())
                        .Where(l => l.Length > 0 && l[0] != '#' && l.Contains('='))
                        .Select(l => l.Split('=', 2))
                        .GroupBy(p => p[0].Trim())
                        .ToDictionary(g => g.Key, g => g.First()[1].Trim());
                    if (properties.TryGetValue("artifactId", out var pomArtifact))
                    {
                        poms.Add(new JsonObject
                        {
                            ["group"] = properties.GetValueOrDefault("groupId"),
                            ["artifact"] = pomArtifact,
                            ["version"] = properties.GetValueOrDefault("version"),
                        });
                    }
                }
            }
        }

        var facts = new JsonObject { ["classMajor"] = classMajor, ["poms"] = poms };
        Directory.CreateDirectory(cacheFolder);
        await File.WriteAllTextAsync(cacheFile, facts.ToJsonString(), cancel);
        return facts;
    }

    private static string Describe(Exception ex) => ex switch
    {
        HttpRequestException { StatusCode: System.Net.HttpStatusCode.NotFound } => "not found on Maven Central",
        HttpRequestException http => $"Maven Central could not be reached ({http.Message})",
        TaskCanceledException => "Maven Central did not answer in time",
        _ => ex.Message,
    };
}
