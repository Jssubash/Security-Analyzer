using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Reads version history from the Mendix Marketplace Content API, for the Upgrades tab: every
/// published version of a module or widget with the minimum Mendix version it supports.
/// <para>
/// The API needs a Mendix Personal Access Token (created at user-settings.mendix.com ▸ Developer
/// Settings, with the Marketplace content read scope). The token is taken from, in order: the
/// one the user typed in the pane, the one they chose to remember (encrypted with Windows DPAPI
/// for the current Windows user, under %LOCALAPPDATA%\Mendix Security Analyzer), and the
/// <c>MENDIX_PAT</c> environment variable. It is sent only to marketplace-api.mendix.com, never
/// to the pane, and never written to a log or a report.
/// </para>
/// <para>
/// What is sent: Marketplace content ids (public numbers such as 170 for Community Commons).
/// Nothing from the app model. The catalog (needed only to match widgets by name) is cached for
/// a day, and version lists for an hour.
/// </para>
/// </summary>
internal sealed class MarketplaceClient
{
    private const string Api = "https://marketplace-api.mendix.com/v1";
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(60) };
    private static readonly string Folder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mendix Security Analyzer");
    private static readonly string TokenFile = Path.Combine(Folder, "marketplace-token.bin");
    private static readonly string CacheFolder = Path.Combine(Folder, "marketplace-cache");

    static MarketplaceClient()
    {
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("MendixSecurityAnalyzer/1.0");
    }

    private readonly string token;

    private MarketplaceClient(string token) => this.token = token;

    // ------------------------------------------------------------------ token

    public enum TokenSource { None, Typed, Remembered, Environment }

    /// <summary>Where a token would come from right now, without revealing it.</summary>
    public static TokenSource AvailableToken(string? typed)
    {
        if (!string.IsNullOrWhiteSpace(typed)) return TokenSource.Typed;
        if (LoadRemembered() is not null) return TokenSource.Remembered;
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MENDIX_PAT"))) return TokenSource.Environment;
        return TokenSource.None;
    }

    public static MarketplaceClient? Create(string? typed, bool remember)
    {
        var token = !string.IsNullOrWhiteSpace(typed) ? typed.Trim() : LoadRemembered() ?? Environment.GetEnvironmentVariable("MENDIX_PAT")?.Trim();
        if (string.IsNullOrWhiteSpace(token)) return null;
        if (remember && !string.IsNullOrWhiteSpace(typed)) Remember(token);
        return new MarketplaceClient(token);
    }

    public static void Forget()
    {
        try
        {
            if (File.Exists(TokenFile)) File.Delete(TokenFile);
        }
        catch
        {
            // Nothing to forget, or it is already gone.
        }
    }

    private static void Remember(string token)
    {
        Directory.CreateDirectory(Folder);
        File.WriteAllBytes(TokenFile, Dpapi.Protect(Encoding.UTF8.GetBytes(token)));
    }

    private static string? LoadRemembered()
    {
        try
        {
            return File.Exists(TokenFile) ? Encoding.UTF8.GetString(Dpapi.Unprotect(File.ReadAllBytes(TokenFile))) : null;
        }
        catch
        {
            // Encrypted for another Windows user or damaged: treat as absent.
            return null;
        }
    }

    // ------------------------------------------------------------------ API

    /// <summary>Every published version of a content item, newest first as the API returns them.</summary>
    public async Task<JsonArray> VersionsAsync(int contentId, CancellationToken cancel)
    {
        // "v2": lists cached before paging was fixed hold only the first page and must not be reused.
        var cacheFile = Path.Combine(CacheFolder, $"versions-v2-{contentId}.json");
        if (Fresh(cacheFile, TimeSpan.FromHours(1)) is JsonArray cached) return cached;

        var all = new JsonArray();
        // The API pages at its own size (20 for version lists, whatever `limit` asks for), so read
        // until a page comes back empty and advance by what actually arrived.
        for (int offset = 0, pages = 0; pages < 500; pages++)
        {
            var page = await GetAsync($"{Api}/content/{contentId}/versions?limit=100&offset={offset}", cancel);
            var items = page?["items"] as JsonArray ?? new JsonArray();
            foreach (var item in items)
            {
                if (item is not JsonObject v) continue;
                all.Add(new JsonObject
                {
                    ["versionNumber"] = Text(v["versionNumber"]),
                    ["versionId"] = Text(v["versionId"]),
                    ["minSupportedMendixVersion"] = Text(v["minSupportedMendixVersion"]),
                    ["publicationDate"] = Text(v["publicationDate"]),
                    ["name"] = Text(v["name"]),
                });
            }
            if (items.Count == 0) break;
            offset += items.Count;
        }
        Save(cacheFile, all);
        return all;
    }

    /// <summary>
    /// The public catalog reduced to what widget matching needs: id, name, type, publisher,
    /// support category, latest version. Private content the token can see is included, flagged.
    /// </summary>
    public async Task<JsonArray> CatalogAsync(CancellationToken cancel)
    {
        var cacheFile = Path.Combine(CacheFolder, "catalog.json");
        if (Fresh(cacheFile, TimeSpan.FromDays(1)) is JsonArray cached) return cached;

        var all = new JsonArray();
        for (int offset = 0, pages = 0; pages < 2000; pages++)
        {
            var page = await GetAsync($"{Api}/content?limit=100&offset={offset}", cancel);
            var items = page?["items"] as JsonArray ?? new JsonArray();
            foreach (var item in items)
            {
                if (item is not JsonObject c) continue;
                var latest = c["latestVersion"] as JsonObject;
                all.Add(new JsonObject
                {
                    ["contentId"] = c["contentId"]?.DeepClone(),
                    ["name"] = Text(latest?["name"]) ?? Text(c["name"]),
                    ["type"] = Text(c["type"]),
                    ["publisher"] = Text(c["publisher"]),
                    ["supportCategory"] = Text(c["supportCategory"]),
                    ["isPrivate"] = c["isPrivate"]?.DeepClone(),
                    ["latestVersion"] = Text(latest?["versionNumber"]),
                    ["latestMinMendix"] = Text(latest?["minSupportedMendixVersion"]),
                });
            }
            if (items.Count == 0) break;
            offset += items.Count;
        }
        Save(cacheFile, all);
        return all;
    }

    private async Task<JsonObject?> GetAsync(string url, CancellationToken cancel)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("MxToken", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await Http.SendAsync(request, cancel);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            throw new UnauthorizedAccessException(
                "The Marketplace refused the token. Check that it has not expired and that it was created with the Marketplace content read scope.");
        }
        if (response.StatusCode == HttpStatusCode.NotFound) return null; // private or removed content
        response.EnsureSuccessStatusCode();
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(cancel)) as JsonObject;
    }

    private static string? Text(JsonNode? node) =>
        node is JsonValue v ? (v.TryGetValue<string>(out var s) ? s : v.ToJsonString()) : null;

    private static JsonNode? Fresh(string file, TimeSpan maxAge)
    {
        try
        {
            if (File.Exists(file) && DateTime.UtcNow - File.GetLastWriteTimeUtc(file) < maxAge) return JsonNode.Parse(File.ReadAllText(file));
        }
        catch
        {
            // A damaged cache entry is fetched again.
        }
        return null;
    }

    private static void Save(string file, JsonNode node)
    {
        try
        {
            Directory.CreateDirectory(CacheFolder);
            File.WriteAllText(file, node.ToJsonString());
        }
        catch
        {
            // Caching is an optimisation only.
        }
    }

    /// <summary>Windows DPAPI (CryptProtectData), scoped to the current Windows user.</summary>
    private static class Dpapi
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DataBlob
        {
            public int Size;
            public IntPtr Data;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(ref DataBlob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        private const int UiForbidden = 0x1;

        public static byte[] Protect(byte[] data) => Run(data, protect: true);

        public static byte[] Unprotect(byte[] data) => Run(data, protect: false);

        private static byte[] Run(byte[] data, bool protect)
        {
            var input = new DataBlob { Size = data.Length, Data = Marshal.AllocHGlobal(data.Length) };
            var output = new DataBlob();
            try
            {
                Marshal.Copy(data, 0, input.Data, data.Length);
                var ok = protect
                    ? CryptProtectData(ref input, "Mendix Security Analyzer", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, UiForbidden, ref output)
                    : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, UiForbidden, ref output);
                if (!ok) throw new InvalidOperationException($"DPAPI failed ({Marshal.GetLastWin32Error()}).");
                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, output.Size);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(input.Data);
                if (output.Data != IntPtr.Zero) LocalFree(output.Data);
            }
        }
    }
}
