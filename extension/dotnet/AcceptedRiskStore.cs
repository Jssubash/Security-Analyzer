using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Reads and writes the app's accepted-risk decisions, <c>.security-analyzer/accepted-risks.json</c>
/// in the app folder. Kept with the app so the decisions are committed, shared with the team and
/// reviewed like any other change. The pane proposes a decision; this class validates it and
/// stamps who accepted it and when, so neither can be typed in. "Who" is the person's Git identity
/// (name and email, see <see cref="GitIdentity"/>) — the name their commits carry — with the Windows
/// account kept beside it; on a computer without a Git identity it is the Windows account alone.
/// </summary>
internal static class AcceptedRiskStore
{
    public const string RelativePath = ".security-analyzer/accepted-risks.json";
    private const int MinReasonLength = 15;
    private const int MaxReviewDays = 365;
    private static readonly Regex Date = new("^\\d{4}-\\d{2}-\\d{2}$", RegexOptions.Compiled);
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    public static string PathFor(string directory) => Path.Combine(directory, ".security-analyzer", "accepted-risks.json");

    /// <summary>The decisions as the pane reads them: <c>{ path, risks, error? }</c>.</summary>
    public static JsonObject Read(string? directory)
    {
        var result = new JsonObject { ["path"] = RelativePath, ["risks"] = new JsonArray() };
        if (directory is null) return result;
        var file = PathFor(directory);
        if (!File.Exists(file)) return result;
        try
        {
            var doc = JsonNode.Parse(File.ReadAllText(file)) as JsonObject;
            result["risks"] = (doc?["risks"] as JsonArray)?.DeepClone() ?? new JsonArray();
        }
        catch (Exception ex)
        {
            result["error"] = $"{RelativePath} could not be read ({ex.Message}); fix or delete it. Until then no risk counts as accepted.";
        }
        return result;
    }

    /// <summary>Adds or replaces the decision for the same advisory, library version and target.</summary>
    public static JsonObject Accept(string directory, JsonObject proposed)
    {
        var risk = new JsonObject
        {
            ["advisoryId"] = Text(proposed, "advisoryId"),
            ["scope"] = Text(proposed, "scope") is "library" or "widget" ? Text(proposed, "scope") : null,
            ["target"] = Text(proposed, "target"),
            ["package"] = Text(proposed, "package"),
            ["version"] = Text(proposed, "version"),
            ["reason"] = Text(proposed, "reason")?.Trim(),
            ["acceptedAt"] = DateTime.UtcNow.ToString("o"),
            ["reviewBy"] = Text(proposed, "reviewBy"),
        };
        var (gitName, gitEmail) = GitIdentity.Read(directory);
        risk["acceptedBy"] = gitName ?? Environment.UserName;
        risk["acceptedByEmail"] = gitName is null ? null : gitEmail;
        risk["acceptedByAccount"] = Environment.UserName;
        risk["acceptedBySource"] = gitName is null ? "windows" : "git";
        var problem = Validate(risk);
        if (problem is not null) throw new ArgumentException(problem);

        var risks = Load(directory);
        var key = Key(risk);
        for (var i = risks.Count - 1; i >= 0; i--)
        {
            if (risks[i] is JsonObject existing && Key(existing) == key) risks.RemoveAt(i);
        }
        risks.Add(risk);
        Save(directory, risks);
        return Read(directory);
    }

    public static JsonObject Revoke(string directory, JsonObject which)
    {
        var risks = Load(directory);
        var key = Key(which);
        for (var i = risks.Count - 1; i >= 0; i--)
        {
            if (risks[i] is JsonObject existing && Key(existing) == key) risks.RemoveAt(i);
        }
        Save(directory, risks);
        return Read(directory);
    }

    private static string? Validate(JsonObject r)
    {
        if (new[] { "advisoryId", "scope", "target", "package", "version" }.Any(k => string.IsNullOrWhiteSpace(Text(r, k))))
        {
            return "The advisory to accept is not identified.";
        }
        if ((Text(r, "reason") ?? "").Length < MinReasonLength)
        {
            return $"Explain why the risk is acceptable (at least {MinReasonLength} characters).";
        }
        var reviewBy = Text(r, "reviewBy");
        if (reviewBy is null || !Date.IsMatch(reviewBy) || !DateTime.TryParse(reviewBy, out var date))
        {
            return "Choose a review-by date.";
        }
        if (date.Date <= DateTime.Today) return "The review-by date must be in the future.";
        if (date.Date > DateTime.Today.AddDays(MaxReviewDays)) return $"Choose a review-by date within {MaxReviewDays} days.";
        return null;
    }

    private static JsonArray Load(string directory)
    {
        var file = PathFor(directory);
        if (!File.Exists(file)) return new JsonArray();
        // A file that cannot be parsed is not silently replaced: the team's decisions would be lost.
        var doc = JsonNode.Parse(File.ReadAllText(file)) as JsonObject
            ?? throw new InvalidOperationException($"{RelativePath} is not a JSON object; fix or delete it first.");
        return (doc["risks"] as JsonArray)?.DeepClone() as JsonArray ?? new JsonArray();
    }

    private static void Save(string directory, JsonArray risks)
    {
        var file = PathFor(directory);
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        var sorted = new JsonArray(risks.OfType<JsonObject>()
            .OrderBy(r => Text(r, "scope")).ThenBy(r => Text(r, "target")).ThenBy(r => Text(r, "advisoryId"))
            .Select(r => (JsonNode?)r.DeepClone()).ToArray());
        var doc = new JsonObject
        {
            ["description"] = "Security risks this team has reviewed and accepted, recorded by the Mendix Security Analyzer extension. "
                + "Each decision covers one advisory in one library version and lapses on its reviewBy date. Commit this file so decisions are shared and reviewed.",
            ["version"] = 1,
            ["risks"] = sorted,
        };
        var temp = file + ".tmp";
        File.WriteAllText(temp, doc.ToJsonString(Indented));
        File.Move(temp, file, overwrite: true);
    }

    private static string Key(JsonObject r) =>
        string.Join("|", Text(r, "scope"), Text(r, "target"), Text(r, "advisoryId"), Text(r, "package"), Text(r, "version"));

    private static string? Text(JsonObject o, string key) =>
        o[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
}
