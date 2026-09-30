using System.Text.Json.Nodes;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Reduces credentials found in the model to the features the weakness check needs.
///
/// The administrator and demo-user passwords are the only plaintext secrets the security units
/// hold. They are replaced here, before the snapshot leaves the host, so the value never reaches
/// the web view, an exported report, or a diagnostic dump. The shape must match
/// <c>RedactedSecret</c> in <c>src/snapshot/types.ts</c>.
/// </summary>
internal static class SecretRedactor
{
    private static readonly HashSet<string> SecretPropertyNames =
        new(StringComparer.OrdinalIgnoreCase) { "adminPassword", "password" };

    public static bool IsSecretProperty(string propertyName) => SecretPropertyNames.Contains(propertyName);

    public static JsonObject Redact(string value) => new()
    {
        ["$redacted"] = true,
        ["length"] = value.Length,
        ["hasDigit"] = value.Any(char.IsAsciiDigit),
        ["hasLower"] = value.Any(char.IsAsciiLetterLower),
        ["hasUpper"] = value.Any(char.IsAsciiLetterUpper),
        ["hasSymbol"] = value.Any(c => !char.IsAsciiLetterOrDigit(c)),
    };
}
