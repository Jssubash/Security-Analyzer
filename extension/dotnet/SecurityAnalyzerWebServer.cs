using System.ComponentModel.Composition;
using System.Net;
using Mendix.StudioPro.ExtensionsAPI.UI.WebServer;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Serves the pane's web page from the extension's <c>wwwroot</c> folder through Studio Pro's
/// internal web server. Only the three known files are served; any other path is a 404, so a
/// crafted URL cannot read other files next to the extension.
/// </summary>
[Export(typeof(WebServerExtension))]
public sealed class SecurityAnalyzerWebServer : WebServerExtension
{
    public const string Route = "security-analyzer";

    private static readonly Dictionary<string, string> Files = new(StringComparer.OrdinalIgnoreCase)
    {
        ["index.html"] = "text/html; charset=utf-8",
        ["app.js"] = "text/javascript; charset=utf-8",
        ["app.css"] = "text/css; charset=utf-8",
    };

    private static readonly string WebRoot =
        Path.Combine(Path.GetDirectoryName(typeof(SecurityAnalyzerWebServer).Assembly.Location)!, "wwwroot");

    public override void InitializeWebServer(IWebServer webServer) => webServer.AddRoute(Route, ServeAsync);

    private static async Task ServeAsync(HttpListenerRequest request, HttpListenerResponse response, CancellationToken cancellationToken)
    {
        var name = request.Url?.Segments.LastOrDefault()?.Trim('/') ?? "";
        if (name.Length == 0 || name.Equals(Route, StringComparison.OrdinalIgnoreCase)) name = "index.html";

        if (!Files.TryGetValue(name, out var contentType) || !File.Exists(Path.Combine(WebRoot, name)))
        {
            response.StatusCode = 404;
            response.Close();
            return;
        }

        var bytes = await File.ReadAllBytesAsync(Path.Combine(WebRoot, name), cancellationToken);
        response.StatusCode = 200;
        response.ContentType = contentType;
        response.ContentLength64 = bytes.Length;
        response.Headers["Cache-Control"] = "no-store";
        await response.OutputStream.WriteAsync(bytes, cancellationToken);
        response.Close();
    }
}
