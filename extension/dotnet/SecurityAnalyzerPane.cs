using System.ComponentModel.Composition;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Mendix.StudioPro.ExtensionsAPI.Model;
using Mendix.StudioPro.ExtensionsAPI.Services;
using Mendix.StudioPro.ExtensionsAPI.UI.DockablePane;
using Mendix.StudioPro.ExtensionsAPI.UI.Services;
using Mendix.StudioPro.ExtensionsAPI.UI.WebView;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>The dockable "Security Analyzer" pane.</summary>
[Export(typeof(DockablePaneExtension))]
public sealed class SecurityAnalyzerPane : DockablePaneExtension
{
    public const string PaneId = "mendix-governance-security-analyzer";

    private readonly IUntypedModelAccessService untypedModel;
    private readonly IDockingWindowService dockingWindows;
    private readonly ILogService log;

    [ImportingConstructor]
    public SecurityAnalyzerPane(
        IUntypedModelAccessService untypedModel,
        IDockingWindowService dockingWindows,
        ILogService log)
    {
        this.untypedModel = untypedModel;
        this.dockingWindows = dockingWindows;
        this.log = log;
    }

    public override string Id => PaneId;

    public override DockablePaneViewModelBase Open() =>
        new SecurityAnalyzerPaneViewModel(WebServerBaseUrl, () => CurrentApp, untypedModel, dockingWindows, log)
        {
            Title = "Security Analyzer",
        };
}

/// <summary>
/// Hosts the web page and answers its messages. Everything runs on Studio Pro's UI thread,
/// which is where the model may be read.
/// </summary>
internal sealed class SecurityAnalyzerPaneViewModel : WebViewDockablePaneViewModel
{
    private readonly Uri baseUrl;
    private readonly Func<IModel?> currentApp;
    private readonly IUntypedModelAccessService untypedModel;
    private readonly IDockingWindowService dockingWindows;
    private readonly ILogService log;
    private IWebView? webView;

    public SecurityAnalyzerPaneViewModel(
        Uri baseUrl,
        Func<IModel?> currentApp,
        IUntypedModelAccessService untypedModel,
        IDockingWindowService dockingWindows,
        ILogService log)
    {
        this.baseUrl = baseUrl;
        this.currentApp = currentApp;
        this.untypedModel = untypedModel;
        this.dockingWindows = dockingWindows;
        this.log = log;
    }

    public override void InitWebView(IWebView view)
    {
        webView = view;
        view.Address = new Uri(baseUrl, $"{SecurityAnalyzerWebServer.Route}/index.html");
        view.MessageReceived += OnMessageReceived;
    }

    private void OnMessageReceived(object? sender, MessageReceivedEventArgs args)
    {
        try
        {
            switch (args.Message)
            {
                case "RunAnalysis":
                    SendSnapshot();
                    break;
                case "OpenUnit":
                    OpenUnit(ReadString(args, "unitId"), ReadString(args, "entity"));
                    break;
                case "ExportReport":
                    ExportReport(ReadString(args, "fileName"), ReadString(args, "content"));
                    break;
                case "AnalysisComplete":
                    var failures = ReadInt(args, "failures");
                    BadgeValue = failures;
                    IsBadgeVisible = failures > 0;
                    break;
            }
        }
        catch (Exception ex)
        {
            log.Error($"Security Analyzer: handling '{args.Message}' failed", ex);
        }
    }

    private void SendSnapshot()
    {
        var app = currentApp();
        if (app is null)
        {
            Post("SnapshotFailed", new { error = "No app is open in Studio Pro." });
            return;
        }
        try
        {
            var watch = Stopwatch.StartNew();
            var root = untypedModel.GetUntypedModel(app);
            var snapshot = new ModelSnapshotReader().Read(app, root);
            var json = snapshot.ToJsonString();
            log.Info($"Security Analyzer: read the model in {watch.ElapsedMilliseconds} ms ({json.Length / 1024} KB)");
            SaveLastSnapshot(json);
            Post("Snapshot", new { json });
        }
        catch (Exception ex)
        {
            log.Error("Security Analyzer: reading the model failed", ex);
            Post("SnapshotFailed", new { error = $"The model could not be read: {ex.Message}" });
        }
    }

    /// <summary>
    /// Opens a document, and — when the finding is about an entity — selects that entity in its
    /// domain model, so a model with fifty entities does not leave the developer searching the
    /// canvas for the one the finding names.
    /// </summary>
    private void OpenUnit(string? unitId, string? entityQualifiedName)
    {
        var app = currentApp();
        if (app is null || string.IsNullOrEmpty(unitId))
        {
            Post("OpenUnitResult", new { ok = false, error = "No app is open." });
            return;
        }

        if (!string.IsNullOrEmpty(entityQualifiedName) && TryOpenEntity(app, entityQualifiedName))
        {
            Post("OpenUnitResult", new { ok = true, error = (string?)null });
            return;
        }

        if (TryOpenById(app, unitId) || TryOpenByName(app, unitId))
        {
            Post("OpenUnitResult", new { ok = true, error = (string?)null });
            return;
        }

        // The Extensions API has no nanoflow type (10.24 through 11.12), so a nanoflow can be
        // unreachable to it. Say where the document is instead of failing silently.
        var (name, location) = Locate(app, unitId);
        Post("OpenUnitResult", new
        {
            ok = false,
            error = (string?)(location is null
                ? "Studio Pro could not open that document."
                : $"Studio Pro's extension API cannot open this document directly. Find it in the App Explorer at {location}."),
            name,
            location,
        });
    }

    private bool TryOpenById(IModel app, string unitId)
    {
        try
        {
            return app.TryGetAbstractUnitById(unitId, out var unit) && unit is not null && dockingWindows.TryOpenEditor(unit, null);
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: opening {unitId} by id failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Finds the document by name among its module's typed documents and opens that. A document
    /// kind the API does not model by id may still be listed as a document of its folder.
    /// </summary>
    private bool TryOpenByName(IModel app, string unitId)
    {
        try
        {
            var target = FindUntypedUnit(app, unitId);
            if (target is null) return false;
            var (moduleName, name) = target.Value;
            var module = app.Root.GetModules().FirstOrDefault(m => m.Name == moduleName);
            if (module is null) return false;
            var documents = DocumentsOf(module).ToList();
            var match = documents.FirstOrDefault(d => d.Id.ToString() == unitId) ?? documents.FirstOrDefault(d => d.Name == name);
            return match is not null && dockingWindows.TryOpenEditor(match, null);
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: opening {unitId} by name failed: {ex.Message}");
            return false;
        }
    }

    private static IEnumerable<Mendix.StudioPro.ExtensionsAPI.Model.Projects.IDocument> DocumentsOf(
        Mendix.StudioPro.ExtensionsAPI.Model.Projects.IFolderBase folder)
    {
        foreach (var document in folder.GetDocuments()) yield return document;
        foreach (var child in folder.GetFolders())
        {
            foreach (var document in DocumentsOf(child)) yield return document;
        }
    }

    /// <summary>The owning module and name of a unit, read through the untyped model.</summary>
    private (string module, string name)? FindUntypedUnit(IModel app, string unitId)
    {
        var root = untypedModel.GetUntypedModel(app);
        foreach (var module in root.GetUnitsOfType("Projects$Module"))
        {
            foreach (var unit in module.GetUnits())
            {
                if (unit.ID.ToString() == unitId) return (module.Name ?? "", unit.Name ?? "");
            }
        }
        return null;
    }

    /// <summary>
    /// The App Explorer path of a unit — <c>Module › Folder › Sub-folder › Name</c> — worked out
    /// from which folders contain it. Folders nest, so the outermost contains the most units.
    /// </summary>
    private (string? name, string? location) Locate(IModel app, string unitId)
    {
        try
        {
            var root = untypedModel.GetUntypedModel(app);
            foreach (var module in root.GetUnitsOfType("Projects$Module"))
            {
                var descendants = module.GetUnits().ToList();
                var unit = descendants.FirstOrDefault(u => u.ID.ToString() == unitId);
                if (unit is null) continue;
                var folders = descendants
                    .Where(u => u.Type.EndsWith("$Folder", StringComparison.Ordinal))
                    .Select(f => (folder: f, contents: f.GetUnits().ToList()))
                    .Where(f => f.contents.Any(u => u.ID.ToString() == unitId))
                    .OrderByDescending(f => f.contents.Count)
                    .Select(f => f.folder.Name ?? "?");
                var path = new[] { module.Name ?? "?" }.Concat(folders).Append(unit.Name ?? "?");
                return (unit.Name, string.Join(" › ", path));
            }
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: could not locate {unitId}: {ex.Message}");
        }
        return (null, null);
    }

    /// <summary>
    /// Opens the domain model owning <paramref name="qualifiedName"/> with the entity selected.
    /// Returns false when the entity cannot be found, so the caller falls back to opening the
    /// document without a selection.
    /// </summary>
    private bool TryOpenEntity(IModel app, string qualifiedName)
    {
        var dot = qualifiedName.IndexOf('.');
        if (dot <= 0) return false;
        var moduleName = qualifiedName[..dot];
        var entityName = qualifiedName[(dot + 1)..];
        try
        {
            var domainModel = app.Root.GetModules().FirstOrDefault(m => m.Name == moduleName)?.DomainModel;
            var entity = domainModel?.GetEntities().FirstOrDefault(e => e.Name == entityName);
            return domainModel is not null && entity is not null && dockingWindows.TryOpenEditor(domainModel, entity);
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: could not select entity {qualifiedName}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Saves a report under Documents\Mendix Security Analyzer. Not the app directory: a report
    /// written there would be committed to the app's repository with the next commit.
    /// </summary>
    private void ExportReport(string? fileName, string? content)
    {
        if (string.IsNullOrWhiteSpace(fileName) || content is null)
        {
            Post("ExportDone", new { path = (string?)null, error = (string?)"Nothing to export." });
            return;
        }
        try
        {
            var safeName = string.Concat(Path.GetFileName(fileName).Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
            var extension = Path.GetExtension(safeName).ToLowerInvariant();
            if (extension is not (".html" or ".json")) safeName += ".txt";

            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Mendix Security Analyzer");
            Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, safeName);
            File.WriteAllText(path, content);
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
            Post("ExportDone", new { path = (string?)path, error = (string?)null });
        }
        catch (Exception ex)
        {
            log.Error("Security Analyzer: export failed", ex);
            Post("ExportDone", new { path = (string?)null, error = (string?)ex.Message });
        }
    }

    /// <summary>
    /// Keeps the most recent snapshot at %LOCALAPPDATA%\Mendix Security Analyzer\last-snapshot.json,
    /// so a result that looks wrong can be traced to what Studio Pro actually returned. The file is
    /// overwritten on every run, stays on this machine, and holds no password (they are redacted
    /// before the snapshot is built).
    /// </summary>
    private void SaveLastSnapshot(string json)
    {
        try
        {
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mendix Security Analyzer");
            Directory.CreateDirectory(folder);
            File.WriteAllText(Path.Combine(folder, "last-snapshot.json"), json);
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: could not save the diagnostic snapshot: {ex.Message}");
        }
    }

    private void Post(string message, object data) => webView?.PostMessage(message, data);

    private static string? ReadString(MessageReceivedEventArgs args, string key) =>
        Field(args, key) is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private static int ReadInt(MessageReceivedEventArgs args, string key) =>
        Field(args, key) is JsonValue v && v.TryGetValue<int>(out var i) ? i : 0;

    private static JsonNode? Field(MessageReceivedEventArgs args, string key) =>
        args.Data is JsonObject o ? o[key] : null;
}
