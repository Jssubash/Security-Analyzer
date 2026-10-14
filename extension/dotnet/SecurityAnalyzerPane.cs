using System.ComponentModel.Composition;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json.Nodes;
using Mendix.StudioPro.ExtensionsAPI.Model;
using Mendix.StudioPro.ExtensionsAPI.Model.Microflows;
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
    private readonly IMicroflowService microflows;
    private readonly ILogService log;

    [ImportingConstructor]
    public SecurityAnalyzerPane(
        IUntypedModelAccessService untypedModel,
        IDockingWindowService dockingWindows,
        IMicroflowService microflows,
        ILogService log)
    {
        this.untypedModel = untypedModel;
        this.dockingWindows = dockingWindows;
        this.microflows = microflows;
        this.log = log;
    }

    public override string Id => PaneId;

    public override DockablePaneViewModelBase Open() =>
        new SecurityAnalyzerPaneViewModel(WebServerBaseUrl, () => CurrentApp, untypedModel, dockingWindows, microflows, log)
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
    private readonly IMicroflowService microflows;
    private readonly ILogService log;
    private IWebView? webView;

    public SecurityAnalyzerPaneViewModel(
        Uri baseUrl,
        Func<IModel?> currentApp,
        IUntypedModelAccessService untypedModel,
        IDockingWindowService dockingWindows,
        IMicroflowService microflows,
        ILogService log)
    {
        this.baseUrl = baseUrl;
        this.currentApp = currentApp;
        this.untypedModel = untypedModel;
        this.dockingWindows = dockingWindows;
        this.microflows = microflows;
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
                    OpenUnit(ReadString(args, "unitId"), ReadString(args, "entity"), ReadString(args, "activity"));
                    break;
                case "ExportReport":
                    ExportReport(ReadString(args, "fileName"), ReadString(args, "content"));
                    break;
                case "CheckVulnerabilities":
                    CheckVulnerabilities(Field(args, "packages") as JsonArray, ReadString(args, "purpose") ?? "libraries");
                    break;
                case "AcceptRisk":
                    ChangeAcceptedRisks(Field(args, "risk") as JsonObject, revoke: false);
                    break;
                case "RevokeRisk":
                    ChangeAcceptedRisks(Field(args, "risk") as JsonObject, revoke: true);
                    break;
                case "MarketplaceTokenStatus":
                    Post("MarketplaceTokenStatus", new { source = MarketplaceClient.AvailableToken(null).ToString() });
                    break;
                case "CheckMarketplace":
                    CheckMarketplace(ReadString(args, "token"), Field(args, "remember") is JsonValue r && r.TryGetValue<bool>(out var keep) && keep,
                        Field(args, "contentIds") as JsonArray, Field(args, "catalog") is JsonValue c && c.TryGetValue<bool>(out var wantCatalog) && wantCatalog);
                    break;
                case "ForgetMarketplaceToken":
                    MarketplaceClient.Forget();
                    Post("MarketplaceTokenStatus", new { source = MarketplaceClient.AvailableToken(null).ToString() });
                    break;
                case "OpenMarketplacePage":
                    if (ReadInt(args, "contentId") is var contentId and > 0)
                    {
                        Process.Start(new ProcessStartInfo($"https://marketplace.mendix.com/link/component/{contentId}") { UseShellExecute = true });
                    }
                    break;
                case "OpenLibraryFolder":
                    OpenLibraryFolder(ReadString(args, "folder"), ReadString(args, "fileName"));
                    break;
                case "OpenAdvisory":
                    OpenAdvisory(ReadString(args, "id"));
                    break;
                case "MavenVersions":
                    FindSafeVersions(args, inspect: false);
                    break;
                case "InspectCandidates":
                    FindSafeVersions(args, inspect: true);
                    break;
                case "OpenMavenCentral":
                    OpenMavenCentral(ReadString(args, "group"), ReadString(args, "artifact"), ReadString(args, "version"));
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

    private CancellationTokenSource? vulnerabilityCheck;

    /// <summary>
    /// Looks the app's Java libraries up in OSV.dev (see <see cref="OsvClient"/>), off the UI
    /// thread, and posts the answer back on the thread the request came in on.
    /// </summary>
    private void CheckVulnerabilities(JsonArray? packages, string purpose)
    {
        if (packages is null || packages.Count == 0)
        {
            Post("VulnerabilityResult", new { ok = false, purpose, error = "There are no libraries with known names and versions to check." });
            return;
        }
        vulnerabilityCheck?.Cancel();
        var cancel = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        vulnerabilityCheck = cancel;
        var context = SynchronizationContext.Current;
        var request = (JsonArray)packages.DeepClone();
        void Reply(object data)
        {
            if (context is null) Post("VulnerabilityResult", data);
            else context.Post(_ => Post("VulnerabilityResult", data), null);
        }

        Task.Run(async () =>
        {
            try
            {
                var watch = Stopwatch.StartNew();
                var result = await new OsvClient().CheckAsync(request, cancel.Token);
                log.Info($"Security Analyzer: checked {request.Count} {purpose} packages against OSV.dev in {watch.ElapsedMilliseconds} ms");
                Reply(new { ok = true, purpose, json = result.ToJsonString() });
            }
            catch (Exception ex)
            {
                log.Warn($"Security Analyzer: the vulnerability check failed: {ex.Message}");
                var reason = ex is TaskCanceledException or OperationCanceledException
                    ? "the check timed out"
                    : ex is HttpRequestException ? $"OSV.dev could not be reached ({ex.Message})" : ex.Message;
                Reply(new { ok = false, purpose, error = $"The vulnerability check failed: {reason}. Check the internet connection or proxy and try again." });
            }
        });
    }

    private CancellationTokenSource? versionSearch;

    /// <summary>
    /// The "safe version" lookup behind How to resolve, in two calls from the pane: first the release
    /// lists of the vulnerable libraries (<c>MavenVersions</c>), then, for the few candidate releases
    /// the pane picks from them, what is inside each jar and whether OSV.dev knows advisories for it
    /// (<c>InspectCandidates</c>). Replies with <c>VersionAdviceResult</c>.
    /// </summary>
    private void FindSafeVersions(MessageReceivedEventArgs args, bool inspect)
    {
        versionSearch?.Cancel();
        var cancel = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        versionSearch = cancel;
        var context = SynchronizationContext.Current;
        var stage = inspect ? "inspect" : "versions";
        void Reply(object data)
        {
            if (context is null) Post("VersionAdviceResult", data);
            else context.Post(_ => Post("VersionAdviceResult", data), null);
        }
        var libraries = (Field(args, "libraries") as JsonArray)?.Select(n => n?.GetValue<string>()).OfType<string>().ToList() ?? new List<string>();
        var candidates = (Field(args, "candidates") as JsonArray)?.DeepClone() as JsonArray ?? new JsonArray();

        Task.Run(async () =>
        {
            try
            {
                var watch = Stopwatch.StartNew();
                var maven = new MavenClient();
                if (!inspect)
                {
                    var versions = await maven.VersionsAsync(libraries, cancel.Token);
                    log.Info($"Security Analyzer: read {libraries.Count} release lists from Maven Central in {watch.ElapsedMilliseconds} ms");
                    Reply(new { ok = true, stage, json = versions.ToJsonString() });
                    return;
                }
                var packages = new JsonArray(candidates.OfType<JsonObject>()
                    .Select(c => (JsonNode?)new JsonObject { ["name"] = $"{c["group"]}:{c["artifact"]}", ["version"] = c["version"]?.GetValue<string>() })
                    .ToArray());
                var jarsTask = maven.InspectAsync(candidates, cancel.Token);
                var osvTask = new OsvClient().CheckAsync(packages, cancel.Token);
                await Task.WhenAll(jarsTask, osvTask);
                log.Info($"Security Analyzer: inspected {candidates.Count} candidate releases in {watch.ElapsedMilliseconds} ms");
                var osvIds = new JsonObject();
                foreach (var r in (osvTask.Result["results"] as JsonArray ?? new JsonArray()).OfType<JsonObject>())
                {
                    osvIds[$"{r["name"]}@{r["version"]}"] = r["ids"]?.DeepClone();
                }
                Reply(new { ok = true, stage, json = new JsonObject { ["jars"] = jarsTask.Result, ["osv"] = osvIds }.ToJsonString() });
            }
            catch (Exception ex)
            {
                log.Warn($"Security Analyzer: the safe-version lookup failed: {ex.Message}");
                var reason = ex is TaskCanceledException or OperationCanceledException ? "it timed out" : ex.Message;
                Reply(new { ok = false, stage, error = $"Maven Central could not be checked: {reason}" });
            }
        });
    }

    private void OpenMavenCentral(string? group, string? artifact, string? version)
    {
        var page = MavenClient.ReleasePage(group, artifact, version);
        if (page is null) return;
        try
        {
            Process.Start(new ProcessStartInfo(page.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: could not open {page}: {ex.Message}");
        }
    }

    /// <summary>Records or revokes an accepted-risk decision in the app folder; see <see cref="AcceptedRiskStore"/>.</summary>
    private void ChangeAcceptedRisks(JsonObject? risk, bool revoke)
    {
        var directory = currentApp()?.Root.DirectoryPath;
        if (string.IsNullOrEmpty(directory) || risk is null)
        {
            Post("AcceptedRisks", new { ok = false, error = "The app directory is not known, so the decision cannot be saved." });
            return;
        }
        try
        {
            var result = revoke ? AcceptedRiskStore.Revoke(directory, risk) : AcceptedRiskStore.Accept(directory, risk);
            log.Info($"Security Analyzer: {(revoke ? "revoked" : "recorded")} an accepted risk in {AcceptedRiskStore.RelativePath}");
            Post("AcceptedRisks", new { ok = true, json = result.ToJsonString() });
        }
        catch (Exception ex)
        {
            Post("AcceptedRisks", new { ok = false, error = ex is ArgumentException ? ex.Message : $"{AcceptedRiskStore.RelativePath} could not be updated: {ex.Message}" });
        }
    }

    private CancellationTokenSource? marketplaceCheck;

    /// <summary>
    /// Fetches version histories (and, for widget matching, the catalog) from the Marketplace
    /// Content API off the UI thread; see <see cref="MarketplaceClient"/> for what is sent and how
    /// the token is kept. The token itself never goes back to the pane.
    /// </summary>
    private void CheckMarketplace(string? typedToken, bool remember, JsonArray? contentIds, bool catalog)
    {
        MarketplaceClient? client;
        try
        {
            client = MarketplaceClient.Create(typedToken, remember);
        }
        catch (Exception ex)
        {
            Post("MarketplaceResult", new { ok = false, error = $"The token could not be stored: {ex.Message}" });
            return;
        }
        if (client is null)
        {
            Post("MarketplaceResult", new { ok = false, needsToken = true, error = "A Mendix Personal Access Token is needed to read version information from the Marketplace." });
            return;
        }
        var ids = (contentIds ?? new JsonArray())
            .Select(n => n is JsonValue v && v.TryGetValue<int>(out var i) ? i : 0)
            .Where(i => i > 0).Distinct().ToList();

        marketplaceCheck?.Cancel();
        var cancel = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        marketplaceCheck = cancel;
        var context = SynchronizationContext.Current;
        var source = MarketplaceClient.AvailableToken(typedToken).ToString();
        void Reply(object data)
        {
            if (context is null) Post("MarketplaceResult", data);
            else context.Post(_ => Post("MarketplaceResult", data), null);
        }

        Task.Run(async () =>
        {
            try
            {
                var watch = Stopwatch.StartNew();
                var versions = new JsonObject();
                using var gate = new SemaphoreSlim(6);
                var fetched = await Task.WhenAll(ids.Select(async id =>
                {
                    await gate.WaitAsync(cancel.Token);
                    try
                    {
                        return (id, list: (JsonNode?)await client.VersionsAsync(id, cancel.Token), error: (string?)null);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        return (id, list: (JsonNode?)null, error: (string?)ex.Message);
                    }
                    finally
                    {
                        gate.Release();
                    }
                }));
                var failures = new JsonObject();
                foreach (var (id, list, error) in fetched)
                {
                    if (list is not null) versions[id.ToString()] = list;
                    else failures[id.ToString()] = error;
                }
                var result = new JsonObject
                {
                    ["checkedAt"] = DateTime.UtcNow.ToString("o"),
                    ["versions"] = versions,
                    ["failures"] = failures,
                };
                if (catalog) result["catalog"] = await client.CatalogAsync(cancel.Token);
                log.Info($"Security Analyzer: read {ids.Count} Marketplace version lists{(catalog ? " and the catalog" : "")} in {watch.ElapsedMilliseconds} ms");
                Reply(new { ok = true, json = result.ToJsonString(), tokenSource = source });
            }
            catch (UnauthorizedAccessException ex)
            {
                if (remember) MarketplaceClient.Forget();
                Reply(new { ok = false, needsToken = true, error = ex.Message });
            }
            catch (Exception ex)
            {
                log.Warn($"Security Analyzer: the Marketplace check failed: {ex.Message}");
                var reason = ex is TaskCanceledException or OperationCanceledException ? "the check timed out" : ex.Message;
                Reply(new { ok = false, error = $"The Marketplace could not be read: {reason}. Check the internet connection or proxy and try again." });
            }
        });
    }

    /// <summary>
    /// Shows a jar in Windows Explorer, selected in its folder — what Studio Pro's own
    /// App ▸ Show App Directory in Explorer does for the app directory, which the extensions API
    /// gives as <c>IProject.DirectoryPath</c>. The path is built here from that directory: the pane
    /// only names <c>userlib</c>, <c>vendorlib</c> or <c>widgets</c> and a file name, and anything that would
    /// resolve outside those folders is refused.
    /// </summary>
    private void OpenLibraryFolder(string? folder, string? fileName)
    {
        try
        {
            var directory = currentApp()?.Root.DirectoryPath;
            if (string.IsNullOrEmpty(directory) || folder is not ("userlib" or "vendorlib" or "widgets"))
            {
                Post("OpenFolderResult", new { ok = false, error = "The app directory is not known." });
                return;
            }
            var libraryFolder = Path.GetFullPath(Path.Combine(directory, folder));
            if (!Directory.Exists(libraryFolder))
            {
                Post("OpenFolderResult", new { ok = false, error = $"{folder} does not exist in the app directory any more." });
                return;
            }

            string arguments;
            var valid = !string.IsNullOrEmpty(fileName) && fileName == Path.GetFileName(fileName)
                && fileName.EndsWith(folder == "widgets" ? ".mpk" : ".jar", StringComparison.OrdinalIgnoreCase);
            var file = valid ? Path.GetFullPath(Path.Combine(libraryFolder, fileName!)) : null;
            if (file is not null && file.StartsWith(libraryFolder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) && File.Exists(file))
            {
                arguments = $"/select,\"{file}\"";
            }
            else
            {
                // The jar is gone (synchronised away, deleted): open its folder instead.
                arguments = $"\"{libraryFolder}\"";
                Post("OpenFolderResult", new { ok = true, error = (string?)$"{fileName} is no longer in {folder}; opened the folder instead." });
            }
            Process.Start(new ProcessStartInfo("explorer.exe", arguments) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: could not open the folder of {folder}/{fileName}: {ex.Message}");
            Post("OpenFolderResult", new { ok = false, error = $"Windows Explorer could not be opened: {ex.Message}" });
        }
    }

    /// <summary>Opens an advisory's osv.dev page in the default browser. Only osv.dev pages, built from the id.</summary>
    private void OpenAdvisory(string? id)
    {
        var page = OsvClient.AdvisoryPage(id);
        if (page is null) return;
        try
        {
            Process.Start(new ProcessStartInfo(page.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: could not open {page}: {ex.Message}");
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
    private void OpenUnit(string? unitId, string? entityQualifiedName, string? activityId = null)
    {
        var app = currentApp();
        if (app is null || string.IsNullOrEmpty(unitId))
        {
            Post("OpenUnitResult", new { ok = false, error = "No app is open." });
            return;
        }

        if (!string.IsNullOrEmpty(activityId))
        {
            if (TryOpenActivity(app, unitId, activityId))
            {
                Post("OpenUnitResult", new { ok = true, error = (string?)null });
                return;
            }
            // The activity was not found (changed since the analysis): open the microflow itself.
            if (TryOpenById(app, unitId) || TryOpenByName(app, unitId))
            {
                Post("OpenUnitResult", new { ok = true, error = (string?)"The activity was not found any more; opened the microflow. Run the analysis again." });
                return;
            }
        }

        if (!string.IsNullOrEmpty(entityQualifiedName) && TryOpenEntity(app, entityQualifiedName))
        {
            Post("OpenUnitResult", new { ok = true, error = (string?)null });
            return;
        }

        if (TryOpenById(app, unitId) || TryOpenByName(app, unitId) || TryOpenViaEditorManager(app, unitId))
        {
            Post("OpenUnitResult", new { ok = true, error = (string?)null });
            return;
        }

        // Every way of opening failed (e.g. a future Studio Pro reshaped its internals). Say where
        // the document is instead of failing silently.
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

    /// <summary>
    /// Opens a document the typed API has no type for — nanoflows, through 11.12 — the way Studio
    /// Pro's own Changes pane does. <c>TryOpenEditor</c> only unwraps its argument to Studio Pro's
    /// internal document and hands that to the editor manager's <c>EditDocument</c>; a nanoflow has
    /// no typed wrapper to pass in, so this takes the internal document from the untyped unit and
    /// calls <c>EditDocument</c> directly.
    /// <para>
    /// These are Studio Pro internals, found by shape rather than by name: the manager is whichever
    /// field of the docking service has an <c>EditDocument</c> accepting the document (it is
    /// <c>tabbedEditorManager</c> in 10.24 and <c>documentEditorManager</c> in 11.x). Any mismatch
    /// returns false and the caller falls back to telling the user where the document is.
    /// </para>
    /// </summary>
    private bool TryOpenViaEditorManager(IModel app, string unitId)
    {
        try
        {
            var unit = FindUntypedUnitObject(app, unitId);
            var document = unit is null ? null : FieldValueOfType(unit, "IStorageObject");
            if (document is null) return false;

            // Studio Pro's own opener first: it shows dialog-style documents (App Security, …) as
            // their dialog and everything else in a tab, which is what the Errors pane uses.
            if (TryOpenWithDocumentViewManager(document, unitId)) return true;

            foreach (var candidate in FieldValues(dockingWindows).Prepend(dockingWindows))
            {
                var editDocument = candidate.GetType().GetInterfaces().Prepend(candidate.GetType())
                    .SelectMany(t => t.GetMethods())
                    .FirstOrDefault(m => m.Name == "EditDocument"
                        && m.GetParameters().Length is 1 or 2
                        && m.GetParameters()[0].ParameterType.IsInstanceOfType(document)
                        && m.GetParameters().Skip(1).All(p => !p.ParameterType.IsValueType || Nullable.GetUnderlyingType(p.ParameterType) is not null));
                if (editDocument is null) continue;

                var arguments = editDocument.GetParameters().Length == 1 ? new[] { document } : new[] { document, null };
                editDocument.Invoke(candidate, arguments);
                return true;
            }
            log.Warn("Security Analyzer: Studio Pro's editor manager was not found; cannot open the document directly.");
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: opening {unitId} through the editor manager failed: {Reason(ex)}");
        }
        return false;
    }

    /// <summary>
    /// Opens a document through Studio Pro's <c>IDocumentViewManager.EditDocument</c>, resolved from
    /// Studio Pro's service locator. In 10.x this is the opener that knows which documents have a
    /// modal editor — App Security is a dialog, not a tab — while the docking service only reaches
    /// the tab manager, which throws for them. In 11.x the interface no longer opens documents and
    /// the method is absent, so this returns false and the editor manager (which handles dialogs
    /// there) is used instead.
    /// </summary>
    private bool TryOpenWithDocumentViewManager(object document, string unitId)
    {
        try
        {
            var assemblies = AppDomain.CurrentDomain.GetAssemblies();
            var locator = assemblies.Select(a => a.GetType("Mendix.Modeler.Utility.DIContainer.ServiceLocator", throwOnError: false)).FirstOrDefault(t => t is not null);
            var viewManagerType = assemblies.Select(a => a.GetType("Mendix.Modeler.Common.IDocumentViewManager", throwOnError: false)).FirstOrDefault(t => t is not null);
            var editDocument = viewManagerType?.GetMethods().FirstOrDefault(m => m.Name == "EditDocument" && m.GetParameters().Length is 1 or 2);
            var resolve = locator?.GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)
                .FirstOrDefault(m => m.Name == "ObsoleteResolve" && m.IsGenericMethodDefinition && m.GetParameters().Length == 0);
            if (viewManagerType is null || editDocument is null || resolve is null) return false;
            if (!editDocument.GetParameters()[0].ParameterType.IsInstanceOfType(document)) return false;

            var viewManager = resolve.MakeGenericMethod(viewManagerType).Invoke(null, null);
            if (viewManager is null) return false;

            var parameters = editDocument.GetParameters();
            var arguments = new object?[parameters.Length];
            arguments[0] = document;
            // FocusInfo is a struct: its default focuses nothing in particular.
            for (var i = 1; i < parameters.Length; i++)
            {
                var type = parameters[i].ParameterType;
                arguments[i] = type.IsValueType && Nullable.GetUnderlyingType(type) is null ? Activator.CreateInstance(type) : null;
            }
            editDocument.Invoke(viewManager, arguments);
            return true;
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: opening {unitId} through the document view manager failed: {Reason(ex)}");
            return false;
        }
    }

    /// <summary>The real failure behind a reflection call, rather than "the target of an invocation threw".</summary>
    private static string Reason(Exception ex)
    {
        while (ex is System.Reflection.TargetInvocationException { InnerException: { } inner }) ex = inner;
        return $"{ex.GetType().Name}: {ex.Message}";
    }

    private const System.Reflection.BindingFlags InstanceFields =
        System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic;

    /// <summary>The values of every instance field of <paramref name="target"/>, base classes included.</summary>
    private static IEnumerable<object> FieldValues(object target)
    {
        for (var type = target.GetType(); type is not null; type = type.BaseType)
        {
            foreach (var field in type.GetFields(InstanceFields | System.Reflection.BindingFlags.DeclaredOnly))
            {
                var value = field.GetValue(target);
                if (value is not null) yield return value;
            }
        }
    }

    /// <summary>The first instance field whose declared type is named <paramref name="typeName"/>.</summary>
    private static object? FieldValueOfType(object target, string typeName)
    {
        for (var type = target.GetType(); type is not null; type = type.BaseType)
        {
            foreach (var field in type.GetFields(InstanceFields | System.Reflection.BindingFlags.DeclaredOnly))
            {
                if (field.FieldType.Name == typeName && field.GetValue(target) is { } value) return value;
            }
        }
        return null;
    }

    /// <summary>
    /// App-level documents, which belong to no module: App Security (where every project-security
    /// finding points), Navigation and App Settings. Each name with its storage spelling, and where
    /// the App Explorer shows it.
    /// </summary>
    private static readonly (string Type, string Location)[] ProjectDocuments =
    {
        ("Security$ProjectSecurity", "App ▸ Security"),
        ("Navigation$NavigationDocument", "App ▸ Navigation"),
        ("Settings$ProjectSettings", "App ▸ Settings"),
    };

    private Mendix.StudioPro.ExtensionsAPI.Model.UntypedModel.IModelUnit? FindUntypedUnitObject(IModel app, string unitId)
    {
        var root = untypedModel.GetUntypedModel(app);
        foreach (var module in root.GetUnitsOfType("Projects$Module"))
        {
            var unit = module.GetUnits().FirstOrDefault(u => u.ID.ToString() == unitId);
            if (unit is not null) return unit;
        }
        return FindProjectDocument(root, unitId)?.Unit;
    }

    private static (Mendix.StudioPro.ExtensionsAPI.Model.UntypedModel.IModelUnit Unit, string Location)? FindProjectDocument(
        Mendix.StudioPro.ExtensionsAPI.Model.UntypedModel.IModelRoot root, string unitId)
    {
        foreach (var (type, location) in ProjectDocuments)
        {
            foreach (var candidate in new[] { type, type + "Impl" })
            {
                IReadOnlyList<Mendix.StudioPro.ExtensionsAPI.Model.UntypedModel.IModelUnit> units;
                try
                {
                    units = root.GetUnitsOfType(candidate);
                }
                catch
                {
                    continue; // a spelling this Studio Pro version does not know
                }
                var unit = units.FirstOrDefault(u => u.ID.ToString() == unitId);
                if (unit is not null) return (unit, location);
            }
        }
        return null;
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
            if (FindProjectDocument(root, unitId) is { } project) return (null, project.Location);
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
    /// Opens a microflow with one of its activities selected, so the developer lands on the step a
    /// finding names instead of searching a large canvas. The activity is looked up by its id among
    /// all activities, including those inside loops.
    /// </summary>
    private bool TryOpenActivity(IModel app, string unitId, string activityId)
    {
        try
        {
            if (!app.TryGetAbstractUnitById(unitId, out var unit) || unit is not IMicroflow microflow) return false;
            var activity = microflows.GetAllMicroflowActivities(microflow).FirstOrDefault(a => SameId(ElementId(a), activityId));
            if (activity is null)
            {
                log.Warn($"Security Analyzer: activity {activityId} was not found in {unitId}");
                return false;
            }
            return dockingWindows.TryOpenEditor(microflow, activity);
        }
        catch (Exception ex)
        {
            log.Warn($"Security Analyzer: could not select activity {activityId} in {unitId}: {Reason(ex)}");
            return false;
        }
    }

    /// <summary>
    /// The id of a typed model element. The Extensions API does not expose element ids, so this
    /// reads the <c>Original</c> Studio Pro element the typed wrapper carries and takes its
    /// <c>Id</c> — the same id the untyped model (and so the snapshot) reports. <c>null</c> when a
    /// Studio Pro version shapes its wrappers differently.
    /// </summary>
    private static string? ElementId(object element)
    {
        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance;
        var original = element.GetType().GetProperty("Original", All)?.GetValue(element);
        foreach (var candidate in new[] { original, element })
        {
            if (candidate is null) continue;
            var type = candidate.GetType();
            var id = type.GetProperty("Id", All) ?? type.GetProperty("ID", All)
                ?? type.GetInterfaces().Select(i => i.GetProperty("Id") ?? i.GetProperty("ID")).FirstOrDefault(p => p is not null);
            var value = id?.GetValue(candidate)?.ToString();
            if (!string.IsNullOrEmpty(value)) return value;
        }
        return null;
    }

    private static bool SameId(string? a, string b) =>
        a is not null && (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)
            || (Guid.TryParse(a, out var ga) && Guid.TryParse(b, out var gb) && ga == gb));

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
