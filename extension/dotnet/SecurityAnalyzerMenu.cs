using System.ComponentModel.Composition;
using Mendix.StudioPro.ExtensionsAPI.UI.Menu;
using Mendix.StudioPro.ExtensionsAPI.UI.Services;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>Adds Extensions ▸ SecurityAnalyzer ▸ Open Security Analyzer to the menu bar.</summary>
[Export(typeof(MenuExtension))]
public sealed class SecurityAnalyzerMenu : MenuExtension
{
    private readonly IDockingWindowService dockingWindows;

    [ImportingConstructor]
    public SecurityAnalyzerMenu(IDockingWindowService dockingWindows)
    {
        this.dockingWindows = dockingWindows;
    }

    public override IEnumerable<MenuViewModel> GetMenus()
    {
        yield return new MenuViewModel("Open Security Analyzer", () => dockingWindows.OpenPane(SecurityAnalyzerPane.PaneId));
    }
}
