using System.Text.RegularExpressions;

namespace MendixGovernance.SecurityAnalyzer;

/// <summary>
/// Who the person at this computer is, as Git knows them: the <c>user.name</c> and <c>user.email</c>
/// their commits carry. Studio Pro commits a Git app under this identity, so it is the same name
/// that will appear on the commit of a decision recorded with it — and, unlike the Windows account
/// name, it is the person's real name.
/// <para>
/// Read the way Git resolves it, without running Git: the app's own <c>.git/config</c> first, then
/// the global <c>%USERPROFILE%\.gitconfig</c>, then <c>%XDG_CONFIG_HOME%\git\config</c>
/// (<c>%USERPROFILE%\.config\git\config</c>). Each key is taken from the first file that sets it.
/// <c>include</c> directives are not followed.
/// </para>
/// </summary>
internal static class GitIdentity
{
    private static readonly Regex Section = new(@"^\[\s*([A-Za-z0-9.-]+)(?:\s+""[^""]*"")?\s*\]", RegexOptions.Compiled);
    private static readonly Regex Entry = new(@"^([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*)$", RegexOptions.Compiled);

    public static (string? Name, string? Email) Read(string? appDirectory)
    {
        string? name = null, email = null;
        foreach (var file in ConfigFiles(appDirectory))
        {
            var (n, e) = ReadFile(file);
            name ??= n;
            email ??= e;
            if (name is not null && email is not null) break;
        }
        return (name, email);
    }

    private static IEnumerable<string> ConfigFiles(string? appDirectory)
    {
        if (!string.IsNullOrEmpty(appDirectory))
        {
            var gitDir = GitDirectory(appDirectory);
            if (gitDir is not null) yield return Path.Combine(gitDir, "config");
        }
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(home)) yield return Path.Combine(home, ".gitconfig");
        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        yield return Path.Combine(string.IsNullOrEmpty(xdg) ? Path.Combine(home ?? "", ".config") : xdg, "git", "config");
    }

    /// <summary>
    /// The app's Git directory: <c>.git</c> itself, or where a <c>.git</c> file points (worktrees and
    /// submodules write <c>gitdir: &lt;path&gt;</c>).
    /// </summary>
    private static string? GitDirectory(string appDirectory)
    {
        var dotGit = Path.Combine(appDirectory, ".git");
        if (Directory.Exists(dotGit)) return dotGit;
        if (!File.Exists(dotGit)) return null;
        try
        {
            var line = File.ReadLines(dotGit).FirstOrDefault(l => l.StartsWith("gitdir:", StringComparison.OrdinalIgnoreCase));
            if (line is null) return null;
            var target = line["gitdir:".Length..].Trim();
            var full = Path.IsPathRooted(target) ? target : Path.GetFullPath(Path.Combine(appDirectory, target));
            // A worktree's own directory has no config of its own; its "commondir" names the main one.
            var common = Path.Combine(full, "commondir");
            if (File.Exists(common))
            {
                var c = File.ReadAllText(common).Trim();
                full = Path.IsPathRooted(c) ? c : Path.GetFullPath(Path.Combine(full, c));
            }
            return full;
        }
        catch
        {
            return null;
        }
    }

    private static (string? Name, string? Email) ReadFile(string file)
    {
        if (!File.Exists(file)) return (null, null);
        string? name = null, email = null;
        try
        {
            var inUser = false;
            foreach (var raw in File.ReadLines(file))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line[0] is '#' or ';') continue;
                var section = Section.Match(line);
                if (section.Success)
                {
                    inUser = section.Groups[1].Value.Equals("user", StringComparison.OrdinalIgnoreCase);
                    continue;
                }
                if (!inUser) continue;
                var entry = Entry.Match(line);
                if (!entry.Success) continue;
                var value = Value(entry.Groups[2].Value);
                if (value.Length == 0) continue;
                // Later lines win within one file, as in Git.
                switch (entry.Groups[1].Value.ToLowerInvariant())
                {
                    case "name": name = value; break;
                    case "email": email = value; break;
                }
            }
        }
        catch
        {
            // An unreadable file simply contributes nothing.
        }
        return (name, email);
    }

    /// <summary>A config value without its trailing comment and surrounding quotes.</summary>
    private static string Value(string raw)
    {
        var text = raw.Trim();
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            return (end > 0 ? text[1..end] : text[1..]).Trim();
        }
        var comment = text.IndexOfAny(new[] { '#', ';' });
        return (comment >= 0 ? text[..comment] : text).Trim();
    }
}
