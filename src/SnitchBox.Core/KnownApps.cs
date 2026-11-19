using System.Text.RegularExpressions;

namespace SnitchBox.Core;

/// <summary>Rolle eines Programms innerhalb einer bekannten App.</summary>
public enum AppRole
{
    /// <summary>Das Programm selbst (chrome.exe, ChatGPT.exe).</summary>
    App,
    /// <summary>Hält die App aktuell (GoogleUpdater\…\updater.exe, BraveUpdate.exe, Firefox-Wartungsdienst).</summary>
    Updater,
    /// <summary>Hilfsprogramm der App (elevation_service.exe, codex.exe, WebView2).</summary>
    Helper,
    /// <summary>Kommandozeilenfassung (Claude Code).</summary>
    CommandLine,
}

/// <summary>Bekannte App: Markenname (wird nicht übersetzt), Kennung für das Symbol und Fundorte ihres Hauptprogramms, dessen Symbol
/// auch ihre Updater und Hilfsprogramme zeigen. <paramref name="Packages"/>: Store-Pakete als (Paketfamilie, Programm im Paket).</summary>
public sealed record KnownApp(string Id, string Title, string[] Files, (string Family, string Exe)[] Packages);

/// <summary>Ergebnis der Erkennung: App, Rolle und – wo der Dateiname nichts sagt – ein fester Name.</summary>
public sealed record AppMatch(KnownApp App, AppRole Role, string? FixedLabel = null)
{
    /// <summary>Name für Listen und Warnfenster: „Google Chrome“, „Brave · Updater“, „ChatGPT · codex.exe“.</summary>
    public string Label(string processPath) => FixedLabel ?? Role switch
    {
        AppRole.App or AppRole.CommandLine => App.Title,
        AppRole.Updater => Loc.F("{0} · Updater", "{0} · Updater", App.Title),
        _ => App.Title + " · " + Rule.NameOf(processPath),
    };
}

/// <summary>Erkennt verbreitete Apps, deren Programme sonst schwer zuzuordnen sind: Claude, Claude Code, ChatGPT, Google Chrome,
/// Brave, Firefox, Microsoft Edge – samt ihren Updatern („updater.exe“ sagt allein nichts) und Hilfsprogrammen. Erkannt wird am Ort
/// (Programm- und Paketordner, auch als Regel-Muster mit „*“). Die Erkennung ändert nur Anzeige und Symbol, nie, welche Regel greift:
/// Name und Symbol einer Datei kann ihr Hersteller ohnehin frei wählen, verlässlich ist erst die geprüfte Signatur im Warnfenster.</summary>
public static class KnownApps
{
    public static readonly KnownApp Claude = new("claude", "Claude", [@"AnthropicClaude\claude.exe"], [("Claude_pzs8sxrjxfjjc", @"app\claude.exe")]);
    public static readonly KnownApp ClaudeCode = Claude with { Id = "claude-code", Title = "Claude Code" };
    public static readonly KnownApp ChatGpt = new("chatgpt", "ChatGPT", [],
        [("OpenAI.Codex_2p2nqsd0c76g0", @"app\ChatGPT.exe"), ("OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0", @"app\ChatGPT.exe")]);
    public static readonly KnownApp Chrome = new("chrome", "Google Chrome", [@"Google\Chrome\Application\chrome.exe"], []);
    public static readonly KnownApp Brave = new("brave", "Brave", [@"BraveSoftware\Brave-Browser\Application\brave.exe"], []);
    public static readonly KnownApp Firefox = new("firefox", "Firefox", [@"Mozilla Firefox\firefox.exe"],
        [("Mozilla.Firefox_n80bbvh6b1yt2", @"VFS\ProgramFiles\Firefox Package Root\firefox.exe")]);
    public static readonly KnownApp Edge = new("edge", "Microsoft Edge", [@"Microsoft\Edge\Application\msedge.exe"], []);

    public static readonly KnownApp[] All = [Claude, ClaudeCode, ChatGpt, Chrome, Brave, Firefox, Edge];

    // Vorlagen, die erste passende gewinnt (Genaues vor „alles darunter“). {PF} = beide Programmordner, {WA} = WindowsApps,
    // {LOCAL} = AppData\Local eines Benutzers, {HOME} = Benutzerordner, {PD} = ProgramData, {V} = ein wechselnder Name (Version,
    // Hash, auch „*“ aus einem Regel-Muster), {ANY} = beliebiger Rest des Pfads.
    private static readonly (KnownApp App, AppRole Role, string Template, string? Label)[] Templates =
    [
        (Claude, AppRole.App, @"{WA}\Claude_{V}__pzs8sxrjxfjjc\app\claude.exe", null),
        (Claude, AppRole.Helper, @"{WA}\Claude_{V}__pzs8sxrjxfjjc\{ANY}", null),
        (Claude, AppRole.App, @"{LOCAL}\AnthropicClaude\claude.exe", null),
        (Claude, AppRole.App, @"{LOCAL}\AnthropicClaude\app-{V}\claude.exe", null),
        (Claude, AppRole.Updater, @"{LOCAL}\AnthropicClaude\Update.exe", null),
        (Claude, AppRole.Helper, @"{LOCAL}\AnthropicClaude\{ANY}", null),
        (ClaudeCode, AppRole.CommandLine, @"{LOCAL}\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\{ANY}\claude.exe", null),
        (ClaudeCode, AppRole.CommandLine, @"{HOME}\.local\bin\claude.exe", null),

        (ChatGpt, AppRole.App, @"{WA}\OpenAI.Codex_{V}__2p2nqsd0c76g0\app\ChatGPT.exe", null),
        (ChatGpt, AppRole.Helper, @"{WA}\OpenAI.Codex_{V}__2p2nqsd0c76g0\{ANY}", null),
        (ChatGpt, AppRole.App, @"{WA}\OpenAI.ChatGPT-Desktop_{V}__2p2nqsd0c76g0\app\ChatGPT.exe", null),
        (ChatGpt, AppRole.Helper, @"{WA}\OpenAI.ChatGPT-Desktop_{V}__2p2nqsd0c76g0\{ANY}", null),

        (Chrome, AppRole.App, @"{PF}\Google\Chrome\Application\chrome.exe", null),
        (Chrome, AppRole.Updater, @"{PF}\Google\Chrome\Application\{V}\Installer\{ANY}", null),
        (Chrome, AppRole.Helper, @"{PF}\Google\Chrome\Application\{ANY}", null),
        (Chrome, AppRole.App, @"{LOCAL}\Google\Chrome\Application\chrome.exe", null),
        (Chrome, AppRole.Updater, @"{LOCAL}\Google\Chrome\Application\{V}\Installer\{ANY}", null),
        (Chrome, AppRole.Helper, @"{LOCAL}\Google\Chrome\Application\{ANY}", null),
        (Chrome, AppRole.Updater, @"{PF}\Google\GoogleUpdater\{ANY}", "Google Updater"),
        (Chrome, AppRole.Updater, @"{LOCAL}\Google\GoogleUpdater\{ANY}", "Google Updater"),
        (Chrome, AppRole.Updater, @"{PF}\Google\Update\{ANY}", "Google Updater"),
        (Chrome, AppRole.Updater, @"{LOCAL}\Google\Update\{ANY}", "Google Updater"),

        (Brave, AppRole.App, @"{PF}\BraveSoftware\Brave-Browser\Application\brave.exe", null),
        (Brave, AppRole.Updater, @"{PF}\BraveSoftware\Brave-Browser\Application\{V}\Installer\{ANY}", null),
        (Brave, AppRole.Helper, @"{PF}\BraveSoftware\Brave-Browser\Application\{ANY}", null),
        (Brave, AppRole.App, @"{LOCAL}\BraveSoftware\Brave-Browser\Application\brave.exe", null),
        (Brave, AppRole.Updater, @"{LOCAL}\BraveSoftware\Brave-Browser\Application\{V}\Installer\{ANY}", null),
        (Brave, AppRole.Helper, @"{LOCAL}\BraveSoftware\Brave-Browser\Application\{ANY}", null),
        (Brave, AppRole.Updater, @"{PF}\BraveSoftware\Update\{ANY}", null),
        (Brave, AppRole.Updater, @"{LOCAL}\BraveSoftware\Update\{ANY}", null),
        (Brave, AppRole.Updater, @"{PF}\BraveSoftware\BraveUpdater\{ANY}", null),
        (Brave, AppRole.Updater, @"{LOCAL}\BraveSoftware\BraveUpdater\{ANY}", null),

        (Firefox, AppRole.App, @"{PF}\Mozilla Firefox\firefox.exe", null),
        (Firefox, AppRole.Updater, @"{PF}\Mozilla Firefox\updater.exe", null),
        (Firefox, AppRole.Helper, @"{PF}\Mozilla Firefox\{ANY}", null),
        (Firefox, AppRole.App, @"{LOCAL}\Mozilla Firefox\firefox.exe", null),
        (Firefox, AppRole.Updater, @"{LOCAL}\Mozilla Firefox\updater.exe", null),
        (Firefox, AppRole.Helper, @"{LOCAL}\Mozilla Firefox\{ANY}", null),
        (Firefox, AppRole.Updater, @"{PF}\Mozilla Maintenance Service\{ANY}", null),
        (Firefox, AppRole.Updater, @"{PD}\Mozilla-{V}\updates\{ANY}\updater.exe", null),
        (Firefox, AppRole.App, @"{WA}\Mozilla.Firefox_{V}__n80bbvh6b1yt2\VFS\ProgramFiles\Firefox Package Root\firefox.exe", null),
        (Firefox, AppRole.Updater, @"{WA}\Mozilla.Firefox_{V}__n80bbvh6b1yt2\VFS\ProgramFiles\Firefox Package Root\updater.exe", null),
        (Firefox, AppRole.Helper, @"{WA}\Mozilla.Firefox_{V}__n80bbvh6b1yt2\{ANY}", null),

        (Edge, AppRole.App, @"{PF}\Microsoft\Edge\Application\msedge.exe", null),
        (Edge, AppRole.Updater, @"{PF}\Microsoft\Edge\Application\{V}\Installer\{ANY}", null),
        (Edge, AppRole.Helper, @"{PF}\Microsoft\Edge\Application\{ANY}", null),
        (Edge, AppRole.Updater, @"{PF}\Microsoft\EdgeUpdate\{ANY}", null),
        (Edge, AppRole.Helper, @"{PF}\Microsoft\EdgeWebView\Application\{ANY}", "Microsoft Edge WebView2"),
        (Edge, AppRole.Helper, @"{PF}\Microsoft\EdgeCore\{ANY}", null),
    ];

    private static (Regex Pattern, AppMatch Match)[] _compiled = [];

    /// <summary>Orte festlegen (unter Windows beim Start aus den Systemordnern); vorher wird nichts erkannt.</summary>
    public static void Configure(string programFiles, string programFilesX86, string programData)
    {
        static string E(string dir) => Regex.Escape(dir.TrimEnd('\\'));
        var roots = new[] { programFiles, programFilesX86 }.Where(d => d.Length > 0).Select(E).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (roots.Length == 0) { _compiled = []; return; }
        var tokens = new Dictionary<string, string>
        {
            ["{PF}"] = "(?:" + string.Join("|", roots) + ")",
            ["{WA}"] = (programFiles.Length > 0 ? E(programFiles) : roots[0]) + @"\\WindowsApps",
            ["{LOCAL}"] = @"[A-Za-z]:\\Users\\[^\\]+\\AppData\\Local",
            ["{HOME}"] = @"[A-Za-z]:\\Users\\[^\\]+",
            ["{PD}"] = programData.Length > 0 ? E(programData) : "(?!)",
            ["{V}"] = @"[^\\]+",
            ["{ANY}"] = @"[^\\].*",
        };
        _compiled = Templates.Select(t =>
        {
            var re = string.Join("", Regex.Split(t.Template, @"(\{[A-Z]+\})").Select(part => tokens.TryGetValue(part, out var v) ? v : Regex.Escape(part)));
            return (new Regex("^" + re + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), new AppMatch(t.App, t.Role, t.Label));
        }).ToArray();
    }

    /// <summary>Die bekannte App zu einem Programm (voller Pfad, auch ein Regel-Muster mit „*“), sonst null.</summary>
    public static AppMatch? Of(string processPath)
    {
        if (processPath.Length < 4 || processPath[1] != ':' || processPath.Contains("..") || processPath.Contains('/')
            || !processPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        foreach (var (pattern, match) in _compiled)
            if (pattern.IsMatch(processPath)) return match;
        return null;
    }
}
