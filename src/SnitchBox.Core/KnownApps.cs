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
/// Brave, Firefox, Microsoft Edge, Visual Studio Code, Visual Studio, NordVPN, Microsoft Office samt OneDrive, Adobe Creative Cloud und
/// Acrobat – samt ihren Updatern („updater.exe“ sagt allein nichts) und Hilfsprogrammen. Erkannt wird am Ort (Programm-, Paket- und Temp-Ordner, auch als Regel-Muster mit „*“). Die Erkennung ändert nur Anzeige und Symbol, nie, welche Regel greift:
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
    // Fundorte relativ zu den Programmordnern bzw. AppData\Local; „*“ steht für wechselnde Ordner (Version, Ausgabe).
    public static readonly KnownApp VsCode = new("vscode", "Visual Studio Code", [@"Programs\Microsoft VS Code\Code.exe", @"Microsoft VS Code\Code.exe"], []);
    public static readonly KnownApp VsCodeInsiders = new("vscode-insiders", "Visual Studio Code Insiders",
        [@"Programs\Microsoft VS Code Insiders\Code - Insiders.exe", @"Microsoft VS Code Insiders\Code - Insiders.exe"], []);
    public static readonly KnownApp VisualStudio = new("visualstudio", "Visual Studio", [@"Microsoft Visual Studio\*\*\Common7\IDE\devenv.exe"], []);
    public static readonly KnownApp NordVpn = new("nordvpn", "NordVPN", [@"NordVPN\NordVPN.exe"], []);
    // Office: Symbol des Update-Clients (Office-Logo); Word, Excel … zeigen ihr eigenes Symbol (Rolle App).
    public static readonly KnownApp Office = new("office", "Microsoft Office",
        [@"Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe", @"Microsoft Office\root\Office16\WINWORD.EXE"], []);
    public static readonly KnownApp OneDrive = new("onedrive", "Microsoft OneDrive", [@"Microsoft\OneDrive\OneDrive.exe", @"Microsoft OneDrive\OneDrive.exe"], []);
    public static readonly KnownApp Outlook = new("outlook", "Microsoft Outlook", [], [("Microsoft.OutlookForWindows_8wekyb3d8bbwe", "olk.exe")]);
    public static readonly KnownApp Teams = new("teams", "Microsoft Teams", [], [("MSTeams_8wekyb3d8bbwe", "ms-teams.exe")]);
    public static readonly KnownApp CreativeCloud = new("adobe-cc", "Adobe Creative Cloud", [@"Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe"], []);
    public static readonly KnownApp Acrobat = new("acrobat", "Adobe Acrobat",
        [@"Adobe\Acrobat DC\Acrobat\Acrobat.exe", @"Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"], []);

    public static readonly KnownApp[] All =
        [Claude, ClaudeCode, ChatGpt, Chrome, Brave, Firefox, Edge, VsCode, VsCodeInsiders, VisualStudio, NordVpn, Office, OneDrive, Outlook, Teams, CreativeCloud, Acrobat];

    // Programme mit eigenem Namen (Rolle App mit festem Namen): Office-Anwendungen und die Programme der Creative Cloud.
    private static readonly (string File, string Label)[] OfficeApps =
    [
        ("WINWORD.EXE", "Microsoft Word"), ("EXCEL.EXE", "Microsoft Excel"), ("POWERPNT.EXE", "Microsoft PowerPoint"),
        ("OUTLOOK.EXE", "Microsoft Outlook"), ("ONENOTE.EXE", "Microsoft OneNote"), ("MSACCESS.EXE", "Microsoft Access"),
        ("MSPUB.EXE", "Microsoft Publisher"), ("VISIO.EXE", "Microsoft Visio"), ("WINPROJ.EXE", "Microsoft Project"), ("lync.exe", "Skype for Business"),
    ];
    private static readonly (string File, string Label)[] AdobeApps =
    [
        ("Photoshop.exe", "Adobe Photoshop"), ("Illustrator.exe", "Adobe Illustrator"), ("InDesign.exe", "Adobe InDesign"),
        ("Adobe Premiere Pro.exe", "Adobe Premiere Pro"), ("AfterFX.exe", "Adobe After Effects"), ("Adobe Media Encoder.exe", "Adobe Media Encoder"),
        ("Adobe Audition.exe", "Adobe Audition"), ("Adobe Bridge.exe", "Adobe Bridge"), ("Animate.exe", "Adobe Animate"),
        ("Dreamweaver.exe", "Adobe Dreamweaver"), ("Lightroom.exe", "Adobe Lightroom"), ("Adobe Character Animator.exe", "Adobe Character Animator"),
        ("Substance 3D Painter.exe", "Adobe Substance 3D Painter"),
    ];

    // Vorlagen, die erste passende gewinnt (Genaues vor „alles darunter“). {PF} = beide Programmordner, {WA} = WindowsApps,
    // {LOCAL} = AppData\Local eines Benutzers, {HOME} = Benutzerordner, {PD} = ProgramData, {TEMP} = die Temp-Ordner,
    // {V} = ein wechselnder Name (Version, Hash, auch „*“ aus einem Regel-Muster), {ANY} = beliebiger Rest des Pfads.
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

        // VS Code: Benutzer- und Systeminstallation; der Updater liegt in einem Hash-Ordner (…\e646868227\tools\inno_updater.exe),
        // das heruntergeladene Update in %TEMP%\vscode-stable-user-x64\CodeSetup-stable-<Version>.exe; Erweiterungen unter ~\.vscode.
        (VsCode, AppRole.App, @"{LOCAL}\Programs\Microsoft VS Code\Code.exe", null),
        (VsCode, AppRole.Updater, @"{LOCAL}\Programs\Microsoft VS Code\{ANY}\inno_updater.exe", null),
        (VsCode, AppRole.Helper, @"{LOCAL}\Programs\Microsoft VS Code\{ANY}", null),
        (VsCode, AppRole.App, @"{PF}\Microsoft VS Code\Code.exe", null),
        (VsCode, AppRole.Updater, @"{PF}\Microsoft VS Code\{ANY}\inno_updater.exe", null),
        (VsCode, AppRole.Helper, @"{PF}\Microsoft VS Code\{ANY}", null),
        (VsCode, AppRole.Updater, @"{TEMP}\vscode-stable-{V}\CodeSetup-{V}", null),
        (VsCode, AppRole.Helper, @"{HOME}\.vscode\extensions\{ANY}", null),
        (VsCodeInsiders, AppRole.App, @"{LOCAL}\Programs\Microsoft VS Code Insiders\Code - Insiders.exe", null),
        (VsCodeInsiders, AppRole.Updater, @"{LOCAL}\Programs\Microsoft VS Code Insiders\{ANY}\inno_updater.exe", null),
        (VsCodeInsiders, AppRole.Helper, @"{LOCAL}\Programs\Microsoft VS Code Insiders\{ANY}", null),
        (VsCodeInsiders, AppRole.App, @"{PF}\Microsoft VS Code Insiders\Code - Insiders.exe", null),
        (VsCodeInsiders, AppRole.Updater, @"{PF}\Microsoft VS Code Insiders\{ANY}\inno_updater.exe", null),
        (VsCodeInsiders, AppRole.Helper, @"{PF}\Microsoft VS Code Insiders\{ANY}", null),
        (VsCodeInsiders, AppRole.Updater, @"{TEMP}\vscode-insider-{V}\CodeSetup-{V}", null),
        (VsCodeInsiders, AppRole.Helper, @"{HOME}\.vscode-insiders\extensions\{ANY}", null),

        // Visual Studio (Ordner „18“ bzw. „2022“, Ausgabe Community/Professional/Enterprise/BuildTools). Der Installer lädt Updates mit
        // BackgroundDownload.exe, oft aus einer Kopie in einem Zufallsordner unter Temp.
        (VisualStudio, AppRole.App, @"{PF}\Microsoft Visual Studio\{V}\{V}\Common7\IDE\devenv.exe", null),
        (VisualStudio, AppRole.Updater, @"{PF}\Microsoft Visual Studio\Installer\{ANY}", "Visual Studio Installer"),
        (VisualStudio, AppRole.Updater, @"{TEMP}\{V}\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\{ANY}", "Visual Studio Installer"),
        (VisualStudio, AppRole.Helper, @"{PF}\Microsoft Visual Studio\{ANY}", null),

        // NordVPN: NordVPN.exe startet die eigentliche App im Versionsordner (8.15.2.0\NordVPNApp.exe); der NordUpdater ist eigenständig.
        (NordVpn, AppRole.App, @"{PF}\NordVPN\NordVPN.exe", null),
        (NordVpn, AppRole.App, @"{PF}\NordVPN\{V}\NordVPNApp.exe", null),
        (NordVpn, AppRole.Updater, @"{PF}\NordVPN\Extras\NordUpdaterSetup.exe", "NordUpdater"),
        (NordVpn, AppRole.Helper, @"{PF}\NordVPN\{ANY}", null),
        (NordVpn, AppRole.Updater, @"{PF}\NordUpdater\{ANY}", "NordUpdater"),
        (NordVpn, AppRole.Updater, @"{PD}\NordUpdater\{ANY}", "NordUpdater"),
        (NordVpn, AppRole.Helper, @"{PD}\NordVPN\{ANY}", null),
        (NordVpn, AppRole.Helper, @"{LOCAL}\NordVPN\{ANY}", null),

        // Microsoft Office (Klick-und-Los): Der Dienst OfficeClickToRun.exe lädt und installiert die Updates (während eines Updates
        // auch aus einem Unterordner), OfficeC2RClient.exe stößt sie an (Aufgabe „Office Automatic Updates 2.0“).
        (Office, AppRole.Updater, @"{PF}\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe", "Microsoft Office Click-to-Run"),
        (Office, AppRole.Updater, @"{PF}\Common Files\microsoft shared\ClickToRun\{ANY}\OfficeClickToRun.exe", "Microsoft Office Click-to-Run"),
        (Office, AppRole.Updater, @"{PF}\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe", null),
        (Office, AppRole.Updater, @"{PF}\Common Files\microsoft shared\ClickToRun\{ANY}\OfficeC2RClient.exe", null),
        (Office, AppRole.Helper, @"{PF}\Common Files\microsoft shared\ClickToRun\{ANY}", null),
        .. OfficeApps.Select(a => (Office, AppRole.App, @"{PF}\Microsoft Office\{ANY}\" + a.File, (string?)a.Label)),
        (Office, AppRole.Helper, @"{PF}\Microsoft Office\{ANY}", null),
        // Neues Outlook und Teams kommen als Store-Pakete von Microsoft und werden über den Store aktualisiert.
        (Outlook, AppRole.App, @"{WA}\Microsoft.OutlookForWindows_{V}__8wekyb3d8bbwe\olk.exe", null),
        (Outlook, AppRole.Helper, @"{WA}\Microsoft.OutlookForWindows_{V}__8wekyb3d8bbwe\{ANY}", null),
        (Teams, AppRole.App, @"{WA}\MSTeams_{V}__8wekyb3d8bbwe\ms-teams.exe", null),
        (Teams, AppRole.Helper, @"{WA}\MSTeams_{V}__8wekyb3d8bbwe\{ANY}", null),

        // OneDrive: je Benutzer unter AppData\Local\Microsoft\OneDrive oder für alle unter Programme; eigener Updater.
        (OneDrive, AppRole.App, @"{LOCAL}\Microsoft\OneDrive\OneDrive.exe", null),
        (OneDrive, AppRole.Updater, @"{LOCAL}\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe", null),
        (OneDrive, AppRole.Updater, @"{LOCAL}\Microsoft\OneDrive\{ANY}\OneDriveSetup.exe", null),
        (OneDrive, AppRole.Helper, @"{LOCAL}\Microsoft\OneDrive\{ANY}", null),
        (OneDrive, AppRole.App, @"{PF}\Microsoft OneDrive\OneDrive.exe", null),
        (OneDrive, AppRole.Updater, @"{PF}\Microsoft OneDrive\OneDriveStandaloneUpdater.exe", null),
        (OneDrive, AppRole.Updater, @"{PF}\Microsoft OneDrive\{ANY}\OneDriveSetup.exe", null),
        (OneDrive, AppRole.Helper, @"{PF}\Microsoft OneDrive\{ANY}", null),

        // Adobe Acrobat und Reader; ihr Updater (Adobe Acrobat Update Service armsvc.exe, AdobeARM.exe) liegt unter Common Files\Adobe\ARM.
        (Acrobat, AppRole.App, @"{PF}\Adobe\Acrobat{V}\Acrobat\Acrobat.exe", null),
        (Acrobat, AppRole.App, @"{PF}\Adobe\Acrobat{V}\Reader\AcroRd32.exe", "Adobe Acrobat Reader"),
        (Acrobat, AppRole.Helper, @"{PF}\Adobe\Acrobat{V}\{ANY}", null),
        (Acrobat, AppRole.Updater, @"{PF}\Common Files\Adobe\ARM\{ANY}", null),

        // Adobe Creative Cloud: Die App, der Adobe Update Service und das Installationsprogramm (ElevationManager, HDBox, OOBE) sowie
        // Hintergrunddienste (Adobe Desktop Service, CoreSync, Genuine Service); die Programme der Suite mit eigenem Namen.
        .. AdobeApps.Select(a => (CreativeCloud, AppRole.App, @"{PF}\Adobe\{ANY}\" + a.File, (string?)a.Label)),
        (CreativeCloud, AppRole.App, @"{PF}\Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe", null),
        (CreativeCloud, AppRole.Updater, @"{PF}\Common Files\Adobe\Adobe Desktop Common\ElevationManager\AdobeUpdateService.exe", "Adobe Update Service"),
        (CreativeCloud, AppRole.Updater, @"{PF}\Common Files\Adobe\Adobe Desktop Common\ElevationManager\{ANY}", null),
        (CreativeCloud, AppRole.Updater, @"{PF}\Common Files\Adobe\Adobe Desktop Common\HDBox\{ANY}", null),
        (CreativeCloud, AppRole.Updater, @"{PF}\Common Files\Adobe\OOBE\{ANY}", null),
        (CreativeCloud, AppRole.Helper, @"{PF}\Common Files\Adobe\AdobeGCClient\{ANY}", "Adobe Genuine Service"),
        (CreativeCloud, AppRole.Helper, @"{PF}\Common Files\Adobe\{ANY}", null),
        (CreativeCloud, AppRole.Helper, @"{PF}\Adobe\Adobe {ANY}", null),
    ];

    private static (Regex Pattern, AppMatch Match)[] _compiled = [];

    /// <summary>Orte festlegen (unter Windows beim Start aus den Systemordnern); vorher wird nichts erkannt. <paramref name="tempRoots"/>:
    /// die Temp-Ordner wie in <see cref="AlertRules.TempRoots"/> (ein ganzes Laufwerk zählt nie), AppData\Local\Temp gilt immer.</summary>
    public static void Configure(string programFiles, string programFilesX86, string programData, IEnumerable<string>? tempRoots = null)
    {
        static string E(string dir) => Regex.Escape(dir.TrimEnd('\\'));
        var roots = new[] { programFiles, programFilesX86 }.Where(d => d.Length > 0).Select(E).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (roots.Length == 0) { _compiled = []; return; }
        var temps = (tempRoots ?? []).Select(t => t.TrimEnd('\\')).Where(t => t.Length > 3 && t[1] == ':' && t.Contains('\\'))
            .Select(E).Append(@"[A-Za-z]:\\Users\\[^\\]+\\AppData\\Local\\Temp").Distinct(StringComparer.OrdinalIgnoreCase);
        var tokens = new Dictionary<string, string>
        {
            ["{PF}"] = "(?:" + string.Join("|", roots) + ")",
            ["{WA}"] = (programFiles.Length > 0 ? E(programFiles) : roots[0]) + @"\\WindowsApps",
            ["{LOCAL}"] = @"[A-Za-z]:\\Users\\[^\\]+\\AppData\\Local",
            ["{HOME}"] = @"[A-Za-z]:\\Users\\[^\\]+",
            ["{PD}"] = programData.Length > 0 ? E(programData) : "(?!)",
            ["{TEMP}"] = "(?:" + string.Join("|", temps) + ")",
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
