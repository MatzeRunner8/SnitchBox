using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace SnitchBox.Core;

/// <summary>Art eines Windows-Programms; bestimmt das Ersatzsymbol (die meisten Windows-Programme enthalten kein eigenes) und den
/// Hinweis im Warnfenster.</summary>
public enum WinCategory { System, Shell, Search, Settings, Security, Telemetry, Content, Install, CommandLine }

/// <summary>Erkanntes Windows-Programm: Art und Name für Listen und Warnfenster.</summary>
public sealed record WinMatch(WinCategory Category, string Label);

/// <summary>Programme von Windows mit verständlichem Namen statt „CompatTelRunner.exe“ oder „dasHost.exe“: Dienste und Hosts, Startmenü,
/// Suche, Einstellungen, Sicherheit, Telemetrie, Tipps und Werbung, Installation, Kommandozeile. Erkannt am Dateinamen, aber nur an
/// Orten, an die allein Windows und Administratoren schreiben (System32 und SysWOW64 selbst, der Windows-Ordner, SystemApps,
/// ImmersiveControlPanel, ausgewählte Unterordner, Store-Pakete von Microsoft) – Unterordner wie System32\spool\drivers\color sind
/// für alle beschreibbar und zählen nicht. Unbekannte Programme an diesen Orten heißen „Windows · name.exe“. Windows Update und der
/// Viren- &amp; Bedrohungsschutz stehen in <see cref="WindowsComponents"/>. Wie <see cref="KnownApps"/> nur Anzeige, nie Regel-Matching.</summary>
public static class WindowsProcesses
{
    private static readonly Dictionary<string, (WinCategory Category, Func<string> Title)> Catalog = new(StringComparer.OrdinalIgnoreCase)
    {
        // Dienste, Hosts, Systemprozesse
        ["svchost.exe"] = (WinCategory.System, () => Loc.T("Windows-Diensthost", "Windows service host")),
        ["lsass.exe"] = (WinCategory.Security, () => Loc.T("Windows-Anmeldung (LSASS)", "Windows sign-in (LSASS)")),
        ["services.exe"] = (WinCategory.System, () => Loc.T("Dienststeuerung", "Service control manager")),
        ["backgroundTaskHost.exe"] = (WinCategory.System, () => Loc.T("Hintergrundaufgaben", "Background tasks")),
        ["taskhostw.exe"] = (WinCategory.System, () => Loc.T("Aufgabenhost", "Task host")),
        ["RuntimeBroker.exe"] = (WinCategory.System, () => Loc.T("Laufzeitbroker", "Runtime broker")),
        ["dllhost.exe"] = (WinCategory.System, () => Loc.T("COM-Ersatzprozess", "COM surrogate")),
        ["rundll32.exe"] = (WinCategory.System, () => Loc.T("DLL-Starter (rundll32)", "DLL launcher (rundll32)")),
        ["WmiPrvSE.exe"] = (WinCategory.System, () => Loc.T("WMI-Anbieterhost", "WMI provider host")),
        ["dasHost.exe"] = (WinCategory.System, () => Loc.T("Geräteverbindungen", "Device association")),
        ["spoolsv.exe"] = (WinCategory.System, () => Loc.T("Druckwarteschlange", "Print spooler")),
        ["AppHostRegistrationVerifier.exe"] = (WinCategory.System, () => Loc.T("App-Verknüpfungen prüfen", "App link verification")),
        ["Microsoft.AAD.BrokerPlugin.exe"] = (WinCategory.Security, () => Loc.T("Microsoft-Konto-Anmeldung", "Microsoft account sign-in")),
        ["CredDialogHost.exe"] = (WinCategory.Security, () => Loc.T("Anmeldedialog", "Credential dialog")),
        // Oberfläche
        ["explorer.exe"] = (WinCategory.Shell, () => Loc.T("Datei-Explorer", "File Explorer")),
        ["StartMenuExperienceHost.exe"] = (WinCategory.Shell, () => Loc.T("Startmenü", "Start menu")),
        ["ShellExperienceHost.exe"] = (WinCategory.Shell, () => Loc.T("Windows-Shell", "Windows shell")),
        ["TextInputHost.exe"] = (WinCategory.Shell, () => Loc.T("Texteingabe", "Text input")),
        ["LockApp.exe"] = (WinCategory.Shell, () => Loc.T("Sperrbildschirm", "Lock screen")),
        ["CrossDeviceResume.exe"] = (WinCategory.Shell, () => Loc.T("Geräteübergreifend fortsetzen", "Cross-device resume")),
        ["PhoneExperienceHost.exe"] = (WinCategory.Shell, () => Loc.T("Smartphone-Link", "Phone Link")),
        ["mstsc.exe"] = (WinCategory.Shell, () => Loc.T("Remotedesktopverbindung", "Remote Desktop Connection")),
        ["GameBar.exe"] = (WinCategory.Shell, () => "Xbox Game Bar"),
        ["GameBarFTServer.exe"] = (WinCategory.Shell, () => "Xbox Game Bar"),
        // Suche
        ["SearchHost.exe"] = (WinCategory.Search, () => Loc.T("Windows-Suche", "Windows Search")),
        ["SearchApp.exe"] = (WinCategory.Search, () => Loc.T("Windows-Suche", "Windows Search")),
        ["FESearchHost.exe"] = (WinCategory.Search, () => Loc.T("Windows-Suche", "Windows Search")),
        ["SearchIndexer.exe"] = (WinCategory.Search, () => Loc.T("Suchindex", "Search indexer")),
        ["SearchProtocolHost.exe"] = (WinCategory.Search, () => Loc.T("Suchindex", "Search indexer")),
        // Einstellungen
        ["SystemSettings.exe"] = (WinCategory.Settings, () => Loc.T("Einstellungen", "Settings")),
        ["SystemSettingsBroker.exe"] = (WinCategory.Settings, () => Loc.T("Einstellungen", "Settings")),
        ["UserOOBEBroker.exe"] = (WinCategory.Settings, () => Loc.T("Ersteinrichtung", "Initial setup")),
        // Sicherheit
        ["smartscreen.exe"] = (WinCategory.Security, () => "SmartScreen"),
        ["SecurityHealthService.exe"] = (WinCategory.Security, () => Loc.T("Windows-Sicherheit", "Windows Security")),
        ["SecurityHealthHost.exe"] = (WinCategory.Security, () => Loc.T("Windows-Sicherheit", "Windows Security")),
        ["SecurityHealthSystray.exe"] = (WinCategory.Security, () => Loc.T("Windows-Sicherheit", "Windows Security")),
        // Telemetrie und Fehlerberichte
        ["CompatTelRunner.exe"] = (WinCategory.Telemetry, () => Loc.T("Telemetrie: Kompatibilität", "Telemetry: compatibility")),
        ["DeviceCensus.exe"] = (WinCategory.Telemetry, () => Loc.T("Telemetrie: Geräteinventar", "Telemetry: device census")),
        ["wsqmcons.exe"] = (WinCategory.Telemetry, () => Loc.T("Telemetrie: Programm zur Verbesserung", "Telemetry: customer experience program")),
        ["AggregatorHost.exe"] = (WinCategory.Telemetry, () => Loc.T("Telemetrie: Sammelhost", "Telemetry: aggregator host")),
        ["WerFault.exe"] = (WinCategory.Telemetry, () => Loc.T("Fehlerberichterstattung", "Error reporting")),
        ["wermgr.exe"] = (WinCategory.Telemetry, () => Loc.T("Fehlerberichterstattung", "Error reporting")),
        // Tipps, Hinweise, Nachrichten und Werbung
        ["SoftLandingTask.exe"] = (WinCategory.Content, () => Loc.T("Tipps und Vorschläge", "Tips and suggestions")),
        ["ruximih.exe"] = (WinCategory.Content, () => Loc.T("Windows-Update-Hinweise", "Windows Update prompts")),
        ["ruximics.exe"] = (WinCategory.Content, () => Loc.T("Windows-Update-Hinweise", "Windows Update prompts")),
        ["MicrosoftStartFeedProvider.exe"] = (WinCategory.Content, () => Loc.T("Widgets: Nachrichten", "Widgets: news")),
        ["Widgets.exe"] = (WinCategory.Content, () => "Widgets"),
        ["WidgetService.exe"] = (WinCategory.Content, () => "Widgets"),
        ["WebExperienceHostApp.exe"] = (WinCategory.Content, () => "Widgets"),
        ["DiscoveryHubApp.exe"] = (WinCategory.Content, () => Loc.T("Tipps und Vorschläge", "Tips and suggestions")),
        // Installation und Pakete
        ["msiexec.exe"] = (WinCategory.Install, () => "Windows Installer"),
        ["WindowsPackageManagerServer.exe"] = (WinCategory.Install, () => Loc.T("WinGet (Paket-Manager)", "WinGet (package manager)")),
        ["winget.exe"] = (WinCategory.Install, () => Loc.T("WinGet (Paket-Manager)", "WinGet (package manager)")),
        ["AppInstaller.exe"] = (WinCategory.Install, () => Loc.T("App-Installer", "App Installer")),
        ["WinStore.App.exe"] = (WinCategory.Install, () => "Microsoft Store"),
        ["upfc.exe"] = (WinCategory.Install, () => Loc.T("Update-Vorbereitung", "Update facilitation")),
        ["DeploymentAgent.exe"] = (WinCategory.Install, () => Loc.T("App-Laufzeit: Bereitstellung", "App runtime: deployment")),
        // Kommandozeile
        ["powershell.exe"] = (WinCategory.CommandLine, () => "Windows PowerShell"),
        ["cmd.exe"] = (WinCategory.CommandLine, () => Loc.T("Eingabeaufforderung", "Command Prompt")),
        ["conhost.exe"] = (WinCategory.CommandLine, () => Loc.T("Konsolenfenster-Host", "Console window host")),
        ["curl.exe"] = (WinCategory.CommandLine, () => "curl"),
        ["ssh.exe"] = (WinCategory.CommandLine, () => "OpenSSH"),
        ["sftp.exe"] = (WinCategory.CommandLine, () => "OpenSSH"),
        ["scp.exe"] = (WinCategory.CommandLine, () => "OpenSSH"),
    };

    private static Regex? _windowsDir, _microsoftPackage;
    // Ergebnis je Pfad (die Listen fragen jede Zeile mehrmals je Sekunde ab); gespeichert wird die Art und der Katalogeintrag, nicht
    // der Name – der hängt von der eingestellten Sprache ab. Configure ersetzt den Speicher; höchstens 20.000 Einträge.
    private static ConcurrentDictionary<string, (bool Hit, WinCategory Category, Func<string>? Title)> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Orte festlegen (unter Windows beim Start); vorher wird nichts erkannt.</summary>
    public static void Configure(string windowsDir, string programFiles)
    {
        _cache = new(StringComparer.OrdinalIgnoreCase);
        if (windowsDir.Length < 3) { _windowsDir = _microsoftPackage = null; return; }
        var win = Regex.Escape(windowsDir.TrimEnd('\\'));
        // Ordner (mit „\“ am Ende), in denen nur Windows und Administratoren Programme ablegen können.
        _windowsDir = new Regex("^" + win + @"\\(?:(?:System32|SysWOW64)\\(?:wbem\\|WindowsPowerShell\\[^\\]+\\|OpenSSH\\|ruxim\\)?|ImmersiveControlPanel\\|SystemApps\\[^\\]+\\(?:[^\\]+\\)*)?$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        _microsoftPackage = programFiles.Length < 3 ? null : new Regex("^" + Regex.Escape(programFiles.TrimEnd('\\'))
            + @"\\WindowsApps\\[^\\]+__(?:8wekyb3d8bbwe|cw5n1h2txyewy)\\(?:[^\\]+\\)*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    /// <summary>Das Windows-Programm zu einem Pfad (auch ein Regel-Muster wie „…\WindowsPowerShell\*\powershell.exe“), sonst null.
    /// Ein „:“ nach dem Laufwerk (alternativer Datenstrom wie „C:\Windows\Tasks:x.exe“ – Tasks ist für alle beschreibbar) zählt nie.</summary>
    public static WinMatch? Of(string processPath)
    {
        // Felder einmal lesen: Configure könnte sie zwischendurch ersetzen.
        var windowsDir = _windowsDir;
        var microsoftPackage = _microsoftPackage;
        var cache = _cache;
        if (windowsDir == null || processPath.Length < 4 || processPath[1] != ':' || processPath.IndexOf(':', 2) >= 0 || processPath.Contains("..")
            || processPath.Contains('/') || !processPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        var name = Rule.NameOf(processPath);
        if (!cache.TryGetValue(processPath, out var found))
        {
            var dir = processPath[..^name.Length];
            var inWindows = windowsDir.IsMatch(dir);
            found = !inWindows && microsoftPackage?.IsMatch(dir) != true ? (false, default, null)
                : Catalog.TryGetValue(name, out var entry) ? (true, entry.Category, entry.Title)
                : inWindows ? (true, WinCategory.System, null)
                : (false, default, null);
            if (cache.Count >= 20_000) cache.Clear();
            cache[processPath] = found;
        }
        return !found.Hit ? null : new WinMatch(found.Category, found.Title?.Invoke() ?? "Windows · " + name);
    }
}
