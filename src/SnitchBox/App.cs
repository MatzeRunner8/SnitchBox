using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Threading;
using SnitchBox.Core;

namespace SnitchBox;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // Nur eine Instanz für den ganzen Rechner: ein zweiter Start holt das Fenster der laufenden nach vorn.
        using var mutex = new Mutex(true, @"Global\SnitchBox.Single", out var first);
        var showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, @"Global\SnitchBox.Show");
        if (!first)
        {
            if (!args.Contains("--tray")) showEvent.Set();
            return 0;
        }
        var app = new App(args, showEvent);
        return app.Run();
    }
}

/// <summary>Zweisprachige Texte im XAML: {l:L de='…', en='…'} (keine Apostrophe im Text, stattdessen ’).</summary>
public sealed class L : MarkupExtension
{
    public string de { get; set; } = "";
    public string en { get; set; } = "";
    public override object ProvideValue(IServiceProvider serviceProvider) => Loc.T(de, en);
}

public sealed class App : Application
{
    private readonly string[] _args;
    private readonly EventWaitHandle _showEvent;
    private Tray? _tray;
    private MainWindow? _main;
    private AlertWindow? _alert;
    private DispatcherTimer? _housekeeping;
    private Demo? _demo;

    internal static FirewallEngine Engine { get; private set; } = null!;
    internal static FilterService Service { get; private set; } = null!;
    /// <summary>Schaltet das Profil je Netzwerk um (Einstellungen → Profile).</summary>
    internal static NetworkProfileWatcher? NetworkWatcher { get; private set; }

    /// <summary>Profil von Hand wählen (Kopfzeile, Infobereich, neues Profil); siehe <see cref="NetworkProfiles.ChooseByHand"/>.</summary>
    internal static void ChooseProfileByHand(string? profile, Action<Store>? alsoChange = null)
    {
        var connected = NetworkWatcher?.Current ?? [];
        Engine.Mutate(s =>
        {
            alsoChange?.Invoke(s);
            NetworkProfiles.ChooseByHand(connected, s.Settings, profile);
        });
    }
    internal static bool DemoMode { get; private set; }

    /// <summary>Wird gerade gefiltert? Nein, wenn der Netzwerkfilter aus ist oder der Treiber nicht läuft (im Demo-Modus
    /// zählt nur der Schalter). Dann zeigen Infobereich und Taskleiste das rote Schild.</summary>
    internal static bool Filtering(bool filterEnabled) => filterEnabled && (DemoMode || Service.Running);

    /// <summary>Symbol und Tooltip im Infobereich neu setzen (etwa nach einem Neustart des Filters).</summary>
    internal void RefreshTray() => _tray?.Refresh();

    internal App(string[] args, EventWaitHandle showEvent)
    {
        _args = args;
        _showEvent = showEvent;
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
    }

    public static string Version
    {
        get
        {
            var v = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(1, 0, 0, 0);
            return $"{v.Major}.{v.Minor}.{v.Build}";
        }
    }

    public static int Build => Assembly.GetExecutingAssembly().GetName().Version?.Revision ?? 0;
    public static string Title => $"SnitchBox {Version} (Build {Build})";

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try { Start(); }
        catch (Exception ex)
        {
            // Nie mit laufendem Filter, aber ohne Oberfläche weiterlaufen: dann hinge das Netz ohne Ausweg.
            // (Bei unsicherem Datenordner schreibt Log.Write bewusst nichts.)
            Log.Write("Start fehlgeschlagen: " + ex);
            try { Service?.Dispose(); } catch { }
            MessageBox.Show(ex is UnsafeDataDirException ? ex.Message : ErrorText(ex), Title, MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    private void Start()
    {
        DispatcherUnhandledException += (_, a) =>
        {
            Log.Write("Absturz: " + a.Exception);
            MessageBox.Show(ErrorText(a.Exception), Title, MessageBoxButton.OK, MessageBoxImage.Error);
            a.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, a) => Log.Write("Absturz: " + a.ExceptionObject);
        TaskScheduler.UnobservedTaskException += (_, a) => { Log.Write("Aufgabe: " + a.Exception.Message); a.SetObserved(); };

        string? Arg(string name)
        {
            var i = Array.IndexOf(_args, name);
            return i >= 0 && i + 1 < _args.Length ? _args[i + 1] : null;
        }
        var langArg = Arg("--lang");
        if (langArg != null) Loc.Language = langArg;
#pragma warning disable WPF0001
        ThemeMode = Arg("--appearance")?.ToLowerInvariant() switch { "dark" => ThemeMode.Dark, "light" => ThemeMode.Light, _ => ThemeMode.System };
#pragma warning restore WPF0001
        DemoMode = _args.Contains("--demo");
        // Vor dem ersten Lesen oder Schreiben: der Datenordner darf nur für Administratoren beschreibbar sein. Das gilt
        // auch im Demo-Modus (die .exe läuft immer mit Administratorrechten); dessen Daten liegen getrennt im Unterordner „demo“.
        FolderSecurity.HardenDataDir(Paths.DefaultDataDir);
        if (DemoMode) Paths.Override = Path.Combine(Paths.DefaultDataDir, "demo");

        Log.Write("— " + Title + " — " + Environment.ProcessPath + (DemoMode ? " (Demo)" : ""));
        // Temp-Ordner für Regeln an Programmen, die sich bei jedem Start in einen neuen Zufallsordner kopieren (AlertRules.ProcessPattern).
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        // Anzeigenamen der Windows-Dienste (Regeln für einzelne Dienste in svchost.exe).
        Rule.ServiceTitle = Native.ServiceDisplayName;
        // Geschützte Orte von Windows Update und Viren- & Bedrohungsschutz (Werksregeln, Beschriftung in den Listen).
        WindowsComponents.Configure(windows, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        AlertRules.TempRoots = new[]
            {
                Path.GetTempPath(), Environment.GetEnvironmentVariable("TEMP"), Environment.GetEnvironmentVariable("TMP"),
                Path.Combine(windows, "Temp"), Path.Combine(windows, "SystemTemp"),
            }
            .Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => Path.GetFullPath(p!)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        // Bekannte Apps (Claude, ChatGPT, Browser, Entwicklerwerkzeuge, NordVPN und ihre Updater): nur Name und Symbol in den Listen.
        // Die Temp-Ordner braucht sie für Updater, die sich dorthin kopieren (Visual Studio Installer, VS-Code-Update).
        KnownApps.Configure(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            AlertRules.TempRoots);
        // Windows-Programme mit verständlichem Namen und Kategorie-Symbol (nur an geschützten Windows-Orten).
        WindowsProcesses.Configure(windows, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var store = Store.Load();
        // Gewählte Sprache aus den Einstellungen (--lang hat Vorrang).
        if (langArg == null && store.Settings.Language != null) Loc.Language = store.Settings.Language;
        FactoryRules.Ensure(store, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        if (!store.Settings.FirstRunDone)
        {
            // Wie beim Original: vor dem ersten Filtern die Betriebsart wählen lassen.
            var answer = MessageBox.Show(
                Loc.T("Willkommen bei SnitchBox!\n\nSoll SnitchBox bei jeder neuen Verbindung nachfragen?\n\n" +
                      "Ja – Warnmodus: jedes Programm fragt beim ersten Verbindungsversuch (anfangs viele Fragen).\n\n" +
                      "Nein – Stiller Modus: zunächst alles erlauben und nur mitschreiben. Regeln legst du dann in Ruhe im Netzwerkmonitor an.",
                      "Welcome to SnitchBox!\n\nShould SnitchBox ask about every new connection?\n\n" +
                      "Yes – Alert mode: every program asks on its first connection attempt (many questions at first).\n\n" +
                      "No – Silent mode: allow everything for now and just keep a record. You can then create rules at your leisure in the Network Monitor."),
                Title, MessageBoxButton.YesNo, MessageBoxImage.Question);
            store.Settings.Mode = answer == MessageBoxResult.Yes ? OperationMode.Alert : OperationMode.SilentAllow;
            store.Settings.FirstRunDone = true;
        }
        store.Save();

        Service = new FilterService();
        _demo = DemoMode ? new Demo() : null;
        Engine = new FirewallEngine(store, DemoMode ? _demo! : Service, BootId.Current()) { SelfPath = Environment.ProcessPath ?? "" };
        if (DemoMode) _demo!.Start(Engine);
        else
        {
            Service.Attach(Engine);
            if (!Service.Start())
                MessageBox.Show(Loc.T("Der Netzwerkfilter konnte nicht gestartet werden:\n\n", "The network filter could not be started:\n\n") + Service.Error
                                + "\n\n" + Loc.T("Details stehen in ", "Details are in ") + Log.FilePath, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        _tray = new Tray(ShowMain, ShowAlert, QuitAsked);
        Engine.AlertsChanged += () => Dispatcher.BeginInvoke(UpdateAlert);
        Engine.RulesChanged += () => Dispatcher.BeginInvoke(() => _tray?.Refresh());
        NetworkWatcher = new NetworkProfileWatcher(Engine);

        // Stündlich: Blocklisten, die älter als ein Tag sind, neu laden.
        _housekeeping = new DispatcherTimer { Interval = TimeSpan.FromHours(1) };
        _housekeeping.Tick += (_, _) => UpdateBlocklists();
        _housekeeping.Start();
        Dispatcher.BeginInvoke(UpdateBlocklists, DispatcherPriority.ApplicationIdle);

        var waiter = new Thread(() =>
        {
            while (_showEvent.WaitOne()) Dispatcher.BeginInvoke(ShowMain);
        }) { IsBackground = true, Name = "ShowWaiter" };
        waiter.Start();

        if (!_args.Contains("--tray")) ShowMain();
        if (!DemoMode) ThreadPool.QueueUserWorkItem(_ => CheckAutostartTarget());
        WarnAboutRiskyEnvironment();
    }

    /// <summary>Umgebungsvariablen, über die die .NET-Laufzeit fremden Code lädt (Profiler, Diagnose-Ports, zusätzliche
    /// Abhängigkeiten). Der Starter SnitchBoxStart.exe entfernt sie; startet jemand SnitchBox.exe direkt mit ihnen, ist es womöglich
    /// schon geschehen – dann wenigstens Bescheid geben.</summary>
    internal static bool IsRiskyVariable(string name)
    {
        const StringComparison ic = StringComparison.OrdinalIgnoreCase;
        // Profiler, Host-Ablaufverfolgung mit Ausgabedatei (COREHOST_TRACEFILE, DOTNET_HOST_TRACEFILE).
        if (name.StartsWith("CORECLR_", ic) || name.StartsWith("COREHOST_", ic) || name.StartsWith("DOTNET_HOST_", ic)
            || name.StartsWith("COR_ENABLE_PROFILING", ic) || name.StartsWith("COR_PROFILER", ic)) return true;
        // Diagnose-Ports, zusätzliche Abhängigkeiten, Startup-Hooks – die Laufzeit liest Einstellungen unter beiden Vorsilben.
        foreach (var prefix in new[] { "DOTNET_", "COMPlus_" })
            if (name.StartsWith(prefix, ic) && name[prefix.Length..] is var rest
                && (rest.Equals("DiagnosticPorts", ic) || rest.Equals("ADDITIONAL_DEPS", ic) || rest.Equals("SHARED_STORE", ic) || rest.Equals("STARTUP_HOOKS", ic)))
                return true;
        return false;
    }

    private void WarnAboutRiskyEnvironment()
    {
        var risky = Environment.GetEnvironmentVariables().Keys.Cast<string>().Where(IsRiskyVariable).Order(StringComparer.OrdinalIgnoreCase).ToList();
        if (risky.Count == 0) return;
        Log.Write("Bedenkliche Umgebungsvariablen beim Start: " + string.Join(", ", risky));
        var text = Loc.F("SnitchBox wurde mit Umgebungsvariablen gestartet, über die fremder Code in SnitchBox geladen werden kann:\n{0}\n\n" +
                         "Hast du sie nicht bewusst gesetzt (etwa für ein Entwicklerwerkzeug), kann das ein Angriff sein – SnitchBox läuft mit Administratorrechten.\n\n" +
                         "Starte SnitchBox über SnitchBoxStart.exe (Startmenü, Autostart): Der Starter entfernt diese Variablen.",
                         "SnitchBox was started with environment variables that can load foreign code into SnitchBox:\n{0}\n\n" +
                         "If you did not set them on purpose (e.g. for a developer tool), this may be an attack – SnitchBox runs with administrator rights.\n\n" +
                         "Start SnitchBox via SnitchBoxStart.exe (Start menu, autostart): the starter removes these variables.",
                         string.Join(", ", risky));
        Dispatcher.BeginInvoke(() => MessageBox.Show(text, Title, MessageBoxButton.OK, MessageBoxImage.Warning));
    }

    /// <summary>Startet der Autostart eine Datei, die nicht nur Administratoren ändern können, einmal je Build warnen
    /// (auch bei einem schon früher eingerichteten Autostart).</summary>
    private void CheckAutostartTarget()
    {
        // Läuft auf einem Threadpool-Thread: eine Ausnahme hier beendete sonst das ganze Programm (und damit den Filter).
        try
        {
            var command = Autostart.Command;
            if (command == null) return;
            // Älterer Autostart startet SnitchBox.exe direkt, der Starter liegt jetzt daneben: auf den Starter umstellen.
            if (Autostart.Starter is { } starter && command.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
            {
                // Aus der festen Vorlage neu anlegen; nur „abgeschaltet“ bleibt erhalten (siehe Autostart.Retarget).
                Log.Write(Autostart.Retarget() ? $"Autostart startet jetzt {starter}" : "Autostart ließ sich nicht auf den Starter umstellen");
                command = Autostart.Command ?? command;
            }
            string text;
            if (!File.Exists(command))
            {
                Log.Write($"Autostart-Ziel {command} gibt es nicht mehr");
                text = Autostart.MissingText(command);
            }
            else
            {
                var writers = FolderSecurity.WritersOtherThanAdmins(command);
                if (writers.Count == 0) return;
                Log.Write($"Autostart-Ziel {command} ist änderbar durch: {string.Join(", ", writers)}");
                text = Autostart.WarningText(command, writers, false);
            }
            if (Engine.Read(s => s.Settings.AutostartWarnedBuild) == Build) return;
            Engine.Mutate(s => s.Settings.AutostartWarnedBuild = Build);
            Dispatcher.BeginInvoke(() => MessageBox.Show(text, Title, MessageBoxButton.OK, MessageBoxImage.Warning));
        }
        catch (Exception e) { Log.Write("Autostart prüfen: " + e.Message); }
    }

    private static void UpdateBlocklists()
    {
        if (DemoMode) return;
        var due = Engine.Read(s => s.Settings.BlocklistAutoUpdate
            ? s.Blocklists.Where(b => b.Enabled && b.Url.Length > 0 && (b.Updated == null || DateTime.Now - b.Updated > TimeSpan.FromDays(1))).ToList()
            : []);
        foreach (var b in due) _ = BlocklistUpdater.UpdateAsync(Engine, b);
    }

    internal void ShowMain()
    {
        if (_main == null)
        {
            _main = new MainWindow();
            _main.Closed += (_, _) => _main = null;
        }
        _main.Show();
        if (_main.WindowState == WindowState.Minimized) _main.WindowState = WindowState.Normal;
        _main.Activate();
    }

    private void ShowAlert()
    {
        if (_alert != null) _alert.Activate();
        else UpdateAlert();
    }

    /// <summary>Zeigt die älteste offene Nachfrage; weitere folgen, sobald sie beantwortet ist.</summary>
    private void UpdateAlert()
    {
        var alerts = Engine.Alerts;
        _tray?.Refresh();
        if (alerts.Count == 0)
        {
            _alert?.CloseSilently();
            _alert = null;
            return;
        }
        if (_alert != null && alerts.Any(a => a.Id == _alert.Alert.Id))
        {
            _alert.SetWaiting(alerts.Count - 1);
            return;
        }
        _alert?.CloseSilently();
        _alert = null;
        try
        {
            _alert = new AlertWindow(alerts[0], alerts.Count - 1);
            _alert.Show();
        }
        catch (Exception e)
        {
            // Ohne Warnfenster blieben alle neuen Verbindungen für immer angehalten: lieber still erlauben und Bescheid geben.
            Log.Write("Warnfenster: " + e);
            _alert = null;
            Engine.Mutate(s => s.Settings.Mode = OperationMode.SilentAllow);
            MessageBox.Show(Loc.T("Das Warnfenster ließ sich nicht öffnen. SnitchBox hat deshalb in den stillen Modus „alles erlauben“ gewechselt.\n\n",
                                  "The alert window could not be opened. SnitchBox therefore switched to silent mode “allow all”.\n\n") + ErrorText(e),
                Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>Rückfrage, bevor der Schutz endet. Vorauswahl ist „Nein“, damit ein versehentliches Enter nichts ausschaltet.</summary>
    private static bool ConfirmUnprotected(string text)
    {
        var owner = Current.Windows.OfType<SnitchBox.MainWindow>().FirstOrDefault(w => w.IsVisible);
        var result = owner != null
            ? MessageBox.Show(owner, text, Title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No)
            : MessageBox.Show(text, Title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        return result == MessageBoxResult.Yes;
    }

    /// <summary>Netzwerkfilter ein- oder ausschalten (Hauptfenster und Infobereich). Vor dem Ausschalten warnt SnitchBox: danach geht
    /// jede Verbindung ungefragt durch. Liefert false, wenn der Nutzer abbricht.</summary>
    internal static bool SetFilterEnabled(bool on)
    {
        var current = Engine.Read(s => s.Settings.FilterEnabled);
        if (on == current) return true;
        if (!on && !ConfirmUnprotected(Loc.T(
                "Netzwerkfilter ausschalten?\n\nDanach lässt SnitchBox jede Verbindung ungefragt durch – auch solche, die deine Regeln und Blocklisten verbieten. Einschalten geht jederzeit wieder über „Netzwerkfilter“.",
                "Turn off the network filter?\n\nSnitchBox will then let every connection through without asking – including those your rules and blocklists deny. You can turn it back on at any time via “Network Filter”.")))
            return false;
        Engine.Mutate(s => s.Settings.FilterEnabled = on);
        return true;
    }

    /// <summary>„Beenden“ im Infobereich: Ohne laufendes SnitchBox wird nicht gefiltert – solange gerade gefiltert wird, erst nachfragen.</summary>
    private void QuitAsked()
    {
        if (Filtering(Engine.Read(s => s.Settings.FilterEnabled)) && !ConfirmUnprotected(Loc.T(
                "SnitchBox beenden?\n\nOhne SnitchBox wird nicht gefiltert: Jede Verbindung geht ungefragt durch, bis SnitchBox wieder gestartet wird.",
                "Quit SnitchBox?\n\nWithout SnitchBox nothing is filtered: every connection goes through without asking until SnitchBox is started again.")))
            return;
        Quit();
    }

    private void Quit()
    {
        _housekeeping?.Stop();
        _demo?.Stop();
        Service.Dispose();
        NetworkWatcher?.Dispose();
        _tray?.Dispose();
        Log.Write("Beendet");
        Shutdown();
    }

    internal static string ErrorText(Exception e)
    {
        var msg = string.IsNullOrWhiteSpace(e.Message) ? e.GetType().Name : e.Message;
        if (e is FileNotFoundException f && !string.IsNullOrEmpty(f.FileName)) msg += "\n" + f.FileName;
        return msg + "\n\n" + Loc.T("Details stehen in ", "Details are in ") + Log.FilePath;
    }

    internal static void About()
    {
        MessageBox.Show(
            $"SnitchBox\n{Loc.T("Version", "Version")} {Version} (Build {Build})\n\n" +
            Loc.T("Zeigt, welches Programm sich wohin verbinden will, und lässt dich jede Verbindung erlauben oder verbieten.\n\n" +
                  "Verwendet den Treiber WinDivert 2.2.2 von basil00 (LGPLv3).",
                  "Shows which program wants to connect where and lets you allow or deny every connection.\n\n" +
                  "Uses the WinDivert 2.2.2 driver by basil00 (LGPLv3)."),
            Title, MessageBoxButton.OK, MessageBoxImage.Information);
    }
}

/// <summary>Kennung des laufenden Windows-Starts, damit Regeln „bis zum Neustart“ danach verfallen.</summary>
internal static class BootId
{
    public static string Current()
    {
        var boot = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
        var file = Path.Combine(Paths.DataDir, "boot.txt");
        try
        {
            if (File.Exists(file))
            {
                var parts = File.ReadAllText(file).Split('|');
                if (parts.Length == 2 && long.TryParse(parts[0], out var ticks) && Math.Abs((new DateTime(ticks, DateTimeKind.Utc) - boot).TotalMinutes) < 3)
                    return parts[1];
            }
            var id = Guid.NewGuid().ToString("N")[..12];
            File.WriteAllText(file, $"{boot.Ticks}|{id}");
            return id;
        }
        catch { return boot.ToString("yyyyMMddHH"); }
    }
}

/// <summary>Start beim Anmelden über die Aufgabenplanung: nur so läuft ein Programm mit Administratorrechten
/// ohne die Rückfrage der Benutzerkontensteuerung an.</summary>
internal static class Autostart
{
    private const string Task = "SnitchBox";

    /// <summary>Der native Starter neben SnitchBox.exe (SnitchBoxStart.exe), falls vorhanden: Er startet SnitchBox ohne die
    /// Umgebungsvariablen der .NET-Laufzeit, über die sonst jedes Programm Code in das mit Administratorrechten laufende SnitchBox
    /// laden könnte – beim Autostart sogar ohne UAC-Rückfrage.</summary>
    public static string? Starter
    {
        get
        {
            var dir = Path.GetDirectoryName(Environment.ProcessPath ?? "");
            if (string.IsNullOrEmpty(dir)) return null;
            var starter = Path.Combine(dir, "SnitchBoxStart.exe");
            return File.Exists(starter) ? starter : null;
        }
    }

    /// <summary>Was der Autostart startet: der Starter, ohne ihn SnitchBox.exe selbst.</summary>
    public static string Target => Starter ?? Environment.ProcessPath ?? "";

    private static int Run(string arguments) => Run(arguments, out _);

    private static int Run(string arguments, out string output)
    {
        output = "";
        try
        {
            // Voller Pfad: ohne ihn sucht Windows zuerst im Ordner von SnitchBox.exe.
            using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), arguments)
            {
                CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            })!;
            var errTask = p.StandardError.ReadToEndAsync();
            output = p.StandardOutput.ReadToEnd();
            var err = errTask.Result;
            p.WaitForExit(15000);
            if (p.ExitCode != 0 && !arguments.StartsWith("/Query")) Log.Write($"schtasks {arguments}: {err.Trim()}");
            return p.ExitCode;
        }
        catch (Exception e)
        {
            Log.Write("schtasks: " + e.Message);
            return -1;
        }
    }

    /// <summary>Die Datei, die der Autostart startet; null ohne Autostart. Gelesen aus der Aufgabendatei selbst (UTF-16),
    /// nicht aus der Ausgabe von schtasks – deren Kodierung hängt von der Konsolen-Codepage ab und verdirbt Umlaute.</summary>
    public static string? Command
    {
        get
        {
            try
            {
                var file = Path.Combine(Environment.SystemDirectory, "Tasks", Task);
                if (!File.Exists(file)) return null;
                var m = System.Text.RegularExpressions.Regex.Match(File.ReadAllText(file), "<Command>(.*?)</Command>", System.Text.RegularExpressions.RegexOptions.Singleline);
                return m.Success ? Environment.ExpandEnvironmentVariables(System.Net.WebUtility.HtmlDecode(m.Groups[1].Value).Trim().Trim('"')) : null;
            }
            catch (Exception e)
            {
                Log.Write("Autostart lesen: " + e.Message);
                return null;
            }
        }
    }

    /// <summary>Stellt den Autostart auf <see cref="Target"/> um und behält dabei nur eines bei: ob die Aufgabe abgeschaltet ist.
    /// Die Aufgabe wird aus der festen Vorlage neu angelegt, nie aus dem Inhalt der vorhandenen Aufgabendatei – in
    /// %SystemRoot%\System32\Tasks dürfen auch gewöhnliche Benutzer Dateien anlegen; deren Inhalt (Konto SYSTEM, weitere Befehle)
    /// mit Administratorrechten neu zu registrieren, öffnete jedem Programm den Weg zu SYSTEM-Rechten.</summary>
    public static bool Retarget()
    {
        var enabled = true;
        try
        {
            var xml = File.ReadAllText(Path.Combine(Environment.SystemDirectory, "Tasks", Task));
            var settings = System.Text.RegularExpressions.Regex.Match(xml, "<Settings>(.*?)</Settings>", System.Text.RegularExpressions.RegexOptions.Singleline);
            enabled = !(settings.Success && settings.Groups[1].Value.Contains("<Enabled>false</Enabled>", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception e) { Log.Write("Autostart lesen: " + e.Message); }
        return Create(enabled);
    }

    /// <summary>Autostart-Aufgabe aus der festen Vorlage anlegen (ersetzt eine vorhandene).</summary>
    private static bool Create(bool enabled)
    {
        var user = System.Security.SecurityElement.Escape(WindowsIdentity.GetCurrent().Name);
        var exe = System.Security.SecurityElement.Escape(Target);
        var on = enabled ? "true" : "false";
        // Als XML, weil nur so „auch im Akkubetrieb starten“ und „nie nach Zeit beenden“ einstellbar sind.
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
              <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Enabled>{on}</Enabled>
              </Settings>
              <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>--tray</Arguments></Exec></Actions>
            </Task>
            """;
        // Im Datenordner (nur Administratoren dürfen schreiben), nicht in %TEMP%: dort könnte ein anderes Programm die
        // Datei zwischen Schreiben und Einlesen austauschen und so eine eigene Aufgabe mit Administratorrechten anlegen.
        var file = Path.Combine(Paths.DataDir, "autostart-task.xml");
        try
        {
            File.WriteAllText(file, xml, Encoding.Unicode);
            return Run($"/Create /F /TN \"{Task}\" /XML \"{file}\"") == 0;
        }
        finally { try { File.Delete(file); } catch { } }
    }

    /// <summary>Warntext, wenn der Autostart eine Datei startet, die es nicht mehr gibt.</summary>
    public static string MissingText(string exe) =>
        Loc.F("Der Autostart startet eine Datei, die es nicht mehr gibt:\n{0}\n\n" +
              "Darf in diesem Ordner auch ein gewöhnliches Programm Dateien anlegen, könnte es dort eine eigene Datei ablegen, die dann bei jeder Anmeldung ohne Rückfrage mit Administratorrechten startet.\n\n" +
              "Bitte in den Einstellungen den Autostart aus- und wieder einschalten (er startet dann diese SnitchBox).",
              "Autostart runs a file that no longer exists:\n{0}\n\n" +
              "If ordinary programs may create files in that folder, one could place its own file there, which would then run with administrator rights at every sign-in without asking.\n\n" +
              "Please switch autostart off and on again in the settings (it will then run this SnitchBox).", exe);

    /// <summary>Warntext für ein Autostart-Ziel, das nicht nur Administratoren ändern können.</summary>
    public static string WarningText(string exe, IReadOnlyCollection<string> writers, bool askToContinue) =>
        Loc.F("Der Autostart startet eine Datei, die nicht nur Administratoren ändern können ({0}):\n{1}\n\n" +
              "Sie startet bei jeder Anmeldung ohne Rückfrage mit Administratorrechten. Jedes Programm könnte sie vorher austauschen.\n\n" +
              "Empfehlung: SnitchBox beenden, nach „C:\\Program Files\\SnitchBox“ verschieben, von dort starten und den Autostart in den Einstellungen aus- und wieder einschalten.",
              "Autostart runs a file that not only administrators can change ({0}):\n{1}\n\n" +
              "It runs with administrator rights at every sign-in without asking. Any program could replace it beforehand.\n\n" +
              "Recommendation: quit SnitchBox, move it to “C:\\Program Files\\SnitchBox”, start it from there and switch autostart off and on again in the settings.",
              string.Join(", ", writers), exe)
        + (askToContinue ? "\n\n" + Loc.T("Trotzdem einrichten?", "Set it up anyway?") : "");

    public static bool Enabled
    {
        get => Run($"/Query /TN \"{Task}\"") == 0;
        set
        {
            if (!value) { Run($"/Delete /F /TN \"{Task}\""); return; }
            Create(true);
        }
    }
}

/// <summary>Symbol im Infobereich mit Menü für Betriebsart, Profil und Fenster (direkt über Shell_NotifyIcon, ohne WinForms).</summary>
internal sealed class Tray : IDisposable
{
    private const int WM_TRAY = 0x8001; // WM_APP + 1
    private readonly HwndSource _source;
    // App-Symbol (es wird gefiltert) und rotes Schild (Netzwerkfilter aus oder Treiber läuft nicht); _icon ist das gezeigte.
    private readonly IntPtr _iconOn, _iconOff;
    private IntPtr _icon;
    private readonly Action _open, _alerts, _quit;
    private readonly uint _taskbarCreated = TrayNative.RegisterWindowMessage("TaskbarCreated");
    private string _tip = App.Title;

    public Tray(Action open, Action alerts, Action quit)
    {
        _open = open;
        _alerts = alerts;
        _quit = quit;
        // Unsichtbares Popup-Fenster (nicht nur für Nachrichten), damit das Menü Vordergrund bekommt und beim Wegklicken schließt.
        _source = new HwndSource(new HwndSourceParameters("SnitchBoxTray") { Width = 0, Height = 0, WindowStyle = unchecked((int)0x80000000) });
        _source.AddHook(WndProc);
        var size = TrayNative.GetSystemMetrics(49); // SM_CXSMICON
        using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico"))
        {
            var ico = new byte[s!.Length];
            s.ReadExactly(ico);
            _iconOn = FromIco(ico, size);
        }
        _iconOff = ShieldIcon.CreateHIcon(size);
        Refresh(false);
        Send(0 /*NIM_ADD*/, 0x1 | 0x2 | 0x4);
    }

    private void Send(uint message, uint flags)
    {
        var d = new TrayNative.NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<TrayNative.NOTIFYICONDATAW>(), hWnd = _source.Handle, uID = 1,
            uFlags = flags, uCallbackMessage = WM_TRAY, hIcon = _icon, szTip = _tip,
        };
        TrayNative.Shell_NotifyIconW(message, ref d);
    }

    public void Refresh() => Refresh(true);

    private void Refresh(bool send)
    {
        var (mode, on, profile) = App.Engine.Read(s => (s.Settings.Mode, s.Settings.FilterEnabled, s.Settings.ActiveProfile));
        var waiting = App.Engine.Alerts.Count;
        var filtering = App.Filtering(on);
        _icon = filtering ? _iconOn : _iconOff;
        var state = !on ? Loc.T("Netzwerkfilter aus", "Network filter off")
            : !filtering ? Loc.T("Treiber läuft nicht – es wird nicht gefiltert", "Driver not running – nothing is filtered")
            : ModeTitle(mode);
        _tip = App.Title + "\n" + state + (profile != null ? "\n" + Loc.F("Profil: {0}", "Profile: {0}", profile) : "")
               + (waiting > 0 ? "\n" + Loc.F("{0} offene Nachfragen", "{0} pending alerts", waiting) : "");
        if (_tip.Length > 127) _tip = _tip[..127];
        if (send) Send(1 /*NIM_MODIFY*/, 0x2 | 0x4);
    }

    internal static string ModeTitle(OperationMode m) => m switch
    {
        OperationMode.SilentAllow => Loc.T("Stiller Modus – alles erlauben", "Silent Mode – Allow All"),
        OperationMode.SilentDeny => Loc.T("Stiller Modus – alles verbieten", "Silent Mode – Deny All"),
        _ => Loc.T("Warnmodus – nachfragen", "Alert Mode – Ask"),
    };

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == _taskbarCreated) Send(0, 0x1 | 0x2 | 0x4); // Explorer neu gestartet
        if (msg != WM_TRAY) return IntPtr.Zero;
        switch ((int)lParam)
        {
            case 0x0202: _open(); break;     // WM_LBUTTONUP
            case 0x0205: ShowMenu(); break;  // WM_RBUTTONUP
        }
        handled = true;
        return IntPtr.Zero;
    }

    private void ShowMenu()
    {
        var menu = new ContextMenu { Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint };
        MenuItem Item(ItemsControl parent, string text, Action act, bool? check = null)
        {
            var i = new MenuItem { Header = text };
            if (check is { } c) { i.IsCheckable = true; i.IsChecked = c; }
            i.Click += (_, _) => act();
            parent.Items.Add(i);
            return i;
        }
        var settings = App.Engine.Read(s => (s.Settings.Mode, s.Settings.FilterEnabled, s.Settings.ActiveProfile, Profiles: s.Settings.Profiles.ToList()));
        Item(menu, Loc.T("SnitchBox öffnen", "Open SnitchBox"), _open);
        var waiting = App.Engine.Alerts.Count;
        if (waiting > 0) Item(menu, Loc.F("Offene Nachfragen zeigen ({0})", "Show Pending Alerts ({0})", waiting), _alerts);
        menu.Items.Add(new Separator());
        Item(menu, Loc.T("Netzwerkfilter", "Network Filter"), () => App.SetFilterEnabled(!settings.FilterEnabled), settings.FilterEnabled);
        foreach (var m in Enum.GetValues<OperationMode>())
        {
            var item = Item(menu, ModeTitle(m), () => App.Engine.Mutate(s => s.Settings.Mode = m), settings.Mode == m);
            item.Foreground = Ui.ModeBrush(m);
            item.FontWeight = FontWeights.SemiBold;
        }
        if (settings.Profiles.Count > 0)
        {
            var profiles = new MenuItem { Header = Loc.T("Profil", "Profile") };
            Item(profiles, Loc.T("Kein Profil", "No Profile"), () => App.ChooseProfileByHand(null), settings.ActiveProfile == null);
            foreach (var p in settings.Profiles)
                Item(profiles, p, () => App.ChooseProfileByHand(p), settings.ActiveProfile == p);
            menu.Items.Add(profiles);
        }
        menu.Items.Add(new Separator());
        Item(menu, Loc.T("Über SnitchBox", "About SnitchBox"), App.About);
        Item(menu, Loc.T("Beenden (Filter aus)", "Quit (Filter Off)"), _quit);
        Native.SetForegroundWindow(_source.Handle);
        menu.IsOpen = true;
    }

    /// <summary>Passenden PNG-Eintrag aus der .ico wählen (kleinster ≥ Zielgröße).</summary>
    private static IntPtr FromIco(byte[] ico, int size)
    {
        int count = BitConverter.ToUInt16(ico, 4), best = -1, bestSize = int.MaxValue;
        for (var i = 0; i < count; i++)
        {
            var w = ico[6 + 16 * i] == 0 ? 256 : ico[6 + 16 * i];
            if (w >= size && w < bestSize) { best = i; bestSize = w; }
        }
        if (best < 0) best = count - 1;
        var len = BitConverter.ToInt32(ico, 6 + 16 * best + 8);
        var off = BitConverter.ToInt32(ico, 6 + 16 * best + 12);
        var png = ico.AsSpan(off, len).ToArray();
        return TrayNative.CreateIconFromResourceEx(png, (uint)png.Length, true, 0x00030000, size, size, 0);
    }

    public void Dispose()
    {
        Send(2 /*NIM_DELETE*/, 0);
        TrayNative.DestroyIcon(_iconOn);
        TrayNative.DestroyIcon(_iconOff);
        _source.Dispose();
    }
}

internal static class TrayNative
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern bool Shell_NotifyIconW(uint message, ref NOTIFYICONDATAW data);
    [DllImport("user32.dll")] public static extern IntPtr CreateIconFromResourceEx(byte[] bits, uint size, bool icon, uint version, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr icon);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern uint RegisterWindowMessage(string name);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
}

/// <summary>Probelauf ohne Treiber (--demo): erfundene Verbindungen echter Windows-Programme, um die Oberfläche auszuprobieren.
/// Die Daten liegen getrennt in %TEMP%\SnitchBox-Demo.</summary>
internal sealed class Demo : IProcessLookup
{
    private static readonly (string Exe, string Host, string Ip, ushort Port, bool Tcp)[] Samples =
    [
        (@"System32\notepad.exe", "telemetry.example.com", "203.0.113.10", 443, true),
        (@"System32\mspaint.exe", "cdn.example.net", "198.51.100.20", 443, true),
        (@"explorer.exe", "updates.example.org", "203.0.113.77", 80, true),
        (@"System32\notepad.exe", "ads.tracker.example", "198.51.100.99", 443, true),
        (@"System32\calc.exe", "time.example.com", "203.0.113.123", 123, false),
        (@"System32\cmd.exe", "", "192.0.2.55", 22, true),
    ];

    private readonly Dictionary<ushort, int> _ports = [];
    private DispatcherTimer? _timer;
    private int _next;
    private ushort _port = 50000;

    public void Start(FirewallEngine engine)
    {
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
        _timer.Tick += (_, _) => Feed(engine);
        _timer.Start();
        _trafficTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _trafficTimer.Tick += (_, _) => FeedTraffic(engine);
        _trafficTimer.Start();
        Feed(engine);
    }

    public void Stop()
    {
        _timer?.Stop();
        _trafficTimer?.Stop();
    }

    private void Feed(FirewallEngine engine)
    {
        var index = _next++ % Samples.Length;
        var s = Samples[index];
        var ip = System.Net.IPAddress.Parse(s.Ip);
        if (s.Host.Length > 0) engine.Hosts.Add(s.Host, [IpKey.From(ip)]);
        _port++;
        _ports[_port] = index;
        _latest[index] = _port;
        var l4 = s.Tcp ? 20 : 8;
        var p = new byte[20 + l4];
        p[0] = 0x45; p[3] = (byte)p.Length; p[8] = 64; p[9] = (byte)(s.Tcp ? 6 : 17);
        new byte[] { 192, 168, 1, 10 }.CopyTo(p, 12);
        ip.GetAddressBytes().CopyTo(p, 16);
        p[20] = (byte)(_port >> 8); p[21] = (byte)_port; p[22] = (byte)(s.Port >> 8); p[23] = (byte)s.Port;
        if (s.Tcp) { p[32] = 0x50; p[33] = 0x02; } else p[25] = 8;
        engine.Process(p, new PacketMeta(true, false, 1, 0), out _);
    }

    /// <summary>Erfundene Datenmengen für die Programme, deren Verbindungen erlaubt wurden.</summary>
    private void FeedTraffic(FirewallEngine engine)
    {
        var allowed = engine.History.Snapshot().Where(r => r.Allowed == true).Select(r => r.ProcessPath).Distinct().ToList();
        engine.Traffic.Commit(allowed.Select(path => (path, (long)_random.Next(2_000, 900_000), (long)_random.Next(500, 60_000))), 1);
        // Auch je Gegenstelle (die Engine ordnet nur Verbindungen zu, die sie selbst entschieden hat; verbotene bekommen nichts).
        // Je Beispiel nur die jüngste Verbindung – sonst stiege die Menge mit jeder neuen Verbindung immer weiter.
        engine.History.AddVolumes(Enumerable.Range(0, Samples.Length).Where(i => _latest[i] != 0).Select(i => (
            new FlowId(SampleIps[i], _latest[i], Samples[i].Port, Samples[i].Tcp ? Packet.Tcp : Packet.Udp),
            (long)_random.Next(0, 200_000), (long)_random.Next(0, 20_000))), 1);
    }

    private static readonly IpKey[] SampleIps = Samples.Select(s => IpKey.From(System.Net.IPAddress.Parse(s.Ip))).ToArray();
    // Lokaler Port der jüngsten Verbindung je Beispiel (0 = noch keine).
    private readonly ushort[] _latest = new ushort[Samples.Length];
    private readonly Random _random = new();
    private DispatcherTimer? _trafficTimer;

    public ProcessInfo Find(bool tcp, ushort localPort, IpKey remote, ushort remotePort, bool incoming) =>
        _ports.TryGetValue(localPort, out var i)
            ? new ProcessInfo(1000 + i, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), Samples[i].Exe))
            : new ProcessInfo(0, "");

    public bool IsAlive(int pid) => true;
}
