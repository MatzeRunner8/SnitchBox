using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;
using SnitchBox.Core;

namespace SnitchBox;

internal static class Ui
{
    private static SolidColorBrush B(byte r, byte g, byte b)
    {
        var br = new SolidColorBrush(Color.FromRgb(r, g, b));
        br.Freeze();
        return br;
    }

    // Kräftige Farben, die auf hellem wie dunklem Grund lesbar sind.
    public static readonly Brush Allow = B(0x2E, 0xA0, 0x43), Deny = B(0xE0, 0x38, 0x3E), Ask = B(0xE0, 0x8A, 0x2E), NoRule = B(0x80, 0x80, 0x80), None = Brushes.Transparent;

    private static readonly Brush Blue = B(0x2E, 0x8B, 0xE6), Gray = B(0x8A, 0x93, 0x9E);

    private static ImageSource Draw(params (Brush Fill, Geometry Shape)[] parts)
    {
        var group = new DrawingGroup();
        // Unsichtbarer Rahmen legt die Fläche auf 32×32 fest, damit alle Symbole gleich groß erscheinen.
        group.Children.Add(new GeometryDrawing(Brushes.Transparent, null, new RectangleGeometry(new Rect(0, 0, 32, 32))));
        foreach (var (fill, shape) in parts) group.Children.Add(new GeometryDrawing(fill, null, shape));
        var image = new DrawingImage(group);
        image.Freeze();
        return image;
    }

    private static Geometry Box(double x, double y, double w, double h, double r) => new RectangleGeometry(new Rect(x, y, w, h), r, r);

    /// <summary>„Alle Programme“: vier Kacheln in den Farben der App (Blau, Grün, Orange, Rot).</summary>
    public static readonly ImageSource AllProgramsIcon = Draw(
        (Blue, Box(2, 2, 13, 13, 3.5)), (Allow, Box(17, 2, 13, 13, 3.5)),
        (Ask, Box(2, 17, 13, 13, 3.5)), (Deny, Box(17, 17, 13, 13, 3.5)));

    /// <summary>Unbekannter Prozess: graue Kachel mit Fragezeichen.</summary>
    public static readonly ImageSource UnknownIcon = Draw((Gray, Box(2, 2, 28, 28, 7)), (Brushes.White, QuestionMark()));

    private static Geometry QuestionMark()
    {
        try
        {
            return new FormattedText("?", System.Globalization.CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Bold, FontStretches.Normal), 22, Brushes.White, 1.0)
                .BuildGeometry(new Point(10.3, 1.5));
        }
        catch
        {
            // Ohne Schrift bleibt ein Punkt; ein Fehler hier darf nicht die ganze Oberfläche mitreißen.
            return new EllipseGeometry(new Point(16, 16), 4, 4);
        }
    }

    /// <summary>Windows-Kern („System“): blauer Bildschirm auf Fuß.</summary>
    public static readonly ImageSource SystemIcon = Draw(
        (Blue, Box(2, 4, 28, 19, 3.5)), (Brushes.White, Box(5, 7, 22, 13, 1.5)), (Blue, Box(8, 10, 16, 2.4, 1.2)), (Blue, Box(8, 14.4, 10, 2.4, 1.2)),
        (Gray, Box(14, 23, 4, 4, 0)), (Gray, Box(9, 26.5, 14, 2.5, 1.2)));

    /// <summary>Programmsymbol mit Ersatz, wo es keine Datei gibt: leerer Pfad = jeder bzw. unbekannter Prozess. Windows Update und
    /// Viren- &amp; Bedrohungsschutz (auch ihre einzelnen Programme) zeigen das Symbol aus den Einstellungen bzw. der Windows-Sicherheit,
    /// bekannte Apps das ihres Hauptprogramms (mit Abzeichen für Updater und Hilfsprogramme), Regel-Muster das der installierten Datei.</summary>
    public static ImageSource IconFor(string path, bool emptyMeansAll)
    {
        if (path.Length == 0) return emptyMeansAll ? AllProgramsIcon : UnknownIcon;
        if (path == "System") return SystemIcon;
        var component = WindowsComponents.IsComponent(path) ? path : WindowsComponents.Of(path);
        if (component != null)
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var sample = component == WindowsComponents.Update
                ? Path.Combine(windows, "ImmersiveControlPanel", "SystemSettings.exe")
                : Path.Combine(windows, "System32", "SecurityHealthSystray.exe");
            if (Native.IconOf(sample) is { } componentIcon) return componentIcon;
        }
        if (WindowsComponents.IsComponent(path)) return UnknownIcon;
        if (KnownApps.Of(path) is { } app) return AppIcons.For(app, path);
        if (WindowsProcesses.Of(path) is { } win) return AppIcons.ForWindows(win, path);
        return AppIcons.ExistingFile(path) is { } file ? Native.IconOf(file) ?? UnknownIcon : UnknownIcon;
    }

    /// <summary>Name eines erkannten Programms in derselben Reihenfolge wie Regelliste und Warnfenster: Windows Update und
    /// Virenschutz, bekannte App, Windows-Programm; null, wenn es nicht erkannt wird.</summary>
    public static string? KnownLabel(string path) =>
        WindowsComponents.Of(path) is { } component ? WindowsComponents.Title(component) + " · " + Rule.NameOf(path)
        : KnownApps.Of(path) is { } app ? app.Label(path)
        : WindowsProcesses.Of(path)?.Label;

    /// <summary>Farbe der Betriebsart: Orange fragt nach, Grün erlaubt alles, Rot verbietet alles.</summary>
    public static Brush ModeBrush(OperationMode m) => m switch
    {
        OperationMode.SilentAllow => Allow,
        OperationMode.SilentDeny => Deny,
        _ => Ask,
    };

    private static ImageSource? _appIcon;

    public static ImageSource? AppIcon()
    {
        if (_appIcon != null) return _appIcon;
        try
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico");
            return _appIcon = s == null ? null : BitmapFrame.Create(s, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        }
        catch { return null; }
    }

    // Höchstens fünf Zeichen vor der Einheit (die Grenzen liegen dort, wo die Rundung in die nächste Stufe springt), damit die
    // Spalte „Daten“ des Netzwerkmonitors reicht.
    public static string Size(long bytes) => bytes switch
    {
        >= 999_500_000_000 => $"{bytes / 1_000_000_000_000.0:0.00} TB",
        >= 99_950_000_000 => $"{bytes / 1_000_000_000.0:0} GB",
        >= 9_995_000_000 => $"{bytes / 1_000_000_000.0:0.0} GB",
        >= 999_950_000 => $"{bytes / 1_000_000_000.0:0.00} GB",
        >= 999_950 => $"{bytes / 1_000_000.0:0.0} MB",
        >= 1_000 => $"{bytes / 1_000.0:0} kB",
        _ => $"{bytes} B",
    };

    /// <summary>Datenmenge mit aktueller Rate in Klammern, z. B. „↓ 12,3 MB (1,2 MB/s)“.</summary>
    public static string Volume(string arrow, long bytes, double rate) =>
        $"{arrow} {Size(bytes)}" + (rate >= 1 ? $" ({Rate(rate)})" : "");

    public static string Rate(double bytesPerSecond) => bytesPerSecond switch
    {
        >= 1_000_000 => $"{bytesPerSecond / 1_000_000:0.0} MB/s",
        >= 1_000 => $"{bytesPerSecond / 1_000:0} kB/s",
        _ => $"{bytesPerSecond:0} B/s",
    };
}

/// <summary>Eintrag der Modus-Auswahl in der Kopfzeile.</summary>
internal sealed record ModeItem(string Title, Brush Brush);

/// <summary>Zeile der Regelliste.</summary>
internal sealed class RuleRow(Rule rule)
{
    public Rule Rule { get; } = rule;
    /// <summary>Überschrift der Gruppe (KI, Browser, Windows …); leer, wenn nicht gruppiert wird.</summary>
    public string Group { get; init; } = "";
    public bool Enabled
    {
        get => Rule.Enabled;
        set { if (value != Rule.Enabled) App.Engine.Mutate(_ => Rule.Enabled = value); }
    }
    public string ActionText => Rule.Action == RuleAction.Allow ? Loc.T("Erlauben", "Allow") : Loc.T("Verbieten", "Deny");
    public Brush ActionBrush => Rule.Action == RuleAction.Allow ? Ui.Allow : Ui.Deny;
    public string ProcessName => Rule.ProcessName;
    public string ProcessPath => Rule.AnyProcess ? Loc.T("Gilt für alle Programme", "Applies to all programs")
        : WindowsComponents.IsComponent(Rule.Process) ? Loc.T("Alle Programme dieses Windows-Bestandteils an ihrem geschützten Windows-Ort", "All programs of this Windows component at their protected Windows location")
        : Rule.Process;
    public ImageSource Icon => Ui.IconFor(Rule.Process, true);
    public string Description => (Rule.HighPriority ? "❗ " : "") + Rule.Describe();
    public string? Notes => Rule.Notes.Length > 0 ? Rule.Notes : null;
    public string Lifetime => Rule.Factory ? Loc.T("Werksregel", "Factory Rule") : Rule.DescribeLifetime();
    public string Profile => Rule.Profile ?? "";
}

/// <summary>Zeile der Programmliste im Netzwerkmonitor; Path == null steht für „Alle Programme“.</summary>
internal sealed class ProcessRow : INotifyPropertyChanged
{
    private string _summary = "", _down = "", _up = "";
    private Brush _state = Ui.None;

    public string? Path { get; init; }
    public string Name { get; init; } = "";
    /// <summary>Überschrift der Gruppe; leer für „Alle Programme“ und wenn nicht gruppiert wird.</summary>
    public string Group { get; init; } = "";
    public ImageSource Icon => Path == null ? Ui.AllProgramsIcon : Ui.IconFor(Path.Split('|')[0], false);
    public string Summary { get => _summary; set => Set(ref _summary, value); }
    public string DownText { get => _down; set => Set(ref _down, value); }
    public string UpText { get => _up; set => Set(ref _up, value); }
    public Brush StateBrush { get => _state; set => Set(ref _state, value); }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

internal sealed class ConnectionRow(ConnectionRecord record) : INotifyPropertyChanged
{
    /// <summary>Datenmenge dieser Gegenstelle (die aktuelle Rate steht im Tooltip, sonst würde die Spalte zu breit); leer, solange
    /// nichts gezählt wurde.</summary>
    public string VolumeText => Record.Down == 0 && Record.Up == 0 ? "" : $"↓{Ui.Size(Record.Down)} ↑{Ui.Size(Record.Up)}";
    public string? VolumeTip => Record.Down == 0 && Record.Up == 0 ? null
        : Ui.Volume("↓", Record.Down, Record.RateDown) + "\n" + Ui.Volume("↑", Record.Up, Record.RateUp);
    public event PropertyChangedEventHandler? PropertyChanged;
    /// <summary>Neue Datenmengen anzeigen, ohne die Liste neu aufzubauen (das verlöre Auswahl und Rollposition).</summary>
    public void RefreshVolume()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(VolumeText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(VolumeTip)));
    }

    private ConnectionRecord r => Record;
    public ConnectionRecord Record { get; } = record;
    public string StateText => r.Allowed switch
    {
        true => Loc.T("Erlaubt", "Allowed"), false => Loc.T("Verboten", "Denied"),
        _ => r.Pending ? Loc.T("Fragt …", "Asking…") : Loc.T("Ohne Regel", "No rule"),
    };
    public Brush StateBrush => r.Allowed switch { true => Ui.Allow, false => Ui.Deny, _ => r.Pending ? Ui.Ask : Ui.NoRule };
    public string Process => r.ProcessPath.Length == 0 ? Loc.T("Unbekannt", "Unknown")
        : r.Service.Length > 0 ? Rule.NameOf(r.ProcessPath) + " · " + r.Service
        : Rule.NameOf(r.ProcessPath);
    /// <summary>Die Spalte ist schmal: dort Symbol und Dateiname, im Tooltip der Name einer bekannten App und der volle Pfad.</summary>
    public string ProcessTip => r.ProcessPath.Length == 0 ? Loc.T("Unbekannt", "Unknown")
        : (r.Service.Length == 0 && Ui.KnownLabel(r.ProcessPath) is { } label ? label + "\n" : "") + r.ProcessPath + (r.Service.Length > 0 ? " · " + r.Service : "");
    public ImageSource Icon => Ui.IconFor(r.ProcessPath, false);
    public string Host => r.Host;
    public string Address => r.Remote.ToString();
    /// <summary>Für den Tooltip der Gegenstelle: voller Name, Adresse und die Regel, die entschieden hat.</summary>
    public string Details => r.Host + (r.Host == Address ? "" : "\n" + Address) + (r.Reason.Length > 0 ? "\n" + r.Reason : "");
    public string PortText => $"{r.Port} {(r.Protocol == Proto.Tcp ? "TCP" : "UDP")}";
    public string DirectionText => r.Direction == Direction.Outgoing ? Loc.T("→ ausgehend", "→ outgoing") : Loc.T("← eingehend", "← incoming");
    public int Count => r.Count;
    public string Last => r.LastSeen.ToString("HH:mm:ss");
    public string Reason => r.Reason;
}

internal sealed class BlocklistRow(Blocklist list)
{
    public Blocklist List { get; } = list;
    public bool Enabled
    {
        get => List.Enabled;
        set { if (value != List.Enabled) App.Engine.Mutate(_ => List.Enabled = value); }
    }
    public string Name => List.Name.Length > 0 ? List.Name : List.Url;
    public string Count => List.Count.ToString("N0");
    public string Updated => List.Updated?.ToString("g") ?? (List.Url.Length == 0 ? Loc.T("Importiert", "Imported") : Loc.T("Noch nie", "Never"));
    public string Url => List.Url;
}

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly List<double> _down = [], _up = [];
    private bool _loading, _reloadQueued;
    private readonly ObservableCollection<ProcessRow> _processRows = [];
    private long _historyVersion = -1, _trafficVersion = -1, _volumeVersion = -1, _lastRx = -1, _lastTx;
    private string? _selectedProcess;
    // Die Abfrage der Aufgabenplanung startet ein Hilfsprogramm; deshalb nur einmal je Fenster.
    private bool? _autostart;
    private string? _autostartHint;

    public MainWindow()
    {
        InitializeComponent();
        Title = App.Title + (App.DemoMode ? " – Demo" : "");
        if (Ui.AppIcon() is { } icon) Icon = icon;

        _loading = true;
        foreach (var m in Enum.GetValues<OperationMode>()) ModeBox.Items.Add(new ModeItem(Tray.ModeTitle(m), Ui.ModeBrush(m)));
        foreach (var f in new[]
                 {
                     Loc.T("Alle Regeln", "All Rules"), Loc.T("Nur Erlauben", "Allow Only"), Loc.T("Nur Verbieten", "Deny Only"),
                     Loc.T("Zeitlich begrenzt", "Temporary"), Loc.T("Eigene Regeln", "My Rules"), Loc.T("Werksregeln", "Factory Rules"),
                 }) RuleFilterBox.Items.Add(f);
        RuleFilterBox.SelectedIndex = 0;
        foreach (var (name, url) in LsRules.Presets) BlocklistUrlBox.Items.Add(new ComboBoxItem { Content = name, Tag = url });
        _loading = false;

        ProcessList.ItemsSource = _processRows;
        // Je Liste füllt eine Spalte den übrigen Platz; so braucht keine Liste eine waagerechte Rollleiste
        // (die legte sich unter Windows 11 quer über die letzte Zeile).
        FitColumn(RulesList, 3, 220);
        FitColumn(ConnectionList, 2, 160);
        FitColumn(BlocklistList, 4, 200);
        App.Engine.RulesChanged += OnRulesChanged;
        if (App.NetworkWatcher != null) App.NetworkWatcher.Checked += OnNetworksChecked;
        Closed += (_, _) =>
        {
            App.Engine.RulesChanged -= OnRulesChanged;
            if (App.NetworkWatcher != null) App.NetworkWatcher.Checked -= OnNetworksChecked;
            CommitNetworkChoice(); // eine gerade erst getroffene Auswahl gilt auch, wenn das Fenster gleich zugeht
            _timer.Stop();
        };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        ReloadAll();
    }

    private static void FitColumn(ListView list, int flexible, double minimum)
    {
        void Apply()
        {
            if (list.View is not GridView view || list.ActualWidth < 50) return;
            double others = 0;
            for (var i = 0; i < view.Columns.Count; i++)
                if (i != flexible) others += view.Columns[i].ActualWidth > 0 ? view.Columns[i].ActualWidth : view.Columns[i].Width;
            // 36: Platz für die senkrechte Rollleiste und den Innenrand der Liste.
            view.Columns[flexible].Width = Math.Max(minimum, list.ActualWidth - others - 36);
        }
        list.SizeChanged += (_, _) => Apply();
        list.Loaded += (_, _) => Apply();
    }

    /// <summary>Nach jeder Netzwerkprüfung; neu aufgebaut wird nur, wenn sich etwas Sichtbares geändert hat (siehe
    /// <see cref="ReloadNetworkProfiles"/>).</summary>
    private void OnNetworksChecked(IReadOnlyList<ConnectedNetwork> connected) => Dispatcher.BeginInvoke(ReloadNetworkProfiles);

    private void OnRulesChanged()
    {
        // Mehrere Änderungen kurz hintereinander ergeben nur ein Neuzeichnen.
        if (_reloadQueued) return;
        _reloadQueued = true;
        Dispatcher.BeginInvoke(() => { _reloadQueued = false; ReloadAll(); });
    }

    private void ReloadAll()
    {
        ReloadHeader();
        ReloadRules();
        ReloadBlocklists();
        ReloadSettings();
    }

    // ---------------------------------------------------------------- Kopfzeile

    private void ReloadHeader()
    {
        _loading = true;
        var s = App.Engine.Read(st => (st.Settings.FilterEnabled, st.Settings.Mode, st.Settings.ActiveProfile, Profiles: st.Settings.Profiles.ToList()));
        FilterSwitch.IsChecked = s.FilterEnabled;
        ModeBox.SelectedIndex = (int)s.Mode;
        ProfileBox.Items.Clear();
        ProfileBox.Items.Add(Loc.T("Kein Profil", "No Profile"));
        foreach (var p in s.Profiles) ProfileBox.Items.Add(p);
        ProfileBox.SelectedIndex = s.ActiveProfile == null ? 0 : Math.Max(0, s.Profiles.IndexOf(s.ActiveProfile) + 1);
        _loading = false;

        if (App.DemoMode)
            StatusText.Text = Loc.T("Demo: erfundene Verbindungen, kein Treiber", "Demo: made-up connections, no driver");
        else if (App.Service.Running)
            StatusText.Text = s.FilterEnabled ? Loc.T("Filter aktiv", "Filter active") : Loc.T("Filter aus – alles wird durchgelassen", "Filter off – everything passes");
        else
            StatusText.Text = App.Service.Error ?? Loc.T("Treiber läuft nicht", "Driver not running");
        // Grün: geschützt. Rot: es wird nicht gefiltert (Filter aus oder Treiber fehlt). Orange nur im Demo-Modus.
        StatusPill.Background = App.DemoMode ? Ui.Ask : App.Service.Running && s.FilterEnabled ? Ui.Allow : Ui.Deny;
        // Auf der Taskleiste wie im Infobereich: rotes Schild, solange nicht gefiltert wird.
        if ((App.Filtering(s.FilterEnabled) ? Ui.AppIcon() : ShieldIcon.WindowIcon) is { } icon && !ReferenceEquals(Icon, icon)) Icon = icon;
    }

    private void FilterSwitch_Click(object sender, RoutedEventArgs e)
    {
        var on = FilterSwitch.IsChecked == true;
        // Abgebrochen (Rückfrage vor dem Ausschalten): Schalter wieder auf den tatsächlichen Stand.
        if (!App.SetFilterEnabled(on)) FilterSwitch.IsChecked = App.Engine.Read(s => s.Settings.FilterEnabled);
    }

    private void ModeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || ModeBox.SelectedIndex < 0) return;
        var mode = (OperationMode)ModeBox.SelectedIndex;
        App.Engine.Mutate(s => s.Settings.Mode = mode);
    }

    private void ProfileBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || ProfileBox.SelectedIndex < 0) return;
        var profile = ProfileBox.SelectedIndex == 0 ? null : ProfileBox.SelectedItem as string;
        App.ChooseProfileByHand(profile);
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        // Beim Laden wird die erste Schaltfläche gewählt, bevor es das TabControl gibt.
        if (Tabs != null && sender is RadioButton { Tag: string index }) Tabs.SelectedIndex = int.Parse(index);
    }

    private void Tabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.OriginalSource == Tabs && Tabs.SelectedIndex == 1) { _historyVersion = _trafficVersion = _volumeVersion = -1; Tick(); }
    }

    // ---------------------------------------------------------------- Regeln

    private void ReloadRules()
    {
        var selected = RulesList.SelectedItems.Cast<RuleRow>().Select(r => r.Rule.Id).ToHashSet();
        var all = App.Engine.Read(s => s.Rules.ToList());
        var search = RuleSearchBox.Text.Trim();
        IEnumerable<Rule> rules = all;
        rules = RuleFilterBox.SelectedIndex switch
        {
            1 => rules.Where(r => r.Action == RuleAction.Allow),
            2 => rules.Where(r => r.Action == RuleAction.Deny),
            3 => rules.Where(r => r.Lifetime != LifetimeKind.Forever),
            4 => rules.Where(r => !r.Factory),
            5 => rules.Where(r => r.Factory),
            _ => rules,
        };
        if (search.Length > 0)
            // Auch der angezeigte Name („Google Updater“, „Telemetrie: Kompatibilität“) und der Dienst.
            rules = rules.Where(r => r.Process.Contains(search, StringComparison.OrdinalIgnoreCase)
                                     || r.ProcessName.Contains(search, StringComparison.CurrentCultureIgnoreCase)
                                     || r.Service.Contains(search, StringComparison.OrdinalIgnoreCase)
                                     || r.Describe().Contains(search, StringComparison.OrdinalIgnoreCase)
                                     || r.Notes.Contains(search, StringComparison.OrdinalIgnoreCase));
        // Gruppiert: erst nach Gruppe (KI, Browser … Windows, Andere), darin wie bisher eigene vor Werksregeln, dann nach Name.
        var grouped = App.Engine.Read(s => s.Settings.GroupLists);
        var rows = rules.Select(r => (Rule: r, Group: grouped ? ProcessGroups.Of(r.Process, r.Service, emptyMeansAll: true) : ProcessGroup.AllPrograms))
            .OrderBy(x => x.Group).ThenBy(x => x.Rule.Factory).ThenBy(x => x.Rule.ProcessName, StringComparer.CurrentCultureIgnoreCase).ThenBy(x => x.Rule.Created)
            .Select(x => new RuleRow(x.Rule) { Group = grouped ? ProcessGroups.Title(x.Group) : "" }).ToList();
        RulesList.ItemsSource = rows;
        ApplyGrouping(RulesList, grouped);
        foreach (var row in rows.Where(r => selected.Contains(r.Rule.Id))) RulesList.SelectedItems.Add(row);
        RulesInfo.Text = rows.Count == all.Count
            ? Loc.F("{0} Regeln", "{0} rules", all.Count)
            : Loc.F("{0} von {1} Regeln", "{0} of {1} rules", rows.Count, all.Count);
    }

    /// <summary>Gruppen-Überschriften einer Liste ein- oder ausschalten (gruppiert wird nach der Eigenschaft „Group“ der Zeilen; die
    /// Zeilen kommen schon in der richtigen Reihenfolge, die Gruppen erscheinen in der Reihenfolge ihres ersten Eintrags).</summary>
    private static void ApplyGrouping(ItemsControl list, bool on)
    {
        if (list.ItemsSource == null || CollectionViewSource.GetDefaultView(list.ItemsSource) is not { } view) return;
        if (on == view.GroupDescriptions.Count > 0) return;
        view.GroupDescriptions.Clear();
        if (on) view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(RuleRow.Group)));
    }

    private void RuleFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!_loading && IsInitialized && RulesList != null) ReloadRules();
    }

    private void NewRule_Click(object sender, RoutedEventArgs e)
    {
        EditRule(new Rule { Action = RuleAction.Deny }, true);
    }

    private void EditRule_Click(object sender, RoutedEventArgs e)
    {
        if (RulesList.SelectedItem is RuleRow row) EditRule(row.Rule, false);
    }

    private void RulesList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if ((e.OriginalSource as DependencyObject) is { } d && ItemsControl.ContainerFromElement(RulesList, d) is ListViewItem { Content: RuleRow row })
            EditRule(row.Rule, false);
    }

    private void RulesList_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Delete) DeleteRule_Click(sender, e);
    }

    /// <summary>Regel bearbeiten bzw. anlegen; liefert die gespeicherte Regel oder null (abgebrochen, abgelaufen).</summary>
    internal Rule? EditRule(Rule rule, bool isNew)
    {
        if (rule.Factory)
        {
            MessageBox.Show(this, Loc.T("Werksregeln lassen sich nur ein- und ausschalten.", "Factory rules can only be switched on and off."), App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
            return null;
        }
        var dialog = new RuleEditorWindow(rule, isNew) { Owner = this };
        if (dialog.ShowDialog() != true) return null;
        var result = dialog.Result;
        var gone = false;
        App.Engine.Mutate(s =>
        {
            var i = s.Rules.FindIndex(r => r.Id == result.Id);
            if (i >= 0) s.Rules[i] = result;
            // Während der Bearbeitung abgelaufen und weggeräumt (Frist vorbei oder Programm beendet): nicht mit der alten,
            // ungültigen Frist wieder anlegen.
            else if (!isNew && (result.Lifetime == LifetimeKind.UntilQuit || (result.Lifetime == LifetimeKind.Timed && result.Expires <= DateTime.Now))) gone = true;
            else s.Rules.Add(result);
            // Eine andere eigene Regel für genau dieselben Verbindungen ist ein Doppel oder ein Widerspruch: Bei Gleichstand
            // gewinnt „Verbieten“, ein „Erlauben“ für eine schon verbotene Verbindung bliebe also wirkungslos. Die neue ersetzt sie.
            if (gone) return;
            s.Rules.RemoveAll(r => r.Id != result.Id && !r.Factory && r.SameScope(result));
            // Neue Regel: in eine gleichartige einfügen (nur andere Gegenstelle). Danach entfallen Regeln, die sie überflüssig macht.
            if (isNew) result = RuleCleanup.Absorb(s.Rules, result);
            else
            {
                var all = s.Rules.ToList();
                s.Rules.RemoveAll(n => RuleCleanup.MakesRedundant(result, n, all));
            }
        });
        if (gone)
        {
            MessageBox.Show(this, Loc.T("Die Regel ist während der Bearbeitung abgelaufen und wurde entfernt; deine Änderungen wurden nicht übernommen. Lege sie bei Bedarf über „Neue Regel“ wieder an.",
                                        "The rule expired while you were editing it and was removed; your changes were not applied. Create it again via “New Rule” if needed."),
                App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
            return null;
        }
        return result;
    }

    /// <summary>Regeln aufräumen: zeigt, was sich ändert, und wendet es nach Bestätigung an. Ob ein Programm noch existiert,
    /// wird außerhalb der Sperre der Engine geprüft (ein nicht erreichbares Netzlaufwerk hielte sonst den Filter an).</summary>
    private void CleanupRules_Click(object sender, RoutedEventArgs e)
    {
        var processes = App.Engine.Read(s => s.Rules.Where(r => !r.Factory).Select(r => r.Process).Distinct(StringComparer.OrdinalIgnoreCase).ToList());
        var vanished = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in processes)
        {
            // Nur volle Pfade, die nicht verallgemeinert werden (Temp- und Versionsordner werden zu *); nie Muster, Dateinamen oder „System“.
            if (p.Contains('*') || p.IndexOf('\\') < 0 || AlertRules.ProcessPattern(p) != p) continue;
            try { if (!File.Exists(p)) vanished.Add(p); } catch { }
        }
        var plan = App.Engine.Read(s => RuleCleanup.Plan(s.Rules, vanished));
        if (plan.Empty)
        {
            MessageBox.Show(this, Loc.T("Die Regeln sind schon aufgeräumt.", "The rules are already tidy."), App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var lines = new List<string>();
        if (plan.Generalized > 0)
            lines.Add(Loc.F("{0} Regeln gelten künftig für jede Kopie und Version ihres Programms (wechselnde Ordnernamen wie Temp-Zufallsordner oder Versionsnummern werden zu *).",
                            "{0} rules will apply to every copy and version of their program (changing folder names such as random temp folders or version numbers become *).", plan.Generalized));
        if (plan.Redundant > 0)
            lines.Add(Loc.F("{0} doppelte oder überflüssige Regeln entfallen (eine umfassendere Regel entscheidet schon genauso).",
                            "{0} duplicate or superfluous rules are removed (a broader rule already decides the same way).", plan.Redundant));
        if (plan.MergedFrom > 0)
            lines.Add(Loc.F("{0} gleichartige Regeln werden zu {1} zusammengefasst (mehrere Gegenstellen in einer Regel).",
                            "{0} rules of the same kind are combined into {1} (several remotes in one rule).", plan.MergedFrom, plan.MergedInto));
        if (plan.Vanished > 0)
        {
            var names = vanished.Select(Rule.NameOf).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.CurrentCultureIgnoreCase).ToList();
            lines.Add(Loc.F("{0} Regeln für Programme, die es nicht mehr gibt, entfallen:", "{0} rules for programs that no longer exist are removed:", plan.Vanished)
                      + " " + string.Join(", ", names.Take(8)) + (names.Count > 8 ? " …" : ""));
        }
        var text = string.Join("\n\n", lines.Select(l => "• " + l)) + "\n\n"
                   + Loc.F("Werksregeln bleiben unberührt. Vorher {0} Regeln, danach {1}. Jetzt aufräumen?",
                           "Factory rules stay untouched. Before: {0} rules, after: {1}. Clean up now?", plan.Before, plan.Rules.Count);
        if (MessageBox.Show(this, text, App.Title, MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        // Unter der Sperre neu planen: inzwischen geänderte Regeln (z. B. aus einem Warnfenster) gehen so nicht verloren.
        App.Engine.Mutate(s =>
        {
            var fresh = RuleCleanup.Plan(s.Rules, vanished);
            s.Rules.Clear();
            s.Rules.AddRange(fresh.Rules);
        });
    }

    private void DeleteRule_Click(object sender, RoutedEventArgs e)
    {
        var rows = RulesList.SelectedItems.Cast<RuleRow>().ToList();
        if (rows.Count == 0) return;
        var ids = rows.Where(r => !r.Rule.Factory).Select(r => r.Rule.Id).ToHashSet();
        if (ids.Count == 0)
        {
            MessageBox.Show(this, Loc.T("Werksregeln lassen sich nicht löschen, nur ausschalten.", "Factory rules cannot be deleted, only switched off."), App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (ids.Count > 1 && MessageBox.Show(this, Loc.F("{0} Regeln löschen?", "Delete {0} rules?", ids.Count), App.Title, MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        App.Engine.Mutate(s => s.Rules.RemoveAll(r => ids.Contains(r.Id)));
    }

    private void ImportRules_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = Loc.T("Regeln oder Blockliste importieren", "Import Rules or Blocklist"),
            Filter = Loc.T("Regeln und Listen", "Rules and lists") + "|*.lsrules;*.json;*.txt;*.hosts|" + Loc.T("Alle Dateien", "All files") + "|*.*",
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var doc = LsRules.Parse(File.ReadAllText(dialog.FileName));
            if (doc.Rules.Count == 0 && doc.Denied.Count == 0) throw new InvalidDataException(Loc.T("Die Datei enthält keine Regeln.", "The file contains no rules."));
            var name = doc.Name.Length > 0 ? doc.Name : Path.GetFileNameWithoutExtension(dialog.FileName);
            var list = doc.Denied.Count == 0 ? null : new Blocklist { Name = name, Domains = doc.Denied, Count = doc.Denied.Count, Updated = DateTime.Now };
            // Die Listendatei entsteht vor dem Eintragen und außerhalb der Sperre der Engine.
            if (list != null) App.Engine.Store.SaveBlocklist(list);
            App.Engine.Mutate(s =>
            {
                s.Rules.AddRange(doc.Rules);
                if (list != null) s.Blocklists.Add(list);
            });
            MessageBox.Show(this, Loc.F("Importiert: {0} Regeln, {1} Blocklisten-Einträge.", "Imported: {0} rules, {1} blocklist entries.", doc.Rules.Count, doc.Denied.Count),
                App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Loc.T("Import fehlgeschlagen:\n", "Import failed:\n") + ex.Message, App.Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ExportRules_Click(object sender, RoutedEventArgs e)
    {
        var selected = RulesList.SelectedItems.Cast<RuleRow>().Select(r => r.Rule).ToList();
        var rules = selected.Count > 1 ? selected : App.Engine.Read(s => s.Rules.Where(r => !r.Factory).ToList());
        if (rules.Count == 0) return;
        var dialog = new SaveFileDialog { Title = Loc.T("Regeln exportieren", "Export Rules"), Filter = "Little Snitch Rules|*.lsrules", FileName = "SnitchBox.lsrules" };
        if (dialog.ShowDialog(this) != true) return;
        try { File.WriteAllText(dialog.FileName, LsRules.Export("SnitchBox", rules)); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, App.Title, MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    // ---------------------------------------------------------------- Netzwerkmonitor

    private void Tick()
    {
        SampleTraffic();
        if (Tabs.SelectedIndex != 1) return;
        DrawChart();
        long history = App.Engine.History.Version, traffic = App.Engine.Traffic.Version, volume = App.Engine.History.VolumeVersion;
        if (history == _historyVersion && traffic == _trafficVersion && volume == _volumeVersion) return;
        var connectionsChanged = history != _historyVersion;
        var volumesChanged = volume != _volumeVersion;
        _historyVersion = history;
        _trafficVersion = traffic;
        _volumeVersion = volume;
        ReloadMonitor(connectionsChanged);
        // Neu aufgebaute Zeilen zeigen die Datenmengen ohnehin; bestehende nur auffrischen.
        if (volumesChanged && !connectionsChanged && ConnectionList.ItemsSource is IEnumerable<ConnectionRow> shown)
            foreach (var row in shown) row.RefreshVolume();
    }

    private void SampleTraffic()
    {
        long rx = 0, tx = 0;
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                var st = ni.GetIPStatistics();
                rx += st.BytesReceived;
                tx += st.BytesSent;
            }
        }
        catch { return; }
        if (_lastRx >= 0)
        {
            _down.Add(Math.Max(0, rx - _lastRx));
            _up.Add(Math.Max(0, tx - _lastTx));
            if (_down.Count > 120) { _down.RemoveAt(0); _up.RemoveAt(0); }
        }
        _lastRx = rx;
        _lastTx = tx;
    }

    private void DrawChart()
    {
        if (_down.Count == 0) return;
        double w = ChartArea.ActualWidth, h = ChartArea.ActualHeight;
        if (w < 10 || h < 10) return;
        var max = Math.Max(1024, Math.Max(_down.Max(), _up.Max()));
        PointCollection Points(List<double> values)
        {
            var pts = new PointCollection(values.Count);
            for (var i = 0; i < values.Count; i++)
                pts.Add(new Point(w - (values.Count - 1 - i) * (w / 119), h - 1 - values[i] / max * (h - 3)));
            return pts;
        }
        DownLine.Points = Points(_down);
        UpLine.Points = Points(_up);
        DownText.Text = "↓ " + Ui.Rate(_down[^1]);
        UpText.Text = "↑ " + Ui.Rate(_up[^1]);
    }

    /// <summary>Zeile der Programmliste: Pfad, bei einem Windows-Dienst „Pfad|Dienst“ („|“ kommt in Pfaden nicht vor).</summary>
    private static string KeyOf(ConnectionRecord r) => r.Service.Length > 0 ? r.ProcessPath + "|" + r.Service : r.ProcessPath;

    private static string DisplayName(string path)
    {
        if (path.IndexOf('|') is var bar and >= 0)
        {
            var service = path[(bar + 1)..];
            return Loc.F("Windows-Dienst: {0}", "Windows service: {0}", Rule.ServiceTitle(service) ?? service);
        }
        if (path.Length == 0) return Loc.T("Unbekannter Prozess", "Unknown Process");
        if (Ui.KnownLabel(path) is { } label) return label;
        var title = Native.InfoOf(path).Title;
        return title.Length > 0 ? title : Rule.NameOf(path);
    }

    /// <summary>Gruppe einer Zeile der Programmliste („Pfad|Dienst“ ist ein Windows-Dienst; leerer Pfad = unbekannter Prozess).</summary>
    private static ProcessGroup GroupOf(string key) =>
        key.IndexOf('|') is var bar and >= 0 ? ProcessGroups.Of(key[..bar], key[(bar + 1)..]) : ProcessGroups.Of(key);

    /// <summary>Erstes Element eines Typs in der Darstellung (etwa die Rollleiste einer Liste).</summary>
    private static T? FindChild<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T found) return found;
            if (FindChild<T>(child) is { } deeper) return deeper;
        }
        return null;
    }

    /// <summary>Aktualisiert die Programmliste an Ort und Stelle (sie ändert sich jede Sekunde durch die Datenmengen);
    /// neu aufgebaut wird nur, wenn ein Programm dazukommt. So bleiben Auswahl und Rollposition erhalten.</summary>
    private void ReloadMonitor(bool connectionsChanged)
    {
        var records = App.Engine.History.Snapshot();
        var traffic = App.Engine.Traffic.Snapshot().ToDictionary(t => t.ProcessPath, StringComparer.OrdinalIgnoreCase);
        // Je Programm eine Zeile, bei svchost.exe je Windows-Dienst (Schlüssel „Pfad|Dienst“).
        var groups = records.GroupBy(KeyOf, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        // Auch Programme zeigen, die nur Daten übertragen (Verbindungen von vor dem Start).
        // Gruppiert (Einstellung): erst nach Gruppe (KI, Browser … Windows, Andere), darin wie bisher nach Name, Unbekanntes zuletzt.
        var grouped = App.Engine.Read(s => s.Settings.GroupLists);
        var paths = groups.Keys.Union(traffic.Keys, StringComparer.OrdinalIgnoreCase)
            .Select(p =>
            {
                var group = grouped ? GroupOf(p) : ProcessGroup.AllPrograms; // einmal je Zeile
                return (Path: p, Name: DisplayName(p), Order: (int)group, Group: grouped ? ProcessGroups.Title(group) : "");
            })
            .OrderBy(p => p.Order).ThenBy(p => p.Path.Length == 0)
            .ThenBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ThenBy(p => p.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var same = _processRows.Count == paths.Count + 1;
        for (var i = 0; same && i < paths.Count; i++)
            same = string.Equals(_processRows[i + 1].Path, paths[i].Path, StringComparison.OrdinalIgnoreCase) && _processRows[i + 1].Group == paths[i].Group;
        if (!same)
        {
            _loading = true;
            // Beim Neuaufbau (ein Programm kam dazu) die Rollposition behalten; gruppiert werden dabei auch die Gruppen neu angelegt.
            var scroller = FindChild<ScrollViewer>(ProcessList);
            var offset = scroller?.VerticalOffset ?? 0;
            _processRows.Clear();
            _processRows.Add(new ProcessRow { Path = null, Name = Loc.T("Alle Programme", "All Programs") });
            foreach (var p in paths) _processRows.Add(new ProcessRow { Path = p.Path, Name = p.Name, Group = p.Group });
            ApplyGrouping(ProcessList, grouped);
            ProcessList.SelectedItem = _processRows.FirstOrDefault(r => string.Equals(r.Path, _selectedProcess, StringComparison.OrdinalIgnoreCase)) ?? _processRows[0];
            _selectedProcess = (ProcessList.SelectedItem as ProcessRow)?.Path;
            _loading = false;
            connectionsChanged = true;
            if (scroller != null && offset > 0)
                Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () => scroller.ScrollToVerticalOffset(offset));
        }

        static Brush State(IEnumerable<ConnectionRecord> rs) => rs.Any(r => r.Pending) ? Ui.Ask : rs.Any(r => r.Allowed == false) ? Ui.Deny : Ui.None;
        var all = _processRows[0];
        all.Summary = Loc.F("{0} Programme · {1} Gegenstellen", "{0} programs · {1} remotes", paths.Count, records.Count);
        all.DownText = Ui.Volume("↓", traffic.Values.Sum(t => t.Down), traffic.Values.Sum(t => t.RateDown));
        all.UpText = Ui.Volume("↑", traffic.Values.Sum(t => t.Up), traffic.Values.Sum(t => t.RateUp));
        all.StateBrush = State(records);
        var serviceHosts = groups.Keys.Where(k => k.Contains('|')).Select(k => k[..k.IndexOf('|')]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var row in _processRows.Skip(1))
        {
            // Datenmengen: je Programm aus der Programmzählung; ein einzelner Windows-Dienst aus den Summen seiner Gegenstellen
            // (nur Verbindungen, die SnitchBox entschieden hat).
            var isService = row.Path!.Contains('|');
            traffic.TryGetValue(row.Path!, out var t);
            groups.TryGetValue(row.Path!, out var g);
            if (isService && g != null)
            {
                row.DownText = Ui.Volume("↓", g.Sum(r => r.Down), g.Sum(r => r.RateDown));
                row.UpText = Ui.Volume("↑", g.Sum(r => r.Up), g.Sum(r => r.RateUp));
            }
            else
            {
                row.DownText = Ui.Volume("↓", t.Down, t.RateDown);
                row.UpText = Ui.Volume("↑", t.Up, t.RateUp);
            }
            if (g != null)
            {
                row.Summary = Loc.F("{0} Gegenstellen · zuletzt {1:HH:mm:ss}", "{0} remotes · last {1:HH:mm:ss}", g.Count, g.Max(r => r.LastSeen));
                row.StateBrush = State(g);
            }
            else
            {
                row.Summary = serviceHosts.Contains(row.Path!)
                    ? Loc.T("Datenmenge aller Windows-Dienste zusammen", "Data volume of all Windows services combined")
                    : Loc.T("Verbindung bestand schon vor dem Start", "Connection existed before start");
                row.StateBrush = Ui.None;
            }
        }
        if (connectionsChanged) ShowConnections(records);
    }

    private void ShowConnections(List<ConnectionRecord>? records = null)
    {
        records ??= App.Engine.History.Snapshot();
        var selected = (ConnectionList.SelectedItem as ConnectionRow)?.Record;
        var rows = records
            .Where(r => _selectedProcess == null || KeyOf(r).Equals(_selectedProcess, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(r => r.LastSeen).Select(r => new ConnectionRow(r)).ToList();
        ConnectionList.ItemsSource = rows;
        if (selected != null) ConnectionList.SelectedItem = rows.FirstOrDefault(r => r.Record == selected);
    }

    private void ProcessList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        _selectedProcess = (ProcessList.SelectedItem as ProcessRow)?.Path;
        ShowConnections();
    }

    private void MonitorRule(bool allow)
    {
        if (ConnectionList.SelectedItem is not ConnectionRow row)
        {
            MessageBox.Show(this, Loc.T("Wähle zuerst eine Verbindung in der Liste.", "Select a connection in the list first."), App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!AlertRules.CanRemember(row.Record.Template))
        {
            MessageBox.Show(this, Loc.T("Zu dieser Verbindung ist das Programm unbekannt. Eine Regel ohne Programm gälte für alle Programme – lege sie bei Bedarf über „Neue Regel“ bewusst an.",
                                        "The program of this connection is unknown. A rule without a program would apply to every program – create one deliberately via “New Rule” if needed."),
                App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var rule = AlertRules.Create(row.Record.Template, allow, AlertScope.Host, AlertLifetime.Forever, App.Engine.BootId, null, DateTime.Now)!;
        if (EditRule(rule, true) is not { } saved) return;
        // Greift die Regel bei dieser Verbindung? Eine genauere oder vorrangige Regel bzw. eine Blockliste kann sie überstimmen.
        var d = App.Engine.Evaluate(row.Record.Template);
        if (d.Action == saved.Action) return;
        MessageBox.Show(this, d.Action == null
                ? Loc.T("Die Regel ist gespeichert, passt aber nicht auf diese Verbindung (anderes Profil, andere Gegenstelle oder anderer Port).",
                        "The rule was saved but does not match this connection (different profile, remote or port).")
                : Loc.F("Die Regel ist gespeichert, greift bei dieser Verbindung aber nicht. Vorrang hat:\n{0}",
                        "The rule was saved but does not take effect for this connection. Taking precedence:\n{0}", d.Reason),
            App.Title, MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void MonitorAllow_Click(object sender, RoutedEventArgs e) => MonitorRule(true);
    private void MonitorDeny_Click(object sender, RoutedEventArgs e) => MonitorRule(false);

    private void MonitorClear_Click(object sender, RoutedEventArgs e)
    {
        App.Engine.History.Clear();
        App.Engine.Traffic.Clear();
        Tick();
    }

    // ---------------------------------------------------------------- Blocklisten

    private void ReloadBlocklists()
    {
        var selected = (BlocklistList.SelectedItem as BlocklistRow)?.List;
        var rows = App.Engine.Read(s => s.Blocklists.ToList()).Select(b => new BlocklistRow(b)).ToList();
        BlocklistList.ItemsSource = rows;
        if (selected != null) BlocklistList.SelectedItem = rows.FirstOrDefault(r => r.List == selected);
    }

    private async void BlocklistAdd_Click(object sender, RoutedEventArgs e)
    {
        var text = BlocklistUrlBox.Text.Trim();
        var name = "";
        var url = text;
        foreach (ComboBoxItem preset in BlocklistUrlBox.Items)
            if ((string)preset.Content == text) { name = text; url = (string)preset.Tag; }
        if (url.Length == 0) return;
        if (App.Engine.Read(s => s.Blocklists.Any(b => b.Url.Equals(url, StringComparison.OrdinalIgnoreCase))))
        {
            MessageBox.Show(this, Loc.T("Diese Liste ist schon abonniert.", "This list is already subscribed."), App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var list = new Blocklist { Name = name, Url = url };
        BlocklistInfo.Text = Loc.T("Liste wird geladen …", "Loading list…");
        App.Engine.Mutate(s => s.Blocklists.Add(list));
        var error = await BlocklistUpdater.UpdateAsync(App.Engine, list);
        BlocklistInfo.Text = "";
        if (error == null)
        {
            BlocklistUrlBox.Text = "";
            return;
        }
        App.Engine.Mutate(s => s.Blocklists.Remove(list));
        MessageBox.Show(this, Loc.T("Die Liste konnte nicht geladen werden:\n", "The list could not be loaded:\n") + error, App.Title, MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private async void BlocklistUpdate_Click(object sender, RoutedEventArgs e)
    {
        var lists = App.Engine.Read(s => s.Blocklists.Where(b => b.Url.Length > 0).ToList());
        if (lists.Count == 0) return;
        BlocklistInfo.Text = Loc.T("Listen werden aktualisiert …", "Updating lists…");
        var errors = new List<string>();
        foreach (var l in lists)
            if (await BlocklistUpdater.UpdateAsync(App.Engine, l) is { } err) errors.Add($"{l.Name}: {err}");
        BlocklistInfo.Text = errors.Count == 0 ? Loc.T("Alle Listen sind aktuell.", "All lists are up to date.") : string.Join("\n", errors);
    }

    private void BlocklistRemove_Click(object sender, RoutedEventArgs e)
    {
        if (BlocklistList.SelectedItem is not BlocklistRow row) return;
        App.Engine.Mutate(s => s.Blocklists.Remove(row.List));
        App.Engine.Store.DeleteBlocklistFile(row.List);
    }

    // ---------------------------------------------------------------- Einstellungen

    private void ReloadSettings()
    {
        ReloadNetworkProfiles();
        var s = App.Engine.Read(st => (st.Settings.MonitorIncoming, st.Settings.BlocklistAutoUpdate, st.Settings.GroupLists));
        IncomingBox.IsChecked = s.MonitorIncoming;
        AutoUpdateBox.IsChecked = s.BlocklistAutoUpdate;
        GroupListsBox.IsChecked = s.GroupLists;
        _autostart ??= !App.DemoMode && Autostart.Enabled;
        AutostartBox.IsChecked = _autostart;
        AutostartBox.IsEnabled = !App.DemoMode;
        ShowAutostartHint();

        // Sprache: „Wie Windows“ und die unterstützten Sprachen, jeweils in sich selbst benannt.
        _loading = true;
        if (LanguageBox.Items.Count == 0)
        {
            LanguageBox.Items.Add(Loc.F("Wie Windows ({0})", "Same as Windows ({0})", Loc.NameOf(Loc.WindowsLanguage)));
            foreach (var (_, name) in Loc.Languages) LanguageBox.Items.Add(name);
        }
        var chosen = App.Engine.Read(st => st.Settings.Language);
        LanguageBox.SelectedIndex = chosen == null ? 0 : Array.FindIndex(Loc.Languages, l => l.Code == chosen) + 1;
        _loading = false;
        DriverText.Text = App.DemoMode
            ? Loc.T("Demo-Modus: Der Treiber ist nicht geladen, es wird nichts gefiltert.", "Demo mode: the driver is not loaded, nothing is filtered.")
            : App.Service.Running
                ? Loc.T("Der Treiber WinDivert 2.2.2 ist geladen und fängt Verbindungen ab.", "The WinDivert 2.2.2 driver is loaded and intercepts connections.")
                : Loc.T("Der Treiber läuft nicht: ", "The driver is not running: ") + App.Service.Error;
    }

    /// <summary>Hinweis unter „Beim Anmelden starten“, wenn die Aufgabe eine andere oder eine für alle änderbare Datei startet
    /// (je Fenster einmal ermittelt, weil dafür schtasks läuft).</summary>
    private void ShowAutostartHint()
    {
        if (_autostartHint == null)
        {
            _autostartHint = "";
            if (_autostart == true && Autostart.Command is { } command)
            {
                var parts = new List<string>();
                if (!File.Exists(command))
                    parts.Add(Loc.F("Der Autostart startet eine Datei, die es nicht mehr gibt: {0}. Aus- und wieder einschalten, um diese hier zu verwenden.",
                                    "Autostart runs a file that no longer exists: {0}. Switch it off and on again to use this one.", command));
                else if (!string.Equals(command, Autostart.Target, StringComparison.OrdinalIgnoreCase)
                         && !string.Equals(command, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                    parts.Add(Loc.F("Der Autostart startet eine andere Datei: {0}. Aus- und wieder einschalten, um diese hier zu verwenden.",
                                    "Autostart runs a different file: {0}. Switch it off and on again to use this one.", command));
                if (File.Exists(command) && FolderSecurity.WritersOtherThanAdmins(command) is { Count: > 0 } writers)
                    parts.Add(Loc.F("Diese Datei können auch Nicht-Administratoren austauschen ({0}); sie startet trotzdem mit Administratorrechten. Besser nach „C:\\Program Files\\SnitchBox“ verschieben.",
                                    "Non-administrators can replace this file ({0}), yet it runs with administrator rights. Better move it to “C:\\Program Files\\SnitchBox”.", string.Join(", ", writers)));
                _autostartHint = string.Join("\n", parts);
            }
        }
        AutostartHint.Text = _autostartHint;
        AutostartHint.Visibility = _autostartHint.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Autostart_Click(object sender, RoutedEventArgs e)
    {
        if (AutostartBox.IsChecked == true && Autostart.Target is { Length: > 0 } exe && FolderSecurity.WritersOtherThanAdmins(exe) is { Count: > 0 } writers
            && MessageBox.Show(this, Autostart.WarningText(exe, writers, true), App.Title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            AutostartBox.IsChecked = _autostart;
            return;
        }
        Autostart.Enabled = AutostartBox.IsChecked == true;
        _autostart = Autostart.Enabled;
        AutostartBox.IsChecked = _autostart;
        _autostartHint = null;
        ShowAutostartHint();
    }

    private void LanguageBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || LanguageBox.SelectedIndex < 0) return;
        var code = LanguageBox.SelectedIndex == 0 ? null : Loc.Languages[LanguageBox.SelectedIndex - 1].Code;
        App.Engine.Mutate(s => s.Settings.Language = code);
        var target = code ?? Loc.WindowsLanguage;
        if (target == Loc.Language) return;
        Loc.Language = target;
        // Sofort wirksam: das Hauptfenster in der neuen Sprache neu öffnen (seine Texte werden beim Laden gesetzt).
        Dispatcher.BeginInvoke(() =>
        {
            var app = Application.Current as App;
            Close();
            app?.ShowMain();
            app?.RefreshTray();
        });
    }

    private void Incoming_Click(object sender, RoutedEventArgs e)
    {
        var on = IncomingBox.IsChecked == true;
        App.Engine.Mutate(s => s.Settings.MonitorIncoming = on);
    }

    private void AutoUpdate_Click(object sender, RoutedEventArgs e)
    {
        var on = AutoUpdateBox.IsChecked == true;
        App.Engine.Mutate(s => s.Settings.BlocklistAutoUpdate = on);
    }

    private void GroupLists_Click(object sender, RoutedEventArgs e)
    {
        var on = GroupListsBox.IsChecked == true;
        App.Engine.Mutate(s => s.Settings.GroupLists = on); // baut auch die Regelliste neu auf (RulesChanged)
        _historyVersion = -1; // die Programmliste beim nächsten Takt neu ordnen
    }

    private void ProfileAdd_Click(object sender, RoutedEventArgs e)
    {
        var name = ProfileNameBox.Text.Trim();
        if (name.Length == 0) return;
        App.ChooseProfileByHand(name, s =>
        {
            if (!s.Settings.Profiles.Contains(name)) s.Settings.Profiles.Add(name);
        });
        ProfileNameBox.Text = "";
    }

    private void ProfileDelete_Click(object sender, RoutedEventArgs e)
    {
        CommitNetworkChoice(); // eine noch wartende Zuordnung nicht erst nach dem Löschen (womöglich auf das gelöschte Profil) anwenden
        var active = App.Engine.Read(s => s.Settings.ActiveProfile);
        if (active == null) return;
        var count = App.Engine.Read(s => s.Rules.Count(r => r.Profile == active));
        if (MessageBox.Show(this, Loc.F("Profil „{0}“ samt seinen {1} Regeln löschen?", "Delete profile “{0}” and its {1} rules?", active, count),
                App.Title, MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        var connected = App.NetworkWatcher?.Current ?? [];
        App.Engine.Mutate(s =>
        {
            s.Rules.RemoveAll(r => r.Profile == active);
            // Das Profil und seine Zuordnungen entfallen; ändert das die Wahl für das verbundene Netz, gilt die neue.
            NetworkProfiles.ChangeBindings(connected, s.Settings, st =>
            {
                st.Profiles.Remove(active);
                st.NetworkProfiles.RemoveAll(b => !b.NoSwitch && b.Profile == active);
                if (st.UnknownNetworkProfile != active) return;
                st.UnknownNetworkProfile = null;
                st.SwitchOnUnknownNetwork = false;
            });
            // Hat inzwischen schon das Netzwerk ein anderes Profil gewählt, bleibt es; sonst gilt wieder, was zum Netz gehört
            // (ohne verbundenes Netz beim nächsten Verbinden).
            if (s.Settings.ActiveProfile != active) return;
            s.Settings.ActiveProfile = null;
            if (!NetworkProfiles.HasRelevant(connected, s.Settings)) NetworkProfiles.Forget(s.Settings);
            else if (NetworkProfiles.ChooseHere(connected, s.Settings) is (true, var profile, _)) s.Settings.ActiveProfile = profile;
        });
    }

    /// <summary>Was zuletzt in „Profil je Netzwerk“ gezeichnet wurde – neu aufgebaut wird nur bei einer sichtbaren Änderung, sonst
    /// schlösse jede Regeländerung ein gerade offenes Auswahlfeld.</summary>
    private string _networkPanelShown = "";

    /// <summary>Zeilen „Profil je Netzwerk“: erst die verbundenen Netzwerke, dann die übrigen schon zugeordneten, zuletzt „Andere
    /// Netzwerke“. Je Netzwerk eine Auswahl: wie andere Netzwerke / nicht automatisch wechseln / kein Profil / ein Profil.</summary>
    private void ReloadNetworkProfiles()
    {
        if (_pendingNetworkChoice != null) return; // die Auswahl des Nutzers nicht überzeichnen; CommitNetworkChoice holt es nach
        var connected = App.NetworkWatcher?.Current ?? [];
        var s = App.Engine.Read(st => (
            Bindings: st.Settings.NetworkProfiles.Select(b => (b.NetworkId, b.Name, b.Profile, b.NoSwitch)).ToList(),
            Profiles: st.Settings.Profiles.ToList(), st.Settings.SwitchOnUnknownNetwork, st.Settings.UnknownNetworkProfile));
        var shown = string.Join("\n", Loc.Language, string.Join("|", connected.Select(c => c.Id + "=" + c.Name)), string.Join("|", s.Bindings),
            string.Join("|", s.Profiles), s.SwitchOnUnknownNetwork, s.UnknownNetworkProfile);
        if (shown == _networkPanelShown) return;
        // Eine gerade aufgeklappte Liste nicht unter dem Nutzer wegziehen; DropDownClosed holt den Neuaufbau nach.
        if (NetworkProfilesPanel.Children.OfType<StackPanel>().SelectMany(l => l.Children.OfType<ComboBox>()).Any(c => c.IsDropDownOpen)) return;
        _networkPanelShown = shown;

        var rows = connected.Select(c => (c.Id, c.Name, Connected: true)).ToList();
        foreach (var b in s.Bindings)
            if (!rows.Any(r => r.Id.Equals(b.NetworkId, StringComparison.OrdinalIgnoreCase))) rows.Add((b.NetworkId, b.Name, false));

        ComboBox Choice(IEnumerable<string> fixedItems, int selected, object tag)
        {
            // 265: Platz für den längsten festen Eintrag („Ne pas changer automatiquement“, gemessen mit Segoe UI 14).
            var combo = new ComboBox { Width = 265, VerticalAlignment = VerticalAlignment.Center, Tag = tag };
            foreach (var item in fixedItems) combo.Items.Add(item);
            combo.Items.Add(Loc.T("Kein Profil", "No Profile"));
            foreach (var p in s.Profiles) combo.Items.Add(p);
            combo.SelectedIndex = selected;
            WireNetworkChoice(combo);
            return combo;
        }
        // Index in der Auswahl: nach den festen Einträgen „Kein Profil“, dann die Profile. Ein unbekanntes Profil gibt den ersten Eintrag.
        int IndexOf(string? profile, int fixedCount) =>
            profile == null ? fixedCount : s.Profiles.IndexOf(profile) is >= 0 and var i ? fixedCount + 1 + i : 0;
        StackPanel Line(string label, string? tooltip, ComboBox combo)
        {
            var line = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            line.Children.Add(new TextBlock { Text = label, ToolTip = tooltip, Width = 330, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis });
            line.Children.Add(combo);
            return line;
        }

        // Hatte eine der Auswahlen den Fokus, bekommt ihn die neue an derselben Stelle wieder – auch den logischen Fokus eines gerade
        // inaktiven Fensters (nach dem Zurückwechseln steht er sonst auf dem Fenster selbst).
        var logical = FocusManager.GetFocusedElement(this) as DependencyObject;
        var focused = NetworkProfilesPanel.Children.OfType<StackPanel>().SelectMany(l => l.Children.OfType<ComboBox>())
            .FirstOrDefault(c => c.IsKeyboardFocusWithin || (logical != null && (logical == c || c.IsAncestorOf(logical))))?.Tag;
        NetworkProfilesPanel.Children.Clear();
        if (connected.Count == 0)
            NetworkProfilesPanel.Children.Add(new TextBlock { Text = Loc.T("Gerade ist kein Netzwerk verbunden.", "No network is connected right now."), Style = (Style)FindResource("Dim"), Margin = new Thickness(0, 2, 0, 2) });
        string[] networkItems = [Loc.T("Wie andere Netzwerke", "Like other networks"), Loc.T("Nicht automatisch wechseln", "Don't switch automatically")];
        ComboBox? refocus = null;
        foreach (var row in rows)
        {
            var binding = s.Bindings.FirstOrDefault(b => b.NetworkId.Equals(row.Id, StringComparison.OrdinalIgnoreCase));
            var selected = binding.NetworkId == null ? 0 : binding.NoSwitch ? 1 : IndexOf(binding.Profile, networkItems.Length);
            var combo = Choice(networkItems, selected, (row.Id, row.Name));
            combo.SelectionChanged += NetworkProfile_Changed; // erst nach dem Vorbelegen, sonst feuert es beim Aufbau
            NetworkProfilesPanel.Children.Add(Line(row.Name + (row.Connected ? Loc.T("  (verbunden)", "  (connected)") : ""), row.Name, combo));
            if (Equals(focused, combo.Tag)) refocus = combo;
        }
        var other = Choice([Loc.T("Profil unverändert lassen", "Keep the current profile")],
            s.SwitchOnUnknownNetwork ? IndexOf(s.UnknownNetworkProfile, 1) : 0, "other");
        other.SelectionChanged += UnknownNetworkProfile_Changed;
        NetworkProfilesPanel.Children.Add(Line(Loc.T("Andere Netzwerke", "Other networks"), null, other));
        if (Equals(focused, other.Tag)) refocus = other;
        if (refocus == null) return;
        if (IsActive) refocus.Focus();
        else FocusManager.SetFocusedElement(this, refocus);
    }

    private (ComboBox Combo, Action<Settings> Change)? _pendingNetworkChoice;

    /// <summary>Auswahl übernehmen: aus der aufgeklappten Liste (Klick, Eingabetaste, Alt+Pfeil) sofort; mit den Pfeiltasten oder
    /// Buchstaben im zugeklappten Feld erst mit der Eingabetaste oder wenn das Feld den Fokus verliert – sonst schaltete jeder
    /// Zwischenwert (etwa „Kein Profil“ auf dem Weg nach oben) das Profil um, auch mit Pausen (Sprachausgabe).</summary>
    private void QueueNetworkChoice(ComboBox combo, Action<Settings> change)
    {
        if (_pendingNetworkChoice is { } pending && pending.Combo != combo) CommitNetworkChoice();
        _pendingNetworkChoice = (combo, change);
        if (combo.IsDropDownOpen || !combo.IsKeyboardFocusWithin || Keyboard.IsKeyDown(Key.Enter) || Keyboard.IsKeyDown(Key.F4)
            || (Keyboard.Modifiers & ModifierKeys.Alt) != 0)
            CommitNetworkChoice();
    }

    /// <summary>Netzwerk-Auswahlfeld: übernimmt eine wartende Auswahl mit der Eingabetaste oder beim Verlassen; das Mausrad über dem
    /// zugeklappten Feld rollt die Seite, statt die Auswahl zu ändern.</summary>
    private void WireNetworkChoice(ComboBox combo)
    {
        combo.IsKeyboardFocusWithinChanged += (_, e) =>
        {
            if (e.NewValue is false && _pendingNetworkChoice?.Combo == combo) CommitNetworkChoice();
        };
        combo.PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter && !combo.IsDropDownOpen && _pendingNetworkChoice?.Combo == combo) CommitNetworkChoice();
        };
        // Während die Liste offen war, ausgelassenen Neuaufbau nachholen.
        combo.DropDownClosed += (_, _) => Dispatcher.BeginInvoke(ReloadNetworkProfiles);
        combo.PreviewMouseWheel += (_, e) =>
        {
            if (combo.IsDropDownOpen || combo.Parent is not UIElement parent) return;
            e.Handled = true;
            parent.RaiseEvent(new MouseWheelEventArgs(e.MouseDevice, e.Timestamp, e.Delta) { RoutedEvent = MouseWheelEvent, Source = combo });
        };
        combo.SetBinding(ToolTipProperty, new System.Windows.Data.Binding(nameof(ComboBox.SelectedItem)) { RelativeSource = System.Windows.Data.RelativeSource.Self });
    }

    private void CommitNetworkChoice()
    {
        if (_pendingNetworkChoice is not { } pending) return;
        _pendingNetworkChoice = null;
        _networkPanelShown = ""; // während der Wartezeit ausgelassenen Neuaufbau nachholen
        ChangeNetworkProfiles(pending.Change);
    }

    /// <summary>Zuordnungen ändern; umgeschaltet wird nur, wenn das die verbundenen Netzwerke betrifft (ein von Hand gewähltes Profil
    /// bleibt sonst bis zum nächsten Netzwerkwechsel).</summary>
    private static void ChangeNetworkProfiles(Action<Settings> change)
    {
        var connected = App.NetworkWatcher?.Current ?? [];
        string? switchedTo = null;
        var switched = false;
        App.Engine.Mutate(s =>
        {
            switched = NetworkProfiles.ChangeBindings(connected, s.Settings, change);
            switchedTo = s.Settings.ActiveProfile;
        });
        if (switched) Log.Write($"Profil je Netzwerk: „{switchedTo ?? "Kein Profil"}“ nach geänderter Zuordnung");
    }

    private void NetworkProfile_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (sender is not ComboBox { Tag: ValueTuple<string, string> tag } combo || combo.SelectedIndex < 0) return;
        var (id, name) = tag;
        // 0 = wie andere Netzwerke (keine Zuordnung), 1 = nicht automatisch wechseln, 2 = kein Profil, ab 3 die Profile.
        var index = combo.SelectedIndex;
        var profile = index >= 3 ? combo.SelectedItem as string : null;
        QueueNetworkChoice(combo, s => NetworkProfiles.SetBinding(s, id,
            index == 0 ? null : new NetworkProfile { NetworkId = id, Name = name, Profile = profile, NoSwitch = index == 1 }));
    }

    private void UnknownNetworkProfile_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (sender is not ComboBox combo || combo.SelectedIndex < 0) return;
        // 0 = Profil unverändert lassen, 1 = kein Profil, ab 2 die Profile.
        var index = combo.SelectedIndex;
        var profile = index >= 2 ? combo.SelectedItem as string : null;
        QueueNetworkChoice(combo, s =>
        {
            s.SwitchOnUnknownNetwork = index >= 1;
            s.UnknownNetworkProfile = profile;
        });
    }

    private void RestartFilter_Click(object sender, RoutedEventArgs e)
    {
        if (App.DemoMode) return;
        App.Service.Stop();
        App.Service.Start();
        ReloadHeader();
        ReloadSettings();
        (Application.Current as App)?.RefreshTray(); // läuft der Treiber danach nicht, wird das Symbol rot
    }

    private void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "notepad.exe"), $"\"{Log.FilePath}\"") { UseShellExecute = false }); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, App.Title); }
    }

    private void RestoreFactory_Click(object sender, RoutedEventArgs e)
    {
        App.Engine.Mutate(s =>
        {
            s.Settings.FactoryRulesCreated = false;
            FactoryRules.Ensure(s, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        });
    }

    private void About_Click(object sender, RoutedEventArgs e) => App.About();

    private void Kofi_Click(object sender, RoutedEventArgs e) => DesktopShell.OpenUrl(this, "https://ko-fi.com/C5H12AP4UV");
}
