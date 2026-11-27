using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Eine Zeile der Hop-Liste; wird bei jedem Zwischenstand an Ort und Stelle aktualisiert (Auswahl und Rollposition bleiben).</summary>
internal sealed class HopRow(int number) : INotifyPropertyChanged
{
    public int Number { get; } = number;
    public string AddressText { get; private set; } = "";
    public string NameText { get; private set; } = "";
    public string TimesText { get; private set; } = "";
    public string CountryText { get; private set; } = "";
    public string Tip { get; private set; } = "";
    public event PropertyChangedEventHandler? PropertyChanged;

    public void Set(string address, string name, string times, string country, string tip)
    {
        if (address == AddressText && name == NameText && times == TimesText && country == CountryText && tip == Tip) return;
        (AddressText, NameText, TimesText, CountryText, Tip) = (address, name, times, country, tip);
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }
}

/// <summary>Eine Zeile der Übersicht „wohin sendet dieses Programm“: ein Ziel mit Land, Hops, Zeit, Datenmenge und Stand.</summary>
internal sealed class DestRow(TraceTarget target) : INotifyPropertyChanged
{
    public TraceTarget Target { get; } = target;
    public string HostText => Target.Host.Length > 0 ? Target.Host : Target.Address.ToString();
    public string AddressText => Target.Address.ToString();
    public string DataText => Target.Bytes > 0 ? Ui.Size(Target.Bytes) : "";
    public string CountryText { get; private set; } = "";
    public string HopsText { get; private set; } = "";
    public string TimeText { get; private set; } = "";
    public string StateText { get; private set; } = "";
    public string Tip { get; private set; } = "";
    public event PropertyChangedEventHandler? PropertyChanged;

    public void Set(string country, string hops, string time, string state, string tip)
    {
        if (country == CountryText && hops == HopsText && time == TimeText && state == StateText && tip == Tip) return;
        (CountryText, HopsText, TimeText, StateText, Tip) = (country, hops, time, state, tip);
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }
}

/// <summary>Routenverfolgung (wie tracert) zu einer Gegenstelle, auf Wunsch mit Weltkarte. Proben: <see cref="IcmpProber"/>,
/// Ablauf: <see cref="Tracer"/>, Länder: <see cref="GeoData"/> (nur nach Zustimmung heruntergeladen), Karte: <see cref="MapView"/>.</summary>
public partial class TraceWindow : Window
{
    private readonly ObservableCollection<HopRow> _rows = [];
    private readonly Dictionary<IPAddress, string?> _names = [];
    private readonly HashSet<IPAddress> _lookups = [];
    private (string Text, IPAddress Address)? _preset;
    private CancellationTokenSource? _run;
    private Tracer? _tracer;
    private IPAddress? _target;
    private string _targetText = "";
    private bool _refreshQueued, _closed, _downloading;
    private readonly CancellationTokenSource _life = new();
    // Übersicht „wohin sendet dieses Programm“ (sonst null): Name des Programms, seine Ziele, ausgelassene ältere Ziele.
    private readonly string? _program;
    private readonly bool _allPrograms;
    // Holt die Ziele frisch aus dem Netzwerkmonitor – bei jedem Start, damit „Erneut verfolgen“ auch neue Ziele nimmt.
    private readonly Func<(List<TraceTarget> Targets, int Omitted)>? _collect;
    private List<TraceTarget> _targets = [];
    private int _omitted;
    private readonly ObservableCollection<DestRow> _dests = [];
    private List<(Tracer Tracer, DestRow Row)> _group = [];
    /// <summary>So viele Ziele laufen gleichzeitig (gemessen: 15 Ziele in rund 7 s, ohne verlorene Antworten von Hop 1).</summary>
    private const int Parallel = 6;

    /// <param name="host">Angezeigter Name der Gegenstelle (oder die Adresse).</param>
    /// <param name="address">Adresse der Verbindung: verfolgt wird genau sie, solange der Name im Feld nicht geändert wird.</param>
    public TraceWindow(string? host = null, IPAddress? address = null) : this(program: null)
    {
        Title = Loc.T("Route verfolgen", "Trace Route") + " – SnitchBox";
        HopList.ItemsSource = _rows;
        Ui.FitColumn(HopList, 2, 100); // die Spalte „Name“ nimmt den übrigen Platz
        if (address != null)
        {
            var text = string.IsNullOrWhiteSpace(host) ? address.ToString() : host.Trim();
            _preset = (text, address);
            TargetBox.Text = text;
        }
    }

    /// <summary>Übersicht: die Wege zu allen <paramref name="targets"/> eines Programms (aus dem Netzwerkmonitor) auf einmal, auf der Karte
    /// zusammen. Doppelklick auf ein Ziel öffnet seine Hops in einem eigenen Fenster.</summary>
    /// <param name="allPrograms">„Alle Programme“: eigene Texte (kein Programmname in den Sätzen).</param>
    /// <param name="collect">Liefert die Ziele (die zuletzt benutzten zuerst) und wie viele ältere ausgelassen sind.</param>
    public TraceWindow(string program, bool allPrograms, Func<(List<TraceTarget> Targets, int Omitted)> collect) : this(program: (string?)program)
    {
        _allPrograms = allPrograms;
        _collect = collect;
        Title = (allPrograms ? Loc.T("Wohin senden alle Programme?", "Where do all programs send to?")
            : Loc.F("Wohin sendet {0}?", "Where does {0} send to?", program)) + " – SnitchBox";
        TargetLabel.Text = Loc.T("Programm", "Program");
        TargetBox.Text = program;
        TargetBox.IsReadOnly = true;
        TargetBox.ToolTip = null;
        NamesBox.Visibility = Visibility.Collapsed;
        HopList.View = (GridView)FindResource("DestView");
        HopList.ItemsSource = _dests;
        Ui.FitColumn(HopList, 0, 120); // die Spalte „Ziel“ nimmt den übrigen Platz
        HopList.SelectionChanged += (_, _) => Refresh();
        HopList.MouseDoubleClick += Dest_DoubleClick;
        StartButton.Content = Loc.T("Erneut verfolgen", "Trace Again");
        StartButton.IsDefault = false;
        UpdateHint(null, 0);
    }

    private TraceWindow(string? program)
    {
        InitializeComponent();
        _program = program;
        if (Ui.AppIcon() is { } icon) Icon = icon;
        var (names, showMap) = App.Engine.Read(s => (s.Settings.TraceResolveNames, s.Settings.TraceShowMap));
        NamesBox.IsChecked = names;
        // Die Karte nur, wenn sie schon einmal gewünscht war (in der Übersicht immer) und die Ländertabelle da ist – sonst fragt erst der Klick.
        MapBox.IsChecked = (showMap || program != null) && GeoData.Current != null;
        ShowMap(MapBox.IsChecked == true);
        UpdateCredit();
        UpdateHint(null, 0);
        Loaded += (_, _) =>
        {
            if (_program != null) _ = StartGroupAsync();
            else if (_preset != null) _ = StartAsync();
            else { TargetBox.Focus(); Status(Loc.T("Adresse oder Namen eingeben und „Verfolgen“ wählen.", "Enter an address or name and choose “Trace”."), false); }
        };
        Closed += (_, _) =>
        {
            _closed = true;
            _run?.Cancel();
            _life.Cancel();
        };
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int Size;
        public int MonLeft, MonTop, MonRight, MonBottom, WorkLeft, WorkTop, WorkRight, WorkBottom;
        public uint Flags;
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo info);

    /// <summary>Zeigt das Fenster mittig über <paramref name="main"/> und ganz im Arbeitsbereich von dessen Bildschirm (das übernimmt
    /// WPF mit CenterOwner), danach ohne Besitzer: Es bleibt offen, wenn der Netzwerkmonitor zugeht, und sein Trace läuft weiter.</summary>
    public void ShowNear(Window? main)
    {
        var work = SystemParameters.WorkArea.Size; // Hauptbildschirm, falls das Hauptfenster nicht hilft
        if (main is { IsVisible: true } && main.WindowState != WindowState.Minimized)
        {
            var info = new MonitorInfo { Size = System.Runtime.InteropServices.Marshal.SizeOf<MonitorInfo>() };
            var monitor = MonitorFromWindow(new System.Windows.Interop.WindowInteropHelper(main).Handle, 2 /* MONITOR_DEFAULTTONEAREST */);
            if (monitor != IntPtr.Zero && GetMonitorInfo(monitor, ref info))
            {
                var dpi = System.Windows.Media.VisualTreeHelper.GetDpi(main);
                work = new Size((info.WorkRight - info.WorkLeft) / dpi.DpiScaleX, (info.WorkBottom - info.WorkTop) / dpi.DpiScaleY);
            }
            Owner = main;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Loaded += (_, _) => Owner = null;
        }
        // Bei 175 % auf kleinen Bildschirmen wäre das Fenster sonst höher als der Arbeitsbereich.
        Width = Math.Min(Width, Math.Max(MinWidth, work.Width - 40));
        Height = Math.Min(Height, Math.Max(MinHeight, work.Height - 40));
        Show();
    }

    private void Status(string text, bool error)
    {
        StatusText.Text = text;
        StatusText.Foreground = error ? Ui.Deny : (System.Windows.Media.Brush)GetValue(ForegroundProperty);
        StatusText.Opacity = error ? 1 : 0.8;
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        if (_run != null) { _run.Cancel(); return; }
        if (_program != null) await StartGroupAsync();
        else await StartAsync();
    }

    /// <summary>Übersicht: alle Ziele verfolgen – Hop 1 nacheinander, der Rest gleichzeitig (<see cref="TraceGroup"/>); Ziele über
    /// dasselbe Gateway übernehmen Hop 1 voneinander (<see cref="IcmpProber.GatewayKey"/>).</summary>
    private async Task StartGroupAsync()
    {
        if (_run != null) return;
        _run = new CancellationTokenSource();
        var cancel = _run.Token;
        StartButton.Content = Loc.T("Abbrechen", "Cancel");
        _dests.Clear();
        Map.ResetView();
        if (_collect != null)
        {
            try { (_targets, _omitted) = _collect(); }
            catch (Exception e) { Log.Write("Ziele sammeln: " + e.Message); _targets = []; _omitted = 0; }
        }
        UpdateHint(null, 0);
        var prober = new IcmpProber();
        _group = _targets.Select(t => (new Tracer(prober), new DestRow(t))).ToList();
        foreach (var (tracer, row) in _group)
        {
            _dests.Add(row);
            tracer.Changed += QueueRefresh;
        }
        try
        {
            if (_group.Count == 0)
            {
                Status(_allPrograms
                    ? Loc.T("SnitchBox kennt noch keine Gegenstelle, deren Weg sich verfolgen lässt (Verbindungen von vor dem Start von SnitchBox fehlen).",
                            "SnitchBox does not know any remote yet whose route can be traced (connections made before SnitchBox started are missing).")
                    : Loc.F("SnitchBox kennt noch keine Gegenstelle von {0}, deren Weg sich verfolgen lässt (Verbindungen von vor dem Start von SnitchBox fehlen).",
                            "SnitchBox does not know any remote of {0} yet whose route can be traced (connections made before SnitchBox started are missing).", _program!), false);
                return;
            }
            Log.Write($"Ziele verfolgen: {_program}, {_group.Count} Ziele");
            Refresh();
            await TraceGroup.RunAsync(_group.Select(g => (g.Tracer, g.Row.Target.Address)).ToList(), Parallel, cancel, IcmpProber.GatewayKey);
            if (!_closed) Refresh();
        }
        finally
        {
            _run?.Dispose();
            _run = null;
            if (!_closed) StartButton.Content = Loc.T("Erneut verfolgen", "Trace Again");
        }
    }

    private void Dest_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject d && ItemsControl.ContainerFromElement(HopList, d) is not ListViewItem) return; // Kopfzeile/leer
        if (HopList.SelectedItem is not DestRow row) return;
        new TraceWindow(row.Target.Host.Length > 0 ? row.Target.Host : null, row.Target.Address).ShowNear(this);
    }

    private async Task StartAsync()
    {
        if (_run != null) return;
        var text = TargetBox.Text.Trim();
        if (text.Length == 0) { Status(Loc.T("Bitte eine Adresse oder einen Namen eingeben.", "Please enter an address or a name."), true); return; }
        _run = new CancellationTokenSource();
        var cancel = _run.Token;
        StartButton.Content = Loc.T("Abbrechen", "Cancel");
        // Das alte Ergebnis verschwindet sofort: Sonst holte ein späteres Neuzeichnen (Namen, Schalter) es nach einem Fehler zurück.
        _tracer = null;
        _target = null;
        _rows.Clear();
        Map.ResetView();
        UpdateHint(null, 0);
        try
        {
            IPAddress target;
            if (_preset is { } p && p.Text == text) target = p.Address;
            else if (IPAddress.TryParse(text, out var parsed) && text.Contains(parsed.AddressFamily == AddressFamily.InterNetwork ? '.' : ':')) target = parsed;
            else
            {
                Status(Loc.F("Löse „{0}“ auf …", "Resolving “{0}”…", text), false);
                IPAddress[] all;
                try { all = await Dns.GetHostAddressesAsync(text, cancel); }
                catch (Exception ex) when (ex is SocketException or ArgumentException)
                {
                    if (cancel.IsCancellationRequested) { if (!_closed) Status(Loc.T("Abgebrochen.", "Cancelled."), false); }
                    else Status(Loc.F("„{0}“ ließ sich nicht auflösen.", "“{0}” could not be resolved.", text), true);
                    return;
                }
                // IPv4 bevorzugt (wie tracert ohne -6); IPv6 nur, wenn der Name nichts anderes hat.
                var pick = all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);
                if (pick == null) { Status(Loc.F("„{0}“ hat keine Adresse.", "“{0}” has no address.", text), true); return; }
                target = pick;
            }
            if (target.IsIPv4MappedToIPv6) target = target.MapToIPv4();
            if (GeoIp.ScopeOf(target) is AddressScope.Multicast || target.Equals(IPAddress.Any) || target.Equals(IPAddress.IPv6Any) || target.Equals(IPAddress.Broadcast)
                || IcmpProber.SubnetBroadcasts().Contains(target))
            {
                Status(Loc.T("An diese Adresse lässt sich keine Route verfolgen.", "No route can be traced to this address."), true);
                return;
            }
            _target = target;
            _targetText = text == target.ToString() ? text : $"{text} ({target})";
            var tracer = _tracer = new Tracer(new IcmpProber());
            tracer.Changed += QueueRefresh;
            Status(Loc.F("Verfolge die Route zu {0} …", "Tracing the route to {0}…", _targetText), false);
            Log.Write($"Route verfolgen: {_targetText}");
            await tracer.RunAsync(target, cancel);
            if (!_closed) Refresh();
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            if (!_closed) Status(Loc.T("Abgebrochen.", "Cancelled."), false);
        }
        finally
        {
            _run?.Dispose();
            _run = null;
            if (!_closed) StartButton.Content = Loc.T("Verfolgen", "Trace");
        }
    }

    private void QueueRefresh()
    {
        if (_refreshQueued || _closed) return;
        _refreshQueued = true;
        Dispatcher.BeginInvoke(() =>
        {
            _refreshQueued = false;
            if (!_closed) Refresh();
        });
    }

    private void Refresh()
    {
        if (_program != null) { RefreshGroup(); return; }
        if (_tracer == null || _target == null) return;
        var snap = _tracer.Snapshot();
        var geo = GeoData.Current;
        var map = WorldMap.Default;
        while (_rows.Count > snap.Hops.Count) _rows.RemoveAt(_rows.Count - 1);
        var stops = new List<MapStop>();
        var tipLines = new List<string>();
        MapCountry? stopCountry = null;
        string? stopLabel = null;
        void CloseStop(bool last)
        {
            if (stopCountry == null) return;
            var kind = stops.Count == 0 ? StopKind.Start : StopKind.Hop;
            if (last && snap.End == TraceEnd.Reached) kind = StopKind.End;
            stops.Add(new MapStop(stopCountry, stopLabel!, stopCountry.Name + "\n" + string.Join("\n", tipLines), kind));
            tipLines.Clear();
        }
        for (var i = 0; i < snap.Hops.Count; i++)
        {
            var hop = snap.Hops[i];
            if (i >= _rows.Count) _rows.Add(new HopRow(hop.Number));
            var addresses = hop.Addresses;
            var address = hop.Address;
            foreach (var a in addresses) LookupName(a);
            var name = address != null && _names.TryGetValue(address, out var n) ? n ?? "" : "";
            var times = string.Join("   ", hop.Probes.Select(p => Time(p, snap.End)));
            if (hop.Unreachable is { } u) times += " – " + IcmpProber.Describe(u.Code);
            string country = "";
            MapCountry? where = null;
            if (address != null)
            {
                var scope = GeoIp.ScopeOf(address);
                if (scope == AddressScope.Public)
                {
                    var code = geo?.CountryOf(address);
                    where = map.Find(code);
                    country = where?.Name ?? code ?? "";
                }
                else country = ScopeText(scope);
            }
            var addressText = addresses.Count == 0 ? "*" : string.Join(" / ", addresses);
            var tip = $"{Loc.F("Hop {0}", "Hop {0}", hop.Number)}: {addressText}" + (name.Length > 0 ? "\n" + name : "")
                      + "\n" + times + (country.Length > 0 ? "\n" + country : "");
            _rows[i].Set(addressText, name, times, country, tip);
            // Stationen der Karte: aufeinanderfolgende Hops im selben Land bilden eine.
            if (where != null && address != null)
            {
                if (where != stopCountry)
                {
                    CloseStop(false);
                    stopCountry = where;
                    stopLabel = hop.Number.ToString();
                }
                tipLines.Add($"{Loc.F("Hop {0}", "Hop {0}", hop.Number)} · {address}" + (name.Length > 0 ? " · " + name : "") + (Best(hop) is { } ms ? $" · {ms}" : ""));
            }
        }
        // Die letzte Station ist das Ziel nur, wenn der letzte Hop (das Ziel) darin liegt.
        var lastInStop = snap.Hops.Count > 0 && snap.Hops[^1].Address is { } la && GeoIp.ScopeOf(la) == AddressScope.Public && map.Find(geo?.CountryOf(la)) == stopCountry;
        CloseStop(lastInStop);
        if (MapBox.IsChecked == true) Map.SetStops(stops);
        if (geo != null && CreditText.Visibility != Visibility.Visible) UpdateCredit(); // Tabelle kam aus einem anderen Fenster
        UpdateStatus(snap);
        UpdateHint(snap, stops.Count);
    }

    /// <summary>Übersicht: Zeilen, Karte (ein Punkt je Land, Wege als Stücke zwischen Ländern; das gewählte Ziel hervorgehoben) und Stand.</summary>
    private void RefreshGroup()
    {
        if (_group.Count == 0) { UpdateHint(null, 0); return; } // keine Ziele: die Meldung von StartGroupAsync bleibt
        var geo = GeoData.Current;
        var map = WorldMap.Default;
        var selected = HopList.SelectedItem as DestRow;
        var marks = new Dictionary<MapCountry, (bool Start, List<string> Ends, int Transit)>();
        // Je Länderpaar ein Stück: gestrichelt nur, wenn jeder Weg darüber vermutet ist; das gewählte Ziel behält seinen eigenen Stil.
        // Schlüssel ohne Richtung (A→B und B→A sind derselbe Großkreis); die Richtung für den Pfeil kommt vom ersten Weg bzw. vom gewählten.
        var segments = new Dictionary<(MapCountry, MapCountry), Segment>();
        int running = 0, reached = 0, cancelled = 0, noReply = 0, unreachable = 0, tooLong = 0, local = 0;
        MapCountry? CountryOf(IPAddress a) => GeoIp.ScopeOf(a) == AddressScope.Public ? map.Find(geo?.CountryOf(a)) : null;
        foreach (var (tracer, row) in _group)
        {
            var snap = tracer.Snapshot();
            var target = row.Target;
            var scope = GeoIp.ScopeOf(target.Address);
            var dest = CountryOf(target.Address);
            var country = scope != AddressScope.Public ? ScopeText(scope) : dest?.Name ?? geo?.CountryOf(target.Address) ?? "";
            switch (snap.End)
            {
                case TraceEnd.Running: running++; break;
                case TraceEnd.Reached: reached++; break;
                case TraceEnd.Cancelled: cancelled++; break;
                case TraceEnd.HopLimit: tooLong++; break;
                case TraceEnd.Unreachable: unreachable++; break;
                default: noReply++; break;
            }
            // Kam gar nichts von außen (kein Netz, Senden scheitert, das System meldet „nicht erreichbar“)?
            if (snap.End is TraceEnd.NoAnswer or TraceEnd.Unreachable && (snap.Hops.Count == 0 || snap.Hops.All(h => h.Address == null))) local++;
            // Weg auf der Karte: Länder der Hops nacheinander; antwortet das Ziel nicht, führt ein gestricheltes Stück zu seinem Land.
            var path = new List<MapCountry>();
            foreach (var hop in snap.Hops)
                if (hop.Address is { } a && CountryOf(a) is { } c && (path.Count == 0 || path[^1] != c)) path.Add(c);
            var assumed = false;
            if (dest != null && snap.End is TraceEnd.NoAnswer or TraceEnd.Unreachable or TraceEnd.HopLimit && (path.Count == 0 || path[^1] != dest))
            {
                path.Add(dest);
                assumed = path.Count > 1;
            }
            for (var i = 0; i < path.Count; i++)
            {
                var m = marks.TryGetValue(path[i], out var known) ? known : (Start: false, Ends: new List<string>(), Transit: 0);
                if (i == 0 && path.Count > 1) m.Start = true;
                if (i == path.Count - 1 && path[i] == dest) m.Ends.Add(row.HostText + (row.HostText == row.AddressText ? "" : $" ({row.AddressText})"));
                else if (i > 0) m.Transit++;
                marks[path[i]] = m;
                if (i == 0) continue;
                var (from, to) = (path[i - 1], path[i]);
                var key = string.CompareOrdinal(from.Code + from.Name, to.Code + to.Name) <= 0 ? (from, to) : (to, from);
                var dashed = assumed && i == path.Count - 1;
                if (!segments.TryGetValue(key, out var seg)) segments[key] = seg = new Segment { From = from, To = to };
                else if (seg.From != from) seg.BothWays = true;
                if (!dashed) seg.Solid = true;
                if (row == selected) { seg.Highlight = true; seg.SelectedDashed = dashed; seg.From = from; seg.To = to; }
            }
            // Zeile
            var hops = snap.End == TraceEnd.Reached ? snap.Hops.Count.ToString() : snap.End == TraceEnd.Running ? "…" : "–";
            var time = snap.End == TraceEnd.Reached && snap.Hops.Count > 0 ? Best(snap.Hops[^1]) ?? "" : "";
            var lines = new List<string> { row.HostText + (row.HostText == row.AddressText ? "" : $" ({row.AddressText})") };
            if (target.Bytes > 0 || target.Count > 0)
                lines.Add(Loc.F("{0} Verbindungen, {1}", "{0} connections, {1}", target.Count, Ui.Size(target.Bytes)));
            foreach (var hop in snap.Hops)
            {
                var a = hop.Address;
                var where = a == null ? "" : GeoIp.ScopeOf(a) == AddressScope.Public ? CountryOf(a)?.Name ?? "" : ScopeText(GeoIp.ScopeOf(a));
                lines.Add($"{Loc.F("Hop {0}", "Hop {0}", hop.Number)} · {(a?.ToString() ?? "*")}" + (where.Length > 0 ? " · " + where : "") + (Best(hop) is { } ms ? " · " + ms : ""));
            }
            lines.Add(Loc.T("Doppelklick: alle Hops in einem eigenen Fenster", "Double-click: all hops in a window of their own"));
            row.Set(country, hops, time, GroupState(snap), string.Join("\n", lines));
        }
        // Ein Punkt je Land: Ziele (orange, Zahl der Ziele), Start (grün), Durchgang (kleiner Punkt).
        var stops = new List<MapStop>();
        foreach (var (c, m) in marks)
        {
            var tip = new List<string> { c.Name };
            if (m.Start) tip.Add(Loc.T("Start: erster Router mit öffentlicher Adresse", "Start: first router with a public address"));
            foreach (var end in m.Ends.Take(15)) tip.Add(Loc.F("Ziel: {0}", "Destination: {0}", end));
            if (m.Ends.Count > 15) tip.Add(Loc.F("… und {0} weitere", "… and {0} more", m.Ends.Count - 15));
            if (m.Transit > 0) tip.Add(Loc.F("Durchgang für {0} Wege", "Transit for {0} routes", m.Transit));
            var kind = m.Ends.Count > 0 ? StopKind.End : m.Start ? StopKind.Start : StopKind.Hop;
            var label = m.Ends.Count > 0 ? m.Ends.Count.ToString() : m.Start ? "▶" : "";
            stops.Add(new MapStop(c, label, string.Join("\n", tip), kind));
        }
        // Zeichenreihenfolge: Durchgang, Ziele, zuletzt der Start (liegt sonst oft unter einem Ziel im Nachbarland).
        stops = stops.OrderBy(s => s.Kind switch { StopKind.Hop => 0, StopKind.End => 1, _ => 2 }).ToList();
        if (MapBox.IsChecked == true)
            Map.SetRoutes(stops, segments.Values.Select(s => new MapSegment(s.From, s.To, s.Highlight,
                s.Highlight ? s.SelectedDashed : !s.Solid, s.BothWays)).ToList());
        if (geo != null && CreditText.Visibility != Visibility.Visible) UpdateCredit();
        var n = _group.Count;
        if (running > 0)
            Status(Loc.F("Verfolge die Wege zu {0} Zielen … {1} fertig", "Tracing the routes to {0} destinations… {1} done", n, n - running), false);
        else if (cancelled > 0)
            Status(Loc.T("Abgebrochen.", "Cancelled."), false);
        else if (reached == n)
            Status(Loc.F("Alle {0} Ziele erreicht.", "All {0} destinations reached.", n), false);
        else if (local == n)
            Status(Loc.T("Keine Antwort – kein Netz, oder ICMP wird gefiltert.", "No reply – no network, or ICMP is being filtered."), true);
        else
        {
            var parts = new List<string> { Loc.F("{0} erreicht", "{0} reached", reached) };
            if (noReply > 0) parts.Add(Loc.F("{0} ohne Antwort (das Ziel beantwortet keinen Ping, oder ein Router filtert)",
                "{0} without reply (the destination does not answer pings, or a router filters them)", noReply));
            if (unreachable > 0) parts.Add(Loc.F("{0} nicht erreichbar", "{0} unreachable", unreachable));
            if (tooLong > 0) parts.Add(Loc.F("{0} über 30 Hops (Weg länger oder Routing-Schleife)", "{0} over 30 hops (longer route or routing loop)", tooLong));
            Status(Loc.F("{0} Ziele verfolgt: {1}.", "{0} destinations traced: {1}.", n, string.Join(", ", parts)), false);
        }
        UpdateHint(null, stops.Count);
    }

    /// <summary>Ein Stück Weg zwischen zwei Ländern in der Übersicht (zusammengefasst über alle Ziele).</summary>
    private sealed class Segment
    {
        public required MapCountry From, To;
        public bool Highlight, Solid, SelectedDashed, BothWays;
    }

    private static string GroupState(TraceSnapshot snap) => snap.End switch
    {
        TraceEnd.Running => Loc.T("läuft …", "running…"),
        TraceEnd.Reached => Loc.T("erreicht", "reached"),
        TraceEnd.Unreachable => Loc.T("nicht erreichbar", "unreachable"),
        TraceEnd.HopLimit => Loc.T("über 30 Hops", "over 30 hops"),
        TraceEnd.Cancelled => Loc.T("abgebrochen", "cancelled"),
        _ => Loc.T("keine Antwort", "no reply"),
    };

    /// <summary>Eine Zeit der Spalte „Zeiten“: „…“ = Antwort steht aus; nach dem Ende (abgebrochen) „–“ = nicht mehr abgewartet.</summary>
    private static string Time(ProbeResult? p, TraceEnd end) => p switch
    {
        null => end == TraceEnd.Running ? "…" : "–",
        { Answered: true } r => r.Milliseconds < 1 ? "<1 ms" : $"{r.Milliseconds} ms",
        { Status: ProbeStatus.Error } => "!",
        _ => "*",
    };

    private static string? Best(TraceHop hop)
    {
        var ms = hop.Probes.Where(p => p is { Answered: true }).Select(p => p!.Value.Milliseconds).DefaultIfEmpty(-1).Min();
        return ms < 0 ? null : ms < 1 ? "<1 ms" : $"{ms} ms";
    }

    private static string ScopeText(AddressScope scope) => scope switch
    {
        AddressScope.Private => Loc.T("Privates Netz", "Private network"),
        AddressScope.CarrierNat => Loc.T("Netz des Anbieters (CGNAT)", "Provider network (CGNAT)"),
        AddressScope.Loopback => Loc.T("Dieser PC", "This PC"),
        AddressScope.LinkLocal => Loc.T("Lokale Verbindung", "Link-local"),
        _ => Loc.T("Besondere Adresse", "Special address"),
    };

    private void UpdateStatus(TraceSnapshot snap)
    {
        var hops = snap.Hops.Count;
        switch (snap.End)
        {
            case TraceEnd.Running:
                Status(Loc.F("Verfolge die Route zu {0} … bisher {1} Hops", "Tracing the route to {0}… {1} hops so far", _targetText, hops), false);
                break;
            case TraceEnd.Reached:
                Status(Loc.F("Ziel {0} nach {1} Hops erreicht ({2}).", "Reached {0} after {1} hops ({2}).", _targetText, hops, Best(snap.Hops[^1]) ?? "–"), false);
                break;
            case TraceEnd.Unreachable:
                var u = snap.Hops.Count > 0 ? snap.Hops[^1].Unreachable : null;
                Status(Loc.F("{0} ist nicht erreichbar (Hop {1}: {2}).", "{0} is not reachable (hop {1}: {2}).", _targetText, hops,
                    u is { } r ? IcmpProber.Describe(r.Code) : "–"), true);
                break;
            case TraceEnd.HopLimit:
                Status(Loc.F("{0} nach {1} Hops nicht erreicht: Der Weg ist länger, oder die Pakete kreisen (Routing-Schleife).",
                    "{0} not reached after {1} hops: the route is longer, or the packets are going round in circles (routing loop).", _targetText, hops), true);
                break;
            case TraceEnd.NoAnswer:
                if (hops > 0)
                    Status(Loc.F("Ab Hop {0} keine Antwort mehr: {1} beantwortet keinen Ping, oder ein Router unterwegs filtert. Die Route bis dahin steht unten.",
                        "No reply from hop {0} on: {1} does not answer pings, or a router on the way filters them. The route up to there is shown below.", hops + 1, _targetText), false);
                else if (snap.Error != 0)
                    Status(Loc.F("Die Proben ließen sich nicht senden ({0}).", "The probes could not be sent ({0}).", IcmpProber.Describe(snap.Error)), true);
                else
                    Status(Loc.T("Keine Antwort – kein Netz, oder ICMP wird gefiltert.", "No reply – no network, or ICMP is being filtered."), true);
                break;
            case TraceEnd.Cancelled:
                Status(Loc.T("Abgebrochen.", "Cancelled."), false);
                break;
        }
    }

    private void UpdateHint(TraceSnapshot? snap, int stops)
    {
        if (_program != null)
        {
            var text = Loc.T("Ziele aus dem Netzwerkmonitor seit dem Start von SnitchBox, das zuletzt benutzte zuerst. Doppelklick auf ein Ziel zeigt alle seine Hops.",
                             "Destinations from the Network Monitor since SnitchBox started, the most recent first. Double-click a destination to see all its hops.");
            if (_omitted > 0) text += " " + Loc.F("{0} ältere Ziele sind ausgelassen.", "{0} older destinations are left out.", _omitted);
            text += " " + (MapBox.IsChecked == true
                ? Loc.T("Länder nach Registrierung der Adressen; gestrichelt: Ziel antwortet nicht, liegt aber in diesem Land.",
                        "Countries by address registration; dashed: the destination does not answer but is located in this country.")
                : Loc.T("Weltkarte einschalten, um Länder und Wege zu sehen.", "Turn on the world map to see countries and routes."));
            HintText.Text = text;
            return;
        }
        if (MapBox.IsChecked != true || snap == null)
            HintText.Text = Loc.T("Proben mit begrenzter Lebensdauer (ICMP, wie tracert); drei je Hop. „*“ = keine Antwort.",
                                  "Probes with a limited time to live (ICMP, like tracert); three per hop. “*” = no reply.");
        else if (stops == 0 && snap.End != TraceEnd.Running)
            HintText.Text = Loc.T("Kein Router mit öffentlicher Adresse und bekanntem Land – nichts für die Karte.", "No router with a public address and known country – nothing to show on the map.");
        else
            HintText.Text = Loc.T("Länder nach Registrierung der Adressen: Router großer Netze stehen oft woanders. Private Router (z. B. 192.168.x.x) fehlen auf der Karte.",
                                  "Countries by address registration: routers of large networks are often located elsewhere. Private routers (e.g. 192.168.x.x) are not on the map.");
    }

    /// <summary>Name eines Routers über DNS (Rückwärtssuche), einmal je Adresse und nur auf Wunsch.</summary>
    private void LookupName(IPAddress address)
    {
        if (NamesBox.IsChecked != true || !_lookups.Add(address)) return;
        _ = Task.Run(async () =>
        {
            string? name = null;
            try
            {
                var entry = await Dns.GetHostEntryAsync(address).WaitAsync(TimeSpan.FromSeconds(4), _life.Token);
                if (!string.IsNullOrWhiteSpace(entry.HostName) && entry.HostName != address.ToString()) name = entry.HostName.TrimEnd('.');
            }
            catch (Exception) { }
            await Dispatcher.BeginInvoke(() =>
            {
                // Inzwischen abgeschaltet (das leert _lookups): das Ergebnis verwerfen.
                if (_closed || NamesBox.IsChecked != true || !_lookups.Contains(address)) return;
                _names[address] = name;
                if (name != null) QueueRefresh();
            });
        });
    }

    private void NamesBox_Click(object sender, RoutedEventArgs e)
    {
        var on = NamesBox.IsChecked == true;
        App.Engine.Mutate(s => s.Settings.TraceResolveNames = on);
        if (!on) { _lookups.Clear(); _names.Clear(); }
        Refresh();
    }

    private async void MapBox_Click(object sender, RoutedEventArgs e)
    {
        var on = MapBox.IsChecked == true;
        if (on && GeoData.Current == null)
        {
            MapBox.IsChecked = false;
            if (!await DownloadCountries(true)) return;
            MapBox.IsChecked = true;
        }
        App.Engine.Mutate(s => s.Settings.TraceShowMap = on);
        ShowMap(on);
        Refresh();
    }

    /// <summary>Ländertabelle herunterladen (nur nach Rückfrage); true, wenn sie danach da ist.</summary>
    private async Task<bool> DownloadCountries(bool first)
    {
        if (_downloading) return false;
        var question = first
            ? Loc.T("Für die Karte braucht SnitchBox eine Ländertabelle: „IP to Country Lite“ von DB-IP (rund 4 MB, Lizenz CC BY 4.0).\n\n" +
                    "Sie wird einmal von download.db-ip.com geladen und auf diesem PC gespeichert. Dabei werden keine Adressen übertragen – " +
                    "welches Land zu einem Router gehört, ermittelt SnitchBox hier.\n\nJetzt herunterladen?",
                    "For the map, SnitchBox needs a country table: “IP to Country Lite” by DB-IP (about 4 MB, license CC BY 4.0).\n\n" +
                    "It is downloaded once from download.db-ip.com and stored on this PC. No addresses are sent – SnitchBox determines " +
                    "the country of each router right here.\n\nDownload now?")
            : Loc.T("Die aktuelle Ländertabelle von download.db-ip.com laden (rund 4 MB)? DB-IP erneuert sie jeden Monat.",
                    "Download the current country table from download.db-ip.com (about 4 MB)? DB-IP renews it every month.");
        if (MessageBox.Show(this, question, App.Title, MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return false;
        _downloading = true;
        var before = StatusText.Text;
        var loading = Loc.T("Lade die Ländertabelle von DB-IP …", "Downloading the country table from DB-IP…");
        Status(loading, false);
        MapBox.IsEnabled = false;
        try
        {
            var error = await GeoData.DownloadAsync(_life.Token);
            if (_closed) return false;
            // Inzwischen kann ein Trace gelaufen sein: dessen Stand gewinnt, sonst der Text von vorher.
            void Restore()
            {
                if (_tracer != null) Refresh();
                else if (StatusText.Text == loading) Status(before, false);
            }
            if (error != null)
            {
                if (StatusText.Text == loading) Status(error, true);
                MessageBox.Show(this, error, App.Title, MessageBoxButton.OK, MessageBoxImage.Warning);
                if (!_closed) Restore();
                return GeoData.Current != null;
            }
            Restore();
            UpdateCredit();
            return true;
        }
        finally
        {
            _downloading = false;
            if (!_closed) MapBox.IsEnabled = true;
        }
    }

    private void ShowMap(bool on)
    {
        if (_tracer == null) UpdateHint(null, 0);
        MapFrame.Visibility = Splitter.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        SplitRow.Height = on ? new GridLength(10) : new GridLength(0);
        // Der Teiler schreibt Pixelwerte als Sterne zurück; beim Einschalten wieder im Verhältnis 1 : 1,25.
        if (on) ListRow.Height = new GridLength(1, GridUnitType.Star);
        MapRow.Height = on ? new GridLength(1.25, GridUnitType.Star) : new GridLength(0);
        MapRow.MinHeight = on ? 160 : 0;
        UpdateCredit();
    }

    private void UpdateCredit()
    {
        var db = GeoData.Current;
        // Sobald Länder von DB-IP zu sehen sind (auch nur in der Liste), gehört die Quellenangabe dazu (CC BY 4.0).
        CreditText.Visibility = db != null ? Visibility.Visible : Visibility.Collapsed;
        if (db == null) return;
        // Monat in der Sprache von SnitchBox (nicht in der von Windows).
        System.Globalization.CultureInfo culture;
        try { culture = System.Globalization.CultureInfo.GetCultureInfo(Loc.Language); }
        catch (System.Globalization.CultureNotFoundException) { culture = System.Globalization.CultureInfo.CurrentCulture; }
        CountryStand.Text = Loc.F("Länder: Stand {0}", "Countries: as of {0}", db.BuildTime.ToString("MMMM yyyy", culture)) + " ";
    }

    private async void UpdateCountries_Click(object sender, RoutedEventArgs e)
    {
        if (await DownloadCountries(false)) Refresh();
    }

    private void DbIp_Click(object sender, RoutedEventArgs e) => DesktopShell.OpenUrl(this, GeoData.AttributionUrl);
    private void NaturalEarth_Click(object sender, RoutedEventArgs e) => DesktopShell.OpenUrl(this, "https://www.naturalearthdata.com");
    private void ZoomIn_Click(object sender, RoutedEventArgs e) => Map.ZoomBy(1.5);
    private void ZoomOut_Click(object sender, RoutedEventArgs e) => Map.ZoomBy(1 / 1.5);
    private void FitRoute_Click(object sender, RoutedEventArgs e) => Map.FitRoute();
    private void FitWorld_Click(object sender, RoutedEventArgs e) => Map.FitWorld();
}
