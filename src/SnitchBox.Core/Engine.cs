using System.Buffers.Binary;

namespace SnitchBox.Core;

/// <summary>Was mit einem abgefangenen Paket geschieht.</summary>
public enum Verdict
{
    /// <summary>Unverändert weiterleiten.</summary>
    Pass,
    /// <summary>Verwerfen.</summary>
    Drop,
    /// <summary>Verwerfen und dem Absender ein TCP-RST zustellen (in „reply“).</summary>
    Reject,
    /// <summary>Zurückhalten, bis der Nutzer im Warnfenster entschieden hat.</summary>
    Hold,
}

/// <summary>Begleitdaten eines Pakets, die zum Wiedereinspeisen nötig sind. <paramref name="Raw"/> sind die
/// unveränderten Adress-Flags des Treibers (u. a. ob die Prüfsummen schon stimmen); 0 bei selbst gebauten Paketen.</summary>
public readonly record struct PacketMeta(bool Outbound, bool V6, uint IfIdx, uint SubIfIdx, uint Raw = 0);

/// <summary>Prozess zu einer Verbindung. <paramref name="Service"/>: der Windows-Dienst bei svchost.exe, wenn der Prozess genau einen
/// Dienst beherbergt (sonst leer – mehrere Dienste in einem Prozess lassen sich nicht auseinanderhalten).</summary>
public readonly record struct ProcessInfo(int Pid, string Path, string Service = "");

/// <summary>Findet den Prozess zu einem lokalen Port (unter Windows über Socket-Ereignisse und die Tabellen der IP-Hilfe).</summary>
public interface IProcessLookup
{
    ProcessInfo Find(bool tcp, ushort localPort, IpKey remote, ushort remotePort, bool incoming);
    bool IsAlive(int pid);
}

/// <summary>Offene Nachfrage: ein Prozess wartet auf die Entscheidung des Nutzers.</summary>
public sealed class PendingAlert
{
    public long Id { get; init; }
    public required Connection Connection { get; init; }
    public DateTime Created { get; init; }
    /// <summary>Aufgehobene Pakete (begrenzt), die nach der Antwort eingespeist werden.</summary>
    internal readonly List<(FlowKey Key, byte[] Packet, PacketMeta Meta)> Held = [];
    /// <summary>Alle Verbindungen, die auf diese Nachfrage warten – auch die, von denen kein Paket mehr aufgehoben wurde.</summary>
    internal readonly HashSet<FlowKey> Keys = [];
}

public readonly record struct FlowKey(IpKey Remote, ushort LocalPort, ushort RemotePort, byte Protocol, bool Incoming);

/// <summary>Zeile des Netzwerkmonitors: ein Prozess und eine Gegenstelle.</summary>
public sealed class ConnectionRecord
{
    public required string ProcessPath { get; init; }
    /// <summary>Windows-Dienst (svchost.exe), sonst leer.</summary>
    public string Service { get; init; } = "";
    public required string Host { get; init; }
    public required IpKey Remote { get; init; }
    public required ushort Port { get; init; }
    public required Proto Protocol { get; init; }
    public required Direction Direction { get; init; }
    public DateTime LastSeen { get; set; }
    public int Count { get; set; }
    /// <summary>true = erlaubt, false = verboten, null = wartet auf Antwort (<see cref="Pending"/>) oder – nach einer
    /// Regeländerung – keine passende Regel mehr, der nächste Versuch fragt nach.</summary>
    public bool? Allowed { get; set; }
    /// <summary>Ein Warnfenster zu dieser Verbindung ist offen.</summary>
    public bool Pending { get; set; }
    public string Reason { get; set; } = "";
    public Connection Template { get; set; } = null!;
    /// <summary>Empfangene/gesendete Bytes aller Verbindungen dieser Zeile seit dem Start (nur Verbindungen, die SnitchBox selbst
    /// entschieden hat; ältere zählen nur beim Programm) und die Rate der letzten Sekunde.</summary>
    public long Down { get; internal set; }
    public long Up { get; internal set; }
    /// <summary>Zuletzt Verkehr gezählt (für den Verlauf: eine lange offene Verbindung entscheidet nur einmal, überträgt aber weiter).</summary>
    public DateTime LastActive { get; internal set; }
    /// <summary>Datenmenge je Tag (Ortszeit); <see cref="Down"/>/<see cref="Up"/> sind ihre Summe über die aufgehobenen Tage.</summary>
    internal Dictionary<DateOnly, (long Down, long Up)> DayVolumes { get; } = [];
    /// <summary>Zuletzt entschieden oder Verkehr gezählt (für das Kürzen des Verlaufs).</summary>
    internal DateTime Recent => LastActive > LastSeen ? LastActive : LastSeen;
    public double RateDown { get; internal set; }
    public double RateUp { get; internal set; }
    /// <summary>Zuletzt entschieden oder Verkehr gezählt (Zählerstand von <see cref="ConnectionLog"/>): Zeilen mit laufenden
    /// Verbindungen werden so nicht als „alt“ verdrängt.</summary>
    internal long Activity { get; set; }
}

/// <summary>Eine Verbindung aus Sicht der Datenzählung: Gegenadresse, lokaler Port, Gegenport, Protokoll (6/17).</summary>
public readonly record struct FlowId(IpKey Remote, ushort LocalPort, ushort RemotePort, byte Protocol)
{
    public static FlowId Of(FlowKey k) => new(k.Remote, k.LocalPort, k.RemotePort, k.Protocol);
}

/// <summary>Verlauf für den Netzwerkmonitor; je Prozess und Gegenstelle eine Zeile.</summary>
public sealed class ConnectionLog
{
    public const int Max = 4000, MaxFlows = 50_000;
    private readonly Dictionary<(string, string, string, ushort, Proto, Direction), ConnectionRecord> _records = [];
    private readonly object _gate = new();
    // Verbindung → Zeile, für die Datenmengen je Gegenstelle. Ab MaxFlows fallen die am längsten untätigen Verbindungen heraus.
    private sealed class FlowEntry
    {
        public required ConnectionRecord Record;
        public long Activity;
    }
    private readonly Dictionary<FlowId, FlowEntry> _flows = [];
    // Zeilen mit einer Rate ungleich 0 (werden beim nächsten Abschnitt auf 0 gesetzt, wenn nichts mehr kommt).
    private readonly HashSet<ConnectionRecord> _active = [];
    // Steigt mit jeder Entscheidung und jedem Messabschnitt; ersetzt eine Uhrzeit beim Verdrängen untätiger Einträge.
    private long _clock;
    public long Version { get; private set; }
    /// <summary>Erhöht sich, wenn sich Datenmengen der Zeilen ändern (eigener Zähler: sonst würde die Verbindungsliste jede
    /// Sekunde neu aufgebaut und verlöre Rollposition und Auswahl).</summary>
    public long VolumeVersion { get; private set; }

    /// <summary>Wie <see cref="Add(Connection, bool?, string, DateTime)"/>; die Verbindungen <paramref name="flows"/> werden dieser Zeile
    /// zugeordnet (Datenmengen je Gegenstelle).</summary>
    internal void Add(Connection c, bool? allowed, string reason, DateTime now, IEnumerable<FlowKey> flows)
    {
        lock (_gate)
        {
            var r = Add(c, allowed, reason, now);
            foreach (var f in flows)
            {
                var id = FlowId.Of(f);
                if (_flows.TryGetValue(id, out var entry))
                {
                    entry.Record = r; // dieselben Ports später neu: gilt für die neue Verbindung
                    entry.Activity = _clock;
                    continue;
                }
                if (_flows.Count >= MaxFlows)
                {
                    // Gleich ein Zehntel der am längsten untätigen Verbindungen entfernen, damit das nicht bei jeder neuen anfällt.
                    foreach (var old in _flows.OrderBy(p => p.Value.Activity).Take(MaxFlows / 10).Select(p => p.Key).ToList())
                        _flows.Remove(old);
                }
                _flows[id] = new FlowEntry { Record = r, Activity = _clock };
            }
        }
    }

    /// <summary>Bytes eines Messabschnitts (je Verbindung) den Zeilen zuschreiben; Zeilen ohne Verkehr in diesem Abschnitt fallen auf Rate 0.</summary>
    public void AddVolumes(IEnumerable<(FlowId Flow, long Down, long Up)> volumes, double seconds)
    {
        if (seconds <= 0) seconds = 1;
        lock (_gate)
        {
            var changed = false;
            foreach (var r in _active)
            {
                changed |= r.RateDown != 0 || r.RateUp != 0;
                r.RateDown = r.RateUp = 0;
            }
            _active.Clear();
            var clock = ++_clock;
            var now = DateTime.Now;
            var today = DateOnly.FromDateTime(now);
            foreach (var (flow, down, up) in volumes)
            {
                if ((down == 0 && up == 0) || !_flows.TryGetValue(flow, out var entry)) continue;
                entry.Activity = clock;
                var r = entry.Record;
                r.Activity = clock;
                r.LastActive = now;
                r.Down += down;
                r.Up += up;
                var day = r.DayVolumes.GetValueOrDefault(today);
                r.DayVolumes[today] = (day.Down + down, day.Up + up);
                r.RateDown += down / seconds;
                r.RateUp += up / seconds;
                _active.Add(r);
                changed = true;
            }
            if (changed) VolumeVersion++;
        }
    }

    /// <summary>Wie viele Verbindungen gerade einer Zeile zugeordnet sind (für Tests).</summary>
    public int FlowCount
    {
        get { lock (_gate) return _flows.Count; }
    }

    internal ConnectionRecord Add(Connection c, bool? allowed, string reason, DateTime now)
    {
        lock (_gate)
        {
            var key = (c.ProcessPath.ToLowerInvariant(), c.Service.ToLowerInvariant(), c.Host, c.Port, c.Protocol, c.Direction);
            if (!_records.TryGetValue(key, out var r))
            {
                if (_records.Count >= Max)
                {
                    // Gleich ein Zehntel der am längsten untätigen Zeilen entfernen, damit das nicht bei jeder neuen Zeile anfällt.
                    // Ihre Verbindungen fallen mit heraus – sonst zählten sie weiter auf eine Zeile, die niemand mehr sieht.
                    var removed = new HashSet<ConnectionRecord>();
                    foreach (var old in _records.OrderBy(p => p.Value.Activity).Take(Max / 10).ToList())
                    {
                        _records.Remove(old.Key);
                        removed.Add(old.Value);
                    }
                    foreach (var flow in _flows.Where(p => removed.Contains(p.Value.Record)).Select(p => p.Key).ToList())
                        _flows.Remove(flow);
                    _active.ExceptWith(removed);
                }
                _records[key] = r = new ConnectionRecord
                {
                    ProcessPath = c.ProcessPath, Service = c.Service, Host = c.Host, Remote = c.Remote, Port = c.Port, Protocol = c.Protocol, Direction = c.Direction,
                };
            }
            r.Activity = ++_clock;
            r.LastSeen = now;
            r.Count++;
            r.Allowed = allowed;
            r.Pending = allowed == null;
            r.Reason = reason;
            r.Template = c;
            Version++;
            return r;
        }
    }

    /// <summary>Nach einer Regeländerung: jede Zeile zeigt, wie die jetzt geltenden Regeln entscheiden – sonst stünde
    /// dort bis zum nächsten Versuch des Programms weiter der alte Zustand. <paramref name="decide"/> liefert null, wenn
    /// keine Regel passt (dann fragt der nächste Versuch nach). Zeilen mit offenem Warnfenster bleiben, wie sie sind.</summary>
    internal void Reevaluate(Func<Connection, (bool Allowed, string Reason)?> decide, string noRule)
    {
        lock (_gate)
        {
            var changed = false;
            foreach (var r in _records.Values)
            {
                if (r.Pending) continue;
                var d = decide(r.Template);
                bool? allowed = d?.Allowed;
                var reason = d?.Reason ?? noRule;
                if (allowed == r.Allowed && reason == r.Reason) continue;
                r.Allowed = allowed;
                r.Reason = reason;
                changed = true;
            }
            if (changed) Version++;
        }
    }

    public List<ConnectionRecord> Snapshot()
    {
        lock (_gate) return _records.Values.ToList();
    }

    /// <summary>Für den gespeicherten Verlauf (<see cref="HistoryFile"/>): alle Zeilen; eine mit offenem Warnfenster ohne Entscheidung.</summary>
    public List<HistoryEntry> Export()
    {
        lock (_gate)
            return _records.Values.Select(r => new HistoryEntry
            {
                ProcessPath = r.ProcessPath, Service = r.Service, Host = r.Host, Remote = r.Remote.ToString(), Port = r.Port, Protocol = r.Protocol,
                Direction = r.Direction, LastSeen = r.LastSeen, Count = r.Count, Allowed = r.Pending ? null : r.Allowed, Reason = r.Pending ? "" : r.Reason,
                Down = r.Down, Up = r.Up, LastActive = r.LastActive, Pid = r.Template?.Pid ?? 0,
                Hostnames = r.Template?.Hostnames is { Count: > 0 } names ? names.Take(6).Where(n => n.Length <= 255).ToList() : null,
                Days = r.DayVolumes.Select(d => new DayVolume
                {
                    Day = d.Key.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), Down = d.Value.Down, Up = d.Value.Up,
                }).ToList(),
            }).ToList();
    }

    /// <summary>Gespeicherte Zeilen übernehmen (beim Start, bevor neue dazukommen): nur gültige und solche, die ab <paramref name="since"/>
    /// noch entschieden oder übertragen haben, die neuesten zuerst bis <see cref="Max"/>; Datenmengen nur der Tage ab
    /// <paramref name="keepFrom"/>. Ihr Zustand wird danach nach den geltenden Regeln neu bewertet.</summary>
    public void Restore(IEnumerable<HistoryEntry> entries, DateTime since, DateOnly keepFrom)
    {
        static DateTime RecentOf(HistoryEntry e) => e.LastActive > e.LastSeen ? e.LastActive : e.LastSeen;
        // Prozessnummern gelten nur bis zum Neustart von Windows (danach vergibt es sie neu). In UTC: Sommerzeit verschiebt sonst die Grenze.
        var boot = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
        lock (_gate)
        {
            var valid = entries
                .Where(e => e is { ProcessPath: not null, Service: not null, Host: not null, Remote: not null } && RecentOf(e) >= since
                            && e.ProcessPath.Length <= HistoryFile.MaxText && e.Service.Length <= 256
                            && e.Host.Length is > 0 and <= 255 && Enum.IsDefined(e.Protocol) && Enum.IsDefined(e.Direction))
                .Select(e => (Entry: e, Ok: IpKey.TryParse(e.Remote, out var remote), Remote: remote))
                .Where(x => x.Ok)
                .OrderByDescending(x => RecentOf(x.Entry)).Take(Math.Max(0, Max - _records.Count)).Reverse(); // älteste zuerst: die Aktivität steigt mit
            foreach (var (e, _, remote) in valid)
            {
                var key = (e.ProcessPath.ToLowerInvariant(), e.Service.ToLowerInvariant(), e.Host, e.Port, e.Protocol, e.Direction);
                if (_records.ContainsKey(key)) continue;
                var names = e.Hostnames?.Where(n => n is { Length: > 0 and <= 255 }).Take(6).ToList();
                if (names is not { Count: > 0 }) names = IpKey.TryParse(e.Host, out _) ? [] : [e.Host];
                var reason = e.Reason ?? "";
                var r = new ConnectionRecord
                {
                    ProcessPath = e.ProcessPath, Service = e.Service, Host = e.Host, Remote = remote, Port = e.Port, Protocol = e.Protocol, Direction = e.Direction,
                    LastSeen = e.LastSeen, LastActive = e.LastActive, Count = Math.Max(0, e.Count), Allowed = e.Allowed,
                    Reason = reason.Length > 500 ? reason[..500] : reason, Activity = ++_clock,
                    Template = new Connection
                    {
                        ProcessPath = e.ProcessPath, Service = e.Service, Direction = e.Direction, Protocol = e.Protocol, Remote = remote, Port = e.Port,
                        Hostnames = names, Pid = e.LastSeen.ToUniversalTime() >= boot ? Math.Max(0, e.Pid) : 0,
                    },
                };
                // Datenmengen je Tag (nur aufgehobene Tage); eine Datei ohne Tage zählt ihre Summe am Tag der letzten Entscheidung.
                var days = e.Days?.Where(d => d != null).Select(d => (Ok: DateOnly.TryParseExact(d.Day, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.None, out var day), Day: day, Down: Math.Max(0, d.Down), Up: Math.Max(0, d.Up)))
                    .Where(d => d.Ok).ToList() ?? [(true, DateOnly.FromDateTime(e.LastSeen), Math.Max(0, e.Down), Math.Max(0, e.Up))];
                foreach (var (_, day, down, up) in days.Where(d => d.Day >= keepFrom).Take(4000))
                {
                    var sum = r.DayVolumes.GetValueOrDefault(day);
                    r.DayVolumes[day] = (Add(sum.Down, down), Add(sum.Up, up));
                }
                r.Down = r.DayVolumes.Values.Aggregate(0L, (s, v) => Add(s, v.Down));
                r.Up = r.DayVolumes.Values.Aggregate(0L, (s, v) => Add(s, v.Up));
                _records[key] = r;
            }
            Version++;
            VolumeVersion++;
        }
    }

    private static long Add(long a, long b) => b > long.MaxValue - a ? long.MaxValue : a + b;

    /// <summary>Verlauf auf die eingestellten Tage begrenzen: Datenmengen von Tagen vor <paramref name="keepFrom"/> fallen weg, Zeilen, die seit
    /// <paramref name="before"/> weder entschieden noch übertragen haben, ganz.</summary>
    public void Prune(DateTime before, DateOnly keepFrom)
    {
        lock (_gate)
        {
            var changed = false;
            foreach (var r in _records.Values)
            {
                var oldDays = r.DayVolumes.Keys.Where(d => d < keepFrom).ToList();
                if (oldDays.Count == 0) continue;
                foreach (var d in oldDays) r.DayVolumes.Remove(d);
                r.Down = r.DayVolumes.Values.Aggregate(0L, (s, v) => Add(s, v.Down));
                r.Up = r.DayVolumes.Values.Aggregate(0L, (s, v) => Add(s, v.Up));
                changed = true;
            }
            if (changed) VolumeVersion++;
            var old = _records.Where(p => p.Value.Recent < before && !p.Value.Pending).ToList();
            if (old.Count == 0) return;
            var removed = new HashSet<ConnectionRecord>();
            foreach (var (key, r) in old)
            {
                _records.Remove(key);
                removed.Add(r);
            }
            foreach (var flow in _flows.Where(p => removed.Contains(p.Value.Record)).Select(p => p.Key).ToList()) _flows.Remove(flow);
            _active.ExceptWith(removed);
            Version++;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _records.Clear();
            _flows.Clear();
            _active.Clear();
            Version++;
            VolumeVersion++;
        }
    }
}

/// <summary>Datenmenge eines Programms seit dem Start von SnitchBox.</summary>
public readonly record struct TrafficRecord(string ProcessPath, long Down, long Up, double RateDown, double RateUp);

/// <summary>Zählt je Programm empfangene und gesendete Bytes und die aktuelle Rate.</summary>
public sealed class TrafficStats
{
    private sealed class Entry { public long Down, Up; public double RateDown, RateUp; }

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    public long Version { get; private set; }

    /// <summary>Trägt die Bytes eines Messabschnitts ein; Programme ohne Verkehr in diesem Abschnitt fallen auf Rate 0.</summary>
    public void Commit(IEnumerable<(string Path, long Down, long Up)> interval, double seconds)
    {
        if (seconds <= 0) seconds = 1;
        lock (_gate)
        {
            var changed = false;
            foreach (var e in _entries.Values)
            {
                changed |= e.RateDown != 0 || e.RateUp != 0;
                e.RateDown = e.RateUp = 0;
            }
            foreach (var (path, down, up) in interval)
            {
                if (down == 0 && up == 0) continue;
                if (!_entries.TryGetValue(path, out var e)) _entries[path] = e = new Entry();
                e.Down += down;
                e.Up += up;
                e.RateDown += down / seconds;
                e.RateUp += up / seconds;
                changed = true;
            }
            if (changed) Version++;
        }
    }

    public List<TrafficRecord> Snapshot()
    {
        lock (_gate) return _entries.Select(p => new TrafficRecord(p.Key, p.Value.Down, p.Value.Up, p.Value.RateDown, p.Value.RateUp)).ToList();
    }

    public void Clear()
    {
        lock (_gate) { _entries.Clear(); Version++; }
    }
}

/// <summary>Herz der Firewall: bekommt jedes abgefangene Paket und entscheidet nach Regeln, Blocklisten und Betriebsart.
/// Plattformunabhängig; unter Windows speist der WinDivert-Dienst die Pakete ein.</summary>
public sealed class FirewallEngine
{
    private sealed class Flow { public bool Allow; public long Generation; public DateTime Expires; }

    private const int MaxAlerts = 100, MaxKeysPerAlert = 1024, MaxDnsQueries = 4096;
    private static readonly TimeSpan TcpTtl = TimeSpan.FromSeconds(30), UdpTtl = TimeSpan.FromSeconds(120), DnsQueryTtl = TimeSpan.FromSeconds(15);

    private readonly object _gate = new();
    private readonly Store _store;
    private readonly IProcessLookup _procs;
    private readonly Func<DateTime> _now;
    private readonly Dictionary<FlowKey, Flow> _flows = [];
    private readonly Dictionary<FlowKey, PendingAlert> _heldFlows = [];
    private readonly List<PendingAlert> _alerts = [];
    private RuleSet _rules;
    private long _generation, _nextAlertId;
    private DateTime _lastPrune;
    // Offene DNS-Anfragen (Server, lokaler Port, Kennung): nur Antworten auf eigene Anfragen liefern Hostnamen.
    private readonly Dictionary<(IpKey Server, ushort Port, ushort Id), DateTime> _dnsQueries = [];
    private readonly object _dnsGate = new();
    // Unveränderliche Mengen, werden nur ausgetauscht. null = unbekannt.
    private volatile IReadOnlySet<IpKey>? _dnsServers, _dnsAnswerSources;

    public HostCache Hosts { get; } = new();
    public ConnectionLog History { get; } = new();
    public TrafficStats Traffic { get; } = new();
    /// <summary>Datenmengen je Tag und Programm (für den Verlauf über Neustarts und das Diagramm je Tag).</summary>
    public DailyTraffic Daily { get; } = new();
    public string BootId { get; }
    /// <summary>Eigener Programmpfad; SnitchBox filtert sich nicht selbst (Blocklisten laden).</summary>
    public string SelfPath { get; init; } = "";
    /// <summary>Speist ein zurückgehaltenes oder selbst gebautes Paket ein.</summary>
    public Action<byte[], PacketMeta>? Injector { get; set; }
    /// <summary>Nach einer Regeländerung bei laufendem Filter, mit den Regeln davor und danach. Der Filter sieht nur den
    /// Verbindungsaufbau: bestehende TCP-Verbindungen, die jetzt verboten sind, muss der Aufrufer selbst trennen.
    /// Wird außerhalb der Sperre gerufen, auch vom Thread-Pool.</summary>
    public Action<RuleSet, RuleSet>? RulesApplied { get; set; }

    public event Action? AlertsChanged;
    public event Action? RulesChanged;

    public FirewallEngine(Store store, IProcessLookup procs, string bootId, Func<DateTime>? now = null)
    {
        _store = store;
        _procs = procs;
        _now = now ?? (() => DateTime.Now);
        BootId = bootId;
        _rules = RuleSet.Build(store, bootId);
    }

    public Store Store => _store;

    public List<PendingAlert> Alerts
    {
        get { lock (_gate) return _alerts.ToList(); }
    }

    /// <summary>Zeilen des Netzwerkmonitors nach den geltenden Regeln neu bewerten (nach dem Laden des gespeicherten Verlaufs).</summary>
    public void ReevaluateHistory()
    {
        lock (_gate)
        {
            // Erst abgelaufene Regeln weg – etwa „bis zum Beenden“ eines Programms, das endete, während SnitchBox aus war; sonst zeigten
            // geladene Zeilen sie noch (sonst geschieht das erst beim nächsten Paket).
            _lastPrune = DateTime.MinValue;
            Prune(_now());
            RefreshHistory();
        }
    }

    /// <summary>Ändert Regeln oder Einstellungen unter der Sperre und wendet sie sofort an.</summary>
    public void Mutate(Action<Store> change)
    {
        List<(byte[], PacketMeta)> inject = [];
        (string, long) snapshot;
        RuleSet before, after;
        bool filtering;
        lock (_gate)
        {
            before = _rules;
            change(_store);
            Rebuild();
            Reevaluate(inject);
            RefreshHistory();
            snapshot = _store.Snapshot();
            after = _rules;
            filtering = _store.Settings.FilterEnabled;
        }
        _store.Write(snapshot);
        Send(inject);
        if (filtering) RulesApplied?.Invoke(before, after);
        RulesChanged?.Invoke();
        AlertsChanged?.Invoke();
    }

    /// <summary>Wie die geltenden Regeln und Blocklisten eine Verbindung jetzt entscheiden (null = keine passt, dann
    /// entscheidet die Betriebsart).</summary>
    public Decision Evaluate(Connection c)
    {
        lock (_gate) return _rules.Evaluate(c, _now());
    }

    private bool IsSelf(string path) => SelfPath.Length > 0 && path.Equals(SelfPath, StringComparison.OrdinalIgnoreCase);

    /// <summary>Zeilen des Netzwerkmonitors an die geltenden Regeln anpassen (bei abgeschaltetem Filter bleibt der letzte Stand).</summary>
    private void RefreshHistory()
    {
        var s = _store.Settings;
        if (!s.FilterEnabled) return;
        var now = _now();
        (bool, string)? Decide(Connection c)
        {
            if (IsSelf(c.ProcessPath)) return (true, "");
            var d = _rules.Evaluate(c, now);
            if (d.Action is { } a) return (a == RuleAction.Allow, d.Reason);
            return s.Mode switch
            {
                OperationMode.SilentAllow => (true, Loc.T("Stiller Modus: alles erlauben", "Silent mode: allow all")),
                OperationMode.SilentDeny => (false, Loc.T("Stiller Modus: alles verbieten", "Silent mode: deny all")),
                _ => null,
            };
        }
        History.Reevaluate(Decide, Loc.T("Keine passende Regel – der nächste Versuch fragt nach", "No matching rule – the next attempt will ask"));
    }

    /// <summary>Die DNS-Server des Systems (aus den Netzwerkeinstellungen). Sie bestimmen, wohin die Werksregel
    /// „Namensauflösung“ erlaubt und von wem DNS-Antworten Hostnamen liefern dürfen.
    /// Ist ein Server auf dem eigenen Rechner eingetragen (127.x, ::1 oder eine eigene Adresse aus <paramref name="ownAddresses"/>),
    /// fragt dieser lokale Resolver selbst weiter: Seine Anfragen nach draußen brauchen dann eine eigene Regel, und
    /// Antworten zählen von jedem Absender, sofern sie zu einer erlaubten, beobachteten Anfrage passen.
    /// Eine leere Liste (Netzwechsel, kein Netz) ändert nichts: es bleibt der letzte bekannte Stand.</summary>
    public void SetDnsServers(IEnumerable<IpKey> servers, IEnumerable<IpKey>? ownAddresses = null)
    {
        var all = servers.ToHashSet();
        if (all.Count == 0 && _dnsServers != null) return;
        var own = ownAddresses?.ToHashSet() ?? [];
        var localResolver = all.Any(a => a.IsLoopback || own.Contains(a));
        List<(byte[], PacketMeta)> inject = [];
        lock (_gate)
        {
            _dnsAnswerSources = localResolver ? null : all;
            if (_dnsServers is { } old && old.SetEquals(all)) return;
            _dnsServers = all;
            Rebuild();
            Reevaluate(inject);
            RefreshHistory();
        }
        Send(inject);
        AlertsChanged?.Invoke();
    }

    /// <summary>Wird gerufen, wenn ein Programm DNS bei einem Server anfragt, der nicht als DNS-Server des Systems bekannt
    /// ist – Anlass, die Liste neu zu lesen (eine Änderung nur der DNS-Server meldet Windows nicht als Adressänderung).</summary>
    public Action? UnknownDnsServer { get; set; }

    /// <summary>Lesender Zugriff auf die gespeicherten Daten, während der Filter weiterläuft.</summary>
    public T Read<T>(Func<Store, T> read)
    {
        lock (_gate) return read(_store);
    }

    private void Rebuild()
    {
        _rules = RuleSet.Build(_store, BootId, _dnsServers);
        _generation++;
    }

    private void Send(List<(byte[] Packet, PacketMeta Meta)> inject)
    {
        var send = Injector;
        if (send == null) return;
        foreach (var (p, m) in inject) send(p, m);
    }

    public Verdict Process(ReadOnlySpan<byte> packet, PacketMeta meta, out byte[]? reply)
    {
        var verdict = Decide(packet, meta, out reply, out var p, out var parsed);
        if (parsed && meta.Outbound && p.DstPort == 53 && (p.Protocol == Packet.Udp || (p.Protocol == Packet.Tcp && p.Syn && !p.Ack)))
        {
            // Nur erlaubte Anfragen merken: sonst könnte jedes Programm über eine eigene (verbotene) Anfrage die Antwort
            // seines eigenen DNS-Servers „passend“ machen.
            if (p.Protocol == Packet.Udp && verdict == Verdict.Pass) NoteDnsQuery(p.Dst, p.SrcPort, packet[p.PayloadOffset..]);
            if (_dnsServers is { } known && !known.Contains(p.Dst)) UnknownDnsServer?.Invoke();
        }
        return verdict;
    }

    private Verdict Decide(ReadOnlySpan<byte> packet, PacketMeta meta, out byte[]? reply, out PacketInfo p, out bool parsed)
    {
        reply = null;
        parsed = Packet.TryParse(packet, out p);
        if (!parsed) return Verdict.Pass;
        var incoming = !meta.Outbound;
        if (incoming && p.Protocol == Packet.Udp)
        {
            if (p.SrcPort == 53 && IsAnswerToOwnQuery(p.Src, p.DstPort, packet[p.PayloadOffset..]))
            {
                var addresses = new List<IpKey>();
                if (DnsReader.TryParseResponse(packet[p.PayloadOffset..], out var name, addresses)) Hosts.Add(name, addresses);
            }
            return Verdict.Pass;
        }
        if (p.Protocol != Packet.Tcp && p.Protocol != Packet.Udp) return Verdict.Pass;
        var tcp = p.Protocol == Packet.Tcp;
        // Bei TCP interessiert nur der Verbindungsaufbau.
        if (tcp && (!p.Syn || p.Ack)) return Verdict.Pass;

        var key = incoming
            ? new FlowKey(p.Src, p.DstPort, p.SrcPort, p.Protocol, true)
            : new FlowKey(p.Dst, p.SrcPort, p.DstPort, p.Protocol, false);
        var raise = false;
        Verdict verdict;
        lock (_gate)
        {
            var s = _store.Settings;
            if (!s.FilterEnabled || (incoming && !s.MonitorIncoming)) return Verdict.Pass;
            var now = _now();
            if (_flows.TryGetValue(key, out var flow) && flow.Generation == _generation && flow.Expires > now)
            {
                flow.Expires = now + (tcp ? TcpTtl : UdpTtl);
                verdict = flow.Allow ? Verdict.Pass : tcp && !incoming ? Verdict.Reject : Verdict.Drop;
            }
            else if (_heldFlows.TryGetValue(key, out var waiting))
            {
                Hold(waiting, key, packet, meta, tcp);
                verdict = Verdict.Hold;
            }
            else
            {
                Prune(now);
                var proc = _procs.Find(tcp, key.LocalPort, key.Remote, key.RemotePort, incoming);
                // Eingehend, aber kein Programm lauscht auf dem Port (Portscan, Weiterleitung an eine virtuelle Maschine):
                // hier gibt es nichts zu erlauben. Windows antwortet selbst bzw. die Windows-Firewall entscheidet.
                if (incoming && proc.Pid == 0) return Verdict.Pass;
                var conn = new Connection
                {
                    ProcessPath = proc.Path, Pid = proc.Pid, Service = proc.Service,
                    Direction = incoming ? Direction.Incoming : Direction.Outgoing,
                    Protocol = tcp ? Proto.Tcp : Proto.Udp,
                    Remote = key.Remote, Port = incoming ? key.LocalPort : key.RemotePort,
                    Hostnames = Hosts.Lookup(key.Remote),
                };
                bool? allow;
                var reason = "";
                if (IsSelf(proc.Path)) allow = true;
                else
                {
                    var d = _rules.Evaluate(conn, now);
                    reason = d.Reason;
                    allow = d.Action switch
                    {
                        RuleAction.Allow => true,
                        RuleAction.Deny => false,
                        _ => s.Mode switch { OperationMode.SilentAllow => true, OperationMode.SilentDeny => false, _ => null },
                    };
                    if (d.Action == null && allow != null)
                        reason = allow == true ? Loc.T("Stiller Modus: alles erlauben", "Silent mode: allow all") : Loc.T("Stiller Modus: alles verbieten", "Silent mode: deny all");
                }
                // Nur erlaubte Verbindungen zählen bei der Gegenstelle (bei verbotenen sähe der Zähler sonst das eigene RST).
                History.Add(conn, allow, reason, now, allow == true ? [key] : []);
                if (allow is { } a)
                {
                    _flows[key] = new Flow { Allow = a, Generation = _generation, Expires = now + (tcp ? TcpTtl : UdpTtl) };
                    verdict = a ? Verdict.Pass : tcp && !incoming ? Verdict.Reject : Verdict.Drop;
                }
                else
                {
                    // Weitere Versuche desselben Prozesses zur selben Gegenstelle hängen sich an die offene Nachfrage.
                    var alert = _alerts.Find(x => SameQuestion(x.Connection, conn));
                    if (alert == null && _alerts.Count >= MaxAlerts)
                    {
                        // Ein Programm mit hunderten Gegenstellen (z. B. Tauschbörse) soll nicht hunderte Fenster erzeugen.
                        return Verdict.Drop;
                    }
                    if (alert == null)
                    {
                        alert = new PendingAlert { Id = ++_nextAlertId, Connection = conn, Created = now };
                        _alerts.Add(alert);
                        raise = true;
                    }
                    Hold(alert, key, packet, meta, tcp);
                    verdict = Verdict.Hold;
                }
            }
        }
        if (verdict == Verdict.Reject) reply = Packet.BuildReset(packet);
        if (raise) AlertsChanged?.Invoke();
        return verdict;
    }

    private static bool SameQuestion(Connection a, Connection b) =>
        a.Direction == b.Direction && a.Protocol == b.Protocol && a.Port == b.Port && a.Remote == b.Remote
        && a.ProcessPath.Equals(b.ProcessPath, StringComparison.OrdinalIgnoreCase) && a.Service.Equals(b.Service, StringComparison.OrdinalIgnoreCase);

    private void Hold(PendingAlert alert, FlowKey key, ReadOnlySpan<byte> packet, PacketMeta meta, bool tcp)
    {
        // Jede wartende Verbindung wird vermerkt, damit die Antwort sie alle erreicht – auch wenn von ihr kein Paket
        // mehr aufgehoben wird. Über der Obergrenze wird nichts vermerkt: der nächste Versuch wird dann neu bewertet.
        if (!alert.Keys.Contains(key))
        {
            if (alert.Keys.Count >= MaxKeysPerAlert) return;
            alert.Keys.Add(key);
        }
        _heldFlows[key] = alert;
        // TCP wiederholt das SYN selbst; es genügt das jüngste. Bei UDP ein paar Pakete je Verbindung aufheben.
        if (tcp) alert.Held.RemoveAll(h => h.Key == key);
        else if (alert.Held.Count(h => h.Key == key) >= 8) return;
        if (alert.Held.Count >= 64) return;
        alert.Held.Add((key, packet.ToArray(), meta));
    }

    /// <summary>Antwort aus dem Warnfenster. Mit <paramref name="rule"/> wird die Entscheidung als Regel gemerkt.</summary>
    public void Resolve(long alertId, bool allow, Rule? rule)
    {
        List<(byte[], PacketMeta)> inject = [];
        (string, long)? snapshot = null;
        RuleSet before, after;
        bool filtering;
        lock (_gate)
        {
            before = _rules;
            if (rule != null)
            {
                // Gleichartige Regel vorhanden (nur andere Gegenstelle)? Dann kommt die neue Gegenstelle dorthin, statt dass je
                // Nachfrage eine weitere Regel entsteht; überflüssig gewordene Regeln entfallen.
                rule = RuleCleanup.Absorb(_store.Rules, rule);
                Rebuild();
            }
            var alert = _alerts.Find(a => a.Id == alertId);
            if (alert != null) Finish(alert, allow, rule?.Describe() ?? Loc.T("Einmalige Entscheidung", "One-time decision"), inject);
            if (rule != null)
            {
                Reevaluate(inject);
                RefreshHistory();
                snapshot = _store.Snapshot();
            }
            after = _rules;
            filtering = _store.Settings.FilterEnabled;
        }
        if (snapshot is { } snap) _store.Write(snap);
        Send(inject);
        if (rule != null && filtering) RulesApplied?.Invoke(before, after);
        if (rule != null) RulesChanged?.Invoke();
        AlertsChanged?.Invoke();
    }

    private void Finish(PendingAlert alert, bool allow, string reason, List<(byte[], PacketMeta)> inject)
    {
        var now = _now();
        foreach (var key in alert.Keys)
        {
            var tcp = key.Protocol == Packet.Tcp;
            _flows[key] = new Flow { Allow = allow, Generation = _generation, Expires = now + (tcp ? TcpTtl : UdpTtl) };
            if (_heldFlows.TryGetValue(key, out var waiting) && waiting == alert) _heldFlows.Remove(key);
        }
        foreach (var (key, packet, meta) in alert.Held)
        {
            var tcp = key.Protocol == Packet.Tcp;
            // Eine angehaltene, jetzt erlaubte DNS-Anfrage zählt wie eine gleich durchgelassene.
            if (allow && !tcp && !key.Incoming && key.RemotePort == 53 && Packet.TryParse(packet, out var q))
                NoteDnsQuery(q.Dst, q.SrcPort, packet.AsSpan(q.PayloadOffset));
            if (allow) inject.Add((packet, meta));
            else if (tcp && !key.Incoming && Packet.BuildReset(packet) is { } rst)
                inject.Add((rst, meta with { Outbound = false, Raw = 0 }));
        }
        _alerts.Remove(alert);
        History.Add(alert.Connection, allow, reason, now, allow ? alert.Keys : []);
    }

    /// <summary>Nach einer Regeländerung: offene Nachfragen, die jetzt eine Regel beantwortet, erledigen sich von selbst.</summary>
    private void Reevaluate(List<(byte[], PacketMeta)> inject)
    {
        var now = _now();
        var mode = _store.Settings.Mode;
        foreach (var alert in _alerts.ToList())
        {
            var d = _rules.Evaluate(alert.Connection, now);
            if (d.Action is { } a) Finish(alert, a == RuleAction.Allow, d.Reason, inject);
            else if (mode != OperationMode.Alert || !_store.Settings.FilterEnabled)
                Finish(alert, mode != OperationMode.SilentDeny || !_store.Settings.FilterEnabled, Loc.T("Stiller Modus", "Silent mode"), inject);
        }
    }

    /// <summary>Räumt abgelaufene Regeln und Verbindungen weg (höchstens alle fünf Sekunden).</summary>
    private void Prune(DateTime now)
    {
        if (now - _lastPrune < TimeSpan.FromSeconds(5)) return;
        _lastPrune = now;
        if (_flows.Count > 2000)
            foreach (var k in _flows.Where(f => f.Value.Expires <= now || f.Value.Generation != _generation).Select(f => f.Key).ToList())
                _flows.Remove(k);
        var removed = _store.Rules.RemoveAll(r =>
            (r.Lifetime == LifetimeKind.Timed && r.Expires is { } e && e <= now)
            || (r.Lifetime == LifetimeKind.UntilRestart && r.BootId != BootId)
            || (r.Lifetime == LifetimeKind.UntilQuit && !_procs.IsAlive(r.QuitPid)));
        if (removed > 0)
        {
            var before = _rules;
            Rebuild();
            var after = _rules;
            // Schreiben, Monitor anpassen und Benachrichtigen außerhalb des Paketwegs (hier hält der Aufrufer die Sperre).
            var snapshot = _store.Snapshot();
            ThreadPool.QueueUserWorkItem(_ =>
            {
                _store.Write(snapshot);
                bool filtering;
                lock (_gate)
                {
                    // Inzwischen erneut geändert: dann hat jene Änderung den Monitor schon angepasst und gemeldet.
                    if (_rules != after) return;
                    RefreshHistory();
                    filtering = _store.Settings.FilterEnabled;
                }
                if (filtering) RulesApplied?.Invoke(before, after);
                RulesChanged?.Invoke();
            });
        }
    }

    /// <summary>Merkt sich eine ausgehende DNS-Anfrage, damit nur die passende Antwort Hostnamen liefert.</summary>
    private void NoteDnsQuery(IpKey server, ushort localPort, ReadOnlySpan<byte> dns)
    {
        if (dns.Length < 12 || (dns[2] & 0x80) != 0) return; // zu kurz oder selbst eine Antwort
        var id = BinaryPrimitives.ReadUInt16BigEndian(dns);
        var now = _now();
        lock (_dnsGate)
        {
            if (_dnsQueries.Count >= MaxDnsQueries)
            {
                foreach (var k in _dnsQueries.Where(q => q.Value <= now).Select(q => q.Key).ToList()) _dnsQueries.Remove(k);
                // Immer noch voll (Flut): die ältesten verdrängen, nicht alle – sonst könnte ein Programm die Anfragen
                // des Systems wegspülen und damit Hostnamen (und Blocklisten) aushebeln.
                if (_dnsQueries.Count >= MaxDnsQueries)
                    foreach (var k in _dnsQueries.OrderBy(q => q.Value).Take(MaxDnsQueries / 4).Select(q => q.Key).ToList()) _dnsQueries.Remove(k);
            }
            _dnsQueries[(server, localPort, id)] = now + DnsQueryTtl;
        }
    }

    /// <summary>Stammt die DNS-Antwort von einem DNS-Server des Systems und beantwortet sie eine beobachtete Anfrage?
    /// Sonst könnte jedes Programm (über einen eigenen DNS-Server) oder jeder im Netz einer Adresse einen falschen
    /// Namen geben – etwa „update.microsoft.com“ für einen fremden Server.</summary>
    private bool IsAnswerToOwnQuery(IpKey server, ushort localPort, ReadOnlySpan<byte> dns)
    {
        if (dns.Length < 12) return false;
        if (_dnsAnswerSources is { } sources && !sources.Contains(server)) return false;
        var id = BinaryPrimitives.ReadUInt16BigEndian(dns);
        lock (_dnsGate)
            return _dnsQueries.Remove((server, localPort, id), out var expires) && expires > _now();
    }

    /// <summary>Filter anhalten: alles Zurückgehaltene freigeben, damit nichts hängen bleibt.</summary>
    public void ReleaseAll()
    {
        List<(byte[], PacketMeta)> inject = [];
        lock (_gate)
            foreach (var alert in _alerts.ToList()) Finish(alert, true, Loc.T("Filter beendet", "Filter stopped"), inject);
        Send(inject);
        AlertsChanged?.Invoke();
    }
}
