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

public readonly record struct ProcessInfo(int Pid, string Path);

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
}

/// <summary>Verlauf für den Netzwerkmonitor; je Prozess und Gegenstelle eine Zeile.</summary>
public sealed class ConnectionLog
{
    private const int Max = 4000;
    private readonly Dictionary<(string, string, ushort, Proto, Direction), ConnectionRecord> _records = [];
    private readonly object _gate = new();
    public long Version { get; private set; }

    internal void Add(Connection c, bool? allowed, string reason, DateTime now)
    {
        lock (_gate)
        {
            var key = (c.ProcessPath.ToLowerInvariant(), c.Host, c.Port, c.Protocol, c.Direction);
            if (!_records.TryGetValue(key, out var r))
            {
                if (_records.Count >= Max)
                {
                    // Gleich ein Zehntel der ältesten Zeilen entfernen, damit das nicht bei jeder neuen Zeile anfällt.
                    foreach (var old in _records.OrderBy(p => p.Value.LastSeen).Take(Max / 10).Select(p => p.Key).ToList())
                        _records.Remove(old);
                }
                _records[key] = r = new ConnectionRecord
                {
                    ProcessPath = c.ProcessPath, Host = c.Host, Remote = c.Remote, Port = c.Port, Protocol = c.Protocol, Direction = c.Direction,
                };
            }
            r.LastSeen = now;
            r.Count++;
            r.Allowed = allowed;
            r.Pending = allowed == null;
            r.Reason = reason;
            r.Template = c;
            Version++;
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

    public void Clear()
    {
        lock (_gate) { _records.Clear(); Version++; }
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
                    ProcessPath = proc.Path, Pid = proc.Pid,
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
                History.Add(conn, allow, reason, now);
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
        && a.ProcessPath.Equals(b.ProcessPath, StringComparison.OrdinalIgnoreCase);

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
        History.Add(alert.Connection, allow, reason, now);
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
