using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Verbindet den Kern mit Windows: lädt den WinDivert-Treiber, fängt Verbindungsaufbau (TCP-SYN) und UDP ab,
/// reicht jedes Paket an die <see cref="FirewallEngine"/> und führt deren Urteil aus.
/// Endet das Programm, schließt Windows die Treiber-Handles und der Verkehr läuft ungefiltert weiter.</summary>
internal sealed unsafe class FilterService : IProcessLookup, IDisposable
{
    // Nur was für die Entscheidung nötig ist, geht durch das Programm: ausgehend der TCP-Verbindungsaufbau und UDP,
    // eingehend der TCP-Verbindungsaufbau und DNS-Antworten (für die Hostnamen). Alles andere bleibt im Kernel.
    private static readonly string[] Filters =
    [
        "!loopback and ((outbound and ((tcp.Syn and !tcp.Ack) or udp)) or (inbound and ((tcp.Syn and !tcp.Ack) or udp.SrcPort == 53)))",
        "(outbound and ((tcp.Syn and !tcp.Ack) or udp)) or (inbound and ((tcp.Syn and !tcp.Ack) or udp.SrcPort == 53))",
    ];

    // Socket-Ereignisse: lokaler Port → Prozess und Zeitpunkt des Ereignisses (QueryPerformanceCounter, wie WinDivert).
    private readonly ConcurrentDictionary<(bool Tcp, ushort Port), (int Pid, long Time)> _portOwners = new();
    // Kürzlich geschlossene Sockets (Environment.TickCount64): für Pakete und Datenmengen, die erst danach ausgewertet werden.
    private readonly ConcurrentDictionary<(bool Tcp, ushort Port), (int Pid, long Tick)> _recentlyClosed = new();
    // Lauschende TCP-Ports für eingehende Verbindungen: aus der Port-Tabelle, ergänzt um LISTEN-Ereignisse.
    private Dictionary<(bool V6, ushort Port), int>? _listeners;
    // Rückstand der Socket-Ereignisse (QPC-Takte zwischen Ereignis und Verarbeitung). Hinken sie hinterher (z. B. weil ein
    // Programm sie flutet), gelten weder frische Einträge noch „kürzlich geschlossen“ – dann entscheidet nur die Port-Tabelle.
    private long _socketLag;
    private static readonly long LagLimit = Stopwatch.Frequency / 10;
    private long _listenersTick;
    private bool _listenersDirty;
    private readonly object _listenGate = new();
    private readonly object _dnsRefreshGate = new();
    private long _lastDnsRefresh;
    private static readonly long FreshEvent = Stopwatch.Frequency * 2;
    private readonly ConcurrentDictionary<int, (string Path, long Tick)> _paths = new();
    private IntPtr _net = WinDivert.Invalid, _sock = WinDivert.Invalid, _meter = WinDivert.Invalid;
    private Thread? _netThread, _sockThread, _meterThread, _commitThread;
    // Bytes je lokalem Port seit der letzten Auswertung (Down, Up); der Zähl-Thread füllt, der Auswerte-Thread leert.
    private Dictionary<(bool Tcp, ushort Port), (long Down, long Up)> _portBytes = [];
    private readonly object _meterGate = new();
    private volatile bool _stop;
    private FirewallEngine? _engine;
    private int _loggedErrors;
    private Timer? _dnsTimer;
    /// <summary>Markiert in PacketMeta.Raw „Flags stammen vom Treiber“ (liegt in dessen reservierten Bits).</summary>
    private const uint Captured = 0x80000000;
    private static readonly string Svchost = Path.Combine(Environment.SystemDirectory, "svchost.exe");
    // Laufende Windows-Dienste je Prozessnummer (für svchost.exe), mit der Startzeit des Prozesses: Eine neu vergebene Nummer
    // (anderer Prozess) gilt als unbekannt. Unbekannte Nummern lösen sofort ein Neulesen aus – gedrosselt je Nummer (höchstens 1×/s,
    // wenn sie danach immer noch fehlt), nicht für alle gemeinsam; sonst bekäme ein gerade gestarteter Dienst, der sich im selben
    // Augenblick wie ein anderer meldet, keinen Namen und fiele unter die svchost-Regel. Ganz neu gelesen wird alle 15 Sekunden.
    private readonly object _servicesGate = new();
    private Dictionary<int, (string[] Names, long Start)> _servicesByPid = [];
    private readonly Dictionary<int, long> _serviceMisses = [];
    private long _servicesTick = -1_000_000;

    /// <summary>Der Windows-Dienst in einem svchost-Prozess – nur wenn er dort allein läuft. Beherbergt ein Prozess mehrere Dienste
    /// (auf Rechnern mit viel Speicher selten, z. B. RpcSs + RpcEptMapper), lässt sich nicht sagen, welcher die Verbindung aufbaut: leer.</summary>
    private string ServiceOf(int pid)
    {
        var start = Native.ProcessStartTime(pid);
        lock (_servicesGate)
        {
            var now = Environment.TickCount64;
            var known = _servicesByPid.TryGetValue(pid, out var entry) && entry.Start == start;
            var missedRecently = _serviceMisses.TryGetValue(pid, out var missed) && now - missed < 1000;
            var sinceRefresh = now - _servicesTick;
            // Neu lesen: alle 15 s (ein weiterer Dienst kann einem Prozess beitreten), bei unbekannter Nummer sofort – aber höchstens
            // alle 100 ms insgesamt: Das Lesen läuft im Paketweg unter der Sperre der Engine, und ein Programm könnte in schneller
            // Folge neue svchost-Prozesse starten, um den Filter auszubremsen.
            var refreshed = false;
            if (sinceRefresh > 15_000 || (!known && !missedRecently && sinceRefresh > 100))
            {
                refreshed = true;
                try
                {
                    _servicesByPid = Native.Services(true).Where(s => s.Pid != 0).GroupBy(s => s.Pid)
                        .ToDictionary(g => g.Key, g => (g.Select(s => s.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), Native.ProcessStartTime(g.Key)));
                }
                catch (Exception e)
                {
                    if (Interlocked.Increment(ref _loggedErrors) <= 20) Log.Write("Dienste lesen: " + e.Message);
                }
                _servicesTick = now;
                foreach (var stale in _serviceMisses.Where(m => now - m.Value > 10_000).Select(m => m.Key).ToList()) _serviceMisses.Remove(stale);
            }
            if (_servicesByPid.TryGetValue(pid, out entry) && entry.Start == start)
            {
                _serviceMisses.Remove(pid);
                return entry.Names.Length == 1 ? entry.Names[0] : "";
            }
            // Drosseln nur nach einem echten Neulesen, das die Nummer nicht fand – sonst schöbe jede Verbindung eines fleißigen
            // Prozesses das nächste Neulesen immer weiter hinaus.
            if (refreshed) _serviceMisses[pid] = now;
            return "";
        }
    }

    private string ServiceFor(int pid, string path) => path.Equals(Svchost, StringComparison.OrdinalIgnoreCase) ? ServiceOf(pid) : "";

    // Bestehende Verbindungen, die eine Regeländerung verbietet und die sich nicht über Windows trennen lassen (IPv6; IPv4, wenn
    // SetTcpEntry scheitert): Beim nächsten Paket der Verbindung schickt der Zähl-Thread beiden Enden ein RST. Schlüssel wie
    // FlowKey (Gegenadresse, lokaler Port, Gegenport). Vor jedem RST wird geprüft, ob die Regeln die Verbindung noch verbieten
    // und der Filter (bei eingehenden: die Überwachung eingehender Verbindungen) läuft – sonst entfällt die Vormerkung. Aufgeräumt
    // einmal je Sekunde nach fünf Minuten ohne Paket. (Nicht schon kurz nach einem RST: Wurde es verworfen, etwa weil das
    // Segment beim Mitlesen schon veraltet war, soll das nächste Paket der Verbindung erneut eines auslösen.)
    private readonly Dictionary<(IpKey Remote, ushort LocalPort, ushort RemotePort), (long Expires, long LastShot, string What, Connection Conn)> _kill = [];
    private readonly object _killGate = new();
    private volatile int _killPending;
    private const long KillTtl = 5 * 60_000;

    private void MarkForReset(IpKey remote, ushort localPort, ushort remotePort, string what, Connection conn)
    {
        lock (_killGate)
        {
            _kill[(remote, localPort, remotePort)] = (Environment.TickCount64 + KillTtl, 0, what, conn);
            _killPending = _kill.Count;
        }
    }

    /// <summary>Abgelaufene Vormerkungen entfernen (fünf Minuten ohne Paket). Ob die Regeln eine Verbindung noch verbieten, prüft
    /// ResetIfMarked unmittelbar vor jedem RST mit den dann geltenden Regeln.</summary>
    private void PruneResets()
    {
        lock (_killGate)
        {
            if (_kill.Count == 0) return;
            var now = Environment.TickCount64;
            foreach (var (k, e) in _kill.ToList())
                if (now > e.Expires) _kill.Remove(k);
            _killPending = _kill.Count;
        }
    }

    private void ClearResets()
    {
        lock (_killGate)
        {
            _kill.Clear();
            _killPending = 0;
        }
    }

    /// <summary>Vom Zähl-Thread für jedes TCP-Paket, solange Verbindungen zum Trennen vorgemerkt sind.</summary>
    private void ResetIfMarked(ReadOnlySpan<byte> packet, in WinDivertAddress addr)
    {
        if (!Packet.TryParse(packet, out var p) || p.Protocol != Packet.Tcp) return;
        var outbound = addr.Outbound;
        var key = outbound ? (p.Dst, p.SrcPort, p.DstPort) : (p.Src, p.DstPort, p.SrcPort);
        Connection conn;
        string what;
        lock (_killGate)
        {
            if (!_kill.TryGetValue(key, out var entry)) return;
            var now = Environment.TickCount64;
            if (p.Syn && !p.Ack)
            {
                // Ausgehendes SYN: der eigene Rechner baut auf denselben Ports eine neue Verbindung auf (die alte ist weg); sie läuft
                // durch die Regeln. Ein eingehendes SYN dagegen beendet nichts (Windows antwortet auf einer bestehenden Verbindung nur
                // mit einem ACK) und darf die Vormerkung nicht aufheben – sonst könnte die Gegenstelle das Trennen verhindern.
                if (outbound)
                {
                    _kill.Remove(key);
                    _killPending = _kill.Count;
                }
                return;
            }
            if (now > entry.Expires)
            {
                _kill.Remove(key);
                _killPending = _kill.Count;
                return;
            }
            if (now - entry.LastShot < 500) return; // höchstens zweimal je Sekunde, bis die Verbindung still ist
            _kill[key] = (now + KillTtl, now, entry.What, entry.Conn);
            conn = entry.Conn;
            what = entry.LastShot == 0 ? entry.What : "";
        }
        // Noch verboten und Filter an? (Inzwischen wieder erlaubt, Netzwerkfilter aus oder – bei eingehenden – deren Überwachung
        // abgeschaltet: nicht trennen; die Engine ließe eine solche Verbindung jetzt auch neu zu.)
        var (filterOn, incomingOn) = _engine?.Read(s => (s.Settings.FilterEnabled, s.Settings.MonitorIncoming)) ?? (false, false);
        if (_engine is not { } engine || !filterOn || (conn.Direction == Direction.Incoming && !incomingOn) || engine.Evaluate(conn).Action != RuleAction.Deny)
        {
            lock (_killGate)
            {
                // Nur diese Vormerkung entfernen – eine inzwischen neu angelegte für dieselben Ports (spätere Regeländerung) bleibt.
                if (_kill.TryGetValue(key, out var current) && ReferenceEquals(current.Conn, conn)) _kill.Remove(key);
                _killPending = _kill.Count;
            }
            return;
        }
        foreach (var (rst, toSender) in Packet.BuildFlowResets(packet))
        {
            // Ein RST an den Absender eines ausgehenden Pakets geht an den eigenen Rechner (eingehend einspeisen), sonst hinaus.
            var towardsLocal = outbound ? toSender : !toSender;
            Inject(rst, new PacketMeta(!towardsLocal, p.V6, addr.IfIdx, addr.SubIfIdx));
        }
        if (what.Length > 0) Log.Write("Verbindung getrennt (RST, jetzt verboten): " + what);
    }

    public bool Running { get; private set; }
    /// <summary>Lesbare Ursache, wenn der Treiber nicht startet.</summary>
    public string? Error { get; private set; }

    public void Attach(FirewallEngine engine)
    {
        _engine = engine;
        engine.Injector = Inject;
        engine.UnknownDnsServer = OnUnknownDnsServer;
        engine.RulesApplied = OnRulesApplied;
    }

    /// <summary>Nach einer Regeländerung: bestehende TCP-Verbindungen trennen, die erst die Änderung verbietet. Der Filter sieht nur
    /// den Verbindungsaufbau – ohne das liefe etwa eine offene Browserverbindung trotz „Verbieten“ minutenlang weiter. Schon vorher
    /// verbotene Verbindungen (vor dem Start aufgebaut) bleiben unberührt. IPv4 trennt Windows selbst (SetTcpEntry); für IPv6 gibt es
    /// keine solche Funktion – dort (und wenn SetTcpEntry scheitert) schickt SnitchBox beim nächsten Paket der Verbindung RSTs.</summary>
    private void OnRulesApplied(RuleSet before, RuleSet after)
    {
        if (!Running || _engine is not { } engine) return;
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                var incomingFiltered = engine.Read(s => s.Settings.MonitorIncoming);
                var now = DateTime.Now;
                Dictionary<(bool V6, ushort Port), int>? listeners = null;
                // Wird die Verbindung erst durch diese Änderung verboten? Dann die Verbindung, sonst null.
                Connection? NewlyDenied(int pid, ushort localPort, IpKey remote, ushort remotePort, bool v6)
                {
                    var path = PathOf(pid);
                    if (path == null || (engine.SelfPath.Length > 0 && path.Equals(engine.SelfPath, StringComparison.OrdinalIgnoreCase))) return null;
                    listeners ??= Native.ListeningTcpPorts();
                    var incoming = listeners.TryGetValue((v6, localPort), out var owner) && owner == pid;
                    if (incoming && !incomingFiltered) return null;
                    var conn = new Connection
                    {
                        ProcessPath = path, Pid = pid, Service = ServiceFor(pid, path), Protocol = Proto.Tcp, Remote = remote,
                        Direction = incoming ? Direction.Incoming : Direction.Outgoing,
                        Port = incoming ? localPort : remotePort,
                        Hostnames = engine.Hosts.Lookup(remote),
                    };
                    if (after.Evaluate(conn, now).Action != RuleAction.Deny || before.Evaluate(conn, now).Action == RuleAction.Deny) return null;
                    return conn;
                }
                static string Describe(Connection c, ushort remotePort) => $"{Rule.NameOf(c.ProcessPath)} {c.Host}:{remotePort}";
                foreach (var c in Native.TcpConnectionsV4())
                {
                    if (NewlyDenied(c.Pid, c.LocalPort, c.Remote, c.RemotePort, false) is not { } conn) continue;
                    var rc = Native.CloseTcpV4(c);
                    if (rc == 0) Log.Write("Verbindung getrennt (jetzt verboten): " + Describe(conn, c.RemotePort));
                    else
                    {
                        Log.Write($"Verbindung trennen über Windows fehlgeschlagen (Fehler {rc}), RST beim nächsten Paket: {Describe(conn, c.RemotePort)}");
                        MarkForReset(c.Remote, c.LocalPort, c.RemotePort, Describe(conn, c.RemotePort), conn);
                    }
                }
                foreach (var c in Native.TcpConnectionsV6())
                    if (NewlyDenied(c.Pid, c.LocalPort, c.Remote, c.RemotePort, !c.Remote.IsV4) is { } conn)
                        MarkForReset(c.Remote, c.LocalPort, c.RemotePort, Describe(conn, c.RemotePort) + " (IPv6)", conn);
            }
            catch (Exception e)
            {
                if (Interlocked.Increment(ref _loggedErrors) <= 20) Log.Write("Verbindungen trennen: " + e);
            }
        });
    }

    /// <summary>WinDivert.dll und WinDivert64.sys stecken in der .exe; der Treiber muss als Datei vorliegen.
    /// Eine vorhandene Datei wird nur genommen, wenn sie Byte für Byte dem eingebetteten Original gleicht – sonst
    /// lüde SnitchBox mit Administratorrechten eine untergeschobene DLL. Beide Dateien bleiben danach geöffnet (andere
    /// dürfen nur lesen), bis der Aufrufer den Treiber geladen hat: so lassen sie sich zwischen Prüfen und Laden nicht tauschen.</summary>
    private static (string Dir, List<FileStream> Locks) ExtractDriver()
    {
        var dir = Path.Combine(Paths.DataDir, "driver", "2.2.2");
        Directory.CreateDirectory(dir);
        var locks = new List<FileStream>();
        try
        {
            foreach (var name in new[] { "WinDivert.dll", "WinDivert64.sys" })
            {
                byte[] original;
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
                               ?? throw new FileNotFoundException("Eingebettete Datei fehlt: " + name))
                {
                    original = new byte[s.Length];
                    s.ReadExactly(original);
                }
                var expected = SHA256.HashData(original);
                var target = Path.Combine(dir, name);
                if (!File.Exists(target) || !HashOf(target).AsSpan().SequenceEqual(expected))
                {
                    try { File.WriteAllBytes(target, original); }
                    catch (IOException e) when (File.Exists(target))
                    {
                        // Abweichend und gesperrt (z. B. von einem geladenen Treiber): nicht benutzen.
                        throw new InvalidDataException(Loc.F("{0} weicht vom Original ab und lässt sich nicht ersetzen: {1}",
                                                             "{0} differs from the original and cannot be replaced: {1}", name, target), e);
                    }
                }
                var held = new FileStream(target, FileMode.Open, FileAccess.Read, FileShare.Read);
                locks.Add(held);
                if (!SHA256.HashData(held).AsSpan().SequenceEqual(expected))
                    throw new InvalidDataException(Loc.F("{0} ist nicht das Original: {1}", "{0} is not the original: {1}", name, target));
            }
            return (dir, locks);
        }
        catch
        {
            foreach (var l in locks) l.Dispose();
            throw;
        }
    }

    private static byte[] HashOf(string path)
    {
        using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return SHA256.HashData(f);
    }

    private static bool _resolverSet;

    public bool Start()
    {
        if (Running) return true;
        if (_engine == null) throw new InvalidOperationException("Attach fehlt");
        List<FileStream>? driverLocks = null;
        try
        {
            (var dir, driverLocks) = ExtractDriver();
            if (!_resolverSet)
            {
                var dll = Path.Combine(dir, "WinDivert.dll");
                NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), (name, _, _) =>
                    name == "WinDivert.dll" ? NativeLibrary.Load(dll) : IntPtr.Zero);
                _resolverSet = true;
            }
            var code = 0;
            foreach (var filter in Filters)
            {
                _net = WinDivert.Open(filter, WinDivert.LayerNetwork, 0, 0);
                if (_net != WinDivert.Invalid) break;
                code = Marshal.GetLastWin32Error();
                Log.Write($"WinDivertOpen (Netzwerk) Fehler {code} für Filter: {filter}");
                if (code != 87) break; // nur bei „Filter ungültig“ die einfachere Fassung versuchen
            }
            if (_net == WinDivert.Invalid)
            {
                Error = DescribeOpenError(code);
                return false;
            }
            WinDivert.SetParam(_net, WinDivert.ParamQueueLength, 16384);
            WinDivert.SetParam(_net, WinDivert.ParamQueueTime, 4000);
            WinDivert.SetParam(_net, WinDivert.ParamQueueSize, 16 * 1024 * 1024);

            // Socket-Ereignisse nennen den Prozess zu jedem lokalen Port, schon bevor das erste Paket kommt.
            _sock = WinDivert.Open("true", WinDivert.LayerSocket, 0, WinDivert.FlagSniff | WinDivert.FlagRecvOnly);
            if (_sock == WinDivert.Invalid)
                Log.Write($"WinDivertOpen (Socket) Fehler {Marshal.GetLastWin32Error()} – Prozesse werden nur über die Port-Tabellen ermittelt");
            else
            {
                // Lange Warteschlange: ein verlorenes „Socket geschlossen“ ließe eine veraltete Zuordnung stehen.
                WinDivert.SetParam(_sock, WinDivert.ParamQueueLength, 16384);
                WinDivert.SetParam(_sock, WinDivert.ParamQueueTime, 8000);
            }
        }
        catch (Exception e)
        {
            Log.Write("Treiberstart: " + e);
            Error = e.Message;
            return false;
        }
        finally
        {
            // DLL und Treiber sind jetzt geladen (oder der Start ist gescheitert): die Sperren dürfen weg.
            if (driverLocks != null) foreach (var l in driverLocks) l.Dispose();
        }

        // Drittes Handle nur zum Mitzählen der Datenmengen. Niedrigere Priorität als der Filter: es sieht also nur,
        // was der Filter durchgelassen hat. Mitlesen verzögert nichts; läuft die Warteschlange voll, fehlen nur Zahlen.
        _meter = WinDivert.Open("!loopback and (tcp or udp)", WinDivert.LayerNetwork, -1, WinDivert.FlagSniff | WinDivert.FlagRecvOnly);
        if (_meter == WinDivert.Invalid)
            Log.Write($"WinDivertOpen (Zähler) Fehler {Marshal.GetLastWin32Error()} – keine Datenmengen je Programm");
        else
        {
            WinDivert.SetParam(_meter, WinDivert.ParamQueueLength, 16384);
            WinDivert.SetParam(_meter, WinDivert.ParamQueueSize, 32 * 1024 * 1024);
            WinDivert.SetParam(_meter, WinDivert.ParamQueueTime, 1000);
        }

        RefreshDnsServers();
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        _dnsTimer = new Timer(_ => RefreshDnsServers(), null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
        FlushDnsCache();
        _stop = false;
        _netThread = new Thread(NetworkLoop) { IsBackground = true, Name = "SnitchBox.Network", Priority = ThreadPriority.AboveNormal };
        _netThread.Start();
        if (_sock != WinDivert.Invalid)
        {
            _sockThread = new Thread(SocketLoop) { IsBackground = true, Name = "SnitchBox.Sockets" };
            _sockThread.Start();
        }
        if (_meter != WinDivert.Invalid)
        {
            _meterThread = new Thread(MeterLoop) { IsBackground = true, Name = "SnitchBox.Meter" };
            _meterThread.Start();
            _commitThread = new Thread(CommitLoop) { IsBackground = true, Name = "SnitchBox.MeterCommit" };
            _commitThread.Start();
        }
        Running = true;
        Error = null;
        Log.Write("Netzwerkfilter läuft");
        return true;
    }

    /// <summary>Leert den DNS-Zwischenspeicher von Windows. So fragt der Rechner Namen neu ab und SnitchBox sieht die
    /// Antworten – sonst blieben Adressen, die vor dem Start aufgelöst wurden, namenlos.</summary>
    private static void FlushDnsCache()
    {
        try
        {
            // Voller Pfad: ohne ihn sucht Windows zuerst im Ordner von SnitchBox.exe (dort könnte ein fremdes ipconfig.exe liegen).
            using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "ipconfig.exe"), "/flushdns")
            {
                CreateNoWindow = true, UseShellExecute = false,
            });
        }
        catch (Exception e) { Log.Write("DNS-Zwischenspeicher leeren: " + e.Message); }
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        RefreshDnsServers();
        // DHCP trägt die DNS-Server oft erst kurz nach der Adresse ein: in drei Sekunden noch einmal nachsehen.
        try { _dnsTimer?.Change(TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(60)); }
        catch (ObjectDisposedException) { }
    }

    /// <summary>Ein Programm fragt einen DNS-Server an, der nicht in der Liste steht: vielleicht hat sich nur die
    /// DNS-Einstellung geändert (das meldet Windows nicht als Adressänderung). Gedrosselt neu lesen.</summary>
    private void OnUnknownDnsServer()
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref _lastDnsRefresh);
        if (now - last < 3000 || Interlocked.CompareExchange(ref _lastDnsRefresh, now, last) != last) return;
        ThreadPool.QueueUserWorkItem(_ => RefreshDnsServers());
    }

    /// <summary>DNS-Server aus der Namensauflösungsrichtlinie (NRPT: Split-DNS z. B. bei Tailscale, DirectAccess,
    /// Always-On-VPN). Sie stehen in keiner Adapterliste, beantworten aber Anfragen des Systems.</summary>
    private static List<IpKey> PolicyDnsServers()
    {
        var result = new List<IpKey>();
        foreach (var path in new[] { @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig", @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig" })
        {
            try
            {
                using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path);
                if (root == null) continue;
                foreach (var name in root.GetSubKeyNames())
                {
                    using var rule = root.OpenSubKey(name);
                    // Allgemeine NRPT-Regeln (Tailscale, Always-On-VPN) und DirectAccess-Regeln speichern ihre Server getrennt.
                    foreach (var value in new[] { "GenericDNSServers", "DirectAccessDNSServers" })
                    {
                        if (rule?.GetValue(value) is not string list) continue;
                        foreach (var part in list.Split([';', ',', ' '], StringSplitOptions.RemoveEmptyEntries))
                            if (IpKey.TryParse(part, out var ip)) result.Add(ip);
                    }
                }
            }
            catch { /* nicht lesbar: dann eben ohne */ }
        }
        return result;
    }

    /// <summary>Die DNS-Server aller aktiven Netzwerkverbindungen an die Engine geben (Werksregel DNS, Prüfung der Antworten),
    /// dazu die eigenen Adressen (ein DNS-Server unter eigener Adresse ist ein lokaler Resolver).
    /// Nacheinander, damit ein älterer Stand keinen neueren überschreibt.</summary>
    private void RefreshDnsServers()
    {
        lock (_dnsRefreshGate)
        {
            Interlocked.Exchange(ref _lastDnsRefresh, Environment.TickCount64);
            try
            {
                var servers = new List<IpKey>();
                var own = new List<IpKey>();
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    var props = ni.GetIPProperties();
                    foreach (var a in props.DnsAddresses) servers.Add(IpKey.From(a));
                    foreach (var u in props.UnicastAddresses) own.Add(IpKey.From(u.Address));
                }
                servers.AddRange(PolicyDnsServers());
                _engine?.SetDnsServers(servers, own);
            }
            catch (Exception e)
            {
                if (Interlocked.Increment(ref _loggedErrors) <= 20) Log.Write("DNS-Server ermitteln: " + e.Message);
            }
        }
    }

    private static string DescribeOpenError(int code) => code switch
    {
        5 => Loc.T("Zugriff verweigert – SnitchBox braucht Administratorrechte.", "Access denied – SnitchBox needs administrator rights."),
        2 => Loc.T("Die Treiberdatei WinDivert64.sys wurde nicht gefunden (vom Virenscanner entfernt?).", "The driver file WinDivert64.sys was not found (removed by antivirus?)."),
        577 => Loc.T("Windows lehnt die Signatur des Treibers ab.", "Windows rejects the driver signature."),
        1275 => Loc.T("Windows blockiert das Laden des Treibers (z. B. durch Kernisolierung oder Richtlinie).", "Windows blocks loading the driver (e.g. core isolation or policy)."),
        1753 => Loc.T("Der Windows-Dienst „Basisfiltermodul“ läuft nicht.", "The Windows service “Base Filtering Engine” is not running."),
        654 => Loc.T("Eine ältere, unverträgliche WinDivert-Fassung ist bereits geladen.", "An older, incompatible WinDivert version is already loaded."),
        _ => Loc.F("Der Treiber ließ sich nicht starten (Windows-Fehler {0}).", "The driver could not be started (Windows error {0}).", code),
    };

    private void NetworkLoop()
    {
        var buffer = new byte[40 + 0xFFFF];
        var engine = _engine!;
        fixed (byte* p = buffer)
        {
            while (!_stop)
            {
                uint len;
                WinDivertAddress addr;
                if (!WinDivert.Recv(_net, p, (uint)buffer.Length, &len, &addr))
                {
                    var code = Marshal.GetLastWin32Error();
                    if (_stop || code is 232 /*NO_DATA nach Shutdown*/ or 6 or 995) break;
                    if (code != 122) Thread.Sleep(1); // 122: Paket größer als der Puffer, einfach weiter
                    continue;
                }
                // Verkehr am eigenen Rechner bleibt ungefiltert (nur relevant, falls der Ausweichfilter ohne „!loopback“ läuft).
                if (addr.Loopback)
                {
                    WinDivert.Send(_net, p, len, null, &addr);
                    continue;
                }
                var verdict = Verdict.Pass;
                byte[]? reply = null;
                var meta = new PacketMeta(addr.Outbound, addr.IPv6, addr.IfIdx, addr.SubIfIdx, addr.Flags | Captured);
                try
                {
                    verdict = engine.Process(new ReadOnlySpan<byte>(p, (int)len), meta, out reply);
                }
                catch (Exception e)
                {
                    // Im Zweifel durchlassen: ein Fehler hier darf das Netz nicht lahmlegen.
                    if (Interlocked.Increment(ref _loggedErrors) <= 20) Log.Write("Paketauswertung: " + e);
                }
                if (verdict == Verdict.Pass) WinDivert.Send(_net, p, len, null, &addr);
                else if (verdict == Verdict.Reject && reply != null) Inject(reply, meta with { Outbound = false, Raw = 0 });
            }
        }
    }

    private void SocketLoop()
    {
        while (!_stop)
        {
            uint len;
            WinDivertAddress addr;
            if (!WinDivert.Recv(_sock, null, 0, &len, &addr))
            {
                var code = Marshal.GetLastWin32Error();
                if (_stop || code is 232 or 6 or 995) break;
                Thread.Sleep(1);
                continue;
            }
            Volatile.Write(ref _socketLag, Stopwatch.GetTimestamp() - addr.Timestamp);
            if (addr.Protocol is not (6 or 17) || addr.LocalPort == 0) continue;
            var tcp = addr.Protocol == 6;
            var key = (tcp, addr.LocalPort);
            var pid = (int)addr.ProcessId;
            switch (addr.Event)
            {
                case WinDivert.EventBind or WinDivert.EventConnect or WinDivert.EventListen or WinDivert.EventAccept:
                    _portOwners[key] = (pid, addr.Timestamp);
                    _recentlyClosed.TryRemove(key, out _);
                    if (tcp && addr.Event == WinDivert.EventListen)
                        lock (_listenGate)
                        {
                            // Neuer Lauscher: Tabelle beim nächsten eingehenden Verbindungsaufbau neu lesen. Lauscher auf der
                            // Wildcard-Adresse gleich eintragen (dann gibt es kein Zeitfenster ohne Nachfrage); Lauscher auf
                            // Loopback oder einer bestimmten Adresse überlässt das der Tabelle, die das richtig unterscheidet.
                            _listenersDirty = true;
                            if (_listeners != null && addr.LocalIsWildcard)
                            {
                                _listeners[(addr.IPv6, addr.LocalPort)] = pid;
                                if (addr.IPv6) _listeners.TryAdd((false, addr.LocalPort), pid); // vielleicht Dual-Stack
                            }
                        }
                    break;
                case WinDivert.EventClose:
                    // Windows vergibt Ports neu. Bliebe der Eintrag stehen, könnte der nächste Besitzer des Ports – falls
                    // sein Socket-Ereignis erst nach dem ersten Paket eintrifft – als dieses Programm durchgehen.
                    // Entfernt wird nur, was noch demselben Prozess zugeordnet ist; für Nachzügler (Pakete und Datenmengen,
                    // die erst nach dem Schließen ausgewertet werden) bleibt die Zuordnung einige Sekunden als „geschlossen“.
                    if (_portOwners.TryGetValue(key, out var current) && current.Pid == pid
                        && _portOwners.TryRemove(new KeyValuePair<(bool, ushort), (int, long)>(key, current)))
                        _recentlyClosed[key] = (pid, Environment.TickCount64);
                    if (tcp) lock (_listenGate) _listenersDirty = true;
                    break;
            }
        }
    }

    /// <summary>Zählt die Bytes aller TCP/UDP-Pakete je lokalem Port. Der Treiber liefert viele Pakete auf einmal.</summary>
    private void MeterLoop()
    {
        const int MaxBatch = 255;
        var buffer = new byte[2 * 1024 * 1024];
        var addrs = new WinDivertAddress[MaxBatch];
        var local = new Dictionary<(bool, ushort), (long Down, long Up)>();
        fixed (byte* p = buffer)
        fixed (WinDivertAddress* a = addrs)
        {
            while (!_stop)
            {
                uint len;
                var addrLen = (uint)(MaxBatch * sizeof(WinDivertAddress));
                if (!WinDivert.RecvEx(_meter, p, (uint)buffer.Length, &len, 0, a, &addrLen, IntPtr.Zero))
                {
                    var code = Marshal.GetLastWin32Error();
                    if (_stop || code is 232 or 6 or 995) break;
                    Thread.Sleep(1);
                    continue;
                }
                var count = (int)(addrLen / (uint)sizeof(WinDivertAddress));
                var span = new ReadOnlySpan<byte>(p, (int)len);
                var offset = 0;
                for (var i = 0; i < count && offset < span.Length; i++)
                {
                    var size = Packet.Measure(span[offset..], out var tcp, out var counted, out var src, out var dst);
                    if (size == 0) break;
                    // Zum Trennen vorgemerkte Verbindung (IPv6 u. a.)? Nur dann das Paket genauer ansehen.
                    if (tcp && _killPending > 0)
                    {
                        try { ResetIfMarked(span.Slice(offset, size), a[i]); }
                        catch (Exception e) { if (Interlocked.Increment(ref _loggedErrors) <= 20) Log.Write("RST senden: " + e.Message); }
                    }
                    offset += size;
                    if (!counted) continue;
                    var outbound = a[i].Outbound;
                    var key = (tcp, outbound ? src : dst);
                    local.TryGetValue(key, out var b);
                    local[key] = outbound ? (b.Down, b.Up + size) : (b.Down + size, b.Up);
                }
                // Ergebnis des Stapels in den gemeinsamen Zwischenstand übernehmen.
                lock (_meterGate)
                {
                    foreach (var (key, b) in local)
                    {
                        _portBytes.TryGetValue(key, out var sum);
                        _portBytes[key] = (sum.Down + b.Down, sum.Up + b.Up);
                    }
                }
                local.Clear();
            }
        }
    }

    /// <summary>Ordnet einmal je Sekunde die gezählten Bytes den Programmen zu.</summary>
    private void CommitLoop()
    {
        var last = Environment.TickCount64;
        while (!_stop)
        {
            Thread.Sleep(1000);
            Dictionary<(bool Tcp, ushort Port), (long Down, long Up)> taken;
            lock (_meterGate)
            {
                taken = _portBytes;
                _portBytes = [];
            }
            var now = Environment.TickCount64;
            var seconds = (now - last) / 1000.0;
            last = now;
            try
            {
                var perPath = new Dictionary<string, (long Down, long Up)>(StringComparer.OrdinalIgnoreCase);
                // Verbindungen von vor dem Start kennt nur die Port-Tabelle von Windows; je Durchgang höchstens einmal holen.
                Dictionary<ushort, int>? tcpTable = null, udpTable = null;
                foreach (var (key, b) in taken)
                {
                    var pid = _portOwners.TryGetValue(key, out var owner) ? owner.Pid : 0;
                    if (pid == 0 && _recentlyClosed.TryGetValue(key, out var closed)) pid = closed.Pid;
                    if (pid == 0)
                    {
                        var table = key.Tcp ? tcpTable ??= Native.PortOwners(true) : udpTable ??= Native.PortOwners(false);
                        table.TryGetValue(key.Port, out pid);
                    }
                    var path = pid != 0 ? PathOf(pid) ?? "" : "";
                    perPath.TryGetValue(path, out var sum);
                    perPath[path] = (sum.Down + b.Down, sum.Up + b.Up);
                }
                _engine?.Traffic.Commit(perPath.Select(p => (p.Key, p.Value.Down, p.Value.Up)), seconds);
                // Vormerkungen zum Trennen aufräumen (sonst blieben getrennte Verbindungen für immer stehen); bei abgeschaltetem
                // Filter alle verwerfen – dann wird nichts getrennt.
                if (_killPending > 0)
                {
                    if (_engine is { } e && !e.Read(s => s.Settings.FilterEnabled)) ClearResets();
                    else PruneResets();
                }
                foreach (var (k, v) in _recentlyClosed)
                    if (now - v.Tick > 10_000) _recentlyClosed.TryRemove(new KeyValuePair<(bool, ushort), (int, long)>(k, v));
            }
            catch (Exception e)
            {
                if (Interlocked.Increment(ref _loggedErrors) <= 20) Log.Write("Datenmengen: " + e);
            }
        }
    }

    /// <summary>Speist ein zurückgehaltenes Paket (mit den ursprünglichen Flags) oder ein selbst gebautes RST ein.</summary>
    private void Inject(byte[] packet, PacketMeta meta)
    {
        var net = _net;
        if (net == WinDivert.Invalid) return;
        var addr = new WinDivertAddress { IfIdx = meta.IfIdx, SubIfIdx = meta.SubIfIdx };
        addr.Flags = meta.Raw != 0
            ? meta.Raw & ~Captured
            : (meta.Outbound ? WinDivertAddress.OutboundBit : 0) | (meta.V6 ? WinDivertAddress.IPv6Bit : 0) | WinDivertAddress.ChecksumBits;
        fixed (byte* p = packet)
        {
            if (!WinDivert.Send(net, p, (uint)packet.Length, null, &addr) && Interlocked.Increment(ref _loggedErrors) <= 20)
                Log.Write($"WinDivertSend Fehler {Marshal.GetLastWin32Error()}");
        }
    }

    public ProcessInfo Find(bool tcp, ushort localPort, IpKey remote, ushort remotePort, bool incoming)
    {
        // Eingehend zählt nur ein lauschender Socket: ein SYN an den Port einer ausgehenden Verbindung oder an einen freien
        // Port kann keine Verbindung eröffnen. Dann gibt es nichts zu fragen (PID 0 – die Engine lässt es durch).
        if (incoming) return Info(tcp ? ListenerOf(localPort, !remote.IsV4) : Native.OwnerOfPort(false, localPort, null, 0));
        var key = (tcp, localPort);
        var timely = Volatile.Read(ref _socketLag) < LagLimit;
        var known = _portOwners.TryGetValue(key, out var owner) && owner.Pid != 0;
        // Ein frisches Ereignis ist verlässlich, solange die Ereignisse zeitnah ankommen. Sonst könnte der Eintrag vom
        // Vorbesitzer des Ports stammen (dessen „geschlossen“ noch in der Warteschlange steckt): dann entscheidet die
        // Port-Tabelle – bei TCP nur die Zeile mit genau dieser Gegenstelle.
        if (known && timely)
        {
            var age = Stopwatch.GetTimestamp() - owner.Time;
            if (age >= 0 && age < FreshEvent) return Info(owner.Pid);
        }
        var listed = Native.OwnerOfPort(tcp, localPort, remote, remotePort);
        if (listed != 0) return Info(listed);
        if (known) return Info(timely ? owner.Pid : 0);
        // Das Socket-Ereignis kann einen Wimpernschlag nach dem Paket eintreffen.
        Thread.Sleep(15);
        listed = Native.OwnerOfPort(tcp, localPort, remote, remotePort);
        if (listed != 0) return Info(listed);
        if (!timely) return Info(0);
        if (_portOwners.TryGetValue(key, out owner) && owner.Pid != 0) return Info(owner.Pid);
        // Schon wieder geschlossen (z. B. UDP senden und sofort schließen): die Zuordnung der letzten Sekunden.
        return Info(_recentlyClosed.TryGetValue(key, out var closed) && Environment.TickCount64 - closed.Tick < 5000 ? closed.Pid : 0);
    }

    /// <summary>PID 0 heißt „unbekannt“ und darf nicht als Windows-Kern durchgehen.</summary>
    private ProcessInfo Info(int pid) => pid != 0 && PathOf(pid) is { } path ? new ProcessInfo(pid, path, ServiceFor(pid, path)) : new ProcessInfo(pid, "");

    /// <summary>Wer auf einem TCP-Port lauscht (0 = niemand). Die Tabelle wird spätestens alle 2 s neu gelesen, nach
    /// einem geschlossenen Socket oder bei einem unbekannten Port schon nach 25 ms (ein neuer Lauscher, dessen Ereignis
    /// noch unterwegs ist) – bei einem Portscan also höchstens vierzigmal je Sekunde.</summary>
    private int ListenerOf(ushort port, bool v6)
    {
        lock (_listenGate)
        {
            var key = (v6, port);
            var age = Environment.TickCount64 - _listenersTick;
            if (_listeners == null || age > 2000 || (age > 25 && (_listenersDirty || !_listeners.ContainsKey(key))))
            {
                _listeners = Native.ListeningTcpPorts();
                _listenersTick = Environment.TickCount64;
                _listenersDirty = false;
            }
            return _listeners.TryGetValue(key, out var pid) ? pid : 0;
        }
    }

    private string? PathOf(int pid)
    {
        var now = Environment.TickCount64;
        if (_paths.TryGetValue(pid, out var c) && now - c.Tick < 10_000) return c.Path;
        var path = Native.PathOfProcess(pid);
        if (path == null) return null;
        _paths[pid] = (path, now);
        if (_paths.Count > 4000) _paths.Clear();
        return path;
    }

    public bool IsAlive(int pid) => Native.IsProcessAlive(pid);

    public void Stop()
    {
        if (!Running) return;
        _stop = true;
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        _dnsTimer?.Dispose();
        _dnsTimer = null;
        _engine?.ReleaseAll();
        foreach (var h in new[] { _net, _sock, _meter })
        {
            if (h == WinDivert.Invalid) continue;
            WinDivert.Shutdown(h, 3);
        }
        _netThread?.Join(2000);
        _sockThread?.Join(2000);
        // Erst alle Threads beenden, dann die Handles schließen: der Zähl-Thread speist über _net RSTs ein (ResetIfMarked) und
        // dürfte nie ein schon geschlossenes Handle verwenden.
        _meterThread?.Join(2000);
        _commitThread?.Join(1500);
        ClearResets();
        var (net, sock, meter) = (_net, _sock, _meter);
        _net = _sock = _meter = WinDivert.Invalid;
        foreach (var h in new[] { net, sock, meter })
            if (h != WinDivert.Invalid) WinDivert.Close(h);
        Running = false;
        Log.Write("Netzwerkfilter angehalten");
    }

    public void Dispose() => Stop();
}
