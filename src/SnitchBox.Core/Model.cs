using System.Text.Json;
using System.Text.Json.Serialization;

namespace SnitchBox.Core;

public enum RuleAction { Allow, Deny }
public enum Direction { Outgoing, Incoming }
public enum Proto { Any, Tcp, Udp }
/// <summary>Gegenstelle einer Regel. Die Rangfolge (wie genau eine Regel ist) legt <see cref="RuleSet.Specificity"/> fest;
/// neue Werte kommen hinten dazu, weil die Regelbearbeitung die Reihenfolge als Listenposition nutzt.</summary>
public enum RemoteKind { Any, LocalNet, Addresses, Domains, Hosts, DnsServers }
public enum LifetimeKind { Forever, UntilQuit, UntilRestart, Timed }
/// <summary>Betriebsart wie im Original: Warnfenster zeigen oder still erlauben/verbieten.</summary>
public enum OperationMode { Alert, SilentAllow, SilentDeny }

public sealed class Rule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public bool Enabled { get; set; } = true;
    public RuleAction Action { get; set; }
    /// <summary>Voller Pfad der .exe, nur ein Dateiname („chrome.exe“) oder leer für jeden Prozess.</summary>
    public string Process { get; set; } = "";
    /// <summary>Nur für diesen Windows-Dienst (Kurzname wie „DiagTrack“, bei svchost.exe); leer = für jeden.</summary>
    public string Service { get; set; } = "";
    public Direction Direction { get; set; }
    public RemoteKind Remote { get; set; }
    /// <summary>Hostnamen, Domains oder Adressbereiche, je nach <see cref="Remote"/>.</summary>
    public List<string> Targets { get; set; } = [];
    /// <summary>Bei eingehenden Verbindungen der lokale Port.</summary>
    public string Ports { get; set; } = "";
    public Proto Protocol { get; set; }
    public bool HighPriority { get; set; }
    public LifetimeKind Lifetime { get; set; }
    public DateTime? Expires { get; set; }
    public int QuitPid { get; set; }
    public string? BootId { get; set; }
    /// <summary>Nur in diesem Profil wirksam; null = in allen.</summary>
    public string? Profile { get; set; }
    public string Notes { get; set; } = "";
    public DateTime Created { get; set; } = DateTime.Now;
    /// <summary>Werksregel: lässt sich abschalten, aber nicht löschen.</summary>
    public bool Factory { get; set; }

    /// <summary>Prozessangabe für den Windows-Kern (PID 4). Wird nur genau so verglichen, nie als Dateiname –
    /// sonst gälte eine Regel für „System“ auch für jede Datei C:\…\System.</summary>
    public const string KernelProcess = "System";

    /// <summary>Unabhängige Kopie mit derselben Kennung (zum Bearbeiten).</summary>
    public Rule Clone()
    {
        var r = (Rule)MemberwiseClone();
        r.Targets = [.. Targets];
        return r;
    }

    /// <summary>Gilt für genau dieselben Verbindungen (Prozess, Richtung, Gegenstelle, Ports, Protokoll, Profil)?
    /// Aktion, Priorität, Dauer und Notizen zählen nicht: eine solche Regel ist ein Doppel oder ein Widerspruch.</summary>
    public bool SameScope(Rule o) =>
        Process.Equals(o.Process, StringComparison.OrdinalIgnoreCase) && Service.Equals(o.Service, StringComparison.OrdinalIgnoreCase)
        && Direction == o.Direction && Remote == o.Remote
        && Protocol == o.Protocol && Profile == o.Profile
        && (PortSet.TryParse(Ports, out var a) && PortSet.TryParse(o.Ports, out var b) ? a.SameAs(b) : Ports.Trim() == o.Ports.Trim())
        && Targets.Select(t => t.Trim().TrimEnd('.').ToLowerInvariant()).ToHashSet().SetEquals(o.Targets.Select(t => t.Trim().TrimEnd('.').ToLowerInvariant()));

    [JsonIgnore] public bool AnyProcess => Process.Length == 0;
    /// <summary>Anzeigename: bei Windows Update und dem Viren- &amp; Bedrohungsschutz deren Name vorn, damit solche Regeln sofort
    /// erkennbar sind („Windows Update · SIHClient.exe“); bekannte Apps mit ihrem Namen und ihrer Rolle („Google Updater“,
    /// „ChatGPT · codex.exe“, siehe <see cref="KnownApps"/>).</summary>
    [JsonIgnore]
    public string ProcessName => Service.Length > 0 ? Loc.F("Windows-Dienst: {0}", "Windows service: {0}", ServiceTitle(Service) ?? Service)
        : AnyProcess ? Loc.T("Jeder Prozess", "Any Process")
        : WindowsComponents.IsComponent(Process) ? WindowsComponents.Title(Process)
        : WindowsComponents.Of(Process) is { } c ? WindowsComponents.Title(c) + " · " + NameOf(Process)
        : KnownApps.Of(Process) is { } app ? app.Label(Process)
        : WindowsProcesses.Of(Process) is { } win ? win.Label
        : NameOf(Process);

    /// <summary>Anzeigename eines Windows-Dienstes (unter Windows vom Dienst-Manager, z. B. „Benutzererfahrung und Telemetrie im
    /// verbundenen Modus“ für DiagTrack); null = unbekannt.</summary>
    public static Func<string, string?> ServiceTitle { get; set; } = _ => null;

    public static string NameOf(string path)
    {
        var i = path.LastIndexOfAny(['\\', '/']);
        return i >= 0 ? path[(i + 1)..] : path;
    }

    public string Describe()
    {
        var verb = Action == RuleAction.Allow
            ? (Direction == Direction.Outgoing ? Loc.T("Erlaube ausgehende Verbindungen", "Allow outgoing connections") : Loc.T("Erlaube eingehende Verbindungen", "Allow incoming connections"))
            : (Direction == Direction.Outgoing ? Loc.T("Verbiete ausgehende Verbindungen", "Deny outgoing connections") : Loc.T("Verbiete eingehende Verbindungen", "Deny incoming connections"));
        var outgoing = Direction == Direction.Outgoing;
        var list = string.Join(", ", Targets);
        var target = Remote switch
        {
            RemoteKind.Any => outgoing ? Loc.T("zu jedem Server", "to any server") : Loc.T("von jedem Rechner", "from any computer"),
            RemoteKind.LocalNet => outgoing ? Loc.T("ins lokale Netzwerk", "to the local network") : Loc.T("aus dem lokalen Netzwerk", "from the local network"),
            RemoteKind.DnsServers => outgoing ? Loc.T("zu den DNS-Servern des Systems", "to the system’s DNS servers") : Loc.T("von den DNS-Servern des Systems", "from the system’s DNS servers"),
            RemoteKind.Domains => outgoing ? Loc.F("zu Domain {0}", "to domain {0}", list) : Loc.F("von Domain {0}", "from domain {0}", list),
            _ => outgoing ? Loc.F("zu {0}", "to {0}", list) : Loc.F("von {0}", "from {0}", list),
        };
        var port = PortSet.TryParse(Ports, out var ps) && !ps.Any ? Loc.F(", Port {0}", ", port {0}", Ports) : "";
        var proto = Protocol == Proto.Any ? "" : $" ({Protocol.ToString().ToUpperInvariant()})";
        return $"{verb} {target}{port}{proto}";
    }

    public string DescribeLifetime() => Lifetime switch
    {
        LifetimeKind.UntilQuit => Loc.T("Bis zum Beenden", "Until Quit"),
        LifetimeKind.UntilRestart => Loc.T("Bis zum Neustart", "Until Restart"),
        LifetimeKind.Timed when Expires is { } e => Loc.F("Bis {0}", "Until {0}", e.ToString("g")),
        _ => Loc.T("Für immer", "Forever"),
    };
}

/// <summary>Ein Verbindungsversuch, wie ihn die Regeln sehen.</summary>
public sealed class Connection
{
    public string ProcessPath { get; init; } = "";
    /// <summary>Windows-Dienst bei svchost.exe (eindeutig bestimmt), sonst leer.</summary>
    public string Service { get; init; } = "";
    public int Pid { get; init; }
    public Direction Direction { get; init; }
    public Proto Protocol { get; init; }
    public IpKey Remote { get; init; }
    /// <summary>Entfernter Port (ausgehend) oder lokaler Port (eingehend).</summary>
    public ushort Port { get; init; }
    /// <summary>Namen aus beobachteten DNS-Antworten, der neueste zuerst; leer, wenn unbekannt.</summary>
    public IReadOnlyList<string> Hostnames { get; init; } = [];

    public string ProcessName => ProcessPath.Length == 0 ? Loc.T("Unbekannter Prozess", "Unknown Process") : Rule.NameOf(ProcessPath);
    public string Host => Hostnames.Count > 0 ? Hostnames[0] : Remote.ToString();
}

public sealed class Settings
{
    public OperationMode Mode { get; set; } = OperationMode.Alert;
    public bool FilterEnabled { get; set; } = true;
    public bool MonitorIncoming { get; set; } = true;
    public string? ActiveProfile { get; set; }
    public List<string> Profiles { get; set; } = [];
    /// <summary>Profil je Netzwerk: beim Verbinden mit einem dieser Netzwerke schaltet SnitchBox das Profil um
    /// (Reihenfolge = Vorrang, falls mehrere zugleich verbunden sind; eine geänderte Zuordnung behält ihre Stelle).</summary>
    public List<NetworkProfile> NetworkProfiles { get; set; } = [];
    /// <summary>In Netzwerken ohne Zuordnung auf <see cref="UnknownNetworkProfile"/> umschalten (sonst das Profil lassen).</summary>
    public bool SwitchOnUnknownNetwork { get; set; }
    /// <summary>Profil für Netzwerke ohne Zuordnung; null = „Kein Profil“.</summary>
    public string? UnknownNetworkProfile { get; set; }
    /// <summary>Kennungen der Netze, die beim letzten Netzwerkwechsel den Ausschlag gaben (<see cref="NetworkProfiles.Observe"/>):
    /// Nach einem Neustart von SnitchBox im selben Netz bleibt ein von Hand gewähltes Profil so erhalten.</summary>
    public List<string> NetworkPlace { get => _networkPlace; set => _networkPlace = value ?? []; }
    private List<string> _networkPlace = [];
    /// <summary>Netze, die danach nur dazukamen (VPN, zweiter Adapter) – sie lösen keinen Wechsel aus.</summary>
    public List<string> NetworkExtras { get => _networkExtras; set => _networkExtras = value ?? []; }
    private List<string> _networkExtras = [];
    public bool BlocklistAutoUpdate { get; set; } = true;
    /// <summary>Regelliste und Programmliste des Netzwerkmonitors nach Art gruppieren (KI, Browser, Windows …); fehlt der Eintrag in
    /// einer älteren config.json, gilt eingeschaltet.</summary>
    public bool GroupLists { get; set; } = true;
    /// <summary>Routenverfolgung: Namen der Router über DNS abfragen (wie tracert).</summary>
    public bool TraceResolveNames { get; set; } = true;
    /// <summary>Routenverfolgung: Weltkarte zeigen (nur auf Wunsch; braucht die Ländertabelle von DB-IP).</summary>
    public bool TraceShowMap { get; set; }
    /// <summary>Oberflächensprache (zweibuchstabiger Code); null = wie Windows.</summary>
    public string? Language { get; set; }
    /// <summary>Build, in dem zuletzt vor einem unsicheren Autostart-Ziel gewarnt wurde (einmal je Build).</summary>
    public int AutostartWarnedBuild { get; set; }
    public bool FactoryRulesCreated { get; set; }
    /// <summary>Stand der Werksregeln; ältere Stände werden beim Start angepasst (siehe <see cref="FactoryRules.Ensure"/>).</summary>
    public int FactoryRulesVersion { get; set; }
    public bool FirstRunDone { get; set; }
}

public sealed class Blocklist
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public string Name { get; set; } = "";
    public string Url { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public DateTime? Updated { get; set; }
    public int Count { get; set; }
    /// <summary>Kleingeschriebene Domains; ein Eintrag sperrt auch alle Subdomains.</summary>
    [JsonIgnore] public HashSet<string> Domains { get; set; } = [];
}

/// <summary>Alles, was gespeichert wird: Einstellungen, Regeln, Blocklisten (Einträge je Liste in eigener Datei).</summary>
public sealed class Store
{
    public Settings Settings { get; set; } = new();
    public List<Rule> Rules { get; set; } = [];
    public List<Blocklist> Blocklists { get; set; } = [];

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static string ConfigPath => Path.Combine(Paths.DataDir, "config.json");
    private static string ListPath(string id) => Path.Combine(Paths.DataDir, "blocklists", id + ".txt");

    // Schreiben geschieht nacheinander; ein älterer Stand überschreibt nie einen neueren.
    private readonly object _fileGate = new();
    private long _nextVersion, _writtenVersion;

    public static Store Load()
    {
        Store s;
        try
        {
            s = File.Exists(ConfigPath) ? JsonSerializer.Deserialize<Store>(File.ReadAllText(ConfigPath), Json) ?? new Store() : new Store();
        }
        catch (Exception e)
        {
            // Mit Zeitstempel, damit ein zweiter Fehlschlag die erste Sicherung nicht überschreibt.
            var copy = $"{ConfigPath}.defekt-{DateTime.Now:yyyyMMdd-HHmmss}";
            Log.Write($"Konfiguration unlesbar, starte mit Werkseinstellungen (Sicherung: {copy}): {e.Message}");
            try { File.Copy(ConfigPath, copy, false); } catch { }
            s = new Store();
        }
        foreach (var b in s.Blocklists)
        {
            try
            {
                if (File.Exists(ListPath(b.Id))) b.Domains = new HashSet<string>(File.ReadLines(ListPath(b.Id)), StringComparer.Ordinal);
            }
            catch (Exception e) { Log.Write($"Blockliste {b.Name} unlesbar: {e.Message}"); }
        }
        return s;
    }

    /// <summary>Nimmt den aktuellen Stand als Text auf. Der Aufrufer sorgt dafür, dass währenddessen niemand ändert
    /// (in der Engine: unter ihrer Sperre); geschrieben wird danach mit <see cref="Write"/> außerhalb der Sperre.</summary>
    public (string Json, long Version) Snapshot() => (JsonSerializer.Serialize(this, Json), Interlocked.Increment(ref _nextVersion));

    /// <summary>Schreibt einen mit <see cref="Snapshot"/> aufgenommenen Stand; ein inzwischen überholter Stand wird verworfen.</summary>
    public void Write((string Json, long Version) snapshot)
    {
        lock (_fileGate)
        {
            if (snapshot.Version <= _writtenVersion) return;
            try
            {
                var tmp = ConfigPath + ".tmp";
                WriteFresh(tmp, w => w.Write(snapshot.Json));
                File.Move(tmp, ConfigPath, true);
                _writtenVersion = snapshot.Version;
            }
            catch (Exception e) { Log.Write("Speichern fehlgeschlagen: " + e.Message); }
        }
    }

    /// <summary>Schreibt eine Zwischendatei immer neu: eine vorhandene (womöglich untergeschobene, etwa ein Hardlink auf eine
    /// fremde Datei) wird gelöscht, nicht überschrieben.</summary>
    private static void WriteFresh(string path, Action<StreamWriter> write)
    {
        File.Delete(path);
        using var w = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None), new System.Text.UTF8Encoding(false));
        write(w);
    }

    /// <summary>Aufnehmen und sofort schreiben; nur wenn niemand gleichzeitig ändert (beim Start, in Tests).</summary>
    public void Save() => Write(Snapshot());

    /// <summary>Einmalige Sicherung der Konfiguration unter „config.json.&lt;Name&gt;“ (wird nie überschrieben), z. B. vor
    /// einer Umstellung, die ältere Versionen nicht mehr lesen können.</summary>
    public static void Backup(string name)
    {
        try
        {
            var target = ConfigPath + "." + name;
            if (File.Exists(ConfigPath) && !File.Exists(target)) File.Copy(ConfigPath, target, false);
        }
        catch (Exception e) { Log.Write("Sicherung der Konfiguration fehlgeschlagen: " + e.Message); }
    }

    /// <summary>Schreibt die Einträge einer Liste (Standard: ihre aktuellen). Ohne Sperre der Engine aufrufbar.</summary>
    public void SaveBlocklist(Blocklist b, IEnumerable<string>? domains = null)
    {
        lock (_fileGate)
        {
            try
            {
                var path = ListPath(b.Id);
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                WriteFresh(path + ".tmp", w => { foreach (var d in domains ?? b.Domains) w.WriteLine(d); });
                File.Move(path + ".tmp", path, true);
            }
            catch (Exception e) { Log.Write("Blockliste speichern fehlgeschlagen: " + e.Message); }
        }
    }

    public void DeleteBlocklistFile(Blocklist b)
    {
        lock (_fileGate)
        {
            try { File.Delete(ListPath(b.Id)); } catch { }
        }
    }
}

/// <summary>Werksregeln: ohne sie stünde Windows selbst (Namensauflösung, DHCP, Updates) sofort still.</summary>
public static class FactoryRules
{
    /// <summary>2: DNS nur noch zu den DNS-Servern des Systems, DHCP nur noch ins lokale Netz (vorher je „jeder Server“).
    /// 3: Windows Update und Viren- &amp; Bedrohungsschutz (<see cref="WindowsComponents"/>) dazu.</summary>
    public const int Version = 3;

    /// <summary>Werksregeln für Windows-Bestandteile außerhalb von svchost.exe (ab Stand 3).</summary>
    private static List<Rule> ComponentRules() =>
    [
        new()
        {
            Action = RuleAction.Allow, Process = WindowsComponents.Update, Direction = Direction.Outgoing, Factory = true,
            Notes = Loc.T("Updates von Windows (SIHClient, MoUsoCoreWorker, WaaSMedicAgent …); die Dienste in svchost.exe erlaubt eine eigene Werksregel",
                          "Windows updates (SIHClient, MoUsoCoreWorker, WaaSMedicAgent …); the services in svchost.exe are allowed by a factory rule of their own"),
        },
        new()
        {
            Action = RuleAction.Allow, Process = WindowsComponents.Defender, Direction = Direction.Outgoing, Factory = true,
            Notes = Loc.T("Microsoft Defender: neue Virensignaturen und Cloud-Schutz (MsMpEng, MpCmdRun, NisSrv …)",
                          "Microsoft Defender: new virus signatures and cloud protection (MsMpEng, MpCmdRun, NisSrv …)"),
        },
    ];
    private const string DnsPorts = "53", DhcpPorts = "67, 68, 546, 547";

    public static List<Rule> Create(string systemRoot)
    {
        var sys = systemRoot.TrimEnd('\\') + @"\System32\";
        Rule R(string process, Direction dir, RemoteKind remote, string ports, Proto proto, string notes) => new()
        {
            Action = RuleAction.Allow, Process = process, Direction = dir, Remote = remote, Ports = ports, Protocol = proto,
            Factory = true, Notes = notes,
        };
        return
        [
            // Nur zu den eingetragenen DNS-Servern: sonst wäre Port 53 ein offener Tunnel zu jedem Server der Welt.
            R("", Direction.Outgoing, RemoteKind.DnsServers, DnsPorts, Proto.Any, Loc.T("Namensauflösung (DNS)", "Name resolution (DNS)")),
            R("", Direction.Outgoing, RemoteKind.LocalNet, DhcpPorts, Proto.Udp, Loc.T("Adressvergabe (DHCP)", "Address assignment (DHCP)")),
            R("", Direction.Outgoing, RemoteKind.LocalNet, "137, 138, 1900, 5353, 5355", Proto.Udp, Loc.T("Geräte im lokalen Netz finden (mDNS, LLMNR, SSDP, NetBIOS)", "Discover devices on the local network (mDNS, LLMNR, SSDP, NetBIOS)")),
            R(sys + "svchost.exe", Direction.Outgoing, RemoteKind.Any, "", Proto.Any, Loc.T("Windows-Dienste (Updates, Uhrzeit, Zertifikate, Store)", "Windows services (updates, time, certificates, Store)")),
            R(Rule.KernelProcess, Direction.Outgoing, RemoteKind.Any, "", Proto.Any, Loc.T("Windows-Kern (Dateifreigaben, VPN)", "Windows kernel (file sharing, VPN)")),
            R(sys + "lsass.exe", Direction.Outgoing, RemoteKind.Any, "", Proto.Any, Loc.T("Windows-Anmeldung", "Windows sign-in")),
            R(sys + "svchost.exe", Direction.Incoming, RemoteKind.LocalNet, "", Proto.Any, Loc.T("Windows-Dienste aus dem lokalen Netz", "Windows services from the local network")),
            R(Rule.KernelProcess, Direction.Incoming, RemoteKind.LocalNet, "", Proto.Any, Loc.T("Dateifreigaben aus dem lokalen Netz", "File sharing from the local network")),
            .. ComponentRules(),
        ];
    }

    /// <summary>Legt die Werksregeln beim ersten Start an (oder nach „Werkseinstellungen“) und bringt ältere Stände auf
    /// <see cref="Version"/>; dabei bleibt erhalten, ob der Nutzer eine Werksregel abgeschaltet hat.</summary>
    public static void Ensure(Store store, string systemRoot)
    {
        var s = store.Settings;
        if (!s.FactoryRulesCreated)
        {
            store.Rules.RemoveAll(r => r.Factory);
            store.Rules.InsertRange(0, Create(systemRoot));
            s.FactoryRulesCreated = true;
        }
        else if (s.FactoryRulesVersion < 2)
        {
            // Stand 2 schreibt „DnsServers“, das Build 12 und älter nicht lesen können: vorher den alten Stand sichern.
            Store.Backup("vor-werksregeln-2");
            foreach (var r in store.Rules.Where(r => r.Factory && r.AnyProcess && r.Direction == Direction.Outgoing && r.Remote == RemoteKind.Any))
            {
                if (r.Ports == DnsPorts) r.Remote = RemoteKind.DnsServers;
                else if (r.Ports == DhcpPorts) r.Remote = RemoteKind.LocalNet;
            }
        }
        if (s.FactoryRulesCreated && s.FactoryRulesVersion < 3)
        {
            // Stand 3: Windows Update und Viren- & Bedrohungsschutz. Eigene Verbieten-Regeln für einzelne ihrer Programme gehen weiter
            // vor (gleiche Rangstufe, bei Gleichstand gewinnt „Verbieten“).
            var at = store.Rules.FindLastIndex(r => r.Factory) + 1;
            store.Rules.InsertRange(at, ComponentRules().Where(n => !store.Rules.Any(r => r.Factory && r.Process == n.Process)));
        }
        s.FactoryRulesVersion = Version;
    }
}
