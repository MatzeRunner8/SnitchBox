using System.Text.RegularExpressions;

namespace SnitchBox.Core;

/// <summary>Ergebnis der Regelsuche; ohne Treffer entscheidet die Betriebsart.</summary>
public readonly record struct Decision(RuleAction? Action, Rule? Rule, Blocklist? Blocklist)
{
    public string Reason => Rule != null ? Rule.Describe()
        : Blocklist != null ? Loc.T("Blockliste ", "Blocklist ") + Blocklist.Name
        : "";
}

/// <summary>Unveränderliche, vorbereitete Fassung aller Regeln; wird bei jeder Änderung neu gebaut.</summary>
public sealed class RuleSet
{
    private sealed class Compiled
    {
        public required Rule Rule;
        public required PortSet Ports;
        public AddressRange[] Ranges = [];
        public string[] Names = [];
        public bool NameOnly; // Prozess nur als Dateiname angegeben
        public Regex? Glob;   // Prozessangabe mit * (z. B. R:\Temp\*\setup.exe)
    }

    /// <summary>Prozessangabe mit „*“ als Muster: * steht für einen beliebigen Teil eines Ordner- oder Dateinamens
    /// (nie für „\“). Ohne * null.</summary>
    internal static Regex? ProcessGlob(string process) =>
        process.Contains('*')
            ? new Regex("^" + Regex.Escape(process).Replace(@"\*", @"[^\\/]*") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
            : null;

    private readonly Compiled[] _rules;
    private readonly Blocklist[] _blocklists;
    private readonly IReadOnlySet<IpKey>? _dnsServers;

    private RuleSet(Compiled[] rules, Blocklist[] lists, IReadOnlySet<IpKey>? dnsServers)
    {
        _rules = rules;
        _blocklists = lists;
        _dnsServers = dnsServers;
    }

    /// <param name="dnsServers">Die DNS-Server des Systems für Regeln mit <see cref="RemoteKind.DnsServers"/>.
    /// null heißt „nie ermittelt“ (Tests, Demo) – dann passt jede Adresse; eine leere Menge heißt „keine“.</param>
    public static RuleSet Build(Store store, string bootId, IReadOnlySet<IpKey>? dnsServers = null)
    {
        var list = new List<Compiled>();
        foreach (var r in store.Rules)
        {
            if (!r.Enabled) continue;
            if (r.Profile != null && r.Profile != store.Settings.ActiveProfile) continue;
            if (r.Lifetime == LifetimeKind.UntilRestart && r.BootId != bootId) continue;
            if (!PortSet.TryParse(r.Ports, out var ports)) continue;
            // „chrome.exe“ passt auf jeden Ort, „System“ (Windows-Kern) dagegen nur genau so – nie auf C:\…\System.
            var nameOnly = r.Process.Length > 0 && r.Process.IndexOfAny(['\\', '/']) < 0
                           && !r.Process.Equals(Rule.KernelProcess, StringComparison.OrdinalIgnoreCase)
                           && !WindowsComponents.IsComponent(r.Process);
            var c = new Compiled { Rule = r, Ports = ports, NameOnly = nameOnly, Glob = ProcessGlob(r.Process) };
            if (r.Remote == RemoteKind.Addresses)
                c.Ranges = r.Targets.Select(t => AddressRange.TryParse(t, out var a) ? a : (AddressRange?)null).Where(a => a != null).Select(a => a!.Value).ToArray();
            else if (r.Remote is RemoteKind.Hosts or RemoteKind.Domains)
                c.Names = r.Targets.Select(t => t.Trim().TrimEnd('.').ToLowerInvariant()).Where(t => t.Length > 0).ToArray();
            list.Add(c);
        }
        return new RuleSet(list.ToArray(), store.Blocklists.Where(b => b.Enabled && b.Domains.Count > 0).ToArray(), dnsServers);
    }

    public static bool DomainMatches(string host, string domain) =>
        host.Length == domain.Length ? host == domain
        : host.Length > domain.Length && host[host.Length - domain.Length - 1] == '.' && host.EndsWith(domain, StringComparison.Ordinal);

    private bool Matches(Compiled c, Connection conn, string[] hosts, string remoteText, DateTime now)
    {
        var r = c.Rule;
        if (r.Direction != conn.Direction) return false;
        if (r.Lifetime == LifetimeKind.Timed && r.Expires is { } e && e <= now) return false;
        if (r.Lifetime == LifetimeKind.UntilQuit && r.QuitPid != conn.Pid) return false;
        if (r.Protocol != Proto.Any && r.Protocol != conn.Protocol) return false;
        if (!c.Ports.Contains(conn.Port)) return false;
        if (r.Service.Length > 0 && !r.Service.Equals(conn.Service, StringComparison.OrdinalIgnoreCase)) return false;
        if (r.Process.Length > 0)
        {
            var p = c.NameOnly ? Rule.NameOf(conn.ProcessPath) : conn.ProcessPath;
            if (WindowsComponents.IsComponent(r.Process))
            {
                // Windows Update bzw. Viren- & Bedrohungsschutz: jedes ihrer Programme an seinem geschützten Ort.
                if (WindowsComponents.Of(conn.ProcessPath) != r.Process) return false;
            }
            else if (c.Glob != null)
            {
                // Ein Muster passt nie auf einen unbekannten Prozess (sonst gälte „*“ auch für ihn).
                if (conn.ProcessPath.Length == 0 || !c.Glob.IsMatch(p)) return false;
            }
            else if (!p.Equals(r.Process, StringComparison.OrdinalIgnoreCase)) return false;
        }
        switch (r.Remote)
        {
            case RemoteKind.Any: return true;
            case RemoteKind.LocalNet: return AddressRange.IsLocal(conn.Remote);
            case RemoteKind.DnsServers: return _dnsServers == null || _dnsServers.Contains(conn.Remote);
            case RemoteKind.Addresses:
                foreach (var a in c.Ranges) if (a.Contains(conn.Remote)) return true;
                return false;
            case RemoteKind.Hosts:
                foreach (var n in c.Names)
                {
                    if (n == remoteText) return true;
                    foreach (var h in hosts) if (h == n) return true;
                }
                return false;
            case RemoteKind.Domains:
                foreach (var n in c.Names)
                    foreach (var h in hosts) if (DomainMatches(h, n)) return true;
                return false;
            default:
                return false;
        }
    }

    /// <summary>Wie genau eine Gegenstelle bestimmt ist (höher = genauer).</summary>
    public static int Specificity(RemoteKind k) => k switch
    {
        RemoteKind.Any => 0,
        RemoteKind.LocalNet => 1,
        RemoteKind.Addresses or RemoteKind.DnsServers => 2,
        RemoteKind.Domains => 3,
        RemoteKind.Hosts => 4,
        _ => 0,
    };

    /// <summary>Rangfolge wie im Original: hohe Priorität, dann der genauere Prozess, ein bestimmter Windows-Dienst (genauer als
    /// „svchost.exe“ allein), die genauere Gegenstelle, Port und Protokoll; bei Gleichstand gewinnt „Verbieten“.</summary>
    internal static int Score(Rule r, PortSet ports) =>
        (r.HighPriority ? 1 << 20 : 0) + (r.AnyProcess ? 0 : 1 << 16) + (r.Service.Length > 0 ? 1 << 12 : 0) + (Specificity(r.Remote) << 8)
        + (ports.Any ? 0 : 1 << 4) + (r.Protocol == Proto.Any ? 0 : 1 << 2) + (r.Action == RuleAction.Deny ? 1 : 0);

    public Decision Evaluate(Connection conn, DateTime now)
    {
        var hosts = conn.Hostnames.Count == 0 ? [] : conn.Hostnames.Select(h => h.ToLowerInvariant()).ToArray();
        var remoteText = conn.Remote.ToString();
        Compiled? best = null;
        var bestScore = -1;
        // Eine Blockliste sperrt, solange keine passende Erlauben-Regel ausdrücklich diese Gegenstelle nennt (Host, Domain,
        // Adresse) oder hohe Priorität hat. Allgemeine Erlauben-Regeln („jeder Server“, „lokales Netz“) überstimmen sie
        // nicht – sonst wäre jeder Browser, dem man „jede Verbindung“ erlaubt hat, von allen Blocklisten ausgenommen.
        var exempt = false;
        foreach (var c in _rules)
        {
            if (!Matches(c, conn, hosts, remoteText, now)) continue;
            // „DNS-Server“ zählt nur als bestimmte Gegenstelle, wenn die Server bekannt sind (sonst passt sie auf jede Adresse).
            if (c.Rule.Action == RuleAction.Allow && (c.Rule.HighPriority
                || (c.Rule.Remote is not (RemoteKind.Any or RemoteKind.LocalNet) && !(c.Rule.Remote == RemoteKind.DnsServers && _dnsServers == null))))
                exempt = true;
            var s = Score(c.Rule, c.Ports);
            if (s > bestScore) { best = c; bestScore = s; }
        }

        if (conn.Direction == Direction.Outgoing && !exempt && best?.Rule.Action != RuleAction.Deny && hosts.Length > 0)
        {
            foreach (var b in _blocklists)
                foreach (var h in hosts)
                    if (ListContains(b.Domains, h)) return new Decision(RuleAction.Deny, null, b);
        }
        return best == null ? default : new Decision(best.Rule.Action, best.Rule, null);
    }

    private static bool ListContains(HashSet<string> set, string host)
    {
        // host selbst und jede übergeordnete Domain (ohne die TLD allein).
        var s = host;
        while (true)
        {
            if (set.Contains(s)) return true;
            var dot = s.IndexOf('.');
            if (dot < 0) return false;
            s = s[(dot + 1)..];
            if (s.IndexOf('.') < 0) return false;
        }
    }
}

/// <summary>Wofür eine Regel aus dem Warnfenster gelten soll.</summary>
public enum AlertScope { AnyConnection, Port, Host, HostAndPort, Domain, DomainAndPort }

/// <summary>Gültigkeitsdauer im Warnfenster, Reihenfolge und Werte wie im Original.</summary>
public enum AlertLifetime { Once, UntilQuit, UntilRestart, Minutes10, Hours2, Day1, Days7, Days30, Forever }

public static class AlertRules
{
    public static string Title(AlertLifetime l) => l switch
    {
        AlertLifetime.Once => Loc.T("Einmal", "Once"),
        AlertLifetime.UntilQuit => Loc.T("Bis zum Beenden", "Until Quit"),
        AlertLifetime.UntilRestart => Loc.T("Bis zum Neustart", "Until Restart"),
        AlertLifetime.Minutes10 => Loc.T("Für 10 Minuten", "For 10 Minutes"),
        AlertLifetime.Hours2 => Loc.T("Für 2 Stunden", "For 2 Hours"),
        AlertLifetime.Day1 => Loc.T("Für 1 Tag", "For 1 Day"),
        AlertLifetime.Days7 => Loc.T("Für 7 Tage", "For 7 Days"),
        AlertLifetime.Days30 => Loc.T("Für 30 Tage", "For 30 Days"),
        _ => Loc.T("Für immer", "Forever"),
    };

    private static readonly HashSet<string> SecondLevel = ["co", "com", "org", "net", "gov", "ac", "edu", "or", "ne"];

    /// <summary>Übergeordnete Domain eines Hostnamens (grobe Näherung an die Public-Suffix-Liste), z. B. cdn.example.co.uk → example.co.uk.</summary>
    public static string DomainOf(string host)
    {
        var parts = host.TrimEnd('.').ToLowerInvariant().Split('.');
        if (parts.Length <= 2) return string.Join('.', parts);
        var take = parts[^1].Length == 2 && SecondLevel.Contains(parts[^2]) ? 3 : 2;
        return string.Join('.', parts[^Math.Min(take, parts.Length)..]);
    }

    /// <summary>Lässt sich die Antwort als Regel merken? Nicht bei unbekanntem Prozess: eine Regel ohne Programm
    /// gälte für jedes Programm.</summary>
    public static bool CanRemember(Connection c) => c.ProcessPath.Length > 0;

    /// <summary>Temp-Ordner (vom Aufrufer gesetzt, unter Windows %TEMP%, %SystemRoot%\Temp …). Dazu zählt jedes …\AppData\Local\Temp\.</summary>
    public static IReadOnlyList<string> TempRoots { get; set; } = [];

    private const string UserTemp = @"\AppData\Local\Temp\";

    /// <summary>Der Temp-Ordner, in dem die Datei liegt (mit „\“ am Ende), sonst null.</summary>
    public static string? TempRootOf(string path)
    {
        foreach (var r in TempRoots)
        {
            if (r.Length == 0) continue;
            var root = r.EndsWith('\\') ? r : r + "\\";
            if (root.Count(ch => ch == '\\') < 2) continue; // nie ein ganzes Laufwerk (falsch gesetztes TEMP=C:\)
            if (path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return path[..root.Length];
        }
        var i = path.IndexOf(UserTemp, StringComparison.OrdinalIgnoreCase);
        return i > 0 ? path[..(i + UserTemp.Length)] : null;
    }

    // Ordnernamen, die sich mit jeder Version ändern: 2.1.325, v1.2, app-1.0.3 (Squirrel), GUIDs, Hash-Ordner (806e0a45e6f5).
    private static readonly Regex VersionDir = new(
        @"^(v?\d+(\.\d+){1,3}([-+][0-9A-Za-z.]+)?|app-\d+(\.\d+)+|\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?|(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{10,})$",
        RegexOptions.CultureInvariant);
    // Store-Pakete: Claude_5.11492.5.0_x64__pzs8sxrjxfjjc → Claude_*_x64__pzs8sxrjxfjjc (Name und Herausgeber bleiben).
    private static readonly Regex PackageDir = new(@"^([^_\\]+)_\d+(\.\d+){1,3}_(.+)$", RegexOptions.CultureInvariant);

    /// <summary>Prozessangabe für eine Regel, die auch für die nächste Kopie oder Version des Programms gilt. Wechselnde Ordnernamen
    /// werden zu „*“: der erste Unterordner eines Temp-Ordners (Installer wie der von Visual Studio kopieren sich bei jedem Start in
    /// einen neuen Zufallsordner, R:\Temp\obkz3fue.blc\…\BackgroundDownload.exe), Versions-, GUID- und Hash-Ordner sowie die
    /// Versionsnummer in Store-Paketen. Mit dem vollen Pfad passte die Regel nach dem nächsten Start oder Update nicht mehr, und jedes
    /// Mal kämen neue Nachfragen und Regeln. Der Rest des Pfads und der Dateiname bleiben genau; wer einen passenden Ordner anlegen
    /// kann, hätte auch die Datei am alten Ort ersetzen können.</summary>
    public static string ProcessPattern(string path)
    {
        if (path.Contains('*') || path.IndexOf('\\') < 0) return path;
        var result = path;
        if (TempRootOf(path) is { } root)
        {
            var rest = path[root.Length..];
            var slash = rest.IndexOf('\\');
            if (slash > 0) result = root + "*" + rest[slash..];
        }
        var parts = result.Split('\\');
        for (var i = 1; i < parts.Length - 1; i++) // ohne Laufwerk und Dateinamen
        {
            if (parts[i].Length == 0 || parts[i] == "*") continue;
            if (VersionDir.IsMatch(parts[i])) parts[i] = "*";
            else if (PackageDir.Match(parts[i]) is { Success: true } m) parts[i] = m.Groups[1].Value + "_*_" + m.Groups[3].Value;
        }
        return string.Join('\\', parts);
    }

    /// <summary>Baut die Regel zur Antwort im Warnfenster; null bei „Einmal“ und bei unbekanntem Prozess
    /// (dann gilt die Antwort nur für diesen Versuch, siehe <see cref="CanRemember"/>).</summary>
    public static Rule? Create(Connection c, bool allow, AlertScope scope, AlertLifetime lifetime, string bootId, string? profile, DateTime now)
    {
        if (lifetime == AlertLifetime.Once || !CanRemember(c)) return null;
        var named = c.Hostnames.Count > 0;
        var r = new Rule
        {
            Action = allow ? RuleAction.Allow : RuleAction.Deny,
            Process = ProcessPattern(c.ProcessPath), Service = c.Service, Direction = c.Direction, Profile = profile, Created = now,
        };
        if (scope is AlertScope.Port or AlertScope.HostAndPort or AlertScope.DomainAndPort)
        {
            r.Ports = c.Port.ToString();
            r.Protocol = c.Protocol;
        }
        switch (scope)
        {
            case AlertScope.Host or AlertScope.HostAndPort:
                r.Remote = named ? RemoteKind.Hosts : RemoteKind.Addresses;
                r.Targets = [named ? c.Hostnames[0].ToLowerInvariant() : c.Remote.ToString()];
                break;
            case AlertScope.Domain or AlertScope.DomainAndPort when named:
                r.Remote = RemoteKind.Domains;
                r.Targets = [DomainOf(c.Hostnames[0])];
                break;
            case AlertScope.Domain or AlertScope.DomainAndPort:
                r.Remote = RemoteKind.Addresses;
                r.Targets = [c.Remote.ToString()];
                break;
        }
        switch (lifetime)
        {
            case AlertLifetime.UntilQuit: r.Lifetime = LifetimeKind.UntilQuit; r.QuitPid = c.Pid; break;
            case AlertLifetime.UntilRestart: r.Lifetime = LifetimeKind.UntilRestart; r.BootId = bootId; break;
            case AlertLifetime.Forever: break;
            default:
                r.Lifetime = LifetimeKind.Timed;
                r.Expires = now + lifetime switch
                {
                    AlertLifetime.Minutes10 => TimeSpan.FromMinutes(10),
                    AlertLifetime.Hours2 => TimeSpan.FromHours(2),
                    AlertLifetime.Day1 => TimeSpan.FromDays(1),
                    AlertLifetime.Days7 => TimeSpan.FromDays(7),
                    _ => TimeSpan.FromDays(30),
                };
                break;
        }
        return r;
    }
}
