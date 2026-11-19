// Kern-Tests für SnitchBox; laufen auf jedem System: dotnet run --project tests/SnitchBox.Tests
using System.Buffers.Binary;
using System.Net;
using SnitchBox.Core;

var failed = 0;
var count = 0;
void Check(bool ok, string what)
{
    count++;
    if (ok) return;
    failed++;
    Console.WriteLine("FEHLER: " + what);
}

Paths.Override = Path.Combine(Path.GetTempPath(), "snitchbox-test-" + Guid.NewGuid().ToString("N")[..8]);
Loc.German = true;

// ---- Adressen und Ports
Check(AddressRange.TryParse("10.0.0.0/8", out var r10) && r10.Contains(IpKey.From(IPAddress.Parse("10.255.1.2"))) && !r10.Contains(IpKey.From(IPAddress.Parse("11.0.0.1"))), "CIDR v4");
Check(AddressRange.TryParse("fe80::/10", out var rll) && rll.Contains(IpKey.From(IPAddress.Parse("fe80::1"))) && !rll.Contains(IpKey.From(IPAddress.Parse("2001:db8::1"))), "CIDR v6");
Check(AddressRange.TryParse("1.2.3.4-1.2.3.9", out var rr) && rr.Contains(IpKey.From(IPAddress.Parse("1.2.3.9"))) && !rr.Contains(IpKey.From(IPAddress.Parse("1.2.3.10"))), "Bereich");
Check(AddressRange.IsLocal(IpKey.From(IPAddress.Parse("192.168.178.133"))) && !AddressRange.IsLocal(IpKey.From(IPAddress.Parse("8.8.8.8"))), "lokales Netz");
Check(IpKey.From(IPAddress.Parse("93.184.216.34")).ToString() == "93.184.216.34", "IpKey v4 Text");
Check(PortSet.TryParse("80, 443, 8000-8100", out var ps) && ps.Contains(443) && ps.Contains(8050) && !ps.Contains(81), "Ports");
Check(PortSet.TryParse("", out var pa) && pa.Any && pa.Contains(1) && !PortSet.TryParse("abc", out _), "Ports leer/ungültig");

// ---- Pakete
byte[] V4(byte proto, string src, string dst, byte[] l4)
{
    var p = new byte[20 + l4.Length];
    p[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length); p[8] = 64; p[9] = proto;
    IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 12); IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 16);
    BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), Packet.Checksum(p.AsSpan(0, 20)));
    l4.CopyTo(p, 20);
    return p;
}
byte[] V6(byte proto, string src, string dst, byte[] l4)
{
    var p = new byte[40 + l4.Length];
    p[0] = 0x60; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), (ushort)l4.Length); p[6] = proto; p[7] = 64;
    IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 8); IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 24);
    l4.CopyTo(p, 40);
    return p;
}
byte[] TcpSyn(ushort sport, ushort dport, uint seq, byte flags = 0x02)
{
    var t = new byte[20];
    BinaryPrimitives.WriteUInt16BigEndian(t, sport); BinaryPrimitives.WriteUInt16BigEndian(t.AsSpan(2), dport);
    BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(4), seq); t[12] = 0x50; t[13] = flags;
    return t;
}
byte[] UdpSeg(ushort sport, ushort dport, byte[] payload)
{
    var u = new byte[8 + payload.Length];
    BinaryPrimitives.WriteUInt16BigEndian(u, sport); BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(2), dport);
    BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(4), (ushort)u.Length);
    payload.CopyTo(u, 8);
    return u;
}

// Bekanntes Beispiel für die IPv4-Kopfprüfsumme (Wikipedia): Ergebnis 0xB861.
var hdr = Convert.FromHexString("45000073000040004011" + "0000" + "c0a80001c0a800c7");
Check(Packet.Checksum(hdr) == 0xB861, "IPv4-Prüfsumme");

var syn = V4(6, "192.168.1.10", "93.184.216.34", TcpSyn(50000, 443, 1000));
Check(Packet.TryParse(syn, out var pi) && pi.Protocol == 6 && pi.Syn && !pi.Ack && pi.SrcPort == 50000 && pi.DstPort == 443 && pi.Dst.ToString() == "93.184.216.34", "TCP-SYN lesen");
var rst = Packet.BuildReset(syn)!;
Check(Packet.TryParse(rst, out var ri) && ri.Src.ToString() == "93.184.216.34" && ri.Dst.ToString() == "192.168.1.10" && ri.SrcPort == 443 && ri.DstPort == 50000 && rst[33] == 0x14, "RST Felder");
Check(BinaryPrimitives.ReadUInt32BigEndian(rst.AsSpan(28)) == 1001, "RST bestätigt SEQ+1");
Check(Packet.Checksum(rst.AsSpan(0, 20)) == 0, "RST IPv4-Prüfsumme stimmt");
Check(Packet.TransportChecksum(rst, false, 20, 6) == 0, "RST TCP-Prüfsumme stimmt");
var syn6 = V6(6, "2001:db8::10", "2606:2800:220:1::1", TcpSyn(50001, 443, 7));
var rst6 = Packet.BuildReset(syn6)!;
Check(Packet.TryParse(rst6, out var r6) && r6.V6 && r6.Src.ToString() == "2606:2800:220:1::1" && r6.DstPort == 50001 && Packet.TransportChecksum(rst6, true, 40, 6) == 0, "RST IPv6");
// IPv6 mit Erweiterungskopf (Destination Options, 8 Byte) vor TCP
var ext = new byte[8 + 20]; ext[0] = 6; ext[1] = 0; TcpSyn(1234, 80, 1).CopyTo(ext, 8);
Check(Packet.TryParse(V6(60, "2001:db8::1", "2001:db8::2", ext), out var pe) && pe.Protocol == 6 && pe.DstPort == 80, "IPv6-Erweiterungskopf");
Check(!Packet.TryParse(new byte[10], out _), "zu kurzes Paket");

// Vermessung für die Datenmengen (auch mehrere Pakete hintereinander wie im Stapel des Treibers)
var m1 = V4(6, "192.168.1.10", "93.184.216.34", TcpSyn(50000, 443, 1));
var m2 = V6(17, "2001:db8::1", "2001:db8::2", UdpSeg(40000, 3478, new byte[100]));
var batch = m1.Concat(m2).Concat(new byte[] { 0x45 }).ToArray();
var l1 = Packet.Measure(batch, out var mt, out var mc, out var msp, out var mdp);
Check(l1 == 40 && mt && mc && msp == 50000 && mdp == 443, "Paket vermessen v4/TCP");
var l2 = Packet.Measure(batch.AsSpan(l1), out mt, out mc, out msp, out mdp);
Check(l2 == 148 && !mt && mc && msp == 40000 && mdp == 3478, "Paket vermessen v6/UDP");
Check(Packet.Measure(batch.AsSpan(l1 + l2), out _, out _, out _, out _) == 0, "Stapelrest ungültig");
Check(Packet.Measure(V4(1, "1.1.1.1", "2.2.2.2", new byte[8]), out _, out mc, out _, out _) == 28 && !mc, "ICMP wird nicht gezählt");
var ts = new TrafficStats();
ts.Commit([(@"C:\a.exe", 1000, 200), (@"C:\A.EXE", 500, 0), (@"C:\b.exe", 0, 0)], 0.5);
var tr = ts.Snapshot();
Check(tr.Count == 1 && tr[0].Down == 1500 && tr[0].Up == 200 && tr[0].RateDown == 3000 && tr[0].RateUp == 400, "Datenmengen je Programm");
ts.Commit([(@"C:\b.exe", 10, 20)], 1);
tr = ts.Snapshot();
Check(tr.Count == 2 && tr.Single(t => t.ProcessPath.EndsWith("a.exe")) is { Down: 1500, RateDown: 0 } && tr.Single(t => t.ProcessPath.EndsWith("b.exe")).RateUp == 20, "Raten fallen auf 0, Summen bleiben");

// ---- DNS
byte[] Name(string n) { var l = new List<byte>(); foreach (var part in n.Split('.')) { l.Add((byte)part.Length); l.AddRange(System.Text.Encoding.ASCII.GetBytes(part)); } l.Add(0); return l.ToArray(); }
byte[] DnsAnswer(string q, params (ushort Type, byte[] Data)[] answers)
{
    var m = new List<byte> { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, (byte)answers.Length, 0, 0, 0, 0 };
    m.AddRange(Name(q)); m.AddRange([0, 1, 0, 1]);
    foreach (var (type, data) in answers)
    {
        m.AddRange([0xC0, 0x0C, (byte)(type >> 8), (byte)type, 0, 1, 0, 0, 0, 60, (byte)(data.Length >> 8), (byte)data.Length]);
        m.AddRange(data);
    }
    return m.ToArray();
}
byte[] DnsQuery(string q)
{
    var m = new List<byte> { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
    m.AddRange(Name(q)); m.AddRange([0, 1, 0, 1]);
    return m.ToArray();
}
var dns = DnsAnswer("www.Example.com", (5, Name("cdn.example.net")), (1, [93, 184, 216, 34]), (28, IPAddress.Parse("2606:2800:220:1::1").GetAddressBytes()));
var addrs = new List<IpKey>();
Check(DnsReader.TryParseResponse(dns, out var qn, addrs) && qn == "www.example.com" && addrs.Count == 2 && addrs[0].ToString() == "93.184.216.34", "DNS-Antwort lesen");
Check(!DnsReader.TryParseResponse(dns.AsSpan(0, 20), out _, []), "abgeschnittene DNS-Antwort");
var loop = new byte[] { 0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1 };
Check(!DnsReader.TryParseResponse(loop, out _, []), "DNS-Zeigerschleife");

// ---- Regeln
Check(AlertRules.DomainOf("a.b.example.co.uk") == "example.co.uk" && AlertRules.DomainOf("cdn.example.com") == "example.com" && AlertRules.DomainOf("example.com") == "example.com", "Domain ableiten");
Check(RuleSet.DomainMatches("a.example.com", "example.com") && RuleSet.DomainMatches("example.com", "example.com") && !RuleSet.DomainMatches("badexample.com", "example.com"), "Domain-Vergleich");

const string Chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
Connection Conn(string path, string ip, ushort port, string? host = null, Proto proto = Proto.Tcp, Direction dir = Direction.Outgoing, int pid = 100) => new()
{
    ProcessPath = path, Pid = pid, Direction = dir, Protocol = proto, Remote = IpKey.From(IPAddress.Parse(ip)), Port = port, Hostnames = host == null ? [] : [host],
};
var now = new DateTime(2026, 11, 14, 12, 0, 0);
var store = new Store();
store.Rules.Add(new Rule { Action = RuleAction.Allow, Process = Chrome });
store.Rules.Add(new Rule { Action = RuleAction.Deny, Process = Chrome, Remote = RemoteKind.Domains, Targets = ["doubleclick.net"] });
store.Rules.Add(new Rule { Action = RuleAction.Allow, Process = Chrome, Remote = RemoteKind.Hosts, Targets = ["ok.doubleclick.net"] });
store.Rules.Add(new Rule { Action = RuleAction.Deny, Process = "", Remote = RemoteKind.Addresses, Targets = ["203.0.113.0/24"] });
store.Rules.Add(new Rule { Action = RuleAction.Allow, Process = "curl.exe", Ports = "443", Protocol = Proto.Tcp });
store.Rules.Add(new Rule { Action = RuleAction.Deny, Process = "curl.exe", Ports = "443", Protocol = Proto.Tcp, Enabled = false });
store.Rules.Add(new Rule { Action = RuleAction.Allow, Process = "", Remote = RemoteKind.LocalNet, Lifetime = LifetimeKind.Timed, Expires = now.AddMinutes(5) });
var rs = RuleSet.Build(store, "boot1");
Check(rs.Evaluate(Conn(Chrome, "1.1.1.1", 443, "www.heise.de"), now).Action == RuleAction.Allow, "App-Regel erlaubt");
Check(rs.Evaluate(Conn(Chrome, "1.1.1.2", 443, "ad.doubleclick.net"), now).Action == RuleAction.Deny, "Domain-Regel schlägt allgemeine Regel");
Check(rs.Evaluate(Conn(Chrome, "1.1.1.3", 443, "ok.doubleclick.net"), now).Action == RuleAction.Allow, "Host-Regel schlägt Domain-Regel");
Check(rs.Evaluate(Conn(Chrome, "203.0.113.7", 443), now).Action == RuleAction.Allow, "Prozess-Regel schlägt Regel für jeden Prozess");
Check(rs.Evaluate(Conn(@"C:\x\other.exe", "203.0.113.7", 443), now).Action == RuleAction.Deny, "Adressbereich für jeden Prozess");
Check(rs.Evaluate(Conn(@"C:\x\other.exe", "8.8.8.8", 443), now).Action == null, "keine Regel");
Check(rs.Evaluate(Conn(@"C:\Tools\CURL.EXE", "8.8.8.8", 443), now).Action == RuleAction.Allow, "Prozess nur als Dateiname, Großschreibung egal");
Check(rs.Evaluate(Conn(@"C:\Tools\curl.exe", "8.8.8.8", 80), now).Action == null, "Port passt nicht");
Check(rs.Evaluate(Conn(@"C:\x\other.exe", "192.168.1.5", 80), now).Action == RuleAction.Allow, "zeitlich begrenzte Regel gilt");
Check(rs.Evaluate(Conn(@"C:\x\other.exe", "192.168.1.5", 80), now.AddMinutes(6)).Action == null, "zeitlich begrenzte Regel abgelaufen");
// Gleichstand: Verbieten gewinnt; hohe Priorität schlägt alles
var s2 = new Store();
s2.Rules.Add(new Rule { Action = RuleAction.Allow, Process = Chrome });
s2.Rules.Add(new Rule { Action = RuleAction.Deny, Process = Chrome });
Check(RuleSet.Build(s2, "b").Evaluate(Conn(Chrome, "1.1.1.1", 1), now).Action == RuleAction.Deny, "Gleichstand: Verbieten gewinnt");
s2.Rules.Add(new Rule { Action = RuleAction.Allow, Process = "", HighPriority = true });
Check(RuleSet.Build(s2, "b").Evaluate(Conn(Chrome, "1.1.1.1", 1), now).Action == RuleAction.Allow, "hohe Priorität");
// Profile und Neustart
var s3 = new Store();
s3.Rules.Add(new Rule { Action = RuleAction.Deny, Process = Chrome, Profile = "Unterwegs" });
s3.Rules.Add(new Rule { Action = RuleAction.Allow, Process = "x.exe", Lifetime = LifetimeKind.UntilRestart, BootId = "alt" });
Check(RuleSet.Build(s3, "neu").Evaluate(Conn(Chrome, "1.1.1.1", 1), now).Action == null, "Profilregel inaktiv");
s3.Settings.ActiveProfile = "Unterwegs";
Check(RuleSet.Build(s3, "neu").Evaluate(Conn(Chrome, "1.1.1.1", 1), now).Action == RuleAction.Deny, "Profilregel aktiv");
Check(RuleSet.Build(s3, "neu").Evaluate(Conn(@"C:\x.exe", "1.1.1.1", 1), now).Action == null && RuleSet.Build(s3, "alt").Evaluate(Conn(@"C:\x.exe", "1.1.1.1", 1), now).Action == RuleAction.Allow, "Regel bis Neustart");
// Blocklisten
var s4 = new Store();
s4.Blocklists.Add(new Blocklist { Name = "Test", Domains = ["tracker.example", "ads.example.org"] });
var rs4 = RuleSet.Build(s4, "b");
Check(rs4.Evaluate(Conn(Chrome, "5.5.5.5", 443, "x.tracker.example"), now) is { Action: RuleAction.Deny, Blocklist.Name: "Test" }, "Blockliste sperrt Subdomain");
Check(rs4.Evaluate(Conn(Chrome, "5.5.5.5", 443, "example.org"), now).Action == null, "Blockliste: übergeordnete Domain frei");
s4.Rules.Add(new Rule { Action = RuleAction.Allow, Process = Chrome, Remote = RemoteKind.Hosts, Targets = ["x.tracker.example"] });
Check(RuleSet.Build(s4, "b").Evaluate(Conn(Chrome, "5.5.5.5", 443, "x.tracker.example"), now).Action == RuleAction.Allow, "eigene Host-Regel schlägt Blockliste");

// Regel aus dem Warnfenster
var ac = Conn(Chrome, "93.184.216.34", 443, "www.example.com", pid: 4711);
var ar = AlertRules.Create(ac, true, AlertScope.DomainAndPort, AlertLifetime.Hours2, "b", null, now)!;
Check(ar.Remote == RemoteKind.Domains && ar.Targets[0] == "example.com" && ar.Ports == "443" && ar.Protocol == Proto.Tcp && ar.Expires == now.AddHours(2), "Warnfenster: Domain+Port, 2 Stunden");
Check(AlertRules.Create(ac, false, AlertScope.AnyConnection, AlertLifetime.Once, "b", null, now) == null, "Warnfenster: Einmal ohne Regel");
var aq = AlertRules.Create(ac, false, AlertScope.Host, AlertLifetime.UntilQuit, "b", null, now)!;
Check(aq.Lifetime == LifetimeKind.UntilQuit && aq.QuitPid == 4711 && aq.Remote == RemoteKind.Hosts, "Warnfenster: bis zum Beenden");
Check(AlertRules.Create(Conn(Chrome, "9.9.9.9", 53), true, AlertScope.Domain, AlertLifetime.Forever, "b", null, now)!.Remote == RemoteKind.Addresses, "Warnfenster: ohne Namen wird die Adresse genommen");
Check(ar.Describe().Contains("Domain example.com") && ar.Describe().Contains("Port 443"), "Regelbeschreibung");

// ---- .lsrules und Blocklisten-Formate
var ls = LsRules.Parse("""
{ "name": "Demo", "description": "x", "denied-remote-domains": ["Ads.Example.com", "t.co"],
  "rules": [
    { "action": "deny", "process": "any", "remote-domains": ["facebook.com", "fbcdn.net"], "notes": "n" },
    { "action": "allow", "process": "C:\\Tools\\curl.exe", "remote-hosts": "example.com", "ports": "443", "protocol": "tcp", "priority": "high" },
    { "action": "allow", "process": "any", "remote": "local-net", "direction": "incoming", "disabled": true },
    { "action": "ask", "process": "any", "remote": "any" },
    { "action": "deny", "process": "any", "remote-addresses": "10.0.0.0/8, 1.2.3.4" }
  ] }
""");
Check(ls.Name == "Demo" && ls.Denied.Contains("ads.example.com") && ls.Denied.Contains("t.co") && ls.Rules.Count == 4, "lsrules lesen");
Check(ls.Rules[0].AnyProcess && ls.Rules[0].Remote == RemoteKind.Domains && ls.Rules[0].Targets.Count == 2 && ls.Rules[1].HighPriority && ls.Rules[1].Ports == "443" && ls.Rules[1].Protocol == Proto.Tcp, "lsrules Felder");
Check(ls.Rules[2].Direction == Direction.Incoming && !ls.Rules[2].Enabled && ls.Rules[2].Remote == RemoteKind.LocalNet && ls.Rules[3].Targets.Count == 2, "lsrules Richtung/abgeschaltet/Adressen");
var back = LsRules.Parse(LsRules.Export("Export", ls.Rules));
Check(back.Rules.Count == 4 && back.Rules[1].Process == @"C:\Tools\curl.exe" && back.Rules[3].Targets.Count == 2 && back.Name == "Export", "lsrules schreiben und wieder lesen");
var hosts = LsRules.Parse("# Kommentar\n0.0.0.0 ads.one.example\n127.0.0.1 localhost\n||adblock.example^\nplain.example.net # x\n! adblock-Kommentar\n0.0.0.0 0.0.0.0\n");
Check(hosts.Denied.SetEquals(["ads.one.example", "adblock.example", "plain.example.net"]), "Textlisten lesen: " + string.Join(",", hosts.Denied));

// ---- Engine
var procs = new FakeProcs();
var es = new Store();
FactoryRules.Ensure(es, @"C:\Windows");
Check(es.Rules.Count >= 6 && es.Rules.All(r => r.Factory) && es.Settings.FactoryRulesCreated, "Werksregeln");
var clock = now;
var injected = new List<(byte[] P, PacketMeta M)>();
var eng = new FirewallEngine(es, procs, "boot", () => clock) { SelfPath = @"C:\SnitchBox.exe", Injector = (p, m) => injected.Add((p, m)) };
var alertEvents = 0;
eng.AlertsChanged += () => alertEvents++;
var outMeta = new PacketMeta(true, false, 7, 0);
var inMeta = new PacketMeta(false, false, 7, 0);

// DNS-Antwort merken (nur als Antwort auf eine beobachtete Anfrage), Verbindung danach zeigt den Namen
var dnsPkt = V4(17, "192.168.1.1", "192.168.1.10", UdpSeg(53, 55555, DnsAnswer("www.example.com", (1, [93, 184, 216, 34]))));
Check(eng.Process(dnsPkt, inMeta, out _) == Verdict.Pass && eng.Hosts.Lookup(IpKey.From(IPAddress.Parse("93.184.216.34"))).Count == 0, "unverlangte DNS-Antwort liefert keinen Namen");
Check(eng.Process(V4(17, "192.168.1.10", "192.168.1.1", UdpSeg(55555, 53, DnsQuery("www.example.com"))), outMeta, out _) == Verdict.Pass, "DNS-Anfrage geht durch (Werksregel)");
Check(eng.Process(dnsPkt, inMeta, out _) == Verdict.Pass && eng.Hosts.Lookup(IpKey.From(IPAddress.Parse("93.184.216.34"))).FirstOrDefault() == "www.example.com", "DNS-Antwort wird gemerkt");

procs.Ports[(true, 50000)] = new ProcessInfo(100, Chrome);
Check(eng.Process(syn, outMeta, out _) == Verdict.Hold && eng.Alerts.Count == 1 && alertEvents == 1, "unbekannte Verbindung wird gehalten und nachgefragt");
var alert = eng.Alerts[0];
Check(alert.Connection.Host == "www.example.com" && alert.Connection.ProcessName == "chrome.exe" && alert.Connection.Port == 443, "Nachfrage nennt Namen, Prozess, Port");
Check(eng.Process(syn, outMeta, out _) == Verdict.Hold && eng.Alerts.Count == 1, "wiederholtes SYN erzeugt keine zweite Nachfrage");
// zweiter Versuch von anderem lokalen Port hängt sich an
procs.Ports[(true, 50002)] = new ProcessInfo(100, Chrome);
var synB = V4(6, "192.168.1.10", "93.184.216.34", TcpSyn(50002, 443, 5));
Check(eng.Process(synB, outMeta, out _) == Verdict.Hold && eng.Alerts.Count == 1, "zweiter Versuch hängt sich an dieselbe Nachfrage");
var rule = AlertRules.Create(alert.Connection, true, AlertScope.Domain, AlertLifetime.Forever, eng.BootId, null, clock);
eng.Resolve(alert.Id, true, rule);
Check(eng.Alerts.Count == 0 && injected.Count == 2 && injected.All(i => i.M.Outbound), "Erlauben speist die gehaltenen SYNs ein");
Check(eng.Process(syn, outMeta, out _) == Verdict.Pass, "danach geht die Verbindung durch");
Check(es.Rules.Any(r => r.Remote == RemoteKind.Domains && r.Targets[0] == "example.com"), "Regel gespeichert");
Check(eng.History.Snapshot().Any(c => c.Host == "www.example.com" && c.Allowed == true), "Verlauf");

// Verbieten: RST an den Absender
procs.Ports[(true, 50010)] = new ProcessInfo(200, @"C:\Apps\spy.exe");
var synC = V4(6, "192.168.1.10", "198.51.100.9", TcpSyn(50010, 80, 42));
injected.Clear();
Check(eng.Process(synC, outMeta, out _) == Verdict.Hold, "spy.exe wird gehalten");
eng.Resolve(eng.Alerts[0].Id, false, null);
Check(injected.Count == 1 && !injected[0].M.Outbound && injected[0].P[33] == 0x14, "Verbieten (einmal) stellt ein RST zu");
Check(eng.Process(synC, outMeta, out var reply) == Verdict.Reject && reply != null, "Wiederholung wird sofort abgelehnt");
clock = clock.AddSeconds(40);
Check(eng.Process(synC, outMeta, out _) == Verdict.Hold, "nach Ablauf der einmaligen Entscheidung wird neu gefragt");
eng.Mutate(s => s.Rules.Add(new Rule { Action = RuleAction.Deny, Process = @"C:\Apps\spy.exe" }));
Check(eng.Alerts.Count == 0, "neue Regel erledigt offene Nachfrage");

// Netzwerkmonitor folgt Regeländerungen sofort (nicht erst beim nächsten Versuch des Programms)
ConnectionRecord SpyRow() => eng.History.Snapshot().Single(c => c.ProcessPath == @"C:\Apps\spy.exe" && c.Port == 80);
Check(SpyRow().Allowed == false && !SpyRow().Pending, "Monitor: verboten per Regel");
(RuleSet Before, RuleSet After)? applied = null;
eng.RulesApplied = (b, a) => applied = (b, a);
var spyAllow = new Rule { Action = RuleAction.Allow, Process = @"C:\Apps\spy.exe", Remote = RemoteKind.Addresses, Targets = ["198.51.100.9"] };
eng.Mutate(s => s.Rules.Add(spyAllow));
Check(SpyRow().Allowed == true && SpyRow().Reason == spyAllow.Describe(), "Monitor zeigt nach neuer Erlauben-Regel sofort „erlaubt“");
Check(applied is { } ap && ap.Before.Evaluate(SpyRow().Template, clock).Action == RuleAction.Deny && ap.After.Evaluate(SpyRow().Template, clock).Action == RuleAction.Allow,
    "RulesApplied meldet die Regeln davor und danach");
eng.Mutate(s => s.Rules.RemoveAll(r => r.Process == @"C:\Apps\spy.exe"));
Check(SpyRow().Allowed == null && !SpyRow().Pending, "ohne passende Regel: „Ohne Regel“ statt „Fragt“");
applied = null;
eng.Mutate(s => s.Settings.FilterEnabled = false);
Check(applied == null, "bei abgeschaltetem Filter kein RulesApplied");
eng.Mutate(s => s.Settings.FilterEnabled = true);
eng.RulesApplied = null;
var scopeA = new Rule { Process = @"C:\A\x.exe", Remote = RemoteKind.Hosts, Targets = ["A.example.com."], Ports = "443, 80" };
var scopeB = new Rule { Action = RuleAction.Deny, Process = @"c:\a\X.exe", Remote = RemoteKind.Hosts, Targets = ["a.example.com"], Ports = "80,443", HighPriority = true };
Check(scopeA.SameScope(scopeB), "gleicher Geltungsbereich trotz anderer Schreibweise und Aktion");
Check(!scopeA.SameScope(new Rule { Process = @"C:\A\x.exe", Remote = RemoteKind.Hosts, Targets = ["a.example.com"], Ports = "443" })
      && !scopeA.SameScope(new Rule { Process = @"C:\A\x.exe", Remote = RemoteKind.Domains, Targets = ["a.example.com"], Ports = "80,443" })
      && !scopeA.SameScope(new Rule { Process = @"C:\A\x.exe", Remote = RemoteKind.Hosts, Targets = ["a.example.com"], Ports = "80,443", Profile = "Büro" }),
    "anderer Port, andere Gegenstellenart oder anderes Profil ist ein anderer Geltungsbereich");

// Stiller Modus und Filter aus
eng.Mutate(s => s.Settings.Mode = OperationMode.SilentDeny);
procs.Ports[(false, 40000)] = new ProcessInfo(300, @"C:\Apps\game.exe");
var udp = V4(17, "192.168.1.10", "203.0.113.50", UdpSeg(40000, 3478, [1, 2, 3]));
Check(eng.Process(udp, outMeta, out _) == Verdict.Drop, "stiller Modus: verbieten");
eng.Mutate(s => s.Settings.Mode = OperationMode.SilentAllow);
Check(eng.Process(udp, outMeta, out _) == Verdict.Pass, "stiller Modus: erlauben");
eng.Mutate(s => { s.Settings.Mode = OperationMode.Alert; });
Check(eng.Process(udp, outMeta, out _) == Verdict.Hold && eng.Process(udp, outMeta, out _) == Verdict.Hold, "UDP wird gehalten");
injected.Clear();
eng.Mutate(s => s.Settings.FilterEnabled = false);
Check(eng.Alerts.Count == 0 && injected.Count == 2 && eng.Process(udp, outMeta, out _) == Verdict.Pass, "Filter aus gibt alles frei");
eng.Mutate(s => s.Settings.FilterEnabled = true);

// Werksregeln: DNS und svchost, eigener Prozess, eingehend
procs.Ports[(false, 41000)] = new ProcessInfo(301, @"C:\Apps\game.exe");
Check(eng.Process(V4(17, "192.168.1.10", "9.9.9.9", UdpSeg(41000, 53, [0])), outMeta, out _) == Verdict.Pass, "Werksregel DNS");
procs.Ports[(true, 50020)] = new ProcessInfo(400, @"C:\Windows\System32\svchost.exe");
Check(eng.Process(V4(6, "192.168.1.10", "20.1.2.3", TcpSyn(50020, 443, 1)), outMeta, out _) == Verdict.Pass, "Werksregel svchost");
procs.Ports[(true, 50021)] = new ProcessInfo(401, @"C:\Temp\svchost.exe");
Check(eng.Process(V4(6, "192.168.1.10", "20.1.2.3", TcpSyn(50021, 443, 1)), outMeta, out _) == Verdict.Hold, "falsches svchost an anderem Ort wird nicht durchgewinkt");
procs.Ports[(true, 50030)] = new ProcessInfo(1, @"C:\SnitchBox.exe");
Check(eng.Process(V4(6, "192.168.1.10", "20.1.2.3", TcpSyn(50030, 443, 1)), outMeta, out _) == Verdict.Pass, "eigener Prozess");
procs.Ports[(true, 445)] = new ProcessInfo(4, "System");
Check(eng.Process(V4(6, "192.168.1.77", "192.168.1.10", TcpSyn(60000, 445, 1)), inMeta, out _) == Verdict.Pass, "eingehend aus dem lokalen Netz (Werksregel)");
Check(eng.Process(V4(6, "8.8.4.4", "192.168.1.10", TcpSyn(60000, 445, 1)), inMeta, out _) == Verdict.Hold, "eingehend aus dem Internet wird nachgefragt");
eng.Resolve(eng.Alerts.First(a => a.Connection.Direction == Direction.Incoming).Id, false, null);
Check(eng.Process(V4(6, "8.8.4.4", "192.168.1.10", TcpSyn(60000, 445, 1)), inMeta, out var inReply) == Verdict.Drop && inReply == null, "eingehend verboten: still verwerfen");
Check(eng.Process(V4(6, "192.168.1.10", "20.1.2.3", TcpSyn(50021, 443, 1, 0x10)), outMeta, out _) == Verdict.Pass, "TCP ohne SYN läuft durch");

// Regel „bis zum Beenden“ verschwindet mit dem Prozess
eng.ReleaseAll();
procs.Ports[(true, 50040)] = new ProcessInfo(500, @"C:\Apps\tool.exe");
procs.Alive.Add(500);
var synT = V4(6, "192.168.1.10", "198.51.100.77", TcpSyn(50040, 443, 9));
Check(eng.Process(synT, outMeta, out _) == Verdict.Hold, "tool.exe fragt");
var ta = eng.Alerts.Single();
eng.Resolve(ta.Id, true, AlertRules.Create(ta.Connection, true, AlertScope.AnyConnection, AlertLifetime.UntilQuit, eng.BootId, null, clock));
Check(eng.Process(synT, outMeta, out _) == Verdict.Pass, "bis zum Beenden: erlaubt");
procs.Alive.Remove(500);
clock = clock.AddSeconds(60);
procs.Ports[(true, 50041)] = new ProcessInfo(501, @"C:\Apps\tool.exe");
Check(eng.Process(V4(6, "192.168.1.10", "198.51.100.77", TcpSyn(50041, 443, 9)), outMeta, out _) == Verdict.Hold, "nach dem Beenden wird neu gefragt");
Check(!es.Rules.Any(r => r.Lifetime == LifetimeKind.UntilQuit), "abgelaufene Regel entfernt");

// Speichern und Laden
es.Blocklists.Add(new Blocklist { Name = "L", Url = "https://example.invalid/l", Domains = ["a.example", "b.example"], Count = 2 });
es.SaveBlocklist(es.Blocklists[0]);
es.Save();
var loaded = Store.Load();
Check(loaded.Rules.Count == es.Rules.Count && loaded.Blocklists.Single().Domains.Count == 2 && loaded.Settings.FactoryRulesCreated, "Speichern und Laden");

// ---- Korrekturen aus dem Review (1.0.1, Build 13)
FirewallEngine NewEngine(FakeProcs p)
{
    var st = new Store();
    FactoryRules.Ensure(st, @"C:\Windows");
    return new FirewallEngine(st, p, "boot", () => now) { Injector = (_, _) => { } };
}

// Unbekannter Prozess: nie eine Regel (sie gälte für jedes Programm)
var unknown = Conn("", "198.51.100.9", 443, "x.example", pid: 0);
Check(!AlertRules.CanRemember(unknown)
      && Enum.GetValues<AlertLifetime>().All(l => Enum.GetValues<AlertScope>().All(sc => AlertRules.Create(unknown, true, sc, l, "b", null, now) == null)),
    "unbekannter Prozess: keine Regel");
{
    var p = new FakeProcs();
    var e = NewEngine(p);
    e.Process(V4(6, "192.168.1.10", "198.51.100.9", TcpSyn(50200, 443, 1)), outMeta, out _);
    var a = e.Alerts.Single();
    e.Resolve(a.Id, true, AlertRules.Create(a.Connection, true, AlertScope.AnyConnection, AlertLifetime.Forever, "boot", null, now));
    p.Ports[(true, 50201)] = new ProcessInfo(666, @"C:\Temp\malware.exe");
    Check(e.Process(V4(6, "192.168.1.10", "203.0.113.66", TcpSyn(50201, 8443, 1)), outMeta, out _) == Verdict.Hold, "Erlauben für unbekannten Prozess öffnet nicht alles");
}

// Mehr als 64 wartende Verbindungen einer Nachfrage: alle bekommen die Antwort
{
    var p = new FakeProcs();
    var e = NewEngine(p);
    for (ushort port = 51100; port < 51170; port++)
    {
        p.Ports[(true, port)] = new ProcessInfo(100, Chrome);
        e.Process(V4(6, "192.168.1.10", "93.184.216.34", TcpSyn(port, 443, 1)), outMeta, out _);
    }
    var a = e.Alerts.Single();
    e.Resolve(a.Id, true, null);
    Check(e.Process(V4(6, "192.168.1.10", "93.184.216.34", TcpSyn(51169, 443, 1)), outMeta, out _) == Verdict.Pass
          && e.Process(V4(6, "192.168.1.10", "93.184.216.34", TcpSyn(51100, 443, 1)), outMeta, out _) == Verdict.Pass, "über 64 wartende Verbindungen: alle freigegeben");
}

// Eingehend ohne lauschendes Programm (Portscan): keine Nachfrage
{
    var e = NewEngine(new FakeProcs());
    var verdicts = Enumerable.Range(1, 50).Select(i => e.Process(V4(6, "192.168.1.66", "192.168.1.10", TcpSyn(40000, (ushort)i, 1)), inMeta, out _)).ToList();
    Check(verdicts.All(v => v == Verdict.Pass) && e.Alerts.Count == 0, "Portscan: keine Nachfragen");
}

// DNS: nur Antworten der DNS-Server des Systems auf beobachtete Anfragen; Werksregel nur zu diesen Servern
{
    var p = new FakeProcs();
    var e = NewEngine(p);
    e.SetDnsServers([IpKey.From(IPAddress.Parse("192.168.1.1"))]);
    var six = IpKey.From(IPAddress.Parse("6.6.6.6"));
    var fake = DnsAnswer("update.microsoft.com", (1, [6, 6, 6, 6]));
    e.Process(V4(17, "6.6.6.6", "192.168.1.10", UdpSeg(53, 60000, fake)), inMeta, out _);
    Check(e.Hosts.Lookup(six).Count == 0, "DNS: unverlangte Antwort ignoriert");
    e.Process(V4(17, "192.168.1.10", "6.6.6.6", UdpSeg(60000, 53, DnsQuery("update.microsoft.com"))), outMeta, out _);
    e.Process(V4(17, "6.6.6.6", "192.168.1.10", UdpSeg(53, 60000, fake)), inMeta, out _);
    Check(e.Hosts.Lookup(six).Count == 0, "DNS: Antwort eines fremden DNS-Servers ignoriert");
    e.Process(V4(17, "192.168.1.10", "192.168.1.1", UdpSeg(60001, 53, DnsQuery("www.example.com"))), outMeta, out _);
    e.Process(V4(17, "192.168.1.1", "192.168.1.10", UdpSeg(53, 60002, DnsAnswer("www.example.com", (1, [93, 184, 216, 34])))), inMeta, out _);
    Check(e.Hosts.Lookup(IpKey.From(IPAddress.Parse("93.184.216.34"))).Count == 0, "DNS: Antwort an falschen Port ignoriert");
    e.Process(V4(17, "192.168.1.1", "192.168.1.10", UdpSeg(53, 60001, DnsAnswer("www.example.com", (1, [93, 184, 216, 34])))), inMeta, out _);
    Check(e.Hosts.Lookup(IpKey.From(IPAddress.Parse("93.184.216.34"))).FirstOrDefault() == "www.example.com", "DNS: Antwort des System-DNS-Servers zählt");
    p.Ports[(true, 50300)] = new ProcessInfo(667, @"C:\Users\x\Downloads\tool.exe");
    Check(e.Process(V4(6, "192.168.1.10", "203.0.113.99", TcpSyn(50300, 53, 1)), outMeta, out _) == Verdict.Hold, "DNS-Werksregel: fremder Server wird nachgefragt");
    p.Ports[(false, 50301)] = new ProcessInfo(667, @"C:\Users\x\Downloads\tool.exe");
    Check(e.Process(V4(17, "192.168.1.10", "192.168.1.1", UdpSeg(50301, 53, DnsQuery("a.example"))), outMeta, out _) == Verdict.Pass, "DNS-Werksregel: System-DNS-Server erlaubt");

    // Lokaler Resolver (127.0.0.1 eingetragen): die Werksregel erlaubt nichts nach draußen; der Resolver braucht eine
    // eigene Regel, und nur Antworten auf erlaubte Anfragen zählen (sonst könnte jedes Programm Namen fälschen).
    const string Resolver = @"C:\Tools\dnscrypt\dnscrypt-proxy.exe";
    var rp = new FakeProcs();
    var r = NewEngine(rp);
    r.SetDnsServers([IpKey.From(IPAddress.Loopback)]);
    rp.Ports[(false, 60009)] = new ProcessInfo(900, @"C:\Temp\evil.exe");
    Check(r.Process(V4(17, "192.168.1.10", "6.6.6.6", UdpSeg(60009, 53, DnsQuery("update.microsoft.com"))), outMeta, out _) == Verdict.Hold, "lokaler Resolver: Werksregel öffnet Port 53 nicht nach draußen");
    r.Process(V4(17, "6.6.6.6", "192.168.1.10", UdpSeg(53, 60009, DnsAnswer("update.microsoft.com", (1, [6, 6, 6, 6])))), inMeta, out _);
    Check(r.Hosts.Lookup(six).Count == 0, "lokaler Resolver: Antwort auf angehaltene Anfrage zählt nicht");
    r.Mutate(s => s.Rules.Add(new Rule { Action = RuleAction.Allow, Process = Resolver, Remote = RemoteKind.Any, Ports = "53" }));
    rp.Ports[(false, 60010)] = new ProcessInfo(901, Resolver);
    r.Process(V4(17, "192.168.1.10", "9.9.9.9", UdpSeg(60010, 53, DnsQuery("www.example.org"))), outMeta, out _);
    r.Process(V4(17, "9.9.9.9", "192.168.1.10", UdpSeg(53, 60010, DnsAnswer("www.example.org", (1, [93, 184, 216, 35])))), inMeta, out _);
    Check(r.Hosts.Lookup(IpKey.From(IPAddress.Parse("93.184.216.35"))).FirstOrDefault() == "www.example.org", "lokaler Resolver: erlaubte Anfrage liefert Namen");

    // Resolver unter der eigenen LAN-Adresse gilt ebenfalls als lokal
    var lan = NewEngine(new FakeProcs());
    lan.SetDnsServers([IpKey.From(IPAddress.Parse("192.168.1.10"))], [IpKey.From(IPAddress.Parse("192.168.1.10"))]);
    lan.Mutate(s => s.Rules.Add(new Rule { Action = RuleAction.Allow, Process = "", Remote = RemoteKind.Addresses, Targets = ["1.1.1.1"] }));
    lan.Process(V4(17, "192.168.1.10", "1.1.1.1", UdpSeg(60011, 53, DnsQuery("www.example.net"))), outMeta, out _);
    lan.Process(V4(17, "1.1.1.1", "192.168.1.10", UdpSeg(53, 60011, DnsAnswer("www.example.net", (1, [93, 184, 216, 36])))), inMeta, out _);
    Check(lan.Hosts.Lookup(IpKey.From(IPAddress.Parse("93.184.216.36"))).FirstOrDefault() == "www.example.net", "Resolver unter eigener Adresse");

    // Leere Liste (Netzwechsel) behält den letzten bekannten Stand
    e.SetDnsServers([]);
    Check(e.Process(V4(6, "192.168.1.10", "203.0.113.98", TcpSyn(50302, 53, 1)), outMeta, out _) == Verdict.Hold
          && e.Process(V4(17, "192.168.1.10", "192.168.1.1", UdpSeg(50303, 53, DnsQuery("b.example"))), outMeta, out _) == Verdict.Pass, "leere DNS-Liste öffnet nichts");

    // Flut von Anfragen verdrängt nur die ältesten, nicht die neue echte Anfrage
    for (var i = 0; i < 5000; i++)
        e.Process(V4(17, "192.168.1.10", "192.168.1.1", UdpSeg((ushort)(10000 + i), 53, DnsQuery("flood" + i + ".example"))), outMeta, out _);
    e.Process(V4(17, "192.168.1.10", "192.168.1.1", UdpSeg(60020, 53, DnsQuery("real.example"))), outMeta, out _);
    e.Process(V4(17, "192.168.1.1", "192.168.1.10", UdpSeg(53, 60020, DnsAnswer("real.example", (1, [93, 184, 216, 37])))), inMeta, out _);
    Check(e.Hosts.Lookup(IpKey.From(IPAddress.Parse("93.184.216.37"))).FirstOrDefault() == "real.example", "DNS-Flut verdrängt die echte Anfrage nicht");

    // Unbekannter DNS-Server löst ein Neulesen der Liste aus
    var asked = 0;
    e.UnknownDnsServer = () => asked++;
    e.Process(V4(17, "192.168.1.10", "192.168.1.254", UdpSeg(60021, 53, DnsQuery("c.example"))), outMeta, out _);
    e.Process(V4(17, "192.168.1.10", "192.168.1.1", UdpSeg(60022, 53, DnsQuery("d.example"))), outMeta, out _);
    Check(asked == 1, "unbekannter DNS-Server wird gemeldet");
}

// Werksregel „System“ gilt nur für den Windows-Kern selbst, nicht für Dateien namens System
{
    var p = new FakeProcs();
    var e = NewEngine(p);
    p.Ports[(true, 50400)] = new ProcessInfo(4, Rule.KernelProcess);
    p.Ports[(true, 50401)] = new ProcessInfo(777, @"C:\Users\x\AppData\Local\Temp\System");
    Check(e.Process(V4(6, "192.168.1.10", "20.1.2.3", TcpSyn(50400, 445, 1)), outMeta, out _) == Verdict.Pass
          && e.Process(V4(6, "192.168.1.10", "6.6.6.6", TcpSyn(50401, 4444, 1)), outMeta, out _) == Verdict.Hold, "„System“ nur für den Windows-Kern");
}

// Blocklisten: die DNS-Werksregel nimmt bei unbekannten DNS-Servern nichts aus
{
    var s = new Store();
    FactoryRules.Ensure(s, @"C:\Windows");
    s.Blocklists.Add(new Blocklist { Name = "Tracker", Domains = ["tracker.example"] });
    var c = Conn(@"C:\x\app.exe", "9.9.9.9", 53, "dns.tracker.example", Proto.Udp);
    Check(RuleSet.Build(s, "b").Evaluate(c, now).Blocklist != null
          && RuleSet.Build(s, "b", new HashSet<IpKey> { IpKey.From(IPAddress.Parse("9.9.9.9")) }).Evaluate(c, now).Action == RuleAction.Allow, "DNS-Werksregel und Blocklisten");
}
Check(IpKey.From(IPAddress.Parse("127.0.0.53")).IsLoopback && IpKey.From(IPAddress.IPv6Loopback).IsLoopback && !IpKey.From(IPAddress.Parse("10.0.0.1")).IsLoopback, "Loopback erkennen");

// Blocklisten gelten auch gegen allgemeine Erlauben-Regeln
{
    var s = new Store();
    s.Rules.Add(new Rule { Action = RuleAction.Allow, Process = Chrome });
    s.Blocklists.Add(new Blocklist { Name = "Tracker", Domains = ["tracker.example"] });
    Check(RuleSet.Build(s, "b").Evaluate(Conn(Chrome, "5.5.5.5", 443, "ads.tracker.example"), now) is { Action: RuleAction.Deny, Blocklist.Name: "Tracker" }, "Blockliste schlägt „alles erlauben“");
    s.Rules.Add(new Rule { Action = RuleAction.Allow, Process = "", Remote = RemoteKind.Domains, Targets = ["tracker.example"] });
    Check(RuleSet.Build(s, "b").Evaluate(Conn(Chrome, "5.5.5.5", 443, "ads.tracker.example"), now).Action == RuleAction.Allow, "eigene Domain-Ausnahme schlägt Blockliste");
    var h = new Store();
    h.Rules.Add(new Rule { Action = RuleAction.Allow, Process = Chrome, HighPriority = true });
    h.Blocklists.Add(new Blocklist { Name = "Tracker", Domains = ["tracker.example"] });
    Check(RuleSet.Build(h, "b").Evaluate(Conn(Chrome, "5.5.5.5", 443, "ads.tracker.example"), now).Action == RuleAction.Allow, "hohe Priorität schlägt Blockliste");
}

// Werksregeln Stand 1 → 2: DNS nur zu DNS-Servern, DHCP nur lokal; Abschalten bleibt erhalten
{
    var old = new Store();
    old.Settings.FactoryRulesCreated = true;
    old.Rules.Add(new Rule { Factory = true, Action = RuleAction.Allow, Ports = "53", Remote = RemoteKind.Any, Enabled = false });
    old.Rules.Add(new Rule { Factory = true, Action = RuleAction.Allow, Ports = "67, 68, 546, 547", Protocol = Proto.Udp, Remote = RemoteKind.Any });
    old.Save(); // Stand 1 liegt auf der Platte und wird vor der Umstellung gesichert
    FactoryRules.Ensure(old, @"C:\Windows");
    // Ab Stand 3 kommen Windows Update und Viren- & Bedrohungsschutz dazu (hinten angefügt).
    Check(old.Rules.Count == 4 && old.Rules[0].Remote == RemoteKind.DnsServers && !old.Rules[0].Enabled && old.Rules[1].Remote == RemoteKind.LocalNet
          && old.Rules.Skip(2).All(r => r.Factory && WindowsComponents.IsComponent(r.Process))
          && old.Settings.FactoryRulesVersion == FactoryRules.Version, "Werksregeln Stand 1 → 3");
    var backup = Path.Combine(Paths.DataDir, "config.json.vor-werksregeln-2");
    Check(File.Exists(backup) && File.ReadAllText(backup).Contains("\"Any\""), "Sicherung vor Werksregeln Stand 2");
}
var dnsRule = LsRules.Parse("""{ "rules": [ { "action": "allow", "process": "any", "remote": "dns-servers", "ports": "53" } ] }""").Rules.Single();
Check(dnsRule.Remote == RemoteKind.DnsServers && LsRules.Parse(LsRules.Export("x", [dnsRule])).Rules.Single().Remote == RemoteKind.DnsServers, "lsrules: dns-servers");

// Gleichzeitiges Ändern und Speichern: nichts schlägt fehl, der letzte Stand liegt auf der Platte
{
    var e = NewEngine(new FakeProcs());
    e.Mutate(s => { for (var i = 0; i < 300; i++) s.Rules.Add(new Rule { Process = $"x{i}.exe", Notes = new string('n', 200) }); });
    int Fails() => File.Exists(Log.FilePath) ? File.ReadLines(Log.FilePath).Count(l => l.Contains("Speichern fehlgeschlagen")) : 0;
    var before = Fails();
    Parallel.For(0, 40, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
    {
        if (i % 2 == 0) e.Mutate(s => s.Rules.Add(new Rule { Process = $"p{i}.exe" }));
        else e.Mutate(s => s.Rules.RemoveAt(s.Rules.Count - 1));
    });
    Check(Fails() == before && Store.Load().Rules.Count == e.Read(s => s.Rules.Count), "gleichzeitiges Speichern");
}

// ---- Programme in Temp-Ordnern, Prozess-Muster, Zusammenfassen und Aufräumen von Regeln
{
    AlertRules.TempRoots = [@"R:\Temp\", @"C:\Windows\Temp"];
    const string VsTemp = @"R:\Temp\obkz3fue.blc\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe";
    string Tmp(string folder) => VsTemp.Replace("obkz3fue.blc", folder);
    var vsPattern = AlertRules.ProcessPattern(VsTemp);
    Check(vsPattern == @"R:\Temp\*\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe", "Temp-Programm wird zum Muster: " + vsPattern);
    Check(AlertRules.ProcessPattern(@"C:\Program Files\App\app.exe") == @"C:\Program Files\App\app.exe"
          && AlertRules.ProcessPattern(@"R:\Temp\setup.exe") == @"R:\Temp\setup.exe"
          && AlertRules.ProcessPattern(@"C:\Users\x\AppData\Local\Temp\abc\x.exe") == @"C:\Users\x\AppData\Local\Temp\*\x.exe",
        "nur Programme in Unterordnern von Temp werden verallgemeinert");
    const string StoreApp = @"C:\Program Files\WindowsApps\Claude_5.11492.5.0_x64__pzs8sxrjxfjjc\app\claude.exe";
    Check(AlertRules.ProcessPattern(StoreApp) == @"C:\Program Files\WindowsApps\Claude_*_x64__pzs8sxrjxfjjc\app\claude.exe"
          && AlertRules.ProcessPattern(@"C:\Users\x\AppData\Local\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\2.1.325\806e0a45e6f5\claude.exe")
             == @"C:\Users\x\AppData\Local\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\*\*\claude.exe"
          && AlertRules.ProcessPattern(@"C:\Users\x\AppData\Local\Discord\app-1.0.9163\Discord.exe") == @"C:\Users\x\AppData\Local\Discord\*\Discord.exe",
        "Versions-, Hash- und Store-Paket-Ordner werden zu *");
    Check(AlertRules.ProcessPattern(@"C:\Users\x\Documents\optimizerDuck-src\dotnet-sdk-10.0.404\dotnet.exe") == @"C:\Users\x\Documents\optimizerDuck-src\dotnet-sdk-10.0.404\dotnet.exe"
          && AlertRules.ProcessPattern(@"C:\Program Files\Google\Chrome\Application\chrome.exe") == @"C:\Program Files\Google\Chrome\Application\chrome.exe"
          && AlertRules.ProcessPattern(@"C:\Tools\1.2.3.exe") == @"C:\Tools\1.2.3.exe",
        "gewöhnliche Ordner und der Dateiname bleiben genau");
    var storeRules = new Store();
    storeRules.Rules.Add(new Rule { Action = RuleAction.Allow, Process = AlertRules.ProcessPattern(StoreApp) });
    Check(RuleSet.Build(storeRules, "boot").Evaluate(new Connection { ProcessPath = StoreApp.Replace("5.11492.5.0", "5.12000.1.0"), Pid = 1, Remote = IpKey.From(IPAddress.Parse("20.1.2.3")), Port = 443 }, now).Action == RuleAction.Allow,
        "Regel gilt nach einem Update weiter");
    AlertRules.TempRoots = [@"C:\"];
    Check(AlertRules.ProcessPattern(@"C:\Apps\x.exe") == @"C:\Apps\x.exe", "ein ganzes Laufwerk gilt nie als Temp-Ordner");
    AlertRules.TempRoots = [@"R:\Temp\", @"C:\Windows\Temp"];
    var fromAlert = AlertRules.Create(new Connection { ProcessPath = VsTemp, Pid = 5, Remote = IpKey.From(IPAddress.Parse("20.1.2.3")), Port = 443, Protocol = Proto.Tcp },
        false, AlertScope.AnyConnection, AlertLifetime.Forever, "boot", null, now)!;
    Check(fromAlert.Process == vsPattern, "Warnfenster legt die Regel mit Muster an");

    Connection C(string path, string host = "x.example") => new()
    {
        ProcessPath = path, Pid = 1, Direction = Direction.Outgoing, Protocol = Proto.Tcp,
        Remote = IpKey.From(IPAddress.Parse("20.1.2.3")), Port = 443, Hostnames = [host],
    };
    var gs = new Store();
    gs.Rules.Add(new Rule { Action = RuleAction.Deny, Process = vsPattern });
    gs.Rules.Add(new Rule { Action = RuleAction.Allow, Process = "Background*.exe", Remote = RemoteKind.Hosts, Targets = ["ok.example"] });
    var grs = RuleSet.Build(gs, "boot");
    Check(grs.Evaluate(C(Tmp("zz9.abc")), now).Action == RuleAction.Deny, "Muster passt auf jeden neuen Zufallsordner");
    Check(grs.Evaluate(C(@"R:\Temp\a\b\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe"), now).Action == null
          && grs.Evaluate(C(@"R:\Temp\a\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\Other.exe"), now).Action == null,
        "* steht für genau einen Ordnernamen, der Rest muss stimmen");
    Check(grs.Evaluate(C(Tmp("zz9.abc"), "ok.example"), now).Action == RuleAction.Allow, "Dateinamen-Muster (Background*.exe) passt an jedem Ort");
    var star = new Store();
    star.Rules.Add(new Rule { Action = RuleAction.Deny, Process = "*" });
    Check(RuleSet.Build(star, "boot").Evaluate(C(""), now).Action == null, "ein Muster gilt nie für einen unbekannten Prozess");

    Rule HostRule(string host, RuleAction a = RuleAction.Deny, string proc = @"C:\A\bd.exe") =>
        new() { Action = a, Process = proc, Remote = RemoteKind.Hosts, Targets = [host] };
    var absorbed = new List<Rule>();
    RuleCleanup.Absorb(absorbed, HostRule("a.example"));
    var st = RuleCleanup.Absorb(absorbed, HostRule("B.example."));
    Check(absorbed.Count == 1 && st.Targets.SequenceEqual(["a.example", "b.example"]), "zweite Gegenstelle kommt in die bestehende Regel");
    RuleCleanup.Absorb(absorbed, HostRule("c.example", RuleAction.Allow));
    RuleCleanup.Absorb(absorbed, new Rule { Action = RuleAction.Deny, Process = @"C:\A\bd.exe" });
    Check(absorbed.Count == 3, "liegt eine Erlauben-Regel für dasselbe Programm dazwischen, bleiben die genaueren Verbieten-Regeln");
    absorbed.RemoveAll(r => r.Action == RuleAction.Allow);
    RuleCleanup.Absorb(absorbed, new Rule { Action = RuleAction.Deny, Process = @"C:\A\bd.exe" });
    Check(absorbed.Count == 1 && absorbed[0].Remote == RemoteKind.Any, "„jede Verbindung verbieten“ macht Host-Regeln und das Doppel überflüssig");
    var tl = new List<Rule> { HostRule("a.example") };
    RuleCleanup.Absorb(tl, new Rule { Action = RuleAction.Deny, Process = @"C:\A\bd.exe", Lifetime = LifetimeKind.Timed, Expires = now.AddDays(1) });
    Check(tl.Count == 2, "eine befristete Regel ersetzt keine dauerhafte");
    var bl = new List<Rule> { HostRule("ads.example", RuleAction.Allow) };
    RuleCleanup.Absorb(bl, new Rule { Action = RuleAction.Allow, Process = @"C:\A\bd.exe" });
    Check(bl.Count == 2, "Erlauben für einen Host (nimmt ihn von Blocklisten aus) bleibt neben „jede Verbindung erlauben“");

    // Der Fall des Nutzers: Visual-Studio-Installer aus wechselnden Temp-Ordnern, je Nachfrage eine Regel
    var mess = new List<Rule>();
    foreach (var f in new[] { "obkz3fue.blc", "oow4xwqi.qn1" })
        foreach (var h in new[] { "go.microsoft.com", "aka.ms", "settings.visualstudio.microsoft.com" })
            mess.Add(HostRule(h, proc: Tmp(f)));
    mess.Add(new Rule { Action = RuleAction.Deny, Process = Tmp("yebzrttz.n44") });
    mess.Add(new Rule { Action = RuleAction.Deny, Process = Tmp("vfp5enaw.jsr") });
    mess.Add(new Rule { Action = RuleAction.Deny, Process = Tmp("xd5yyjpi.2s4"), Lifetime = LifetimeKind.Timed, Expires = now.AddDays(30) });
    const string VsInst = @"C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe";
    foreach (var h in new[] { "settings.visualstudio.microsoft.com", "go.microsoft.com", "aka.ms" }) mess.Add(HostRule(h, proc: VsInst));
    mess.Add(new Rule { Action = RuleAction.Allow, Process = @"C:\Gone\old.exe" });
    mess.Add(new Rule { Action = RuleAction.Allow, Process = "svchost.exe", Factory = true });
    mess.Add(new Rule { Action = RuleAction.Allow, Process = "svchost.exe", Factory = true });
    var plan = RuleCleanup.Plan(mess, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"C:\Gone\old.exe" });
    var tempRules = plan.Rules.Where(r => r.Process == vsPattern).ToList();
    var instRules = plan.Rules.Where(r => r.Process == VsInst).ToList();
    Check(plan.Before == 15 && plan.Rules.Count == 4 && plan.Generalized == 9 && plan.Vanished == 1 && plan.Redundant == 8
          && plan.MergedFrom == 3 && plan.MergedInto == 1,
        $"Aufräumen im Fall des Nutzers: {plan.Before} → {plan.Rules.Count} (verallgemeinert {plan.Generalized}, weg {plan.Vanished}, überflüssig {plan.Redundant}, zusammengefasst {plan.MergedFrom}→{plan.MergedInto})");
    Check(tempRules.Count == 1 && tempRules[0].Remote == RemoteKind.Any && tempRules[0].Lifetime == LifetimeKind.Forever,
        "übrig bleibt für die Temp-Kopien eine Regel „jede Verbindung verbieten, für immer“");
    Check(instRules.Count == 1 && instRules[0].Targets.Count == 3 && plan.Rules.Count(r => r.Factory) == 2, "drei Host-Regeln zu einer, Werksregeln unberührt");
    Check(mess[0].Process == Tmp("obkz3fue.blc") && mess.Count == 15, "der Plan ändert die Vorlage nicht");
    var beforeSet = RuleSet.Build(new Store { Rules = mess }, "boot");
    var afterSet = RuleSet.Build(new Store { Rules = plan.Rules }, "boot");
    var same = new[] { C(VsInst, "aka.ms"), C(VsInst, "go.microsoft.com"), C(VsInst, "example.org"), C(Tmp("obkz3fue.blc"), "aka.ms"), C(Tmp("vfp5enaw.jsr"), "example.org") }
        .All(c => beforeSet.Evaluate(c, now).Action == afterSet.Evaluate(c, now).Action);
    Check(same, "aufgeräumte Regeln entscheiden wie vorher");
    Check(RuleCleanup.Plan(plan.Rules, new HashSet<string>()).Empty, "ein zweites Aufräumen findet nichts mehr");

    // Zwei Nachfragen (Reichweite Host) für dasselbe Programm ergeben eine Regel mit beiden Hosts
    var fp = new FakeProcs();
    var fs = new Store();
    var fe = new FirewallEngine(fs, fp, "boot", () => now);
    fe.Hosts.Add("a.example", [IpKey.From(IPAddress.Parse("198.51.100.1"))]);
    fe.Hosts.Add("b.example", [IpKey.From(IPAddress.Parse("198.51.100.2"))]);
    fp.Ports[(true, 51000)] = new ProcessInfo(900, @"C:\A\bd.exe");
    fp.Ports[(true, 51001)] = new ProcessInfo(900, @"C:\A\bd.exe");
    var om = new PacketMeta(true, false, 7, 0);
    fe.Process(V4(6, "192.168.1.10", "198.51.100.1", TcpSyn(51000, 443, 1)), om, out _);
    fe.Process(V4(6, "192.168.1.10", "198.51.100.2", TcpSyn(51001, 443, 1)), om, out _);
    foreach (var a in fe.Alerts) fe.Resolve(a.Id, false, AlertRules.Create(a.Connection, false, AlertScope.Host, AlertLifetime.Forever, "boot", null, now));
    var own = fs.Rules.Where(r => !r.Factory).ToList();
    Check(own.Count == 1 && own[0].Targets.Count == 2 && fe.Alerts.Count == 0, "zwei Nachfragen (Host) ergeben eine Regel mit zwei Hosts");
    AlertRules.TempRoots = [];
}

// ---- Windows Update und Viren- & Bedrohungsschutz als eigene, erkennbare Werksregeln
{
    WindowsComponents.Configure(@"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData");
    Check(WindowsComponents.Of(@"C:\Windows\System32\SIHClient.exe") == WindowsComponents.Update
          && WindowsComponents.Of(@"C:\Windows\UUS\amd64\MoUsoCoreWorker.exe") == WindowsComponents.Update
          && WindowsComponents.Of(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.5-0\MsMpEng.exe") == WindowsComponents.Defender
          && WindowsComponents.Of(@"C:\Program Files\Windows Defender\MpCmdRun.exe") == WindowsComponents.Defender
          && WindowsComponents.Of(@"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe") == WindowsComponents.Defender,
        "Windows Update und Defender an ihren Orten erkannt (auch als Muster)");
    Check(WindowsComponents.Of(@"R:\Temp\SIHClient.exe") == null && WindowsComponents.Of(@"C:\Windows\System32\spool\drivers\color\SIHClient.exe") == null
          && WindowsComponents.Of(@"C:\Users\x\Downloads\MsMpEng.exe") == null && WindowsComponents.Of(@"C:\Windows\System32\notepad.exe") == null
          && WindowsComponents.Of(@"C:\ProgramData\Microsoft\Windows Defender\Platform\..\..\x\MsMpEng.exe") == null,
        "gleicher Dateiname an einem anderen Ort ist kein Windows-Bestandteil");
    var cs = new Store();
    FactoryRules.Ensure(cs, @"C:\Windows");
    Connection P(string path) => new()
    {
        ProcessPath = path, Pid = 9, Direction = Direction.Outgoing, Protocol = Proto.Tcp, Remote = IpKey.From(IPAddress.Parse("20.1.2.3")), Port = 443,
    };
    var crs = RuleSet.Build(cs, "boot");
    Check(crs.Evaluate(P(@"C:\Windows\System32\SIHClient.exe"), now).Action == RuleAction.Allow
          && crs.Evaluate(P(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25110.5-0\MpCmdRun.exe"), now).Action == RuleAction.Allow
          && crs.Evaluate(P(@"R:\Temp\SIHClient.exe"), now).Action == null,
        "Werksregeln erlauben Windows Update und Defender, aber keine Namensvettern");
    cs.Rules.Add(new Rule { Action = RuleAction.Deny, Process = @"C:\Windows\System32\SIHClient.exe" });
    Check(RuleSet.Build(cs, "boot").Evaluate(P(@"C:\Windows\System32\SIHClient.exe"), now).Action == RuleAction.Deny, "eigenes Verbot für ein Programm geht der Werksregel vor");
    Check(cs.Rules.Single(r => r.Process == WindowsComponents.Update).ProcessName == "Windows Update"
          && cs.Rules.Last().ProcessName == "Windows Update · SIHClient.exe"
          && cs.Rules.Single(r => r.Process == WindowsComponents.Defender).ProcessName == "Viren- & Bedrohungsschutz",
        "Regelliste zeigt den Bestandteil");
    var old = new Store();
    FactoryRules.Ensure(old, @"C:\Windows");
    old.Rules.RemoveAll(r => WindowsComponents.IsComponent(r.Process));
    old.Settings.FactoryRulesVersion = 2;
    FactoryRules.Ensure(old, @"C:\Windows");
    FactoryRules.Ensure(old, @"C:\Windows");
    Check(old.Rules.Count(r => WindowsComponents.IsComponent(r.Process)) == 2 && old.Settings.FactoryRulesVersion == FactoryRules.Version,
        "Aktualisierung auf Werksregel-Stand 3 ergänzt die beiden Regeln genau einmal");
    cs.Rules.Add(new Rule { Action = RuleAction.Allow, Process = @"C:\Windows\System32\MoUsoCoreWorker.exe" });
    Check(RuleCleanup.Plan(cs.Rules, new HashSet<string>()).Rules.Any(r => r.Process == @"C:\Windows\System32\MoUsoCoreWorker.exe"),
        "eine Werksregel macht eigene Regeln beim Aufräumen nie überflüssig (abschaltbar)");
    WindowsComponents.Configure("", "", "", "");
}

// ---- Bekannte Apps (Claude, ChatGPT, Browser, Updater): Name und Rolle, nur zur Anzeige
{
    KnownApps.Configure(@"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData");
    string? L(string p) => KnownApps.Of(p)?.Label(p);
    AppRole? R(string p) => KnownApps.Of(p)?.Role;
    const string WA = @"C:\Program Files\WindowsApps\";
    Check(L(WA + @"Claude_6.6395.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe") == "Claude"
          && L(WA + @"Claude_*_x64__pzs8sxrjxfjjc\app\claude.exe") == "Claude"
          && L(WA + @"Claude_6.6395.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe") == "Claude · cowork-svc.exe"
          && R(WA + @"Claude_6.6395.0.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe") == AppRole.Helper,
        "Claude (Store) samt Hilfsprogrammen erkannt, auch als Muster");
    Check(L(@"C:\Users\Justman\AppData\Local\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\2.1.326\d31a4581af92\claude.exe") == "Claude Code"
          && L(@"C:\Users\Justman\AppData\Local\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\*\*\claude.exe") == "Claude Code"
          && R(@"C:\Users\x\.local\bin\claude.exe") == AppRole.CommandLine
          && L(@"C:\Users\x\AppData\Local\AnthropicClaude\Update.exe") == "Claude · Updater",
        "Claude Code (Kommandozeile) und der Updater der älteren Claude-Fassung erkannt");
    Check(L(WA + @"OpenAI.Codex_*_x64__2p2nqsd0c76g0\app\ChatGPT.exe") == "ChatGPT"
          && L(WA + @"OpenAI.Codex_26.1111.9265.0_x64__2p2nqsd0c76g0\app\resources\codex.exe") == "ChatGPT · codex.exe"
          && L(WA + @"OpenAI.Codex_*_x64__2p2nqsd0c76g0\app\resources\cua_node\bin\node_repl.exe") == "ChatGPT · node_repl.exe",
        "ChatGPT samt Hilfsprogrammen erkannt");
    Check(L(@"C:\Program Files\Google\Chrome\Application\chrome.exe") == "Google Chrome"
          && L(@"C:\Program Files\Google\Chrome\Application\157.0.8103.79\elevation_service.exe") == "Google Chrome · elevation_service.exe"
          && R(@"C:\Program Files\Google\Chrome\Application\157.0.8103.79\Installer\setup.exe") == AppRole.Updater
          && L(@"C:\Program Files (x86)\Google\GoogleUpdater\*\updater.exe") == "Google Updater"
          && L(@"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe") == "Google Updater"
          && L(@"C:\Users\x\AppData\Local\Google\Chrome\Application\chrome.exe") == "Google Chrome",
        "Chrome, seine Hilfsprogramme und der Google Updater erkannt (Installer-Ordner zählt als Updater)");
    Check(L(@"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe") == "Brave"
          && L(@"C:\Program Files (x86)\BraveSoftware\Update\BraveUpdate.exe") == "Brave · Updater"
          && L(@"C:\Program Files (x86)\BraveSoftware\Update\1.3.361.151\BraveUpdateCore.exe") == "Brave · Updater",
        "Brave und Brave Update erkannt");
    Check(L(@"C:\Program Files\Mozilla Firefox\firefox.exe") == "Firefox"
          && L(@"C:\Program Files\Mozilla Firefox\updater.exe") == "Firefox · Updater"
          && R(@"C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe") == AppRole.Updater
          && L(@"C:\Program Files\Mozilla Firefox\pingsender.exe") == "Firefox · pingsender.exe"
          && R(@"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB\updates\0\updater.exe") == AppRole.Updater,
        "Firefox, Updater, Wartungsdienst und Hilfsprogramme erkannt");
    Check(L(@"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe") == "Microsoft Edge · Updater"
          && L(@"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe") == "Microsoft Edge WebView2"
          && L(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe") == "Microsoft Edge",
        "Edge, Edge Update und WebView2 erkannt");
    Check(L(@"R:\Temp\chrome.exe") == null && L(@"C:\Users\x\Downloads\updater.exe") == null
          && L(@"C:\Program Files\Google\Chrome\Application\..\..\x\evil.exe") == null
          && L(WA + @"Claude_*_x64__andererherausgeber\app\claude.exe") == null
          && L(@"C:\Program Files\Google\Chrome\Application\chrome.dll") == null
          && L("@windows-update") == null && L("System") == null && L("") == null && L(@"C:\Windows\System32\svchost.exe") == null,
        "gleicher Name an einem anderen Ort, fremder Herausgeber, „..“ und Nicht-Programme sind keine bekannte App");
    Check(new Rule { Process = @"C:\Program Files (x86)\Google\GoogleUpdater\*\updater.exe" }.ProcessName == "Google Updater"
          && new Rule { Process = WA + @"OpenAI.Codex_*_x64__2p2nqsd0c76g0\app\resources\codex.exe" }.ProcessName == "ChatGPT · codex.exe"
          && new Rule { Process = @"C:\Tools\x\updater.exe" }.ProcessName == "updater.exe",
        "Regelliste zeigt bekannte Apps mit Namen und Rolle");
    var appRules = new Store();
    appRules.Rules.Add(new Rule { Action = RuleAction.Deny, Process = @"C:\Program Files (x86)\Google\GoogleUpdater\*\updater.exe" });
    var appConn = new Connection
    {
        ProcessPath = @"C:\Users\x\Downloads\updater.exe", Pid = 9, Direction = Direction.Outgoing, Protocol = Proto.Tcp,
        Remote = IpKey.From(IPAddress.Parse("142.250.1.1")), Port = 443,
    };
    Check(RuleSet.Build(appRules, "boot").Evaluate(appConn, now).Action == null, "die Erkennung ändert nicht, welche Regel greift");

    KnownApps.Configure(@"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData", [@"R:\Temp", @"C:\Windows\Temp", @"C:\"]);
    const string Code = @"C:\Users\Justman\AppData\Local\Programs\Microsoft VS Code\";
    Check(L(Code + "Code.exe") == "Visual Studio Code"
          && L(Code + @"e646868227\tools\inno_updater.exe") == "Visual Studio Code · Updater"
          && L(Code + @"bin\copilot-shim\copilot.exe") == "Visual Studio Code · copilot.exe"
          && L(@"C:\Users\Justman\.vscode\extensions\rust-lang.rust-analyzer-0.3.3105-win32-x64\server\rust-analyzer.exe") == "Visual Studio Code · rust-analyzer.exe"
          && R(@"R:\Temp\vscode-stable-user-x64\CodeSetup-stable-1.106.0.exe") == AppRole.Updater
          && L(@"C:\Program Files\Microsoft VS Code\Code.exe") == "Visual Studio Code"
          && L(@"C:\Users\x\AppData\Local\Programs\Microsoft VS Code Insiders\Code - Insiders.exe") == "Visual Studio Code Insiders",
        "VS Code (Benutzer- und Systeminstallation), Updater im Hash-Ordner, Update in Temp, Erweiterungen und Insiders erkannt");
    Check(L(@"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.exe") == "Visual Studio"
          && L(@"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\PerfWatson2.exe") == "Visual Studio · PerfWatson2.exe"
          && L(@"C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe") == "Visual Studio Installer"
          && R(@"C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe") == AppRole.Updater
          && L(@"R:\Temp\*\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe") == "Visual Studio Installer"
          && L(@"C:\Users\x\AppData\Local\Temp\obkz3fue.blc\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe") == "Visual Studio Installer"
          && L(@"C:\Program Files (x86)\Microsoft Visual Studio\Shared\x.exe") == "Visual Studio · x.exe",
        "Visual Studio, seine Hilfsprogramme und der Installer (auch als Kopie in Temp) erkannt");
    Check(L(@"C:\Program Files\NordVPN\NordVPN.exe") == "NordVPN"
          && L(@"C:\Program Files\NordVPN\8.15.2.0\NordVPNApp.exe") == "NordVPN"
          && L(@"C:\Program Files\NordVPN\nordvpn-service.exe") == "NordVPN · nordvpn-service.exe"
          && L(@"C:\Program Files\NordVPN\NordSec ThreatProtection\8.15.13.0\nordsec-threatprotection-service-app.exe") == "NordVPN · nordsec-threatprotection-service-app.exe"
          && L(@"C:\Program Files\NordUpdater\NordUpdateService.exe") == "NordUpdater"
          && R(@"C:\Program Files\NordVPN\Extras\NordUpdaterSetup.exe") == AppRole.Updater,
        "NordVPN, Dienst, Threat Protection und NordUpdater erkannt");
    Check(L(@"C:\setup\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe") == null
          && L(@"D:\Downloads\vscode-stable-user-x64\CodeSetup-stable-1.exe") == null
          && L(@"C:\Users\x\Downloads\Code.exe") == null && L(@"C:\Tools\NordVPN\NordVPN.exe") == null,
        "ein ganzes Laufwerk zählt nie als Temp-Ordner; gleiche Namen anderswo sind keine bekannte App");
    Check(new Rule { Process = @"R:\Temp\*\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe" }.ProcessName == "Visual Studio Installer"
          && new Rule { Process = @"C:\Program Files\NordUpdater\NordUpdateService.exe" }.ProcessName == "NordUpdater",
        "Regelliste zeigt Visual Studio Installer und NordUpdater");

    const string C2R = @"C:\Program Files\Common Files\microsoft shared\ClickToRun\";
    Check(L(C2R + "OfficeClickToRun.exe") == "Microsoft Office Click-to-Run" && R(C2R + "OfficeClickToRun.exe") == AppRole.Updater
          && L(C2R + @"Updates\16.0.19328.20000\OfficeClickToRun.exe") == "Microsoft Office Click-to-Run"
          && L(C2R + "OfficeC2RClient.exe") == "Microsoft Office · Updater"
          && L(C2R + "AppVShNotify.exe") == "Microsoft Office · AppVShNotify.exe",
        "Office-Updater (Klick-und-Los-Dienst und Update-Client) erkannt");
    Check(L(@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE") == "Microsoft Word"
          && L(@"C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE") == "Microsoft Outlook"
          && L(@"C:\Program Files\Microsoft Office\Office16\EXCEL.EXE") == "Microsoft Excel"
          && L(@"C:\Program Files\Microsoft Office\root\Office16\msoia.exe") == "Microsoft Office · msoia.exe"
          && L(WA + @"Microsoft.OutlookForWindows_1.2026.1013.100_x64__8wekyb3d8bbwe\olk.exe") == "Microsoft Outlook"
          && L(WA + @"Microsoft.OutlookForWindows_*_x64__8wekyb3d8bbwe\olkBg.exe") == "Microsoft Outlook · olkBg.exe"
          && L(WA + @"MSTeams_*_x64__8wekyb3d8bbwe\ms-teams.exe") == "Microsoft Teams",
        "Office-Programme (Klick-und-Los und MSI), neues Outlook und Teams erkannt");
    const string OD = @"C:\Users\Justman\AppData\Local\Microsoft\OneDrive\";
    Check(L(OD + "OneDrive.exe") == "Microsoft OneDrive" && L(OD + "OneDriveStandaloneUpdater.exe") == "Microsoft OneDrive · Updater"
          && R(OD + @"26.198.1011.0006\OneDriveSetup.exe") == AppRole.Updater
          && L(OD + @"26.198.1011.0006\FileCoAuth.exe") == "Microsoft OneDrive · FileCoAuth.exe"
          && L(@"C:\Program Files\Microsoft OneDrive\OneDriveStandaloneUpdater.exe") == "Microsoft OneDrive · Updater",
        "OneDrive samt Updater erkannt (je Benutzer und für alle)");
    Check(L(@"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe") == "Adobe Acrobat · Updater"
          && L(@"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe") == "Adobe Acrobat · Updater"
          && L(@"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe") == "Adobe Acrobat"
          && L(@"C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe") == "Adobe Acrobat Reader"
          && L(@"C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe") == "Adobe Acrobat · AdobeCollabSync.exe",
        "Acrobat, Reader und ihr Updater erkannt");
    const string ADC = @"C:\Program Files\Common Files\Adobe\Adobe Desktop Common\";
    Check(L(ADC + @"ElevationManager\AdobeUpdateService.exe") == "Adobe Update Service" && R(ADC + @"ElevationManager\AdobeUpdateService.exe") == AppRole.Updater
          && L(ADC + @"ElevationManager\Adobe Installer.exe") == "Adobe Creative Cloud · Updater"
          && R(ADC + @"HDBox\Setup.exe") == AppRole.Updater
          && R(@"C:\Program Files (x86)\Common Files\Adobe\OOBE\PDApp\UWA\UpdaterStartupUtility.exe") == AppRole.Updater
          && L(ADC + @"ADS\Adobe Desktop Service.exe") == "Adobe Creative Cloud · Adobe Desktop Service.exe"
          && L(@"C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGSService.exe") == "Adobe Genuine Service"
          && L(@"C:\Program Files\Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe") == "Adobe Creative Cloud",
        "Creative Cloud: App, Adobe Update Service, Installationsprogramm, Hintergrunddienste erkannt");
    Check(L(@"C:\Program Files\Adobe\Adobe Photoshop 2026\Photoshop.exe") == "Adobe Photoshop"
          && L(@"C:\Program Files\Adobe\Adobe Illustrator 2026\Support Files\Contents\Windows\Illustrator.exe") == "Adobe Illustrator"
          && L(@"C:\Program Files\Adobe\Adobe Premiere Pro 2026\Adobe Premiere Pro.exe") == "Adobe Premiere Pro"
          && L(@"C:\Program Files\Adobe\Adobe Photoshop 2026\node.exe") == "Adobe Creative Cloud · node.exe",
        "Programme der Creative Cloud mit eigenem Namen, ihre Hilfsprogramme bei der Creative Cloud");
    Check(L(@"C:\Users\x\Downloads\OfficeClickToRun.exe") == null && L(@"C:\Users\x\AppData\Local\Temp\AdobeARM.exe") == null
          && L(WA + @"Microsoft.OutlookForWindows_*_x64__fremd\olk.exe") == null && L(@"D:\Adobe\Photoshop.exe") == null,
        "Office- und Adobe-Namen an anderen Orten oder von fremdem Herausgeber sind keine bekannte App");

    Check(L(@"C:\Tools\GitHubCLI\bin\gh.exe") == "GitHub CLI" && R(@"C:\Tools\GitHubCLI\bin\gh.exe") == AppRole.CommandLine
          && L(@"C:\Program Files\GitHub CLI\gh.exe") == "GitHub CLI"
          && L(@"C:\Users\x\scoop\apps\gh\current\bin\gh.exe") == "GitHub CLI",
        "GitHub CLI erkannt: portabel (ZIP-Paket), MSI-Installation, Scoop");
    Check(L(@"C:\Tools\MinGit\ucrt64\bin\git-remote-https.exe") == "Git · git-remote-https.exe"
          && R(@"C:\Tools\MinGit\ucrt64\bin\git-remote-https.exe") == AppRole.Helper
          && L(@"C:\Tools\MinGit\cmd\git.exe") == "Git" && R(@"C:\Tools\MinGit\cmd\git.exe") == AppRole.CommandLine
          && L(@"C:\Program Files\Git\mingw64\bin\git-remote-https.exe") == "Git · git-remote-https.exe"
          && L(@"C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe") == "Git · git-remote-https.exe"
          && L(@"C:\Program Files\Git\usr\bin\ssh.exe") == "Git · ssh.exe"
          && L(@"C:\Program Files\Git\cmd\git.exe") == "Git",
        "Git erkannt: MinGit portabel und Git für Windows (mingw64, libexec, usr\\bin)");
    Check(L(@"C:\Users\x\AppData\Local\GitHubDesktop\app-3.5.2\GitHubDesktop.exe") == "GitHub Desktop"
          && L(@"C:\Users\x\AppData\Local\GitHubDesktop\Update.exe") == "GitHub Desktop · Updater"
          && L(@"C:\Users\x\AppData\Local\GitHubDesktop\app-3.5.2\resources\app\git\mingw64\bin\git-remote-https.exe") == "GitHub Desktop · git-remote-https.exe"
          && L(@"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\mingw64\bin\git-remote-https.exe")
             == "Visual Studio · git-remote-https.exe",
        "GitHub Desktop samt Updater; mitgeliefertes Git zählt zur App, die es mitbringt");
    Check(L(@"C:\Tools\x\gh.exe") == null && L(@"C:\Tools\x\bin\git-remote-https.exe") == null && L(@"C:\Tools\x\ucrt64\bin\curl.exe") == null,
        "gh.exe ohne bin-Ordner und Git-Helfer ohne Git-Ordnerstruktur sind keine bekannte App");
    Check(new Rule { Process = @"C:\Tools\GitHubCLI\bin\gh.exe" }.ProcessName == "GitHub CLI"
          && new Rule { Process = @"C:\Tools\MinGit\ucrt64\bin\git-remote-https.exe" }.ProcessName == "Git · git-remote-https.exe",
        "Regelliste zeigt GitHub CLI und Git");

    const string DS = @"C:\Windows\System32\DriverStore\FileRepository\nv_dispig.inf_amd64_cc526ccc3287f5cd\";
    Check(L(DS + @"Display.NvContainer\NVDisplay.Container.exe") == "NVIDIA · NVDisplay.Container.exe"
          && L(DS + "nvngx_update.exe") == "NVIDIA NGX Updater (DLSS)" && R(DS + "nvngx_update.exe") == AppRole.Updater
          && R(DS + "setup.exe") == AppRole.Updater
          && L(@"C:\Windows\System32\DriverStore\FileRepository\nv_dispig.inf_amd64_*\Display.NvContainer\NVDisplay.Container.exe") == "NVIDIA · NVDisplay.Container.exe"
          && L(@"C:\Windows\System32\nvidia-smi.exe") == "NVIDIA SMI"
          && R(@"C:\Program Files\NVIDIA Corporation\Installer2\InstallerCore\SETUP.EXE") == AppRole.Updater
          && L(@"C:\Program Files\NVIDIA Corporation\NVIDIA App\CEF\NVIDIA App.exe") == "NVIDIA App"
          && R(@"C:\NVIDIA\DisplayDriver\610.88\Win11_64\International\setup.exe") == AppRole.Updater,
        "NVIDIA: Treiber-Container, DLSS-Updater, Installation, nvidia-smi, NVIDIA App, entpackter Treiber");
    Check(L(@"C:\Windows\System32\DriverStore\FileRepository\nvdimm.inf_amd64_acc6ca47f92b4065\x.exe") == null
          && L(@"C:\Windows\System32\DriverStore\FileRepository\nvmedisk.inf_amd64_803f3f48841e44d8\x.exe") == null
          && L(@"C:\Tools\nvidia-smi.exe") == null,
        "Treiber von Microsoft mit „nv…“ im Namen und nvidia-smi anderswo sind kein NVIDIA");
    Check(L(@"C:\Program Files (x86)\Steam\steam.exe") == "Steam"
          && L(@"C:\Program Files (x86)\Steam\bin\cef\cef.win7x64\steamwebhelper.exe") == "Steam · steamwebhelper.exe"
          && L(@"C:\Program Files (x86)\Common Files\Steam\steamservice.exe") == "Steam · steamservice.exe"
          && L(@"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe") == "Steam · Counter-Strike Global Offensive"
          && L(@"D:\SteamLibrary\steamapps\common\Portal 2\portal2.exe") == "Steam · Portal 2"
          && R(@"D:\SteamLibrary\steamapps\common\Portal 2\portal2.exe") == AppRole.Game
          && L(@"D:\SteamLibrary\steamapps\common\*\portal2.exe") == "Steam · portal2.exe",
        "Steam: Client, Web-Helper, Dienst und Spiele in jeder Bibliothek mit Spielnamen");
    Check(ProcessGroups.Of(DS + "nvngx_update.exe") == ProcessGroup.Hardware && ProcessGroups.Of(@"D:\SteamLibrary\steamapps\common\Portal 2\portal2.exe") == ProcessGroup.Games
          && ProcessGroups.Of(@"C:\Program Files (x86)\Steam\steam.exe") == ProcessGroup.Games && ProcessGroups.Title(ProcessGroup.Games) == "Spiele"
          && ProcessGroups.Title(ProcessGroup.Hardware) == "Treiber und Hardware",
        "NVIDIA in „Treiber und Hardware“, Steam samt Spielen in „Spiele“");
    KnownApps.Configure("", "", "");
    Check(L(@"C:\Program Files\Google\Chrome\Application\chrome.exe") == null, "ohne festgelegte Orte wird nichts erkannt");
}

// ---- Windows-Programme mit verständlichem Namen und Art (nur Anzeige)
{
    WindowsProcesses.Configure(@"C:\WINDOWS", @"C:\Program Files");
    string? W(string p) => WindowsProcesses.Of(p)?.Label;
    WinCategory? K(string p) => WindowsProcesses.Of(p)?.Category;
    Check(W(@"C:\Windows\System32\svchost.exe") == "Windows-Diensthost" && W(@"C:\WINDOWS\System32\lsass.exe") == "Windows-Anmeldung (LSASS)"
          && W(@"C:\Windows\System32\dasHost.exe") == "Geräteverbindungen" && W(@"C:\Windows\explorer.exe") == "Datei-Explorer"
          && W(@"C:\Windows\ImmersiveControlPanel\SystemSettings.exe") == "Einstellungen"
          && W(@"C:\Windows\System32\wbem\WmiPrvSE.exe") == "WMI-Anbieterhost"
          && W(@"C:\Windows\System32\WindowsPowerShell\*\powershell.exe") == "Windows PowerShell"
          && W(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") == "Windows PowerShell"
          && W(@"C:\Windows\System32\OpenSSH\ssh.exe") == "OpenSSH",
        "Windows-Programme in System32, Windows-Ordner, Einstellungen, wbem, PowerShell und OpenSSH erkannt (auch als Muster)");
    Check(W(@"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe") == "Startmenü"
          && W(@"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe") == "Tipps und Vorschläge"
          && K(@"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe") == WinCategory.Search
          && W(@"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\WindowsPackageManagerServer.exe") == "WinGet (Paket-Manager)"
          && K(@"C:\Program Files\WindowsApps\Microsoft.StartExperiencesApp_*_x64__8wekyb3d8bbwe\MicrosoftStartFeedProvider\MicrosoftStartFeedProvider.exe") == WinCategory.Content
          && W(@"C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_525.1.0.0_x64__cw5n1h2txyewy\Dashboard\Widgets.exe") == "Widgets",
        "Startmenü, Tipps, Suche (SystemApps) und WinGet, Nachrichten-Feed, Widgets (Store-Pakete von Microsoft) erkannt");
    Check(K(@"C:\Windows\System32\CompatTelRunner.exe") == WinCategory.Telemetry && K(@"C:\Windows\System32\DeviceCensus.exe") == WinCategory.Telemetry
          && K(@"C:\Windows\System32\ruxim\ruximih.exe") == WinCategory.Content && K(@"C:\Windows\System32\smartscreen.exe") == WinCategory.Security
          && W(@"C:\Windows\System32\AppHostRegistrationVerifier.exe") == "App-Verknüpfungen prüfen"
          && W(@"C:\Windows\System32\ganzneu.exe") == "Windows · ganzneu.exe" && W(@"C:\Windows\SysWOW64\cmd.exe") == "Eingabeaufforderung",
        "Telemetrie, Hinweise, Sicherheit erkannt; unbekannte Programme in System32 heißen „Windows · name.exe“");
    Check(W(@"C:\Windows\System32\spool\drivers\color\svchost.exe") == null && W(@"C:\Windows\Temp\lsass.exe") == null
          && W(@"C:\Windows\System32\Tasks\x.exe") == null && W(@"C:\Users\x\Downloads\svchost.exe") == null
          && W(@"C:\Windows\System32\DriverStore\FileRepository\nv_dispig.inf_amd64_cc526ccc3287f5cd\Display.NvContainer\NVDisplay.Container.exe") == null
          && W(@"C:\Program Files\WindowsApps\Claude_*_x64__pzs8sxrjxfjjc\app\claude.exe") == null
          && W(@"C:\Program Files\WindowsApps\Fremd.App_1.0.0.0_x64__abcdefghijklm\winget.exe") == null
          && W(@"C:\Windows\System32\..\..\x\svchost.exe") == null && W("System") == null && W(@"C:\Windows\System32\svchost.dll") == null,
        "für alle beschreibbare Unterordner, Temp, Treiber anderer Hersteller und fremde Store-Pakete zählen nicht als Windows");
    Check(new Rule { Process = @"C:\Windows\System32\CompatTelRunner.exe" }.ProcessName == "Telemetrie: Kompatibilität"
          && new Rule { Process = @"C:\Windows\System32\svchost.exe", Service = "DiagTrack" }.ProcessName.StartsWith("Windows-Dienst: ")
          && new Rule { Process = @"C:\Windows\System32\SIHClient.exe" }.ProcessName == "Windows · SIHClient.exe",
        "Regelliste zeigt Windows-Programme mit Namen; Dienst-Regeln bleiben „Windows-Dienst: …“");
    WindowsComponents.Configure(@"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData");
    Check(new Rule { Process = @"C:\Windows\System32\SIHClient.exe" }.ProcessName == "Windows Update · SIHClient.exe",
        "Windows Update geht der allgemeinen Windows-Erkennung vor");
    WindowsComponents.Configure("", "", "", "");
    WindowsProcesses.Configure("", "");
    Check(W(@"C:\Windows\System32\svchost.exe") == null, "ohne festgelegte Orte wird nichts erkannt");
}

// ---- Gruppen in den Listen (KI, Browser, Office, Entwicklung, VPN, Windows, Andere)
{
    KnownApps.Configure(@"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData", [@"R:\Temp"]);
    WindowsProcesses.Configure(@"C:\Windows", @"C:\Program Files");
    WindowsComponents.Configure(@"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData");
    ProcessGroup G(string p, string service = "", bool all = false) => ProcessGroups.Of(p, service, all);
    Check(G(@"C:\Program Files\WindowsApps\Claude_*_x64__pzs8sxrjxfjjc\app\claude.exe") == ProcessGroup.AI
          && G(@"C:\Users\x\AppData\Local\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\*\*\claude.exe") == ProcessGroup.AI
          && G(@"C:\Program Files\WindowsApps\OpenAI.Codex_*_x64__2p2nqsd0c76g0\app\resources\codex.exe") == ProcessGroup.AI,
        "Claude, Claude Code und ChatGPT samt Hilfsprogrammen in der Gruppe KI");
    Check(G(@"C:\Program Files\Google\Chrome\Application\chrome.exe") == ProcessGroup.Browser
          && G(@"C:\Program Files (x86)\Google\GoogleUpdater\*\updater.exe") == ProcessGroup.Browser
          && G(@"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\*\msedgewebview2.exe") == ProcessGroup.Browser,
        "Browser samt ihren Updatern in der Gruppe Browser");
    Check(G(@"C:\Tools\MinGit\ucrt64\bin\git-remote-https.exe") == ProcessGroup.Development && G(@"C:\Tools\GitHubCLI\bin\gh.exe") == ProcessGroup.Development
          && G(@"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.exe") == ProcessGroup.Development
          && G(@"C:\Program Files\NordVPN\nordvpn-service.exe") == ProcessGroup.Vpn
          && G(@"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeClickToRun.exe") == ProcessGroup.Office,
        "Entwicklung, VPN und Office");
    Check(G(@"C:\Windows\System32\svchost.exe") == ProcessGroup.Windows && G(@"C:\Windows\System32\svchost.exe", "DiagTrack") == ProcessGroup.Windows
          && G("", "DiagTrack", true) == ProcessGroup.Windows && G("System") == ProcessGroup.Windows && G("@windows-update") == ProcessGroup.Windows
          && G(@"C:\Windows\System32\SIHClient.exe") == ProcessGroup.Windows && G(@"C:\Windows\System32\CompatTelRunner.exe") == ProcessGroup.Windows,
        "Windows: Programme, Dienste (auch Dienst-Regel ohne Programm), Kern, Windows Update");
    Check(G("", "", true) == ProcessGroup.AllPrograms && G("") == ProcessGroup.Other && G(@"C:\Tools\PhotoCraft\photocraft.exe") == ProcessGroup.Other,
        "„Jeder Prozess“ in Regeln ganz oben, unbekannte und übrige Programme unter Andere");
    Check(Enum.GetValues<ProcessGroup>().Select(ProcessGroups.Title).Distinct().Count() == Enum.GetValues<ProcessGroup>().Length
          && ProcessGroups.Title(ProcessGroup.AI) == "KI" && ProcessGroups.Title(ProcessGroup.Other) == "Andere Programme",
        "jede Gruppe hat eine eigene Überschrift");
    Check(new Settings().GroupLists && System.Text.Json.JsonSerializer.Deserialize<Settings>("{}")!.GroupLists
          && !System.Text.Json.JsonSerializer.Deserialize<Settings>("{\"GroupLists\":false}")!.GroupLists,
        "Gruppieren ist eingeschaltet, auch bei einer älteren config.json ohne den Eintrag, und lässt sich abschalten");
    KnownApps.Configure("", "", "");
    WindowsProcesses.Configure("", "");
    WindowsComponents.Configure("", "", "", "");
}

// ---- Windows-Dienste einzeln (svchost.exe): sehen und regeln
{
    const string Svc = @"C:\Windows\System32\svchost.exe";
    Connection S(string service) => new()
    {
        ProcessPath = Svc, Service = service, Pid = 1200, Direction = Direction.Outgoing, Protocol = Proto.Tcp,
        Remote = IpKey.From(IPAddress.Parse("20.42.65.92")), Port = 443, Hostnames = ["v10.events.data.microsoft.com"],
    };
    var ss = new Store();
    FactoryRules.Ensure(ss, @"C:\Windows");
    ss.Rules.Add(new Rule { Action = RuleAction.Deny, Process = Svc, Service = "DiagTrack" });
    var srs = RuleSet.Build(ss, "boot");
    Check(srs.Evaluate(S("DiagTrack"), now).Action == RuleAction.Deny && srs.Evaluate(S("wuauserv"), now).Action == RuleAction.Allow
          && srs.Evaluate(S(""), now).Action == RuleAction.Allow,
        "„DiagTrack verbieten“ geht der svchost-Werksregel vor, andere Dienste bleiben erlaubt");
    var anyProcess = new Store();
    FactoryRules.Ensure(anyProcess, @"C:\Windows");
    anyProcess.Rules.Add(new Rule { Action = RuleAction.Deny, Service = "diagtrack" });
    var apRules = RuleSet.Build(anyProcess, "boot");
    Check(apRules.Evaluate(S("DiagTrack"), now).Action == RuleAction.Deny && apRules.Evaluate(S("wuauserv"), now).Action == RuleAction.Allow,
        "Dienst ohne Programmangabe (Groß/klein egal) schlägt die svchost-Werksregel");

    var sp = new FakeProcs();
    var se = new FirewallEngine(ss, sp, "boot", () => now);
    sp.Ports[(true, 52000)] = new ProcessInfo(1200, Svc, "DiagTrack");
    sp.Ports[(true, 52001)] = new ProcessInfo(1201, Svc, "wuauserv");
    var sm = new PacketMeta(true, false, 7, 0);
    Check(se.Process(V4(6, "192.168.1.10", "20.42.65.92", TcpSyn(52000, 443, 1)), sm, out _) == Verdict.Reject
          && se.Process(V4(6, "192.168.1.10", "20.42.65.92", TcpSyn(52001, 443, 1)), sm, out _) == Verdict.Pass,
        "Engine: Telemetrie-Dienst abgewiesen, Windows Update durchgelassen");
    var rows = se.History.Snapshot().Where(r => r.ProcessPath == Svc).ToList();
    Check(rows.Count == 2 && rows.Any(r => r.Service == "DiagTrack" && r.Allowed == false) && rows.Any(r => r.Service == "wuauserv" && r.Allowed == true),
        "Monitor: je Dienst eine eigene Zeile");
    var fromMonitor = AlertRules.Create(rows.First(r => r.Service == "wuauserv").Template, false, AlertScope.Host, AlertLifetime.Forever, "boot", null, now)!;
    Check(fromMonitor.Service == "wuauserv" && fromMonitor.Process == Svc, "Regel aus einer Monitor-Zeile gilt für den Dienst");

    var wideSvc = new Rule { Action = RuleAction.Deny, Process = Svc };
    var narrowSvc = new Rule { Action = RuleAction.Deny, Process = Svc, Service = "DiagTrack", Remote = RemoteKind.Hosts, Targets = ["v10.events.data.microsoft.com"] };
    var svcAny = new Rule { Action = RuleAction.Deny, Process = Svc, Service = "DiagTrack" };
    var plainHost = new Rule { Action = RuleAction.Deny, Process = Svc, Remote = RemoteKind.Hosts, Targets = ["x.example"] };
    Check(RuleCleanup.MakesRedundant(wideSvc, narrowSvc, [wideSvc, narrowSvc]) && !RuleCleanup.MakesRedundant(svcAny, plainHost, [svcAny, plainHost])
          && !svcAny.SameScope(wideSvc) && !RuleCleanup.Mergeable(narrowSvc, plainHost),
        "Aufräumen: Regel ohne Dienst erfasst jeden Dienst, eine Dienst-Regel nur ihren");
    var reread = LsRules.Parse(LsRules.Export("x", [svcAny])).Rules.Single();
    Check(reread.Service == "DiagTrack" && reread.Process == Svc, "Export/Import behält den Dienst");
    Rule.ServiceTitle = s => s.Equals("DiagTrack", StringComparison.OrdinalIgnoreCase) ? "Telemetrie" : null;
    Check(svcAny.ProcessName == "Windows-Dienst: Telemetrie" && new Rule { Process = Svc, Service = "Foo" }.ProcessName == "Windows-Dienst: Foo", "Regelliste zeigt den Dienst");
    Rule.ServiceTitle = _ => null;
}

// ---- Bestehende Verbindung trennen (IPv6): RSTs aus einem beobachteten Segment
{
    byte[] Segment(byte flags, uint seq, uint ack, int payload)
    {
        var t = TcpSyn(50500, 443, seq, flags);
        BinaryPrimitives.WriteUInt32BigEndian(t.AsSpan(8), ack);
        return [.. t, .. new byte[payload]];
    }
    var seg6 = V6(6, "2001:db8::10", "2606:4700::1111", Segment(0x18 /*PSH|ACK*/, 1000, 77000, 100));
    var resets = Packet.BuildFlowResets(seg6);
    PacketInfo Info(byte[] p) { Packet.TryParse(p, out var info); return info; }
    var f1 = Info(resets[0].Packet);
    var f2 = Info(resets[1].Packet);
    var toSender = Info(resets[2].Packet);
    Check(resets.Count == 3 && !resets[0].ToSender && !resets[1].ToSender && resets[2].ToSender, "IPv6: zwei RSTs in Richtung des Segments, eins zurück");
    Check(f1.V6 && f1.Src == IpKey.From(IPAddress.Parse("2001:db8::10")) && f1.Dst == IpKey.From(IPAddress.Parse("2606:4700::1111")) && f1.SrcPort == 50500 && f1.DstPort == 443
          && f1.Seq == 1000 && f2.Seq == 1100,
        "Richtung des Segments: Folgenummer vor und nach seinen 100 Bytes");
    Check(toSender.Src == IpKey.From(IPAddress.Parse("2606:4700::1111")) && toSender.SrcPort == 443 && toSender.DstPort == 50500 && toSender.Seq == 77000,
        "zurück an den Absender mit dessen Bestätigungsnummer, Adressen und Ports vertauscht");
    Check(resets.All(r => r.Packet[40 + 13] == 0x04 && Packet.TransportChecksum(r.Packet, true, 40, Packet.Tcp) == 0), "nur RST-Flag, TCP-Prüfsumme stimmt");
    Check(Packet.BuildFlowResets(V6(6, "2001:db8::10", "2606:4700::1111", Segment(0x04, 5, 0, 0))).Count == 0, "auf ein RST folgt kein RST");
    var seg4 = V4(6, "192.168.1.10", "93.184.216.34", Segment(0x11 /*FIN|ACK*/, 4000, 9000, 0));
    var r4 = Packet.BuildFlowResets(seg4);
    Check(r4.Count == 3 && Info(r4[1].Packet).Seq == 4001 && Packet.Checksum(r4[0].Packet.AsSpan(0, 20)) == 0
          && Packet.TransportChecksum(r4[2].Packet, false, 20, Packet.Tcp) == 0,
        "IPv4: FIN zählt eine Folgenummer, IP- und TCP-Prüfsumme stimmen");
}

// ---- Profil automatisch je Netzwerk
{
    var npSettings = new Settings { Profiles = ["Zuhause", "Unterwegs"] };
    npSettings.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{A}", Name = "FRITZ!Box", Profile = "Zuhause" });
    npSettings.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{B}", Name = "Büro", Profile = null });
    ConnectedNetwork Net(string id, string name = "x") => new(id, name);
    Check(NetworkProfiles.Choose([Net("{a}", "FRITZ!Box")], npSettings) == (true, "Zuhause", "FRITZ!Box"), "zugeordnetes Netzwerk (Groß/klein egal) schaltet auf sein Profil");
    Check(NetworkProfiles.Choose([Net("{B}", "Büro")], npSettings) == (true, null, "Büro"), "Zuordnung „Kein Profil“");
    Check(!NetworkProfiles.Choose([Net("{C}", "Café")], npSettings).Switch && !NetworkProfiles.Choose([], npSettings).Switch,
        "unbekanntes Netz ohne Profil für andere Netzwerke und kein Netz: nichts umschalten");
    npSettings.SwitchOnUnknownNetwork = true;
    npSettings.UnknownNetworkProfile = "Unterwegs";
    Check(NetworkProfiles.Choose([Net("{C}", "Café")], npSettings) == (true, "Unterwegs", "Café"), "unbekanntes Netz: Profil für andere Netzwerke");
    Check(NetworkProfiles.Choose([Net("{C}", "Café"), Net("{A}", "FRITZ!Box")], npSettings).Profile == "Zuhause", "eine Zuordnung geht dem Profil für andere Netzwerke vor");
    npSettings.Profiles.Remove("Zuhause");
    Check(NetworkProfiles.Choose([Net("{A}", "FRITZ!Box")], npSettings).Profile == "Unterwegs", "Zuordnung zu einem gelöschten Profil zählt nicht");
    npSettings.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{D}", Name = "Hotspot", NoSwitch = true });
    Check(NetworkProfiles.Choose([Net("{D}", "Hotspot")], npSettings) == (false, null, "Hotspot"),
        "„Nicht automatisch wechseln“ gilt auch, wenn andere Netzwerke ein Profil haben");

    // Zuordnungen ändern: nur umschalten, wenn es die verbundenen Netzwerke betrifft.
    var cb = new Settings { Profiles = ["Zuhause", "Unterwegs", "Arbeit"], ActiveProfile = "Unterwegs" }; // von Hand gewählt
    cb.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{A}", Name = "FRITZ!Box", Profile = "Zuhause" });
    IReadOnlyList<ConnectedNetwork> home = [Net("{A}", "FRITZ!Box")];
    Check(!NetworkProfiles.ChangeBindings(home, cb, s => s.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Hotel", Profile = "Arbeit" }))
          && cb.ActiveProfile == "Unterwegs", "Zuordnung eines anderen Netzes lässt das von Hand gewählte Profil");
    Check(!NetworkProfiles.ChangeBindings(home, cb, s => { s.SwitchOnUnknownNetwork = true; s.UnknownNetworkProfile = "Arbeit"; }) && cb.ActiveProfile == "Unterwegs",
        "„Andere Netzwerke“ ändern lässt es bei zugeordnetem Netz ebenso");
    Check(NetworkProfiles.ChangeBindings(home, cb, s => s.NetworkProfiles[0].Profile = "Arbeit") && cb.ActiveProfile == "Arbeit",
        "neue Zuordnung des verbundenen Netzes schaltet sofort um");
    cb.ActiveProfile = "Zuhause";
    Check(!NetworkProfiles.ChangeBindings(home, cb, s => { s.NetworkProfiles[0].NoSwitch = true; s.NetworkProfiles[0].Profile = null; }) && cb.ActiveProfile == "Zuhause",
        "„Nicht automatisch wechseln“ schaltet nicht auf das Profil für andere Netzwerke");
    Check(NetworkProfiles.ChangeBindings(home, cb, s => s.NetworkProfiles.RemoveAt(0)) && cb.ActiveProfile == "Arbeit",
        "„Wie andere Netzwerke“ übernimmt deren Profil");

    // Mehrere Netze zugleich (LAN an der Dockingstation, Gast-WLAN, VPN).
    var mn = new Settings { Profiles = ["Arbeit", "Unterwegs"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    mn.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "firma.local", Profile = "Arbeit" });
    mn.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{GAST}", Name = "Firma-Gast", Profile = "Unterwegs" });
    IReadOnlyList<ConnectedNetwork> docked = [Net("{GAST}", "Firma-Gast"), Net("{LAN}", "firma.local")];
    Check(NetworkProfiles.Choose(docked, mn) == (true, "Arbeit", "firma.local"), "bei zwei zugeordneten Netzen gilt die ältere Zuordnung");
    NetworkProfiles.SetBinding(mn, "{lan}", new NetworkProfile { NetworkId = "{LAN}", Name = "firma.local", Profile = null });
    Check(mn.NetworkProfiles[0].NetworkId == "{LAN}" && mn.NetworkProfiles.Count == 2 && NetworkProfiles.Choose(docked, mn) == (true, null, "firma.local"),
        "eine geänderte Zuordnung behält ihre Stelle (ihren Vorrang)");
    NetworkProfiles.SetBinding(mn, "{GAST}", new NetworkProfile { NetworkId = "{GAST}", Name = "Firma-Gast", NoSwitch = true });
    NetworkProfiles.SetBinding(mn, "{LAN}", new NetworkProfile { NetworkId = "{LAN}", Name = "firma.local", Profile = "Arbeit" });
    Check(NetworkProfiles.Choose(docked, mn) == (true, "Arbeit", "firma.local"), "ein Netz mit „Nicht automatisch wechseln“ daneben zählt nicht");
    Check(NetworkProfiles.Choose([Net("{GAST}", "Firma-Gast"), Net("{CAFE}", "Café")], mn) == (true, "Unterwegs", "Café"),
        "… auch nicht neben einem unbekannten Netz: dort gilt das Profil für andere Netzwerke");
    NetworkProfiles.SetBinding(mn, "{GAST}", null);
    NetworkProfiles.SetBinding(mn, "{NEU}", new NetworkProfile { NetworkId = "{NEU}", Name = "Neu", Profile = "Arbeit" });
    Check(mn.NetworkProfiles.Select(b => b.NetworkId).SequenceEqual(["{LAN}", "{NEU}"]), "„Wie andere Netzwerke“ entfernt die Zuordnung, eine neue kommt ans Ende");

    // Netzwerkwechsel erkennen – so wie der Watcher: Observe, Stand übernehmen, bei einem Wechsel das Profil neu bestimmen.
    bool See(Settings s, bool placeGone, params string[] ids)
    {
        var nets = ids.Select(id => Net(id, id)).ToList();
        if (NetworkProfiles.Observe(nets, s, placeGone) is not { } seen) return false;
        s.NetworkPlace = seen.Place;
        s.NetworkExtras = seen.Extras;
        if (!seen.Changed) return false;
        if (NetworkProfiles.Choose(nets, s) is (true, var p, _)) s.ActiveProfile = p;
        return true;
    }
    var ob = new Settings { Profiles = ["Zuhause", "Unterwegs", "Arbeit"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    ob.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" });
    Check(See(ob, false, "{H}") && ob.ActiveProfile == "Zuhause", "erstes Netz: Profil bestimmen");
    ob.ActiveProfile = "Arbeit"; // von Hand
    Check(!See(ob, false, "{H}", "{VPN}") && !See(ob, false, "{VPN}") && !See(ob, false) && !See(ob, false, "{H}", "{VPN}") && ob.ActiveProfile == "Arbeit",
        "VPN kommt dazu, das WLAN fällt kurz weg (nur VPN, dann gar kein Netz) und kommt wieder: die Wahl von Hand bleibt");
    Check(See(ob, true, "{VPN}") && ob.ActiveProfile == "Unterwegs", "fehlt das Heimnetz länger, gilt das Profil für das, was noch verbunden ist");
    Check(See(ob, false, "{H}", "{VPN}") && ob.ActiveProfile == "Zuhause", "zurück zu Hause: wieder „Zuhause“");

    var cf = new Settings { Profiles = ["Unterwegs", "Arbeit"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    Check(See(cf, false, "{CAFE}") && cf.ActiveProfile == "Unterwegs", "unbekanntes Netz: Profil für andere Netzwerke");
    cf.ActiveProfile = "Arbeit";
    Check(!See(cf, false, "{CAFE}", "{VPN}") && !See(cf, false, "{VPN}") && cf.ActiveProfile == "Arbeit", "im Café: VPN dazu, WLAN kurz weg – kein Wechsel");
    Check(See(cf, false, "{HOTEL}", "{VPN}") && cf.ActiveProfile == "Unterwegs", "neues unbekanntes Netz, während das VPN weiterläuft: Wechsel");
    cf.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{WORKVPN}", Name = "Firmen-VPN", Profile = "Arbeit" });
    Check(See(cf, false, "{HOTEL}", "{VPN}", "{WORKVPN}") && cf.ActiveProfile == "Arbeit", "ein neu verbundenes, zugeordnetes Netz (Firmen-VPN) schaltet sofort um");
    Check(!See(cf, false, "{HOTEL}", "{VPN}") && cf.ActiveProfile == "Arbeit" && See(cf, true, "{HOTEL}", "{VPN}") && cf.ActiveProfile == "Unterwegs",
        "trennt es sich, gilt nach der Frist wieder das Profil des Hotels");
    cf.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{VPN}", Name = "VPN", NoSwitch = true });
    Check(NetworkProfiles.Observe([Net("{VPN}")], cf, false) == null && NetworkProfiles.Observe([], cf, true) == null
          && NetworkProfiles.Observe([Net("{VPN}")], cf, true) is { Changed: false, Place.Count: 0 },
        "nur Netze mit „Nicht automatisch wechseln“ oder gar keins: nie ein Wechsel (länger nur solche: der Ort wird vergessen)");

    // Heimnetz auf „Nicht automatisch wechseln“: zu Hause von Hand gewählt, am nächsten Morgen im Büro gilt wieder das Büroprofil.
    var ns = new Settings { Profiles = ["Arbeit", "Zuhause"] };
    ns.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "Büro", Profile = "Arbeit" });
    ns.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", NoSwitch = true });
    See(ns, false, "{LAN}");
    Check(!NetworkProfiles.PlaceConnected([Net("{H}")], ns) && NetworkProfiles.PlaceConnected([], ns), "nur das Heimnetz (ohne Wechsel) verbunden: der Ort fehlt; gar kein Netz: zählt nicht");
    Check(!See(ns, false, "{H}") && ns.NetworkPlace.SequenceEqual(["{lan}"]), "kurz nur ein solches Netz (Hotspot im Aufzug): der Ort bleibt");
    Check(!See(ns, true, "{H}") && ns.NetworkPlace.Count == 0 && ns.ActiveProfile == "Arbeit", "länger: der Ort wird vergessen, ohne umzuschalten");
    ns.ActiveProfile = "Zuhause"; // von Hand
    Check(See(ns, false, "{LAN}") && ns.ActiveProfile == "Arbeit", "zurück im Büro: wieder „Arbeit“");

    // Dauerhaft verbundener Adapter (WSL/Hyper-V): wird nie zum Ort.
    var pad = new Settings { Profiles = ["Zuhause", "Unterwegs", "Streng"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    pad.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" });
    See(pad, false, "{H}");
    See(pad, false, "{H}", "{VETH}");
    Check(See(pad, true, "{VETH}") && pad.ActiveProfile == "Unterwegs" && pad.NetworkPlace.Count == 0 && pad.NetworkExtras.SequenceEqual(["{veth}"]),
        "Heimnetz lange weg, nur der Adapter bleibt: Profil für andere Netzwerke, der Ort ist leer");
    Check(See(pad, false, "{CAFE}", "{VETH}") && pad.NetworkPlace.SequenceEqual(["{cafe}"]), "im Café ist das Café der Ort, nicht der Adapter");
    pad.ActiveProfile = "Streng";
    Check(!See(pad, false, "{CAFE}") && pad.ActiveProfile == "Streng", "WSL beendet: kein Wechsel");
    pad.ActiveProfile = "Streng";
    Check(See(pad, false, "{HOTEL}", "{VETH}") && pad.ActiveProfile == "Unterwegs", "nächster Tag im Hotel: Wechsel");
    var tsv = new Settings { Profiles = ["Zuhause", "Unterwegs"] };
    See(tsv, false, "{H}", "{TS}"); // erster Start: beide zugleich neu
    NetworkProfiles.ChangeBindings([Net("{H}"), Net("{TS}")], tsv, s => { s.SwitchOnUnknownNetwork = true; s.UnknownNetworkProfile = "Unterwegs"; });
    tsv.ActiveProfile = "Zuhause";
    Check(See(tsv, false, "{TS}", "{CAFE}") && tsv.ActiveProfile == "Unterwegs",
        "erster Start mit Dauer-VPN im Ort: im Café (Heimnetz fehlt, neues Netz) wird trotzdem gewechselt");

    // „Unterwegs“ (Ort leer, Büro-WLAN als Extra), dann länger nur ein Netz mit „Nicht automatisch wechseln“: auch die Extras vergessen.
    var aw = new Settings { Profiles = ["Arbeit", "Unterwegs", "Zuhause"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    aw.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "Dock", Profile = "Arbeit" });
    aw.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", NoSwitch = true });
    See(aw, false, "{LAN}", "{W}");
    See(aw, true, "{W}");
    Check(aw.NetworkPlace.Count == 0 && aw.NetworkExtras.SequenceEqual(["{w}"]) && !NetworkProfiles.PlaceConnected([Net("{H}")], aw)
          && !See(aw, true, "{H}") && aw.NetworkExtras.Count == 0, "unterwegs, dann länger nur das Heimnetz (ohne Wechsel): alles Gemerkte vergessen");
    aw.ActiveProfile = "Zuhause";
    Check(See(aw, false, "{W}") && aw.ActiveProfile == "Unterwegs", "am nächsten Tag im Büro-WLAN: wieder das Profil für andere Netzwerke");
    var ow = new Settings { Profiles = ["Arbeit", "Unterwegs", "Streng"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    ow.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "Dock", Profile = "Arbeit" });
    See(ow, false, "{LAN}", "{W}");
    See(ow, true, "{W}");
    NetworkProfiles.ChangeBindings([], ow, s => s.UnknownNetworkProfile = "Streng");
    Check(ow.NetworkExtras.Count == 0 && See(ow, false, "{W}") && ow.ActiveProfile == "Streng",
        "offline geändertes Profil für andere Netzwerke gilt auch bei leerem Ort beim nächsten Verbinden");

    // Während der Frist geändert: entschieden wird, als wäre der fehlende Ort noch da.
    var gd = new Settings { Profiles = ["Arbeit", "Unterwegs", "Streng"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    gd.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "Dock", Profile = "Arbeit" });
    See(gd, false, "{LAN}", "{W}");
    Check(!NetworkProfiles.ChangeBindings([Net("{W}")], gd, s => s.UnknownNetworkProfile = "Streng") && gd.ActiveProfile == "Arbeit"
          && !See(gd, false, "{LAN}", "{W}") && gd.ActiveProfile == "Arbeit", "abgedockt „Andere Netzwerke“ geändert, wieder angedockt: weiter „Arbeit“");
    Check(See(gd, true, "{W}") && gd.ActiveProfile == "Streng", "… läuft die Frist ab, gilt das geänderte Profil des WLANs");
    var gv = new Settings { Profiles = ["Zuhause", "Arbeit"] };
    gv.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" });
    See(gv, false, "{H}");
    See(gv, false, "{H}", "{VETH}");
    Check(NetworkProfiles.ChangeBindings([Net("{VETH}")], gv, s => s.NetworkProfiles[0].Profile = "Arbeit") && gv.ActiveProfile == "Arbeit"
          && !See(gv, false, "{H}", "{VETH}") && gv.ActiveProfile == "Arbeit", "WLAN-Aussetzer, dabei Heimnetz umgestellt: gilt sofort und bleibt");

    // Ort aus mehreren Netzen vom ersten Start: eine Änderung verkleinert ihn nicht auf den Dauer-Adapter.
    var fs2 = new Settings { Profiles = ["Zuhause", "Unterwegs"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    See(fs2, false, "{H}", "{VETH}");
    NetworkProfiles.ChangeBindings([Net("{H}"), Net("{VETH}")], fs2, s => NetworkProfiles.SetBinding(s, "{H}", new NetworkProfile { NetworkId = "{H}", Name = "Heim", NoSwitch = true }));
    fs2.ActiveProfile = "Zuhause";
    Check(!See(fs2, false, "{H}", "{VETH}", "{VPN}") && fs2.ActiveProfile == "Zuhause", "Heimnetz ohne Wechsel, VPN kommt dazu: die Wahl von Hand bleibt");
    Check(See(fs2, false, "{VETH}", "{CAFE}") && fs2.ActiveProfile == "Unterwegs", "… im Café wird gewechselt, obwohl der Adapter weiter verbunden ist");

    // Von Hand gewählt, während man nicht am gemerkten Ort ist: die Wahl gilt dem Netz, in dem man gerade ist.
    var bh = new Settings { Profiles = ["Arbeit", "Unterwegs", "Zuhause", "Streng"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    bh.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "Dock", Profile = "Arbeit" });
    bh.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", NoSwitch = true });
    See(bh, false, "{CAFE}");
    NetworkProfiles.ChooseByHand([Net("{CAFE}")], bh, "Streng");
    Check(bh.ActiveProfile == "Streng" && bh.NetworkPlace.SequenceEqual(["{cafe}"]), "am Ort von Hand gewählt: der Ort bleibt");
    NetworkProfiles.ChooseByHand([Net("{H}")], bh, "Zuhause"); // kurz zu Hause (ohne Wechsel), dann zugeklappt
    Check(bh.NetworkPlace.Count == 0 && See(bh, false, "{CAFE}") && bh.ActiveProfile == "Unterwegs",
        "zu Hause nur kurz von Hand gewählt: am nächsten Tag im Café trotzdem das Profil für andere Netzwerke");
    See(bh, false, "{LAN}", "{W}");
    NetworkProfiles.ChooseByHand([Net("{W}")], bh, "Streng"); // abgedockt, Frist läuft
    Check(!See(bh, true, "{W}") && bh.ActiveProfile == "Streng" && See(bh, false, "{LAN}", "{W}") && bh.ActiveProfile == "Arbeit",
        "abgedockt von Hand gewählt: bleibt nach der Frist; wieder angedockt gilt „Arbeit“");

    // „Unterwegs“ mit Dauer-Adapter: ein kurzer WLAN-Aussetzer zählt bei der Rückkehr nicht als neues Netz.
    var ua = new Settings { Profiles = ["Arbeit", "Unterwegs", "Streng"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    ua.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "Dock", Profile = "Arbeit" });
    See(ua, false, "{LAN}", "{W}", "{VETH}");
    See(ua, true, "{W}", "{VETH}");
    ua.ActiveProfile = "Streng";
    Check(!NetworkProfiles.PlaceConnected([Net("{VETH}")], ua) && !See(ua, false, "{VETH}") && !See(ua, false, "{W}", "{VETH}") && ua.ActiveProfile == "Streng",
        "unterwegs: WLAN kurz weg (nur der Adapter) und zurück – die Wahl von Hand bleibt");
    Check(!See(ua, true, "{VETH}") && ua.NetworkExtras.SequenceEqual(["{veth}"]), "… fehlt es länger, wird es vergessen");

    // Während der Frist zugeordnet: das jetzt entscheidende, verbundene Netz wird zum Ort.
    var tt = new Settings { Profiles = ["Unterwegs", "Streng"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    See(tt, false, "{CAFE}");
    See(tt, false, "{CAFE}", "{T}");
    Check(NetworkProfiles.ChangeBindings([Net("{T}")], tt, s => s.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{T}", Name = "Tethering", Profile = "Streng" }))
          && tt.ActiveProfile == "Streng" && tt.NetworkPlace.SequenceEqual(["{t}"]) && See(tt, false, "{CAFE}") && tt.ActiveProfile == "Unterwegs",
        "WLAN weg, Tethering zugeordnet: gilt sofort; WLAN zurück und Tethering ab: wieder das Café-Profil");

    // Ort aus mehreren Netzen: ein gerade getrenntes Mitglied wird zugeordnet – seine Rückkehr schaltet um.
    var mm = new Settings { Profiles = ["Arbeit", "Unterwegs"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    See(mm, false, "{LAN2}", "{W2}");
    NetworkProfiles.ChangeBindings([Net("{W2}")], mm, s => s.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN2}", Name = "Cowork-LAN", Profile = "Arbeit" }));
    Check(mm.NetworkPlace.SequenceEqual(["{w2}"]) && See(mm, false, "{LAN2}", "{W2}") && mm.ActiveProfile == "Arbeit", "Cowork-LAN abgedockt zugeordnet: beim Andocken „Arbeit“");

    // Profil löschen während der Frist: der Rückfall zählt den fehlenden Ort mit.
    var pd = new Settings { Profiles = ["Zuhause", "Unterwegs", "Streng"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    pd.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" });
    See(pd, false, "{H}", "{VETH}");
    Check(NetworkProfiles.ChooseHere([Net("{VETH}")], pd) == (true, "Zuhause", "{h}") && NetworkProfiles.Choose([Net("{VETH}")], pd).Profile == "Unterwegs",
        "WLAN-Aussetzer: für den Rückfall gilt weiter das Heimnetz");

    // Von Hand auf dem Hotspot gewählt, während „unterwegs“ nur Extras gemerkt sind: auch dann gilt die Wahl nur dem Hotspot.
    var hh = new Settings { Profiles = ["Arbeit", "Unterwegs", "Zuhause"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    hh.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "Dock", Profile = "Arbeit" });
    hh.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{D}", Name = "Hotspot", NoSwitch = true });
    See(hh, false, "{LAN}", "{W}");
    See(hh, true, "{W}");
    NetworkProfiles.ChooseByHand([Net("{D}")], hh, "Zuhause");
    Check(hh.NetworkExtras.Count == 0 && See(hh, false, "{W}") && hh.ActiveProfile == "Unterwegs", "zurück im Büro-WLAN: wieder das Profil für andere Netzwerke");

    // Eine Änderung während der Frist verschluckt den anstehenden Wechsel nicht.
    var gr = new Settings { Profiles = ["Arbeit", "Unterwegs", "Gast"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    gr.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "Dock", Profile = "Arbeit" });
    See(gr, false, "{LAN}", "{W}");
    NetworkProfiles.ChangeBindings([Net("{W}")], gr, s => s.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{X}", Name = "X", Profile = "Gast" }));
    Check(gr.NetworkPlace.SequenceEqual(["{lan}"]) && See(gr, true, "{W}") && gr.ActiveProfile == "Unterwegs",
        "abgedockt, während der Frist eine Zuordnung geändert: nach der Frist trotzdem das Profil des WLANs");

    // Noch nicht identifizierte Netze (nach einem Router-Neustart) zählen erst nach 90 s.
    var su = new StableNetworks();
    Check(su.Update([new ConnectedNetwork("{U}", "Nicht identifiziertes Netzwerk", false)], 0) is ({ Count: 0 }, 90_000)
          && su.Update([new ConnectedNetwork("{U}", "x", false)], 60_000).Stable.Count == 0 && su.Update([new ConnectedNetwork("{U}", "x", false)], 90_000).Stable.Count == 1,
        "ein nicht identifiziertes Netz zählt erst nach 90 s");

    // Übergangsnetz beim Verbinden („Netzwerkidentifizierung…“): erst nach 5 s ohne Unterbrechung zählt ein Netz.
    var sn = new StableNetworks();
    var trs = new Settings { Profiles = ["Zuhause", "Arbeit"] };
    trs.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" });
    bool SeeAt(long ms, params string[] ids)
    {
        var (stable, _) = sn.Update(ids.Select(id => Net(id, id)).ToList(), ms);
        return See(trs, false, stable.Select(n => n.Id).ToArray());
    }
    Check(sn.Update([Net("{H}")], 0) is ({ Count: 0 }, 5000) && !SeeAt(500, "{H}") && SeeAt(5500, "{H}") && trs.ActiveProfile == "Zuhause",
        "ein Netz zählt erst, wenn es 5 s verbunden ist");
    trs.ActiveProfile = "Arbeit"; // von Hand
    Check(!SeeAt(20_000) && !SeeAt(22_000, "{IDENT}") && !SeeAt(24_000, "{H}") && !SeeAt(30_000, "{H}") && trs.ActiveProfile == "Arbeit",
        "Aufwachen: kein Netz, kurz das Übergangsnetz, dann wieder das Heimnetz – die Wahl von Hand bleibt");

    // Ein dauerhaft verbundener virtueller Adapter (WSL, Hyper-V) gerät beim ersten Start in den Ort; das darf später nicht hängen bleiben.
    var ve2 = new Settings { Profiles = ["Zuhause", "Unterwegs"] };
    Check(See(ve2, false, "{H}", "{VETH}") && ve2.NetworkPlace.Count == 2, "erste Prüfung ohne Zuordnung: beide Netze bilden den Ort");
    NetworkProfiles.ChangeBindings([Net("{H}"), Net("{VETH}")], ve2, s =>
    {
        NetworkProfiles.SetBinding(s, "{H}", new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" });
        s.SwitchOnUnknownNetwork = true;
        s.UnknownNetworkProfile = "Unterwegs";
    });
    Check(ve2.ActiveProfile == "Zuhause" && ve2.NetworkPlace.SequenceEqual(["{h}"]) && ve2.NetworkExtras.SequenceEqual(["{veth}"]),
        "wird das Heimnetz zugeordnet, ist nur noch es der Ort, der Adapter ein Extra");
    Check(See(ve2, false, "{CAFE}", "{VETH}") && ve2.ActiveProfile == "Unterwegs", "im Café (Adapter weiter verbunden) gilt das Profil für andere Netzwerke");
    var ve3 = new Settings { Profiles = ["Zuhause", "Unterwegs"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    See(ve3, false, "{H}", "{VETH}");
    ve3.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" }); // ohne ChangeBindings geändert
    Check(NetworkProfiles.Observe([Net("{H}"), Net("{VETH}")], ve3, false) is { Changed: false } shrink && shrink.Place.SequenceEqual(["{h}"]),
        "auch die Prüfung selbst verkleinert den Ort auf das entscheidende Netz");

    // Zuordnungen am verbundenen Netz: der gemerkte Ort zieht nach, eine danach von Hand gewählte Einstellung bleibt.
    var dk = new Settings { Profiles = ["Arbeit", "Unterwegs"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    dk.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "LAN", Profile = "Arbeit" });
    See(dk, false, "{LAN}", "{WLAN}");
    IReadOnlyList<ConnectedNetwork> dock = [Net("{LAN}"), Net("{WLAN}")];
    Check(NetworkProfiles.ChangeBindings(dock, dk, s => s.NetworkProfiles[0].NoSwitch = true) && dk.ActiveProfile == "Unterwegs",
        "LAN auf „Nicht automatisch wechseln“: es gilt das Profil des WLANs");
    dk.ActiveProfile = "Arbeit";
    Check(!See(dk, true, "{LAN}", "{WLAN}") && dk.ActiveProfile == "Arbeit", "… und die danach von Hand gewählte Einstellung bleibt, auch nach der Frist");
    var gs = new Settings { Profiles = ["Arbeit", "Unterwegs"] };
    gs.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{GAST}", Name = "Gast", NoSwitch = true });
    gs.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{LAN}", Name = "LAN", Profile = "Arbeit" });
    See(gs, false, "{GAST}", "{LAN}");
    Check(NetworkProfiles.ChangeBindings([Net("{GAST}"), Net("{LAN}")], gs, s => NetworkProfiles.SetBinding(s, "{GAST}",
              new NetworkProfile { NetworkId = "{GAST}", Name = "Gast", Profile = "Unterwegs" })) && gs.ActiveProfile == "Unterwegs",
        "ein bisher ignoriertes Netz bekommt ein Profil (mit Vorrang): sofort umschalten");
    gs.ActiveProfile = "Arbeit";
    Check(!See(gs, false, "{GAST}", "{LAN}") && gs.ActiveProfile == "Arbeit", "… und die nächste Prüfung hält das nicht für ein neues Netz");
    var pend = new Settings { Profiles = ["Zuhause", "Unterwegs"], SwitchOnUnknownNetwork = true, UnknownNetworkProfile = "Unterwegs" };
    pend.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" });
    See(pend, false, "{H}");
    NetworkProfiles.ChangeBindings([Net("{CAFE}")], pend, s => s.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{X}", Name = "X", Profile = "Zuhause" }));
    Check(pend.NetworkPlace.SequenceEqual(["{h}"]) && See(pend, false, "{CAFE}") && pend.ActiveProfile == "Unterwegs",
        "steht ein Netzwechsel noch aus, verschluckt eine Änderung in den Einstellungen ihn nicht");

    var off = new Settings { Profiles = ["Zuhause", "Arbeit"] };
    off.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{H}", Name = "Heim", Profile = "Zuhause" });
    See(off, false, "{H}");
    Check(!NetworkProfiles.ChangeBindings([], off, s => s.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{X}", Name = "X", Profile = "Arbeit" }))
          && off.NetworkPlace.SequenceEqual(["{h}"]), "eine unbeteiligte Änderung ohne Netz lässt den gemerkten Ort");
    Check(!NetworkProfiles.ChangeBindings([], off, s => s.NetworkProfiles[0].Profile = "Arbeit") && off.NetworkPlace.Count == 0
          && See(off, false, "{H}") && off.ActiveProfile == "Arbeit", "eine ohne Netz geänderte Zuordnung gilt beim nächsten Verbinden mit demselben Netz");
    off.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{D}", Name = "Hotspot", NoSwitch = true });
    Check(!NetworkProfiles.ChangeBindings([Net("{D}")], off, s => s.NetworkProfiles[0].Profile = "Zuhause") && off.NetworkPlace.Count == 0
          && See(off, false, "{H}") && off.ActiveProfile == "Zuhause", "… ebenso, wenn nur ein Netz mit „Nicht automatisch wechseln“ verbunden war");

    var npStore = new Store();
    npStore.Settings.Profiles.Add("Zuhause");
    npStore.Settings.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{A}", Name = "FRITZ!Box", Profile = "Zuhause" });
    npStore.Settings.NetworkProfiles.Add(new NetworkProfile { NetworkId = "{D}", Name = "Hotspot", NoSwitch = true });
    npStore.Settings.SwitchOnUnknownNetwork = true;
    npStore.Settings.NetworkPlace = ["{a}"];
    npStore.Settings.NetworkExtras = ["{vpn}"];
    npStore.Save();
    var npLoaded = Store.Load();
    Check(npLoaded.Settings.NetworkProfiles[0].Profile == "Zuhause" && npLoaded.Settings.NetworkProfiles[0].Name == "FRITZ!Box" && npLoaded.Settings.SwitchOnUnknownNetwork
          && npLoaded.Settings.NetworkProfiles[1].NoSwitch && !npLoaded.Settings.NetworkProfiles[0].NoSwitch && npLoaded.Settings.NetworkPlace.SequenceEqual(["{a}"]) && npLoaded.Settings.NetworkExtras.SequenceEqual(["{vpn}"]),
        "Zuordnungen und zuletzt gesehene Netzwerke werden gespeichert und geladen");
}

// ---- Datenmengen je Gegenstelle
{
    var vp = new FakeProcs();
    var vs = new Store();
    vs.Rules.Add(new Rule { Action = RuleAction.Allow, Process = @"C:\A\dl.exe" });
    var ve = new FirewallEngine(vs, vp, "boot", () => now);
    vp.Ports[(true, 53000)] = new ProcessInfo(70, @"C:\A\dl.exe");
    vp.Ports[(false, 53001)] = new ProcessInfo(70, @"C:\A\dl.exe");
    var vm = new PacketMeta(true, false, 7, 0);
    ve.Process(V4(6, "192.168.1.10", "93.184.216.34", TcpSyn(53000, 443, 1)), vm, out _);
    ve.Process(V4(17, "192.168.1.10", "93.184.216.34", UdpSeg(53001, 443, [1])), vm, out _);
    var volRemote = IpKey.From(IPAddress.Parse("93.184.216.34"));
    ve.History.AddVolumes([(new FlowId(volRemote, 53000, 443, Packet.Tcp), 1000, 200), (new FlowId(volRemote, 53001, 443, Packet.Udp), 50, 5),
                           (new FlowId(volRemote, 9, 9, Packet.Tcp), 999, 999)], 2);
    var tcpRow = ve.History.Snapshot().Single(r => r.Protocol == Proto.Tcp);
    var udpRow = ve.History.Snapshot().Single(r => r.Protocol == Proto.Udp);
    Check(tcpRow.Down == 1000 && tcpRow.Up == 200 && tcpRow.RateDown == 500 && udpRow.Down == 50 && udpRow.Up == 5,
        "Bytes landen bei ihrer Verbindungszeile (TCP und UDP), Rate je Sekunde, fremde Verbindung zählt nicht");
    var volVersion = ve.History.VolumeVersion;
    ve.History.AddVolumes([], 1);
    Check(tcpRow.RateDown == 0 && tcpRow.Down == 1000 && ve.History.VolumeVersion > volVersion, "ohne Verkehr fällt die Rate auf 0, die Summe bleibt");
    vp.Ports[(true, 53010)] = new ProcessInfo(71, @"C:\A\other.exe");
    ve.Process(V4(6, "192.168.1.10", "198.51.100.7", TcpSyn(53010, 443, 1)), vm, out _);
    Check(ve.History.FlowCount == 2, "eine offene Nachfrage ordnet noch nichts zu (erst die Antwort)");
    ve.Resolve(ve.Alerts[0].Id, true, null);
    ve.History.AddVolumes([(new FlowId(IpKey.From(IPAddress.Parse("198.51.100.7")), 53010, 443, Packet.Tcp), 77, 7)], 1);
    Check(ve.History.Snapshot().Single(r => r.ProcessPath == @"C:\A\other.exe").Down == 77, "auch nach einer Nachfrage gehören die Bytes zur Zeile");
    ve.Mutate(s => s.Rules.Add(new Rule { Action = RuleAction.Deny, Process = @"C:\A\bad.exe" }));
    vp.Ports[(true, 53020)] = new ProcessInfo(72, @"C:\A\bad.exe");
    ve.Process(V4(6, "192.168.1.10", "198.51.100.8", TcpSyn(53020, 443, 1)), vm, out _);
    ve.History.AddVolumes([(new FlowId(IpKey.From(IPAddress.Parse("198.51.100.8")), 53020, 443, Packet.Tcp), 40, 0)], 1);
    Check(ve.History.FlowCount == 3 && ve.History.Snapshot().Single(r => r.ProcessPath == @"C:\A\bad.exe").Down == 0,
        "verbotene Verbindung wird nicht zugeordnet (das eigene RST zählt nicht als Daten)");
    ve.History.Clear();
    ve.History.AddVolumes([(new FlowId(volRemote, 53000, 443, Packet.Tcp), 10, 10)], 1);
    Check(ve.History.Snapshot().Count == 0 && tcpRow.Down == 1000, "nach „Verlauf leeren“ zählt nichts mehr zu alten Zeilen");
    var m4 = V4(6, "192.168.1.10", "93.184.216.34", TcpSyn(53000, 443, 1));
    Check(Packet.Measure(m4, out _, out _, out var mp4s, out var mp4d, out var ma4s, out var ma4d) == m4.Length
          && ma4s == IpKey.From(IPAddress.Parse("192.168.1.10")) && ma4d == volRemote && mp4s == 53000 && mp4d == 443, "Messung liefert Adressen und Ports (IPv4)");
    var m6 = V6(17, "2001:db8::10", "2606:4700::1111", UdpSeg(5353, 53, [1, 2]));
    Check(Packet.Measure(m6, out _, out _, out _, out _, out var ma6s, out var ma6d) == m6.Length
          && ma6s == IpKey.From(IPAddress.Parse("2001:db8::10")) && ma6d == IpKey.From(IPAddress.Parse("2606:4700::1111")), "Messung liefert Adressen (IPv6)");
}

// ---- Datenmengen: verdrängt wird nach Aktivität, nicht nach Alter
{
    var fp = new FakeProcs();
    var fs = new Store();
    fs.Rules.Add(new Rule { Action = RuleAction.Allow, Process = @"C:\A\p2p.exe" });
    var fe = new FirewallEngine(fs, fp, "boot", () => now);
    var fm = new PacketMeta(true, false, 7, 0);
    void Open(ushort port, string remote = "203.0.113.5")
    {
        fp.Ports[(false, port)] = new ProcessInfo(80, @"C:\A\p2p.exe");
        fe.Process(V4(17, "192.168.1.10", remote, UdpSeg(port, 6881, [1])), fm, out _);
    }
    var peer = IpKey.From(IPAddress.Parse("203.0.113.5"));
    var tunnel = new FlowId(peer, 1000, 6881, Packet.Udp);
    Open(1000);
    Open(1001);
    for (var i = 0; i < ConnectionLog.MaxFlows; i++)
    {
        Open((ushort)(2000 + i));
        if (i % 1000 == 0) fe.History.AddVolumes([(tunnel, 10, 0)], 1); // die frühe Verbindung hat weiter Verkehr
    }
    fe.History.AddVolumes([(tunnel, 10, 0), (new FlowId(peer, 1001, 6881, Packet.Udp), 10, 0)], 1);
    var peerRow = fe.History.Snapshot().Single();
    Check(fe.History.FlowCount <= ConnectionLog.MaxFlows && peerRow.Down == 51 * 10,
        "eine früh zugeordnete Verbindung mit Verkehr bleibt, eine untätige fällt heraus");

    // Zeilen: Wer Verkehr hat, bleibt; mit einer verdrängten Zeile fallen ihre Verbindungen heraus.
    fe.History.Clear();
    Open(3000, "198.51.100.1");
    Open(3001, "198.51.100.2");
    var keep = new FlowId(IpKey.From(IPAddress.Parse("198.51.100.1")), 3000, 6881, Packet.Udp);
    var gone = new FlowId(IpKey.From(IPAddress.Parse("198.51.100.2")), 3001, 6881, Packet.Udp);
    var goneRow = fe.History.Snapshot().Single(r => r.Host == "198.51.100.2");
    for (var i = 0; i < ConnectionLog.Max; i++)
    {
        Open((ushort)(4000 + i), $"10.0.{i / 256}.{i % 256}");
        if (i % 100 == 0) fe.History.AddVolumes([(keep, 1, 0)], 1);
    }
    fe.History.AddVolumes([(gone, 5, 0)], 1);
    var rowHosts = fe.History.Snapshot().Select(r => r.Host).ToHashSet();
    Check(rowHosts.Contains("198.51.100.1") && !rowHosts.Contains("198.51.100.2") && goneRow.Down == 0,
        "Zeile mit Verkehr bleibt; die verdrängte zählt nicht im Verborgenen weiter");
}

// ---- Sprachen: jede Tabelle vollständig, Platzhalter unverändert, string.Format scheitert nicht
Check(Loc.Normalize("pt-BR") == "pt" && Loc.Normalize("zh-Hans") == "zh" && Loc.Normalize("xx") == "en" && Loc.Normalize(null) == "en", "Sprachcodes");
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir != null && !File.Exists(Path.Combine(dir.FullName, "src", "SnitchBox.Core", "Lang", "_source.json"))) dir = dir.Parent;
    Check(dir != null, "Vorlage Lang/_source.json gefunden");
    if (dir != null)
    {
        var source = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(Path.Combine(dir.FullName, "src", "SnitchBox.Core", "Lang", "_source.json")))!;
        var placeholder = new System.Text.RegularExpressions.Regex(@"\{(\d+)(?:[,:][^}]*)?\}");
        string Holes(string s) => string.Join(",", placeholder.Matches(s).Select(m => m.Groups[1].Value).Order());
        foreach (var (code, _) in Loc.Languages)
        {
            if (code is "de" or "en") continue;
            var table = Loc.Load(code);
            var missing = source.Keys.Count(k => !table.TryGetValue(k, out var v) || v.Trim().Length == 0);
            var broken = table.Where(p =>
            {
                try { _ = string.Format(p.Value, 1, 2, 3); return Holes(p.Key) != Holes(p.Value); }
                catch (FormatException) { return true; }
            }).Select(p => p.Key).ToList();
            Check(missing == 0 && broken.Count == 0, $"Sprache {code}: {missing} fehlen, {broken.Count} mit kaputten Platzhaltern {string.Join(" | ", broken.Take(3))}");
        }
    }
    Loc.Language = "fr";
    Check(Loc.T("Erlauben", "Allow") != "Allow" && Loc.F("{0} Regeln", "{0} rules", 7).Contains('7'), "Übersetzung wird verwendet");
    Loc.Language = "de";
}

try { Directory.Delete(Paths.Override!, true); } catch { }
Console.WriteLine(failed == 0 ? $"Alle {count} Prüfungen bestanden." : $"{failed} von {count} Prüfungen fehlgeschlagen.");
return failed == 0 ? 0 : 1;

sealed class FakeProcs : IProcessLookup
{
    public readonly Dictionary<(bool Tcp, ushort Port), ProcessInfo> Ports = [];
    public readonly HashSet<int> Alive = [];
    public ProcessInfo Find(bool tcp, ushort localPort, IpKey remote, ushort remotePort, bool incoming) =>
        Ports.TryGetValue((tcp, localPort), out var p) ? p : new ProcessInfo(0, "");
    public bool IsAlive(int pid) => Alive.Contains(pid);
}
