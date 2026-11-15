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
    Check(old.Rules.Count == 2 && old.Rules[0].Remote == RemoteKind.DnsServers && !old.Rules[0].Enabled && old.Rules[1].Remote == RemoteKind.LocalNet
          && old.Settings.FactoryRulesVersion == FactoryRules.Version, "Werksregeln Stand 1 → 2");
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
