// Tests der Routenverfolgung (Build 40): Ablauf mit nachgebildetem Netzweg, Länder-Datenbank im MaxMind-Format (mit eigenem
// Schreiber, auch absichtlich kaputt), Adressbereiche, eingebettete Weltkarte, Projektion und Großkreis.
using System.Net;
using System.Text;
using SnitchBox.Core;

static class GeoTraceTests
{
    public static void Run(Action<bool, string> check)
    {
        Scopes(check);
        Database(check);
        Fuzz(check);
        Map(check);
        Tracing(check);
        Groups(check);
    }

    // ---- Adressbereiche
    static void Scopes(Action<bool, string> check)
    {
        AddressScope S(string a) => GeoIp.ScopeOf(IPAddress.Parse(a));
        check(S("8.8.8.8") == AddressScope.Public && S("193.99.144.80") == AddressScope.Public, "Bereich öffentlich v4");
        check(S("10.1.2.3") == AddressScope.Private && S("172.16.0.1") == AddressScope.Private && S("172.31.255.1") == AddressScope.Private
              && S("172.32.0.1") == AddressScope.Public && S("192.168.178.1") == AddressScope.Private, "Bereich privat v4");
        check(S("100.64.0.1") == AddressScope.CarrierNat && S("100.127.255.254") == AddressScope.CarrierNat && S("100.128.0.1") == AddressScope.Public, "Bereich CGNAT");
        check(S("127.0.0.1") == AddressScope.Loopback && S("169.254.1.1") == AddressScope.LinkLocal && S("224.0.0.251") == AddressScope.Multicast
              && S("0.1.2.3") == AddressScope.Reserved && S("255.255.255.255") == AddressScope.Reserved && S("192.0.2.5") == AddressScope.Reserved
              && S("198.18.0.1") == AddressScope.Reserved && S("198.51.100.1") == AddressScope.Reserved && S("203.0.113.9") == AddressScope.Reserved, "Bereich besondere v4");
        check(S("2a00:1450:4001::1") == AddressScope.Public && S("fe80::1") == AddressScope.LinkLocal && S("fd00::1") == AddressScope.Private
              && S("::1") == AddressScope.Loopback && S("ff02::1") == AddressScope.Multicast && S("2001:db8::1") == AddressScope.Reserved
              && S("::") == AddressScope.Reserved, "Bereich v6");
        check(S("::ffff:192.168.1.1") == AddressScope.Private && S("::ffff:8.8.8.8") == AddressScope.Public, "Bereich v4 in v6");
    }

    // ---- Schreiber für Testdatenbanken im MaxMind-DB-Format
    sealed class Node { public readonly object?[] Child = new object?[2]; }
    static string DbType = "Test-Country";

    static void Ctrl(List<byte> o, int type, int size)
    {
        var first = type <= 7 ? type << 5 : 0;
        void Ext() { if (type > 7) o.Add((byte)(type - 7)); }
        if (size < 29) { o.Add((byte)(first | size)); Ext(); }
        else if (size < 285) { o.Add((byte)(first | 29)); Ext(); o.Add((byte)(size - 29)); }
        else if (size < 65_821) { o.Add((byte)(first | 30)); Ext(); o.Add((byte)((size - 285) >> 8)); o.Add((byte)((size - 285) & 0xFF)); }
        else { var s = size - 65_821; o.Add((byte)(first | 31)); Ext(); o.Add((byte)(s >> 16)); o.Add((byte)(s >> 8)); o.Add((byte)s); }
    }
    static void Str(List<byte> o, string s) { var b = Encoding.UTF8.GetBytes(s); Ctrl(o, 2, b.Length); o.AddRange(b); }
    static void UInt(List<byte> o, int type, ulong v)
    {
        var bytes = new List<byte>();
        for (; v > 0; v >>= 8) bytes.Insert(0, (byte)v);
        Ctrl(o, type, bytes.Count);
        o.AddRange(bytes);
    }
    static void Pointer(List<byte> o, int p)
    {
        if (p < 2048) { o.Add((byte)(0x20 | (p >> 8))); o.Add((byte)p); }
        else if (p < 526_336) { p -= 2048; o.Add((byte)(0x28 | (p >> 16))); o.Add((byte)(p >> 8)); o.Add((byte)p); }
        else if (p < 134_744_064) { p -= 526_336; o.Add((byte)(0x30 | (p >> 24))); o.Add((byte)(p >> 16)); o.Add((byte)(p >> 8)); o.Add((byte)p); }
        else { o.Add(0x38); o.Add((byte)(p >> 24)); o.Add((byte)(p >> 16)); o.Add((byte)(p >> 8)); o.Add((byte)p); }
    }

    static int Country(List<byte> data, string code, string name, string key = "country")
    {
        var at = data.Count;
        Ctrl(data, 7, 2);
        Str(data, "continent"); Ctrl(data, 7, 1); Str(data, "code"); Str(data, "EU");
        Str(data, key); Ctrl(data, 7, 2);
        Str(data, "iso_code"); Str(data, code);
        Str(data, "names"); Ctrl(data, 7, 1); Str(data, "en"); Str(data, name);
        return at;
    }

    /// <summary>Baut eine Datenbank: Netze (Adresse/Präfix) → Stelle im Datenbereich.</summary>
    static byte[] Build(int recordSize, int ipVersion, List<byte> data, params (string Net, int Data)[] nets)
    {
        var root = new Node();
        var nodes = new List<Node> { root };
        foreach (var (net, at) in nets)
        {
            var parts = net.Split('/');
            var addr = IPAddress.Parse(parts[0]);
            var len = int.Parse(parts[1]);
            var bytes = addr.GetAddressBytes();
            var bits = new List<int>();
            if (bytes.Length == 4 && ipVersion == 6) bits.AddRange(Enumerable.Repeat(0, 96));
            for (var i = 0; i < len; i++) bits.Add((bytes[i >> 3] >> (7 - (i & 7))) & 1);
            var node = root;
            for (var i = 0; i < bits.Count - 1; i++)
            {
                if (node.Child[bits[i]] is not Node next)
                {
                    next = new Node();
                    nodes.Add(next);
                    node.Child[bits[i]] = next;
                }
                node = next;
            }
            node.Child[bits[^1]] = at;
        }
        var count = nodes.Count;
        var index = nodes.Select((n, i) => (n, i)).ToDictionary(x => x.n, x => x.i);
        long Value(object? c) => c switch { Node n => index[n], int d => count + 16 + d, _ => count };
        var o = new List<byte>();
        foreach (var n in nodes)
        {
            long l = Value(n.Child[0]), r = Value(n.Child[1]);
            switch (recordSize)
            {
                case 24: o.AddRange([(byte)(l >> 16), (byte)(l >> 8), (byte)l, (byte)(r >> 16), (byte)(r >> 8), (byte)r]); break;
                case 28: o.AddRange([(byte)(l >> 16), (byte)(l >> 8), (byte)l, (byte)(((l >> 24) & 0xF) << 4 | ((r >> 24) & 0xF)), (byte)(r >> 16), (byte)(r >> 8), (byte)r]); break;
                default: o.AddRange([(byte)(l >> 24), (byte)(l >> 16), (byte)(l >> 8), (byte)l, (byte)(r >> 24), (byte)(r >> 16), (byte)(r >> 8), (byte)r]); break;
            }
        }
        o.AddRange(new byte[16]);
        o.AddRange(data);
        o.AddRange([0xAB, 0xCD, 0xEF, .. "MaxMind.com"u8]);
        Ctrl(o, 7, 6);
        Str(o, "node_count"); UInt(o, 6, (ulong)count);
        Str(o, "record_size"); UInt(o, 5, (ulong)recordSize);
        Str(o, "ip_version"); UInt(o, 5, (ulong)ipVersion);
        Str(o, "database_type"); Str(o, DbType);
        Str(o, "binary_format_major_version"); UInt(o, 5, 2);
        Str(o, "build_epoch"); UInt(o, 9, 1_793_501_259);
        return o.ToArray();
    }

    static byte[] Sample(int recordSize, out List<byte> data)
    {
        data = [];
        var de = Country(data, "DE", "Germany");
        var us = Country(data, "us", "United States"); // kleingeschrieben: wird zu „US“
        var zz = Country(data, "ZZ", "Undefined");
        var reg = Country(data, "NL", "Netherlands", "registered_country");
        // Verweis: ein Datensatz, der nur auf „DE“ zeigt (wie in echten Dateien, die gleiche Teile teilen).
        var ptr = data.Count;
        Pointer(data, de);
        return Build(recordSize, 6, data,
            ("193.99.144.0/24", de), ("8.8.8.0/24", us), ("2a00:1450::/32", de), ("1.2.3.0/24", zz), ("5.6.0.0/16", reg), ("9.9.9.0/24", ptr));
    }

    static void Database(Action<bool, string> check)
    {
        foreach (var size in new[] { 24, 28, 32 })
        {
            var bytes = Sample(size, out _);
            CountryDb db;
            try { db = new CountryDb(bytes); }
            catch (Exception e) { check(false, $"Testdatenbank {size} Bit lesbar: {e.Message}"); continue; }
            string? C(string a) => db.CountryOf(IPAddress.Parse(a));
            check(C("193.99.144.80") == "DE" && C("8.8.8.8") == "US" && C("2a00:1450:4001::1") == "DE", $"Länder-DB {size}: Treffer v4/v6");
            check(C("193.99.145.1") == null && C("8.8.9.1") == null && C("2a01::1") == null, $"Länder-DB {size}: kein Eintrag");
            check(C("1.2.3.4") == null && C("5.6.7.8") == "NL" && C("9.9.9.9") == "DE", $"Länder-DB {size}: ZZ, registered_country, Verweis");
            check(C("::ffff:193.99.144.80") == "DE" && C("192.168.1.1") == null, $"Länder-DB {size}: v4 in v6, privat");
            check(db.BuildTime.Year == 2026, $"Länder-DB {size}: Erstellungszeit");
        }
        // Reine IPv4-Datenbank: IPv6-Adressen haben kein Land.
        var d4 = new List<byte>();
        var at = Country(d4, "FR", "France");
        var v4 = new CountryDb(Build(24, 4, d4, ("80.0.0.0/8", at)));
        check(v4.CountryOf(IPAddress.Parse("80.1.2.3")) == "FR" && v4.CountryOf(IPAddress.Parse("2a00::1")) == null, "Länder-DB nur IPv4");
        // Keine Länder-Datenbank (falscher Typ) und gar keine Datenbank.
        check(Throws(() => new CountryDb(new byte[100])) && Throws(() => new CountryDb([])), "Länder-DB: Unsinn abgewiesen");
        DbType = "Test-ASN";
        var asn = Sample(24, out _);
        DbType = "Test-Country";
        check(Throws(() => new CountryDb(asn)), "Länder-DB: Typ geprüft");
        // Verweis auf sich selbst: endet über die Tiefengrenze, ohne Absturz.
        var loop = new List<byte>();
        var self = loop.Count;
        Ctrl(loop, 7, 1); Str(loop, "country"); Pointer(loop, self);
        var dbLoop = new CountryDb(Build(24, 6, loop, ("7.0.0.0/8", self)));
        check(dbLoop.CountryOf(IPAddress.Parse("7.1.1.1")) == null, "Länder-DB: Verweisschleife");
        // Riesige Map aus Verweisen auf eine große Map: das Arbeitsbudget bricht ab (sonst Milliarden Schritte).
        var bomb = new List<byte>();
        var big = bomb.Count;
        Ctrl(bomb, 11, 200); for (var i = 0; i < 200; i++) Str(bomb, "x");
        var top = bomb.Count;
        Ctrl(bomb, 7, 60_000);
        for (var i = 0; i < 60_000; i++) { Str(bomb, "k" + i); Pointer(bomb, big); }
        var dbBomb = new CountryDb(Build(24, 6, bomb, ("6.0.0.0/8", top)));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        check(dbBomb.CountryOf(IPAddress.Parse("6.1.1.1")) == null && sw.ElapsedMilliseconds < 2000, "Länder-DB: Arbeitsbudget");
        // Viele Verweise auf einen großen Text: Ohne Abrechnung nach Größe entstünden je Abfrage Gigabytes.
        var huge = new List<byte>();
        var text = huge.Count;
        Str(huge, new string('x', 1_000_000));
        var list = huge.Count;
        Ctrl(huge, 11, 9000);
        for (var i = 0; i < 9000; i++) Pointer(huge, text);
        var mem = GC.GetTotalAllocatedBytes();
        var dbHuge = new CountryDb(Build(24, 6, huge, ("5.0.0.0/8", list)));
        sw.Restart();
        check(dbHuge.CountryOf(IPAddress.Parse("5.1.1.1")) == null && sw.ElapsedMilliseconds < 2000 && GC.GetTotalAllocatedBytes() - mem < 200_000_000,
            $"Länder-DB: Budget nach Größe ({(GC.GetTotalAllocatedBytes() - mem) / 1_000_000} MB)");
    }

    static bool Throws(Action a)
    {
        try { a(); return false; }
        catch (InvalidDataException) { return true; }
    }

    /// <summary>Zufällig beschädigte Datenbanken: Der Konstruktor darf nur InvalidDataException werfen, Abfragen gar nichts.</summary>
    static void Fuzz(Action<bool, string> check)
    {
        var rng = new Random(4711);
        var good = Sample(24, out _);
        var probes = new[] { "193.99.144.80", "8.8.8.8", "2a00:1450:4001::1", "1.2.3.4", "5.6.7.8", "9.9.9.9", "44.1.2.3", "::1", "2600::1" }.Select(IPAddress.Parse).ToArray();
        int bad = 0, opened = 0;
        string? first = null;
        for (var round = 0; round < 4000; round++)
        {
            var b = (byte[])good.Clone();
            var flips = 1 + rng.Next(8);
            for (var i = 0; i < flips; i++) b[rng.Next(b.Length)] = (byte)rng.Next(256);
            if (rng.Next(10) == 0) Array.Resize(ref b, rng.Next(b.Length));
            CountryDb db;
            try { db = new CountryDb(b); opened++; }
            catch (InvalidDataException) { continue; }
            catch (Exception e) { bad++; first ??= "Konstruktor: " + e.GetType().Name + " " + e.Message; continue; }
            foreach (var p in probes)
            {
                try { _ = db.CountryOf(p); }
                catch (Exception e) { bad++; first ??= "Abfrage: " + e.GetType().Name + " " + e.Message; }
            }
        }
        check(bad == 0, $"Länder-DB Zufallsschäden: {bad} unerwartete Ausnahmen ({first}); {opened} geöffnet");
        check(opened > 100, "Länder-DB Zufallsschäden: genug Dateien geöffnet");
    }

    // ---- Weltkarte, Projektion, Großkreis
    static void Map(Action<bool, string> check)
    {
        var map = WorldMap.Default;
        check(map.Countries.Count >= 250, "Karte: Länder " + map.Countries.Count);
        var de = map.Find("DE");
        check(de != null && de.Localized("de") == "Deutschland" && de.Localized("en") == "Germany" && de.Localized("xx") == "Germany", "Karte: Namen");
        check(de != null && de.Lon is > 5 and < 15 && de.Lat is > 47 and < 55 && de.Rings.Count > 0, "Karte: Deutschland");
        check(map.Find("gi") is { Rings.Count: 0 } gi && Math.Abs(gi.Lat - 36.14) < 0.01, "Karte: Gibraltar als Punkt");
        check(map.Find("AQ") == null && map.Find("ZZ") == null && map.Find(null) == null, "Karte: ohne Antarktis/ZZ");
        check(map.Find("FR") != null && map.Find("NO") != null && map.Find("XK") != null && map.Find("TW") != null, "Karte: Sonderfälle FR/NO/XK/TW");
        var au = map.Find("AU")!;
        check(au.Lon is > 120 and < 140 && au.Lat is > -30 and < -20, "Karte: Australien-Punkt vom Festland");
        var ok = map.Countries.All(c => c.Rings.All(r => r.Length >= 6 && r.Length % 2 == 0
            && Enumerable.Range(0, r.Length / 2).All(i => r[2 * i] is >= -180 and <= 180 && r[2 * i + 1] is >= -90 and <= 90)));
        check(ok, "Karte: Umrisse gültig");
        // Alle Sprachen haben einen Namen für jedes Land mit Code.
        var unnamed = map.Countries.Where(c => c.Code.Length == 2).SelectMany(c => WorldMap.Languages.Where(l => c.Localized(l).Length == 0).Select(l => c.Code + "/" + l)).ToList();
        check(unnamed.Count == 0, "Karte: Namen vollständig " + string.Join(",", unnamed.Take(5)));

        var (x0, y0) = MapProjection.Project(0, 0);
        var (x1, _) = MapProjection.Project(180, 0);
        var (_, y1) = MapProjection.Project(0, 90);
        check(Math.Abs(x0) < 1e-9 && Math.Abs(y0) < 1e-9 && Math.Abs(x1 - MapProjection.MaxX) < 1e-3 && Math.Abs(y1 - MapProjection.MaxY) < 1e-3, $"Projektion: Ränder {x1:F4} {y1:F4}");
        var mono = true;
        for (var lat = -89; lat < 89; lat++) mono &= MapProjection.Project(10, lat + 1).Y > MapProjection.Project(10, lat).Y;
        check(mono, "Projektion: Breite steigt");

        var ny = MapProjection.GreatCircle(13.4, 52.5, -74.0, 40.7);
        check(ny.Count == 1 && ny[0][0] == (13.4, 52.5) && ny[0][^1] == (-74.0, 40.7) && ny[0].Max(p => p.Lat) > 52.5, "Großkreis Berlin–New York (nach Norden gebogen)");
        var sf = MapProjection.GreatCircle(139.7, 35.7, -122.4, 37.8);
        check(sf.Count == 2 && sf[0][^1].Lon == 180 && sf[1][0].Lon == -180 && Math.Abs(sf[0][^1].Lat - sf[1][0].Lat) < 1e-9
              && sf[1][^1] == (-122.4, 37.8), "Großkreis Tokio–San Francisco über die Datumsgrenze");
        var back = MapProjection.GreatCircle(-122.4, 37.8, 139.7, 35.7);
        check(back.Count == 2 && back[0][^1].Lon == -180 && back[1][0].Lon == 180, "Großkreis zurück über die Datumsgrenze");
        var same = MapProjection.GreatCircle(8, 50, 8, 50);
        check(same.Count == 1 && same[0].Count >= 2 && same[0].All(p => p == (8.0, 50.0)), "Großkreis gleicher Ort");
    }

    // ---- Ablauf der Routenverfolgung mit nachgebildetem Netzweg
    sealed class FakeNet : ITraceProber
    {
        public Func<int, int, ProbeResult> Answer = (_, _) => new ProbeResult(ProbeStatus.Timeout, null, 0);
        public readonly List<(int Ttl, int Round)> Sent = [];
        public int Delay;
        /// <summary>Wie IcmpProber: Die Probe läuft trotz Abbrechen bis zu ihrer Antwort.</summary>
        public bool IgnoreCancel;
        /// <summary>Verzögerung je (TTL, Runde) in ms; überschreibt <see cref="Delay"/>.</summary>
        public Func<int, int, int>? DelayFor;
        private readonly Dictionary<int, int> _seen = [];
        public async Task<ProbeResult> ProbeAsync(IPAddress target, int ttl, int timeoutMs, CancellationToken cancel)
        {
            int round;
            lock (Sent)
            {
                _seen[ttl] = round = _seen.GetValueOrDefault(ttl);
                _seen[ttl]++;
                Sent.Add((ttl, round));
            }
            var wait = DelayFor?.Invoke(ttl, round) ?? Delay;
            if (wait > 0) await Task.Delay(wait, IgnoreCancel ? CancellationToken.None : cancel);
            return Answer(ttl, round);
        }
    }

    static IPAddress R(int n) => IPAddress.Parse("62.155.0." + n);
    static readonly IPAddress Target = IPAddress.Parse("193.99.144.80");
    static readonly TraceOptions Fast = new() { RoundIntervalMs = 10, StaggerMs = 0 };

    static TraceSnapshot Trace(FakeNet net, TraceOptions? o = null, CancellationToken cancel = default) =>
        new Tracer(net, o ?? Fast).RunAsync(Target, cancel).GetAwaiter().GetResult();

    static void Tracing(Action<bool, string> check)
    {
        // Ziel an Hop 9; Hop 3 stumm; Hop 5 mit Lastverteilung (zwei Router im Wechsel).
        var net = new FakeNet
        {
            Answer = (ttl, round) => ttl switch
            {
                3 => new ProbeResult(ProbeStatus.Timeout, null, 0),
                5 => new ProbeResult(ProbeStatus.TimeExceeded, round % 2 == 0 ? R(5) : R(55), 9),
                < 9 => new ProbeResult(ProbeStatus.TimeExceeded, R(ttl), ttl),
                _ => new ProbeResult(ProbeStatus.Reply, Target, 20),
            },
        };
        var t = Trace(net);
        check(t.End == TraceEnd.Reached && t.Hops.Count == 9 && t.Hops[8].Reached && t.Hops[8].Address!.Equals(Target), $"Trace: Ziel an Hop 9 ({t.End}, {t.Hops.Count})");
        check(!t.Hops[2].Answered && t.Hops[2].Probes.All(p => p is { Status: ProbeStatus.Timeout }), "Trace: stummer Hop");
        check(t.Hops[4].Addresses.Count == 2 && t.Hops[4].Address!.Equals(R(5)), "Trace: Lastverteilung, häufigster zuerst");
        check(t.Hops.All(h => h.Probes.Count == 3 && h.Probes.All(p => p != null)), "Trace: drei Proben je Hop");
        check(net.Sent.Where(s => s.Round > 0).All(s => s.Ttl <= 9), "Trace: spätere Runden nur bis zum Ziel");
        check(net.Sent.Take(3).All(s => s.Ttl == 1) && net.Sent.Count(s => s.Ttl == 1) == 3, "Trace: Hop 1 zuerst und allein");

        // Hop 1 stumm: seine übrigen Proben gehen mit den Runden (keine dreifache Wartezeit vorweg).
        net = new FakeNet { Answer = (ttl, _) => ttl == 1 ? new ProbeResult(ProbeStatus.Timeout, null, 0) : ttl < 5 ? new ProbeResult(ProbeStatus.TimeExceeded, R(ttl), 5) : new ProbeResult(ProbeStatus.Reply, Target, 9) };
        t = Trace(net);
        check(t.End == TraceEnd.Reached && t.Hops.Count == 5 && !t.Hops[0].Answered && t.Hops[0].Probes.All(p => p != null)
              && net.Sent[0].Ttl == 1 && net.Sent[1].Ttl == 2, "Trace: stummer Hop 1");

        // Ziel ist der erste Router: fertig ohne Rundenwartezeit.
        net = new FakeNet { Answer = (_, _) => new ProbeResult(ProbeStatus.Reply, Target, 1) };
        var swGate = System.Diagnostics.Stopwatch.StartNew();
        t = Trace(net, new TraceOptions { RoundIntervalMs = 2000, StaggerMs = 0 });
        check(t.End == TraceEnd.Reached && t.Hops.Count == 1 && net.Sent.Count == 3 && swGate.ElapsedMilliseconds < 1000, $"Trace: Ziel an Hop 1 ({swGate.ElapsedMilliseconds} ms)");

        // Das Ziel antwortet nicht auf Ping: Hops bis zum letzten, der antwortet.
        net = new FakeNet { Answer = (ttl, _) => ttl <= 6 ? new ProbeResult(ProbeStatus.TimeExceeded, R(ttl), 5) : new ProbeResult(ProbeStatus.Timeout, null, 0) };
        t = Trace(net);
        check(t.End == TraceEnd.NoAnswer && t.Hops.Count == 6, $"Trace: Ziel stumm ({t.End}, {t.Hops.Count})");
        check(net.Sent.Count == 90, "Trace: ohne Ziel alle 30 Hops je Runde");

        // Router an Hop 4 meldet „Netz nicht erreichbar“.
        net = new FakeNet
        {
            Answer = (ttl, _) => ttl < 4 ? new ProbeResult(ProbeStatus.TimeExceeded, R(ttl), 5)
                : ttl == 4 ? new ProbeResult(ProbeStatus.Unreachable, R(4), 7, 11002) : new ProbeResult(ProbeStatus.Timeout, null, 0),
        };
        t = Trace(net);
        check(t.End == TraceEnd.Unreachable && t.Hops.Count == 4 && t.Hops[3].Unreachable is { Code: 11002 }, "Trace: nicht erreichbar an Hop 4");

        // Ziel begrenzt seine Antworten: in Runde 1 fehlt die Antwort bei TTL 9, sie kommt erst bei TTL 10 – später doch bei 9.
        net = new FakeNet
        {
            Answer = (ttl, round) => ttl < 9 ? new ProbeResult(ProbeStatus.TimeExceeded, R(ttl), 5)
                : ttl == 9 && round == 0 ? new ProbeResult(ProbeStatus.Timeout, null, 0) : new ProbeResult(ProbeStatus.Reply, Target, 20),
        };
        t = Trace(net);
        check(t.End == TraceEnd.Reached && t.Hops.Count == 9, $"Trace: verlorene Zielantwort korrigiert ({t.Hops.Count})");

        // Proben lassen sich gar nicht senden.
        net = new FakeNet { Answer = (_, _) => new ProbeResult(ProbeStatus.Error, null, 0, 11050) };
        t = Trace(net);
        check(t.End == TraceEnd.NoAnswer && t.Hops.Count == 0 && t.Error == 11050, "Trace: Sendefehler gemeldet");

        // Kein Netz: das System meldet sofort „nicht erreichbar“ ohne Absender.
        net = new FakeNet { Answer = (_, _) => new ProbeResult(ProbeStatus.Unreachable, null, 0, 1231) };
        t = Trace(net);
        check(t.End == TraceEnd.Unreachable && t.Hops.Count == 1, "Trace: kein Netz");

        // Abbrechen: endet sofort, auch wenn Antworten ausstehen.
        net = new FakeNet { Delay = 5000, IgnoreCancel = true, Answer = (ttl, _) => new ProbeResult(ProbeStatus.TimeExceeded, R(ttl), 5) };
        using var cts = new CancellationTokenSource(150);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        t = Trace(net, new TraceOptions { RoundIntervalMs = 1000, StaggerMs = 1 }, cts.Token);
        check(t.End == TraceEnd.Cancelled && sw.ElapsedMilliseconds < 1000, $"Trace: Abbrechen während Hop 1 ({sw.ElapsedMilliseconds} ms)");
        // Spät abbrechen: alle Proben sind unterwegs, keine wartet mehr in einer Verzögerung.
        net = new FakeNet { DelayFor = (ttl, _) => ttl == 1 ? 0 : 3000, IgnoreCancel = true, Answer = (ttl, _) => ttl == 1 ? new ProbeResult(ProbeStatus.TimeExceeded, R(1), 1) : new ProbeResult(ProbeStatus.Timeout, null, 0) };
        var late = new Tracer(net, new TraceOptions { RoundIntervalMs = 10, StaggerMs = 0 });
        var lateEvents = 0;
        using var cts2 = new CancellationTokenSource();
        var running = late.RunAsync(Target, cts2.Token);
        Thread.Sleep(400);
        late.Changed += () => Interlocked.Increment(ref lateEvents);
        sw.Restart();
        int sentBefore;
        lock (net.Sent) sentBefore = net.Sent.Count;
        cts2.Cancel();
        t = running.GetAwaiter().GetResult();
        var afterCancel = lateEvents;
        Thread.Sleep(100);
        check(t.End == TraceEnd.Cancelled && sentBefore > 60 && sw.ElapsedMilliseconds < 1000 && afterCancel <= 1,
            $"Trace: spätes Abbrechen ({sentBefore} Proben unterwegs, {sw.ElapsedMilliseconds} ms, {afterCancel} Ereignisse)");

        // Höchstzahl der Hops: jeder Hop antwortet, das Ziel nie (Routing-Schleife).
        net = new FakeNet { Answer = (ttl, _) => new ProbeResult(ProbeStatus.TimeExceeded, R(ttl % 2 == 0 ? 7 : 8), 5) };
        t = Trace(net);
        check(t.End == TraceEnd.HopLimit && t.Hops.Count == 30, $"Trace: Routing-Schleife ({t.End}, {t.Hops.Count})");

        // Totes Ziel im eigenen Netz: Das System meldet erst spät (ARP) „nicht erreichbar“ – ohne Absender, bei irgendeiner TTL.
        // Die Zeitüberschreitung von Hop 1 derselben Runde kommt erst danach und überschreibt die Meldung nicht.
        net = new FakeNet
        {
            DelayFor = (ttl, _) => ttl == 1 ? 150 : 0,
            Answer = (ttl, round) => ttl == 30 && round == 1 ? new ProbeResult(ProbeStatus.Unreachable, null, 433, 11003) : new ProbeResult(ProbeStatus.Timeout, null, 0),
        };
        t = Trace(net);
        check(t.End == TraceEnd.Unreachable && t.Hops.Count == 1 && t.Hops[0].Unreachable is { Code: 11003 }, $"Trace: Systemmeldung gilt für Hop 1 ({t.End}, {t.Hops.Count})");

        // Kurze Störung (WLAN wechselt), nachdem Router schon geantwortet haben: Die Meldung ist ein Fehler, kein Wegende.
        net = new FakeNet
        {
            Answer = (ttl, round) => ttl == 5 && round == 2 ? new ProbeResult(ProbeStatus.Unreachable, null, 0, 1231)
                : ttl < 8 ? new ProbeResult(ProbeStatus.TimeExceeded, R(ttl), 5) : new ProbeResult(ProbeStatus.Reply, Target, 9),
        };
        t = Trace(net);
        check(t.End == TraceEnd.Reached && t.Hops.Count == 8 && t.Hops[4].Probes[2] is { Status: ProbeStatus.Error }, $"Trace: Störung mitten im Lauf ({t.End}, {t.Hops.Count})");

        // Systemmeldung zuerst, dann antwortet der langsame erste Router doch: Die Grenze gilt wieder bis zum Ziel.
        net = new FakeNet
        {
            DelayFor = (ttl, round) => ttl == 1 && round == 1 ? 200 : 0,
            // (round zählt hier die Aufrufe je TTL: TTL 4 und höher kommen in Runde 1 gar nicht dran.)
            Answer = (ttl, round) => round == 0 ? new ProbeResult(ProbeStatus.Timeout, null, 0)
                : ttl == 3 && round == 1 ? new ProbeResult(ProbeStatus.Unreachable, null, 0, 1232)
                : ttl == 2 && round == 1 ? new ProbeResult(ProbeStatus.Timeout, null, 0)
                : ttl < 6 ? new ProbeResult(ProbeStatus.TimeExceeded, R(ttl), 5) : new ProbeResult(ProbeStatus.Reply, Target, 9),
        };
        t = Trace(net, new TraceOptions { RoundIntervalMs = 400, StaggerMs = 0 });
        check(t.End == TraceEnd.Reached && t.Hops.Count == 6 && t.Hops[0].Unreachable == null, $"Trace: Systemmeldung zurückgenommen ({t.End}, {t.Hops.Count})");

        // Zwischenstand während des Laufs: Ereignis bei jeder Antwort, Hops ohne Antwort am Ende fehlen.
        net = new FakeNet { Answer = (ttl, _) => ttl == 1 ? new ProbeResult(ProbeStatus.TimeExceeded, R(1), 1) : ttl == 2 ? new ProbeResult(ProbeStatus.Reply, Target, 3) : new ProbeResult(ProbeStatus.Timeout, null, 0) };
        var tracer = new Tracer(net, Fast);
        var events = 0;
        tracer.Changed += () => Interlocked.Increment(ref events);
        t = tracer.RunAsync(Target, default).GetAwaiter().GetResult();
        check(events > 0 && t.Hops.Count == 2 && tracer.Snapshot().End == TraceEnd.Reached, "Trace: Ereignisse und Zwischenstand");
    }

    // ---- Mehrere Ziele auf einmal (Übersicht „wohin sendet dieses Programm“)
    sealed class GroupNet : ITraceProber
    {
        public static readonly IPAddress Gateway = IPAddress.Parse("192.168.178.1");
        /// <summary>Ziel → Hop, an dem es antwortet (0 = nie, dann antworten Router bis Hop 4).</summary>
        public readonly Dictionary<IPAddress, int> DestHop = [];
        public readonly List<(IPAddress Target, int Ttl)> Sent = [];
        public int Delay, DelayFirst, InFlight, MaxTargetsInFlight;
        /// <summary>Der erste Router antwortet nicht (Firewall, die keine „TTL abgelaufen“ schickt).</summary>
        public bool SilentGateway;
        /// <summary>Adressen, auf die der erste Router selbst antwortet (seine WAN-Adresse).</summary>
        public readonly HashSet<IPAddress> GatewayOwn = [];
        private readonly Dictionary<IPAddress, int> _busy = [];
        public async Task<ProbeResult> ProbeAsync(IPAddress target, int ttl, int timeoutMs, CancellationToken cancel)
        {
            lock (Sent)
            {
                Sent.Add((target, ttl));
                if (ttl > 1)
                {
                    _busy[target] = _busy.GetValueOrDefault(target) + 1;
                    MaxTargetsInFlight = Math.Max(MaxTargetsInFlight, _busy.Count(b => b.Value > 0));
                }
            }
            try
            {
                if (Delay > 0 && ttl > 1) await Task.Delay(Delay, CancellationToken.None);
                if (DelayFirst > 0 && ttl == 1) await Task.Delay(DelayFirst, CancellationToken.None);
                if (GatewayOwn.Contains(target)) return new ProbeResult(ProbeStatus.Reply, target, 1);
                if (SilentGateway && ttl == 1) return new ProbeResult(ProbeStatus.Timeout, null, 0);
                var dest = DestHop[target];
                if (dest > 0 && ttl >= dest) return new ProbeResult(ProbeStatus.Reply, target, 10);
                if (ttl == 1) return new ProbeResult(ProbeStatus.TimeExceeded, Gateway, 1);
                return dest == 0 && ttl > 4 ? new ProbeResult(ProbeStatus.Timeout, null, 0) : new ProbeResult(ProbeStatus.TimeExceeded, IPAddress.Parse("62.155.1." + ttl), 5);
            }
            finally
            {
                if (ttl > 1) lock (Sent) _busy[target]--;
            }
        }
    }

    static void Groups(Action<bool, string> check)
    {
        var a = IPAddress.Parse("193.99.144.80");
        var b = IPAddress.Parse("140.82.121.4");
        var c = IPAddress.Parse("192.168.178.20"); // im eigenen Netz: kein Gateway
        var d = IPAddress.Parse("52.84.150.39");   // antwortet nicht auf Ping
        var net = new GroupNet { Delay = 20 };
        net.DestHop[a] = 5; net.DestHop[b] = 7; net.DestHop[c] = 1; net.DestHop[d] = 0;
        var options = new TraceOptions { RoundIntervalMs = 10, StaggerMs = 0 };
        var items = new[] { a, b, c, d }.Select(t => (new Tracer(net, options), t)).ToList();
        TraceGroup.RunAsync(items, 2, default, t => t.Equals(c) ? null : "21|192.168.178.1").GetAwaiter().GetResult();
        var snaps = items.Select(i => i.Item1.Snapshot()).ToList();
        check(snaps[0].End == TraceEnd.Reached && snaps[0].Hops.Count == 5 && snaps[1].End == TraceEnd.Reached && snaps[1].Hops.Count == 7
              && snaps[2].End == TraceEnd.Reached && snaps[2].Hops.Count == 1 && snaps[3].End == TraceEnd.NoAnswer && snaps[3].Hops.Count == 4,
            "Gruppe: alle Ziele verfolgt (" + string.Join(" ", snaps.Select(x => x.End + ":" + x.Hops.Count)) + ")");
        int Ttl1(IPAddress t) => net.Sent.Count(x => x.Target.Equals(t) && x.Ttl == 1);
        check(Ttl1(a) == 3 && Ttl1(b) == 0 && Ttl1(d) == 0 && Ttl1(c) == 3, $"Gruppe: Hop 1 übernommen (a {Ttl1(a)}, b {Ttl1(b)}, c {Ttl1(c)}, d {Ttl1(d)})");
        check(snaps[1].Hops[0].Address!.Equals(GroupNet.Gateway) && snaps[1].Hops[0].Probes.All(p => p is { Status: ProbeStatus.TimeExceeded }), "Gruppe: übernommener Hop 1 vollständig");
        var firstRound = net.Sent.FindIndex(x => x.Ttl > 1);
        check(firstRound > 0 && net.Sent.Skip(firstRound).All(x => x.Ttl > 1), "Gruppe: Hop 1 aller Ziele vor den Runden");
        check(net.MaxTargetsInFlight <= 2, $"Gruppe: höchstens 2 Ziele gleichzeitig ({net.MaxTargetsInFlight})");

        // Das erste Ziel ist das Gateway selbst: sein Hop 1 ist sein Ende und wird nicht weitergegeben.
        net = new GroupNet();
        net.DestHop[GroupNet.Gateway] = 1; net.DestHop[a] = 5;
        items = new[] { GroupNet.Gateway, a }.Select(t => (new Tracer(net, options), t)).ToList();
        TraceGroup.RunAsync(items, 4, default, _ => "21|192.168.178.1").GetAwaiter().GetResult();
        snaps = items.Select(i => i.Item1.Snapshot()).ToList();
        check(snaps[0].End == TraceEnd.Reached && snaps[0].Hops.Count == 1 && snaps[1].End == TraceEnd.Reached && snaps[1].Hops.Count == 5
              && net.Sent.Count(x => x.Target.Equals(a) && x.Ttl == 1) == 3, "Gruppe: Gateway als Ziel gibt Hop 1 nicht weiter");

        // Abbrechen: alle Läufe enden als abgebrochen, auch die noch nicht begonnenen.
        net = new GroupNet { Delay = 2000 };
        foreach (var t in new[] { a, b, d }) net.DestHop[t] = 9;
        items = new[] { a, b, d }.Select(t => (new Tracer(net, options), t)).ToList();
        using var cts = new CancellationTokenSource(300);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        TraceGroup.RunAsync(items, 1, cts.Token, _ => "gw").GetAwaiter().GetResult();
        check(items.All(i => i.Item1.Snapshot().End == TraceEnd.Cancelled) && sw.ElapsedMilliseconds < 1500, $"Gruppe: Abbrechen ({sw.ElapsedMilliseconds} ms)");

        // Stummer erster Router: nur die ersten beiden Ziele warten auf ihn, die übrigen schicken Hop 1 mit den Runden.
        net = new GroupNet { SilentGateway = true };
        var many = Enumerable.Range(1, 6).Select(i => IPAddress.Parse("62.155.9." + i)).ToList();
        foreach (var t in many) net.DestHop[t] = 6;
        items = many.Select(t => (new Tracer(net, options), t)).ToList();
        TraceGroup.RunAsync(items, 6, default, _ => "gw").GetAwaiter().GetResult();
        var firstRoundAt = net.Sent.FindIndex(x => x.Ttl > 1);
        check(firstRoundAt == 2 && items.All(i => i.Item1.Snapshot() is { End: TraceEnd.Reached, Hops.Count: 6 }),
            $"Gruppe: stummer erster Router kostet nur zwei Wartezeiten ({firstRoundAt} Proben vorweg)");
        check(items.All(i => i.Item1.Snapshot().Hops[0].Probes.All(p => p != null)), "Gruppe: Hop 1 trotzdem dreimal geprüft");

        // Ziele ohne Gateway (im eigenen Netz) fragen Hop 1 gleichzeitig ab.
        net = new GroupNet { DelayFirst = 200 };
        var lan = Enumerable.Range(20, 4).Select(i => IPAddress.Parse("192.168.178." + i)).ToList();
        foreach (var t in lan) net.DestHop[t] = 1;
        items = lan.Select(t => (new Tracer(net, options), t)).ToList();
        sw.Restart();
        TraceGroup.RunAsync(items, 6, default, _ => null).GetAwaiter().GetResult();
        check(items.All(i => i.Item1.Snapshot() is { End: TraceEnd.Reached, Hops.Count: 1 }) && sw.ElapsedMilliseconds < 1500,
            $"Gruppe: Ziele ohne Gateway gleichzeitig ({sw.ElapsedMilliseconds} ms statt 2,4 s)");

        // Eine Adresse des Routers selbst (seine WAN-Adresse) übernimmt Hop 1 – die Probe danach zeigt: Er ist Hop 1.
        net = new GroupNet();
        var wan = IPAddress.Parse("88.70.1.2");
        net.DestHop[a] = 5; net.DestHop[wan] = 1; net.GatewayOwn.Add(wan);
        items = new[] { a, wan }.Select(t => (new Tracer(net, options), t)).ToList();
        TraceGroup.RunAsync(items, 6, default, _ => "gw").GetAwaiter().GetResult();
        var hairpin = items[1].Item1.Snapshot();
        check(hairpin.End == TraceEnd.Reached && hairpin.Hops.Count == 1 && hairpin.Hops[0].Address!.Equals(wan), $"Gruppe: WAN-Adresse des Routers ist Hop 1 ({hairpin.Hops.Count} Hops)");

        // IPv4 und IPv6 über denselben Tunnel: Hop 1 wird nicht über die Adressfamilie hinweg übernommen.
        net = new GroupNet();
        var v6 = IPAddress.Parse("2606:4700::6810:1");
        net.DestHop[a] = 5; net.DestHop[v6] = 5;
        items = new[] { a, v6 }.Select(t => (new Tracer(net, options), t)).ToList();
        TraceGroup.RunAsync(items, 6, default, _ => "25|tunnel").GetAwaiter().GetResult();
        check(net.Sent.Count(x => x.Target.Equals(v6) && x.Ttl == 1) == 3, "Gruppe: Hop 1 nicht von IPv4 nach IPv6 übernommen");

        // Ziele aus den Zeilen des Netzwerkmonitors.
        var now = DateTime.Now;
        ConnectionRecord Rec(string ip, string host, int count, int ageSeconds) => new()
        {
            ProcessPath = @"C:\Program Files\Claude\claude.exe", Host = host, Remote = IpKey.From(IPAddress.Parse(ip)), Port = 443,
            Protocol = Proto.Tcp, Direction = Direction.Outgoing, Count = count, LastSeen = now.AddSeconds(-ageSeconds),
        };
        var records = new List<ConnectionRecord>
        {
            Rec("160.79.104.10", "160.79.104.10", 2, 50), Rec("160.79.104.10", "api.anthropic.com", 3, 10),
            Rec("34.36.57.103", "34.36.57.103", 1, 5), Rec("127.0.0.1", "localhost", 9, 1), Rec("224.0.0.251", "mdns", 4, 1),
            Rec("fe80::1", "fe80::1", 1, 1), Rec("0.0.0.0", "0.0.0.0", 1, 1), Rec("255.255.255.255", "255.255.255.255", 1, 1),
            Rec("192.168.178.1", "fritz.box", 1, 30), Rec("1.1.1.1", "one.one.one.one", 1, 100),
        };
        var targets = TraceTargets.From(records, 3, out var omitted);
        check(targets.Count == 3 && omitted == 1 && targets[0].Address.ToString() == "34.36.57.103" && targets[1].Address.ToString() == "160.79.104.10"
              && targets[2].Address.ToString() == "192.168.178.1", "Zielliste: zuletzt benutzte zuerst, höchstens 3 (" + string.Join(" ", targets.Select(t => t.Address)) + $", {omitted} ausgelassen)");
        check(targets[1].Host == "api.anthropic.com" && targets[1].Count == 5 && targets[0].Host == "" && targets[2].Host == "fritz.box",
            "Zielliste: je Adresse eine Zeile, Name statt Adresse, Verbindungen zusammengezählt");
        check(TraceTargets.From(records, 20, out _).All(t => t.Address.ToString() is not ("127.0.0.1" or "224.0.0.251" or "fe80::1" or "0.0.0.0" or "255.255.255.255")),
            "Zielliste: nicht verfolgbare Adressen ausgelassen");
        records.Add(Rec("192.168.178.255", "192.168.178.255", 9, 0));
        check(TraceTargets.From(records, 20, out _)[0].Address.ToString() == "192.168.178.255"
              && TraceTargets.From(records, 20, out _, x => x.ToString() == "192.168.178.255").All(t => t.Address.ToString() != "192.168.178.255"),
            "Zielliste: Broadcast der eigenen Netze ausschließbar");
    }
}
