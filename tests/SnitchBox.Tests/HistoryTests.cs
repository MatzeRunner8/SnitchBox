// Tests des Verlaufs über Neustarts (Build 43): Datenmengen je Tag, Zeilen des Netzwerkmonitors speichern/laden, Grenzen.
using System.Net;
using SnitchBox.Core;

static class HistoryTests
{
    public static void Run(Action<bool, string> check)
    {
        Daily(check);
        Connections(check);
        Lifetime(check);
        UntilQuit(check);
        Files(check);
    }

    static void Daily(Action<bool, string> check)
    {
        var d = new DailyTraffic();
        var today = new DateOnly(2026, 11, 27);
        d.Add(today, [(@"C:\a.exe", 100, 10), (@"C:\B.exe", 5, 1), (@"C:\zero.exe", 0, 0)]);
        d.Add(today, [(@"c:\A.EXE", 50, 5)]);
        d.Add(today.AddDays(-3), [(@"C:\a.exe", 1000, 100)]);
        d.Add(today.AddDays(-40), [(@"C:\a.exe", 7, 7)]);
        var totals = d.Totals(today.AddDays(-30));
        check(totals.Count == 2 && totals[@"C:\A.exe"] == (1150, 115) && totals[@"C:\b.exe"] == (5, 1), "Tage: Summen je Programm (Groß-/Kleinschreibung egal, Nullen weg)");
        var series = d.Series([@"C:\a.exe"], today.AddDays(-4), today);
        check(series.Count == 5 && series[1] == (today.AddDays(-3), 1000, 100) && series[4] == (today, 150, 15) && series[0].Down == 0, "Tage: Reihe für ein Programm");
        var all = d.Series(null, today, today);
        check(all.Count == 1 && all[0].Down == 155 && all[0].Up == 16, "Tage: Reihe für alle Programme");
        check(d.Series(null, today, today.AddDays(-1)).Count == 0 && d.Series(null, today.AddDays(-5000), today).Count == 0, "Tage: unsinnige Zeiträume");
        d.Prune(today.AddDays(-30));
        check(d.Totals(DateOnly.MinValue)[@"C:\a.exe"] == (1150, 115), "Tage: alte Tage vergessen");
        var copy = new DailyTraffic();
        copy.Restore(d.Export(), today.AddDays(-2));
        check(copy.Totals(DateOnly.MinValue)[@"C:\a.exe"] == (150, 15), "Tage: Sichern und Laden (ab Stichtag)");
        var before = copy.Totals(DateOnly.MinValue).Count;
        copy.Restore([new DailyEntry { Day = "kaputt", Path = "x", Down = 1 }, new DailyEntry { Day = "2026-11-27", Path = null, Down = 1 },
            new DailyEntry { Day = "2026-11-27", Path = new string('x', 5000), Down = 1 }, new DailyEntry { Day = "2026-11-27", Path = "neg", Down = -5, Up = -5 }], DateOnly.MinValue);
        check(before == 2 && copy.Totals(DateOnly.MinValue).Count == before, "Tage: unbrauchbare Einträge fallen weg");
        var many = new DailyTraffic();
        many.Add(today, Enumerable.Range(0, DailyTraffic.MaxPathsPerDay + 50).Select(i => ("p" + i, 1L, 1L)));
        check(many.Totals(today).Count == DailyTraffic.MaxPathsPerDay, "Tage: höchstens 5000 Programme je Tag");
    }

    static ConnectionRecord? Find(ConnectionLog log, string host) => log.Snapshot().FirstOrDefault(r => r.Host == host);

    static void Connections(Action<bool, string> check)
    {
        var now = new DateTime(2026, 11, 27, 12, 0, 0);
        var entries = new List<HistoryEntry>
        {
            new() { ProcessPath = @"C:\Program Files\Claude\claude.exe", Host = "api.anthropic.com", Remote = "160.79.104.10", Port = 443, Protocol = Proto.Tcp,
                    Direction = Direction.Outgoing, LastSeen = now.AddDays(-1), Count = 12, Allowed = true, Reason = "Regel", Down = 5000, Up = 700 },
            new() { ProcessPath = @"C:\Windows\System32\svchost.exe", Service = "DiagTrack", Host = "20.42.65.92", Remote = "20.42.65.92", Port = 443, Protocol = Proto.Tcp,
                    Direction = Direction.Outgoing, LastSeen = now.AddHours(-2), Count = 3, Allowed = false },
            new() { ProcessPath = "old.exe", Host = "old.example", Remote = "1.2.3.4", Port = 80, LastSeen = now.AddDays(-45), Count = 1 },
            new() { ProcessPath = "bad.exe", Host = "bad.example", Remote = "kein-ip", Port = 80, LastSeen = now, Count = 1 },
            new() { ProcessPath = "bad2.exe", Host = "", Remote = "1.2.3.5", Port = 80, LastSeen = now, Count = 1 },
            new() { ProcessPath = new string('x', 2000), Host = "long.example", Remote = "1.2.3.6", Port = 80, LastSeen = now, Count = 1 },
            new() { ProcessPath = "enum.exe", Host = "enum.example", Remote = "1.2.3.7", Port = 80, Protocol = (Proto)99, LastSeen = now, Count = 1 },
        };
        var log = new ConnectionLog();
        log.Restore(entries, now.AddDays(-30), DateOnly.FromDateTime(now.AddDays(-29)));
        var rows = log.Snapshot();
        check(rows.Count == 2, $"Verlauf: nur gültige und junge Zeilen übernommen ({rows.Count})");
        var claude = Find(log, "api.anthropic.com");
        check(claude is { Count: 12, Allowed: true, Down: 5000, Up: 700, Port: 443 } && claude.Remote.ToString() == "160.79.104.10"
              && claude.Template.Hostnames.SequenceEqual(["api.anthropic.com"]) && claude.Template.ProcessPath == claude.ProcessPath, "Verlauf: Zeile mit Vorlage für Regeln");
        var diag = Find(log, "20.42.65.92");
        check(diag is { Service: "DiagTrack", Allowed: false } && diag.Template.Hostnames.Count == 0 && diag.Template.Service == "DiagTrack", "Verlauf: Dienst und Adresse als Name");
        var exported = log.Export();
        check(exported.Count == 2 && exported.Any(e => e.Host == "api.anthropic.com" && e.Down == 5000 && e.Remote == "160.79.104.10"), "Verlauf: Export");
        // Erneut laden fügt nichts doppelt ein.
        log.Restore(exported, now.AddDays(-30), DateOnly.FromDateTime(now.AddDays(-29)));
        check(log.Snapshot().Count == 2, "Verlauf: kein doppelter Eintrag");
        log.Prune(now.AddHours(-12), DateOnly.FromDateTime(now.AddDays(-29)));
        check(log.Snapshot().Count == 1 && Find(log, "20.42.65.92") != null, "Verlauf: auf die eingestellten Tage gekürzt");
        // Obergrenze: höchstens ConnectionLog.Max Zeilen, die neuesten.
        var big = Enumerable.Range(0, ConnectionLog.Max + 100).Select(i => new HistoryEntry
        {
            ProcessPath = "p.exe", Host = "h" + i + ".example", Remote = "10.0." + (i / 250) + "." + (i % 250), Port = 443, LastSeen = now.AddMinutes(-i), Count = 1,
        }).ToList();
        var full = new ConnectionLog();
        full.Restore(big, now.AddDays(-30), DateOnly.FromDateTime(now.AddDays(-29)));
        check(full.Snapshot().Count == ConnectionLog.Max && Find(full, "h0.example") != null && Find(full, "h" + (ConnectionLog.Max + 99) + ".example") == null,
            "Verlauf: höchstens 4000 Zeilen, die neuesten");
    }

    static void Lifetime(Action<bool, string> check)
    {
        var now = DateTime.Now;
        var today = DateOnly.FromDateTime(now);
        string Day(int back) => today.AddDays(-back).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var log = new ConnectionLog();
        log.Restore([
            // Vor 20 Tagen entschieden, aber bis gestern übertragen (z. B. Netzlaufwerk): bleibt.
            new HistoryEntry { ProcessPath = "System", Host = "nas.local", Remote = "192.168.178.5", Port = 445, LastSeen = now.AddDays(-20), LastActive = now.AddDays(-1),
                Count = 1, Days = [new DayVolume { Day = Day(20), Down = 1000 }, new DayVolume { Day = Day(1), Down = 50 }] },
            // Mehrere DNS-Namen bleiben erhalten (Regeln für Hosts prüfen alle).
            new HistoryEntry { ProcessPath = "b.exe", Host = "a.example", Remote = "1.2.3.4", LastSeen = now, Count = 1, Hostnames = ["a.example", "tracker.example"],
                Days = [new DayVolume { Day = Day(0), Down = 7, Up = 3 }] },
            // Vor der Grenze (Mitternacht des ersten aufgehobenen Tages) zuletzt aktiv: fällt weg, auch wenn es keine 7 × 24 Stunden her ist.
            new HistoryEntry { ProcessPath = "c.exe", Host = "old.example", Remote = "5.6.7.8", LastSeen = today.AddDays(-6).ToDateTime(TimeOnly.MinValue).AddMinutes(-30), Count = 1,
                Days = [new DayVolume { Day = Day(7), Down = 9 }] },
            // Prozessnummer: bleibt für Regeln „bis zum Beenden“ (seit dem Hochfahren); von vor dem Hochfahren verworfen.
            new HistoryEntry { ProcessPath = "d.exe", Host = "pid.example", Remote = "5.6.7.9", LastSeen = now, Count = 1, Pid = 4242 },
            new HistoryEntry { ProcessPath = "d.exe", Host = "oldpid.example", Remote = "5.6.7.9", LastSeen = now - TimeSpan.FromMilliseconds(Environment.TickCount64) - TimeSpan.FromMinutes(5),
                LastActive = now, Count = 1, Pid = 4243 },
        ], today.AddDays(-6).ToDateTime(TimeOnly.MinValue), today.AddDays(-6));
        check(Find(log, "old.example") == null, "Verlauf: Zeilen und Tage mit derselben Grenze (ab Mitternacht)");
        check(Find(log, "pid.example")?.Template.Pid == 4242 && Find(log, "oldpid.example")?.Template.Pid == 0, "Verlauf: Prozessnummer nur seit dem Hochfahren");
        check(log.Export().Any(e => e.Host == "pid.example" && e.Pid == 4242), "Verlauf: Prozessnummer im Export");
        check(HistoryFile.KeepFrom(7, new DateTime(2026, 11, 27, 18, 0, 0)) == new DateOnly(2026, 11, 21) && HistoryFile.KeepFrom(0, new DateTime(2026, 11, 27, 0, 5, 0)) == new DateOnly(2026, 11, 27),
            "Verlauf: erster aufgehobener Tag");
        // Grenze der Zeilen = Mitternacht des ersten aufgehobenen Tages (nicht 7 × 24 Stunden zurück): 20.11. 23:30 fällt weg, 21.11. 00:30 bleibt.
        var fixedNow = new DateTime(2026, 11, 27, 18, 0, 0);
        check(HistoryFile.RowCutoff(7, fixedNow) == new DateTime(2026, 11, 21), "Verlauf: Grenze der Zeilen ab Mitternacht");
        var edge = new ConnectionLog();
        edge.Restore([
            new HistoryEntry { ProcessPath = "e.exe", Host = "before.example", Remote = "5.6.7.10", LastSeen = new DateTime(2026, 11, 20, 23, 30, 0), Count = 1 },
            new HistoryEntry { ProcessPath = "e.exe", Host = "after.example", Remote = "5.6.7.10", LastSeen = new DateTime(2026, 11, 21, 0, 30, 0), Count = 1 },
        ], HistoryFile.RowCutoff(7, fixedNow), HistoryFile.KeepFrom(7, fixedNow));
        check(Find(edge, "before.example") == null && Find(edge, "after.example") != null, "Verlauf: Zeile vor Mitternacht des ersten Tages fällt weg");
        var nas = Find(log, "nas.local");
        check(nas != null && nas.Down == 50, $"Verlauf: lange Verbindung bleibt, nur Daten der aufgehobenen Tage ({nas?.Down})");
        check(Find(log, "a.example")?.Template.Hostnames.SequenceEqual(["a.example", "tracker.example"]) == true, "Verlauf: alle DNS-Namen");
        log.Prune(now.AddDays(-7), today);
        check(Find(log, "nas.local") is { Down: 0 } && Find(log, "a.example") is { Down: 7, Up: 3 }, "Verlauf: Kürzen entfernt alte Tage aus den Datenmengen");
        log.Prune(now.AddHours(-1), today);
        check(Find(log, "nas.local") == null, "Verlauf: ohne Verkehr seit der Frist fällt die Zeile weg");
        check(log.Export().Single(e => e.Host == "a.example").Days!.Single() is { Down: 7, Up: 3 }, "Verlauf: Tage je Zeile im Export");
        var settings = new Settings { HistoryDays = 1_000_000 };
        check(settings.HistoryDays == 3650 && new Settings { HistoryDays = -5 }.HistoryDays == 0, "Einstellung: Verlaufstage begrenzt");
    }

    /// <summary>Regeln „bis zum Beenden“ nach einem Neustart von SnitchBox: gelten für geladene Zeilen des noch laufenden Prozesses; die eines
    /// beendeten Prozesses werden vor dem Bewerten weggeräumt.</summary>
    static void UntilQuit(Action<bool, string> check)
    {
        var now = DateTime.Now;
        var store = new Store();
        var procs = new FakeProcs();
        procs.Alive.Add(4242);
        var engine = new FirewallEngine(store, procs, "boot", () => now) { Injector = (_, _) => { } };
        IpKey.TryParse("198.51.100.7", out var remote);
        Rule Quit(int pid, string host) => AlertRules.Create(new Connection
        {
            ProcessPath = @"C:\Apps\d.exe", Pid = pid, Direction = Direction.Outgoing, Protocol = Proto.Tcp, Remote = remote, Port = 443, Hostnames = [host],
        }, true, AlertScope.Host, AlertLifetime.UntilQuit, "boot", null, now)!;
        engine.Mutate(s => { s.Rules.Add(Quit(4242, "live.example")); s.Rules.Add(Quit(999, "dead.example")); });
        engine.History.Restore([
            new HistoryEntry { ProcessPath = @"C:\Apps\d.exe", Host = "live.example", Remote = "198.51.100.7", Port = 443, Protocol = Proto.Tcp, LastSeen = now, Count = 1, Pid = 4242 },
            new HistoryEntry { ProcessPath = @"C:\Apps\d.exe", Host = "dead.example", Remote = "198.51.100.7", Port = 443, Protocol = Proto.Tcp, LastSeen = now, Count = 1, Pid = 999 },
        ], now.AddDays(-1), DateOnly.FromDateTime(now));
        engine.ReevaluateHistory();
        check(Find(engine.History, "live.example")?.Allowed == true, "Verlauf: Regel bis zum Beenden gilt für geladene Zeile");
        check(Find(engine.History, "dead.example")?.Allowed != true && !store.Rules.Any(r => r.QuitPid == 999), "Verlauf: Regel eines beendeten Prozesses vor dem Bewerten entfernt");
    }

    static void Files(Action<bool, string> check)
    {
        var dir = Path.Combine(Path.GetTempPath(), "snitchbox-history-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "history.json");
            check(HistoryFile.Load(path, out var none) == null && !none, "Verlaufsdatei: fehlt");
            var data = new HistoryData
            {
                Connections = [new HistoryEntry { ProcessPath = "a.exe", Host = "a.example", Remote = "2a00:1450::1", Port = 443, LastSeen = DateTime.Now, Count = 2 }],
                Days = [new DailyEntry { Day = "2026-11-27", Path = "a.exe", Down = 10, Up = 2 }],
            };
            check(HistoryFile.Save(path, data), "Verlaufsdatei: gesichert");
            var loaded = HistoryFile.Load(path, out _);
            check(loaded is { Connections.Count: 1, Days.Count: 1 } && loaded.Connections[0].Remote == "2a00:1450::1" && loaded.Days[0].Down == 10
                  && !File.Exists(path + ".neu"), "Verlaufsdatei: Sichern und Laden");
            File.WriteAllText(path, "{ kaputt");
            check(HistoryFile.Load(path, out _) == null && File.Exists(path + ".kaputt") && !File.Exists(path), "Verlaufsdatei: kaputt → beiseitegelegt");
            File.WriteAllText(path, "null");
            check(HistoryFile.Load(path, out _) == null, "Verlaufsdatei: leer");
            // null in Listen und Feldern: geladen, unbrauchbare Einträge fallen weg – kein Absturz beim Start.
            File.WriteAllText(path, "{\"Connections\":null,\"Days\":[null,{\"Day\":\"2026-11-27\",\"Path\":null}]}");
            var nulls = HistoryFile.Load(path, out _);
            check(nulls is { Connections.Count: 0, Days.Count: 1 }, "Verlaufsdatei: null-Listen");
            var nullLog = new ConnectionLog();
            nullLog.Restore([new HistoryEntry { ProcessPath = null!, Host = "x.example", Remote = "1.2.3.4" }, new HistoryEntry { ProcessPath = "a", Host = null!, Remote = "1.2.3.4" },
                new HistoryEntry { ProcessPath = "b", Host = "b.example", Remote = null!, LastSeen = DateTime.Now },
                new HistoryEntry { ProcessPath = "c", Host = "c.example", Remote = "1.2.3.4", Reason = null!, LastSeen = DateTime.Now, Days = [null!] }],
                DateTime.Now.AddDays(-1), DateOnly.FromDateTime(DateTime.Now));
            new DailyTraffic().Restore(nulls!.Days, DateOnly.MinValue);
            check(nullLog.Snapshot().Count == 1 && nullLog.Snapshot()[0].Reason == "", "Verlauf: Einträge mit null übersprungen");
            // Gerade gesperrt (anderes Programm hält die Datei offen): nicht beiseitelegen.
            HistoryFile.Save(path, data);
            using (new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                check(HistoryFile.Load(path, out var locked) == null && locked && File.Exists(path), "Verlaufsdatei: gesperrt, nicht beiseitegelegt");
            File.WriteAllText(path + ".neu", "x");
            File.WriteAllText(path + ".kaputt", "x");
            HistoryFile.Delete(path);
            HistoryFile.Delete(path); // zweimal: kein Fehler
            check(!File.Exists(path) && !File.Exists(path + ".neu") && !File.Exists(path + ".kaputt"), "Verlaufsdatei: löschen samt Kopien");
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}
