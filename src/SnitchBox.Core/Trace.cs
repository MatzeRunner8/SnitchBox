using System.Net;

namespace SnitchBox.Core;

/// <summary>Antwort auf eine Probe mit begrenzter Lebensdauer (TTL / Hop-Limit).</summary>
public enum ProbeStatus
{
    /// <summary>Das Ziel hat geantwortet (Echo-Antwort).</summary>
    Reply,
    /// <summary>Ein Router unterwegs meldet: Lebensdauer abgelaufen – er ist der Hop dieser TTL.</summary>
    TimeExceeded,
    /// <summary>Ziel, Netz oder Port nicht erreichbar oder verboten (meldet ein Router oder das System selbst).</summary>
    Unreachable,
    /// <summary>Keine Antwort in der Wartezeit.</summary>
    Timeout,
    /// <summary>Probe ließ sich nicht senden.</summary>
    Error,
}

/// <param name="From">Wer geantwortet hat (Router oder Ziel), null ohne Antwort.</param>
/// <param name="Milliseconds">Laufzeit hin und zurück in ms (nur mit Antwort).</param>
/// <param name="Code">Rohwert des Systems (für Meldungen).</param>
public readonly record struct ProbeResult(ProbeStatus Status, IPAddress? From, int Milliseconds, int Code = 0)
{
    public bool Answered => From != null && Status is ProbeStatus.Reply or ProbeStatus.TimeExceeded or ProbeStatus.Unreachable;
    /// <summary>Hier endet der Weg: das Ziel antwortet, oder es ist von hier aus nicht erreichbar.</summary>
    public bool Final => Status is ProbeStatus.Reply or ProbeStatus.Unreachable;
}

/// <summary>Sendet eine Probe zum Ziel mit begrenzter Lebensdauer (in SnitchBox: ICMP-Echo über die Windows-ICMP-Schnittstelle).
/// Muss gleichzeitige Aufrufe vertragen.</summary>
public interface ITraceProber
{
    Task<ProbeResult> ProbeAsync(IPAddress target, int ttl, int timeoutMs, CancellationToken cancel);
}

/// <summary>Ein Hop (eine TTL) mit dem Ergebnis jeder Runde; null = Antwort steht noch aus.</summary>
public sealed class TraceHop(int number, int probes)
{
    public int Number { get; } = number;
    private readonly ProbeResult?[] _probes = new ProbeResult?[probes];
    public IReadOnlyList<ProbeResult?> Probes => _probes;

    internal void Set(int round, ProbeResult result) => _probes[round] = result;

    /// <summary>Alle Antwortenden dieses Hops, der häufigste zuerst (mehrere bei Lastverteilung).</summary>
    public IReadOnlyList<IPAddress> Addresses => _probes
        .Where(p => p is { Answered: true }).Select(p => p!.Value.From!)
        .GroupBy(a => a).OrderByDescending(g => g.Count()).Select(g => g.Key).ToList();

    public IPAddress? Address => Addresses.FirstOrDefault();
    public bool Answered => _probes.Any(p => p is { Answered: true });
    public bool Done => _probes.All(p => p != null);
    public bool Reached => _probes.Any(p => p is { Status: ProbeStatus.Reply });
    /// <summary>Die erste Meldung „nicht erreichbar“ (Rohwert), falls dieser Hop eine hatte.</summary>
    public ProbeResult? Unreachable => _probes.FirstOrDefault(p => p is { Status: ProbeStatus.Unreachable });

    public TraceHop Copy()
    {
        var c = new TraceHop(Number, _probes.Length);
        _probes.CopyTo(c._probes, 0);
        return c;
    }
}

public enum TraceEnd
{
    /// <summary>Läuft noch.</summary>
    Running,
    /// <summary>Das Ziel hat geantwortet.</summary>
    Reached,
    /// <summary>Ein Router (oder das System) meldet das Ziel als nicht erreichbar.</summary>
    Unreachable,
    /// <summary>Das Ziel hat bis zur höchsten TTL nicht geantwortet (Ping gesperrt oder Weg bricht ab).</summary>
    NoAnswer,
    /// <summary>Bis zur höchsten TTL hat jeder Hop geantwortet, das Ziel aber nicht: Weg länger als <see cref="TraceOptions.MaxHops"/>
    /// oder die Pakete kreisen (Routing-Schleife).</summary>
    HopLimit,
    Cancelled,
}

/// <summary>Stand einer Routenverfolgung: die Hops bis zum Ziel (oder bis zum letzten, der geantwortet hat).</summary>
/// <param name="Error">Rohwert des ersten Sendefehlers (0 = keiner) – erklärt einen Lauf ganz ohne Antwort.</param>
public sealed record TraceSnapshot(IReadOnlyList<TraceHop> Hops, TraceEnd End, int Error = 0);

public sealed class TraceOptions
{
    public int MaxHops { get; init; } = 30;
    /// <summary>Proben je Hop (Runden).</summary>
    public int Probes { get; init; } = 3;
    public int TimeoutMs { get; init; } = 3000;
    /// <summary>Abstand der Runden: jeder Router bekommt höchstens eine Probe je Runde (viele Router beantworten nur etwa
    /// eine je Sekunde, der Rest ginge als „keine Antwort“ verloren).</summary>
    public int RoundIntervalMs { get; init; } = 1000;
    /// <summary>Abstand zwischen zwei Proben einer Runde (kein Schwall von 30 Paketen auf einmal).</summary>
    public int StaggerMs { get; init; } = 15;
    /// <summary>Wartezeit der Proben an Hop 1, die allein vorweg gehen (der erste Router antwortet sonst in Millisekunden).</summary>
    public int FirstHopTimeoutMs { get; init; } = 1000;
}

/// <summary>Routenverfolgung wie „tracert“, aber schneller: Jede Runde schickt Proben mit TTL 2 bis 30 kurz nacheinander ab,
/// statt Hop für Hop auf Antwort zu warten (tracert braucht bei stummen Routern bis zu zwei Minuten, das hier höchstens
/// Runden × 1 s + Wartezeit). Sobald das Ziel bei einer TTL antwortet, gehen in späteren Runden nur noch Proben bis dorthin.
/// Hop 1 kommt vorher allein dran: Manche Heimrouter (gemessen an einer FRITZ!Box) beantworten TTL 1 nicht, solange
/// weitergeleitete Proben zum selben Ziel unterwegs sind – tracert geht Hop für Hop vor und sieht das nie.</summary>
public sealed class Tracer(ITraceProber prober, TraceOptions? options = null)
{
    private readonly TraceOptions _o = options ?? new TraceOptions();
    private readonly Lock _gate = new();
    private TraceHop[] _hops = [];
    private int _limit, _error;
    private TraceEnd _end = TraceEnd.Running;
    private IPAddress? _target;
    private bool _adopted;

    /// <summary>Nach jeder Antwort (aus einem beliebigen Thread).</summary>
    public event Action? Changed;

    public TraceOptions Options => _o;

    /// <summary>Das Ziel des laufenden oder letzten Laufs.</summary>
    public IPAddress? Target
    {
        get { lock (_gate) return _target; }
    }

    public async Task<TraceSnapshot> RunAsync(IPAddress target, CancellationToken cancel)
    {
        await BeginAsync(target, cancel).ConfigureAwait(false);
        return await ContinueAsync(cancel).ConfigureAwait(false);
    }

    /// <summary>Erster Teil eines Laufs: neu anfangen und Hop 1 allein und nacheinander abfragen (antwortet er nicht, gehen seine übrigen
    /// Proben mit den Runden). Für mehrere Ziele auf einmal (<see cref="TraceGroup"/>) kommt dieser Teil aller Ziele vor den Runden.
    /// Die ICMP-Schnittstelle von Windows lässt sich nicht abbrechen: Auf ausstehende Proben wird bei „Abbrechen“ nicht gewartet
    /// (WaitAsync), ihre späten Antworten verwirft Probe.</summary>
    /// <param name="probeFirstHop">false: nur neu anfangen; die Proben für Hop 1 gehen dann mit den Runden (in der Gruppe, wenn der erste
    /// Router dieses Gateways ohnehin nicht antwortet).</param>
    public async Task BeginAsync(IPAddress target, CancellationToken cancel, bool probeFirstHop = true)
    {
        lock (_gate)
        {
            _hops = Enumerable.Range(1, _o.MaxHops).Select(n => new TraceHop(n, _o.Probes)).ToArray();
            _limit = _o.MaxHops;
            _error = 0;
            _end = TraceEnd.Running;
            _target = target;
            _adopted = false;
        }
        if (!probeFirstHop) return;
        try
        {
            for (var round = 0; round < _o.Probes; round++)
            {
                cancel.ThrowIfCancellationRequested();
                var first = await Probe(target, 1, round, _o.FirstHopTimeoutMs, cancel).WaitAsync(cancel).ConfigureAwait(false);
                if (!first.Answered && !first.Final) break;
            }
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { MarkCancelled(); }
    }

    /// <summary>Statt <see cref="BeginAsync"/>: Hop 1 von einem anderen Lauf übernehmen, dessen Ziel über dasselbe Gateway geht – es ist
    /// derselbe Router, und Heimrouter beantworten nur etwa eine Probe je Sekunde (eine FRITZ!Box nach einem Schub von rund sechs).
    /// Nur wenn dort Hop 1 als Router geantwortet hat und nichts endete (Ziel = Gateway, nicht erreichbar); sonst false.</summary>
    public bool TryAdoptFirstHop(Tracer source, IPAddress target)
    {
        ProbeResult?[] first;
        lock (source._gate)
        {
            if (source._hops.Length == 0 || source._o.Probes != _o.Probes || source._target?.AddressFamily != target.AddressFamily) return false;
            first = source._hops[0].Probes.ToArray();
        }
        if (!first.Any(p => p is { Answered: true }) || first.Any(p => p is { Final: true })) return false;
        lock (_gate)
        {
            _hops = Enumerable.Range(1, _o.MaxHops).Select(n => new TraceHop(n, _o.Probes)).ToArray();
            _limit = _o.MaxHops;
            _error = 0;
            _end = TraceEnd.Running;
            _target = target;
            _adopted = true;
            for (var r = 0; r < first.Length; r++)
                if (first[r] is { } p) _hops[0].Set(r, p);
        }
        Changed?.Invoke();
        return true;
    }

    /// <summary>Hat Hop 1 mindestens einmal geantwortet (als Router, als Ziel oder mit „nicht erreichbar“)?</summary>
    public bool FirstHopAnswered
    {
        get { lock (_gate) return _hops.Length > 0 && _hops[0].Answered; }
    }

    /// <summary>Zweiter Teil: die Runden für TTL 2 bis 30 (nach <see cref="BeginAsync"/>), dann das Ergebnis.</summary>
    public async Task<TraceSnapshot> ContinueAsync(CancellationToken cancel)
    {
        IPAddress target;
        bool running;
        lock (_gate)
        {
            target = _target ?? throw new InvalidOperationException("BeginAsync fehlt");
            running = _end == TraceEnd.Running;
        }
        if (!running) return Snapshot(); // schon abgebrochen
        var pending = new List<Task>();
        try
        {
            cancel.ThrowIfCancellationRequested();
            var started = Environment.TickCount64;
            for (var round = 0; round < _o.Probes; round++)
            {
                bool Open(int ttl)
                {
                    lock (_gate) return ttl <= _limit && _hops[ttl - 1].Probes[round] == null;
                }
                // Nichts mehr zu senden (Ziel ist Hop 1): nicht auf die Runde warten.
                if (!Enumerable.Range(1, _o.MaxHops).Any(Open)) continue;
                var wait = started + (long)round * _o.RoundIntervalMs - Environment.TickCount64;
                if (wait > 0) await Task.Delay((int)wait, cancel).ConfigureAwait(false);
                for (var ttl = 1; ttl <= _o.MaxHops; ttl++)
                {
                    lock (_gate) if (ttl > _limit) break;
                    if (!Open(ttl)) continue;
                    cancel.ThrowIfCancellationRequested();
                    pending.Add(Probe(target, ttl, round, _o.TimeoutMs, cancel));
                    if (_o.StaggerMs > 0) await Task.Delay(_o.StaggerMs, cancel).ConfigureAwait(false);
                }
            }
            await Task.WhenAll(pending).WaitAsync(cancel).ConfigureAwait(false);
            cancel.ThrowIfCancellationRequested();
            // Hop 1 übernommen, aber das Ziel antwortet schon bei TTL 2: Es kann eine andere Adresse des Gateways selbst sein (seine
            // WAN-Adresse). Eine eigene Probe mit TTL 1 – jetzt, wo keine weitergeleiteten Proben mehr unterwegs sind – klärt das.
            bool check;
            lock (_gate) check = _adopted && _hops.Length > 1 && _limit == 2 && _hops[1].Reached;
            if (check)
            {
                ProbeResult own;
                try { own = await prober.ProbeAsync(target, 1, _o.FirstHopTimeoutMs, cancel).WaitAsync(cancel).ConfigureAwait(false); }
                catch (Exception e) when (e is not OperationCanceledException) { own = new ProbeResult(ProbeStatus.Error, null, 0); }
                if (own is { Status: ProbeStatus.Reply, From: not null })
                    lock (_gate)
                    {
                        _hops[0] = new TraceHop(1, _o.Probes);
                        _hops[0].Set(0, own);
                        _limit = 1;
                    }
            }
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            MarkCancelled();
            return Snapshot();
        }
        lock (_gate)
        {
            if (_end != TraceEnd.Running) return Snapshot(); // (Lock ist wiedereintrittsfähig)
            // Proben späterer Runden, die nie abgeschickt wurden (Ziel war schon früher erreicht), zählen als erledigt.
            var reached = _hops.Take(_limit).Any(h => h.Reached);
            _end = reached ? TraceEnd.Reached
                : _hops.Take(_limit).Any(h => h.Unreachable != null) ? TraceEnd.Unreachable
                : _limit == _o.MaxHops && _hops[^1].Answered ? TraceEnd.HopLimit
                : TraceEnd.NoAnswer;
        }
        Changed?.Invoke();
        return Snapshot();
    }

    private void MarkCancelled()
    {
        lock (_gate)
        {
            if (_end != TraceEnd.Running) return;
            _end = TraceEnd.Cancelled;
        }
        Changed?.Invoke();
    }

    private async Task<ProbeResult> Probe(IPAddress target, int ttl, int round, int timeoutMs, CancellationToken cancel)
    {
        ProbeResult result;
        try { result = await prober.ProbeAsync(target, ttl, timeoutMs, cancel).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { throw; }
        catch (Exception) { result = new ProbeResult(ProbeStatus.Error, null, 0); }
        lock (_gate)
        {
            if (_end != TraceEnd.Running || cancel.IsCancellationRequested) return result;
            // „Nicht erreichbar“ ohne Absender meldet das System selbst (keine Route, im eigenen Netz antwortet niemand auf ARP) –
            // unabhängig von der TTL. Das gilt schon für Hop 1; sonst stünden 30 Zeilen „*“ vor der Meldung. Hat aber schon jemand
            // jenseits des PCs geantwortet, war es nur eine kurze Störung (WLAN wechselt): dann zählt die Probe als Fehler.
            var system = result is { Status: ProbeStatus.Unreachable, From: null };
            if (system && _hops.Any(h => h.Answered))
            {
                result = result with { Status = ProbeStatus.Error };
                system = false;
            }
            var hop = system ? 0 : ttl - 1;
            // Eine solche Meldung überschreibt keine spätere Zeitüberschreitung derselben Runde.
            var replaced = _hops[hop].Probes[round] is { Status: ProbeStatus.Unreachable, From: null };
            if (_hops[hop].Probes[round] is not { Final: true } || result.Answered) _hops[hop].Set(round, result);
            else replaced = false;
            if (result.Answered && (WithdrawSystemVerdicts() | replaced)) RecomputeLimit();
            if (result.Status == ProbeStatus.Error && _error == 0) _error = result.Code != 0 ? result.Code : -1;
            if (result.Final && hop + 1 < _limit) _limit = hop + 1;
        }
        Changed?.Invoke();
        return result;
    }

    /// <summary>Kommt nach einer Meldung des Systems doch eine Antwort (der erste Router war nur langsam), war die Meldung eine Störung:
    /// Sie wird zum Fehler, und die Grenze gilt wieder bis zum ersten echten Wegende (unter <see cref="_gate"/>).</summary>
    private bool WithdrawSystemVerdicts()
    {
        var changed = false;
        for (var r = 0; r < _o.Probes; r++)
            if (_hops[0].Probes[r] is { Status: ProbeStatus.Unreachable, From: null } p)
            {
                _hops[0].Set(r, p with { Status = ProbeStatus.Error });
                changed = true;
            }
        return changed;
    }

    private void RecomputeLimit()
    {
        _limit = _o.MaxHops;
        for (var i = 0; i < _hops.Length; i++)
            if (_hops[i].Probes.Any(p => p is { Final: true })) { _limit = i + 1; break; }
    }

    /// <summary>Die Hops, die zählen: bis zum ersten Hop, an dem der Weg endet (Ziel oder „nicht erreichbar“), sonst bis zum letzten,
    /// der geantwortet hat. Während des Laufs sind das die bisher bekannten.</summary>
    public TraceSnapshot Snapshot()
    {
        lock (_gate)
        {
            var last = 0;
            for (var i = 0; i < _hops.Length && i < _limit; i++)
            {
                var h = _hops[i];
                if (h.Reached || h.Unreachable != null) { last = i + 1; break; }
                if (h.Answered) last = i + 1;
            }
            return new TraceSnapshot(_hops.Take(last).Select(h => h.Copy()).ToList(), _end, _error);
        }
    }
}

/// <summary>Mehrere Ziele auf einmal (alle Gegenstellen eines Programms): erst Hop 1 aller Ziele nacheinander, dann die Runden aller Ziele
/// gleichzeitig. Gemessen an einer FRITZ!Box: Laufen ganze Traces parallel, gehen bis zu zwei Drittel der Antworten von Hop 1 verloren
/// (er antwortet nicht, solange weitergeleitete Proben unterwegs sind); so geht keine verloren, und sechs Ziele brauchen kaum länger als eins.</summary>
public static class TraceGroup
{
    /// <param name="firstHopKey">Gateway je Ziel (z. B. Schnittstelle + nächster Hop laut Routing-Tabelle), null = unbekannt oder im eigenen
    /// Netz. Ziele mit demselben Schlüssel übernehmen Hop 1 vom ersten (<see cref="Tracer.TryAdoptFirstHop"/>); Ziele ohne Schlüssel
    /// fragen ihren Hop 1 gleichzeitig ab (es gibt nichts zu teilen). Antwortet der erste Router eines Gateways zweimal hintereinander
    /// nicht, warten die übrigen Ziele nicht je eine Sekunde auf ihn: Ihre Proben für Hop 1 gehen mit den Runden.</param>
    public static async Task RunAsync(IReadOnlyList<(Tracer Tracer, IPAddress Target)> items, int parallel, CancellationToken cancel,
        Func<IPAddress, string?>? firstHopKey = null)
    {
        var shared = new Dictionary<string, Tracer>();
        var silent = new Dictionary<string, int>(); // Schlüssel → selbst abgefragte Quellen in Folge, deren Hop 1 nicht antwortete
        var unkeyed = new List<Task>();
        foreach (var (tracer, target) in items)
        {
            string? key = null;
            try { key = firstHopKey?.Invoke(target); }
            catch (Exception) { }
            if (key == null)
            {
                unkeyed.Add(tracer.BeginAsync(target, cancel)); // bei Abbruch: gleich als abgebrochen markiert
                continue;
            }
            if (!cancel.IsCancellationRequested && shared.TryGetValue(key, out var source) && tracer.TryAdoptFirstHop(source, target)) continue;
            if (silent.GetValueOrDefault(key) >= 2)
            {
                await tracer.BeginAsync(target, cancel, probeFirstHop: false).ConfigureAwait(false);
                continue;
            }
            await tracer.BeginAsync(target, cancel).ConfigureAwait(false);
            shared[key] = tracer; // der zuletzt selbst abgefragte gibt weiter
            silent[key] = tracer.FirstHopAnswered ? 0 : silent.GetValueOrDefault(key) + 1;
        }
        await Task.WhenAll(unkeyed).ConfigureAwait(false);
        using var gate = new SemaphoreSlim(Math.Max(1, parallel));
        await Task.WhenAll(items.Select(async item =>
        {
            try { await gate.WaitAsync(cancel).ConfigureAwait(false); }
            catch (OperationCanceledException)
            {
                await item.Tracer.ContinueAsync(cancel).ConfigureAwait(false); // markiert den Lauf als abgebrochen
                return;
            }
            try { await item.Tracer.ContinueAsync(cancel).ConfigureAwait(false); }
            finally { gate.Release(); }
        })).ConfigureAwait(false);
    }
}

/// <summary>Ein Ziel der Übersicht „wohin sendet dieses Programm“: eine Gegenstelle mit Namen, Zahl der Verbindungen und Datenmenge.</summary>
public sealed record TraceTarget(IPAddress Address, string Host, int Count, long Bytes, DateTime LastSeen);

public static class TraceTargets
{
    /// <summary>Die Gegenstellen aus Zeilen des Netzwerkmonitors, die zuletzt benutzte zuerst; je Adresse eine (Name: der erste, der keine
    /// bloße Adresse ist). Nicht verfolgbar und daher ausgelassen: Loopback, Multicast, Broadcast, unbestimmte und verbindungslokale
    /// Adressen (ihnen fehlt die Schnittstelle). Mehr als <paramref name="max"/>: die ältesten fallen weg (<paramref name="omitted"/>).</summary>
    /// <param name="exclude">Weitere Adressen, die wegfallen (in SnitchBox: Broadcast-Adressen der eigenen Netze, z. B. 192.168.178.255).</param>
    public static List<TraceTarget> From(IEnumerable<ConnectionRecord> records, int max, out int omitted, Func<IPAddress, bool>? exclude = null)
    {
        var byAddress = new Dictionary<IpKey, (string Host, int Count, long Bytes, DateTime Last)>();
        foreach (var r in records)
        {
            var a = r.Remote.ToAddress();
            if (GeoIp.ScopeOf(a) is AddressScope.Loopback or AddressScope.Multicast or AddressScope.LinkLocal) continue;
            if (a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any) || a.Equals(IPAddress.Broadcast)) continue;
            if (exclude != null && exclude(a)) continue;
            var named = r.Host.Length > 0 && !IPAddress.TryParse(r.Host, out _);
            if (byAddress.TryGetValue(r.Remote, out var e))
                byAddress[r.Remote] = (e.Host.Length == 0 && named ? r.Host : e.Host, e.Count + r.Count, e.Bytes + r.Down + r.Up, r.LastSeen > e.Last ? r.LastSeen : e.Last);
            else
                byAddress[r.Remote] = (named ? r.Host : "", r.Count, r.Down + r.Up, r.LastSeen);
        }
        var all = byAddress.OrderByDescending(p => p.Value.Last).ThenByDescending(p => p.Value.Bytes)
            .Select(p => new TraceTarget(p.Key.ToAddress(), p.Value.Host, p.Value.Count, p.Value.Bytes, p.Value.Last)).ToList();
        omitted = Math.Max(0, all.Count - max);
        return all.Take(max).ToList();
    }
}
