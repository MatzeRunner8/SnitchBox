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

    /// <summary>Nach jeder Antwort (aus einem beliebigen Thread).</summary>
    public event Action? Changed;

    public TraceOptions Options => _o;

    public async Task<TraceSnapshot> RunAsync(IPAddress target, CancellationToken cancel)
    {
        lock (_gate)
        {
            _hops = Enumerable.Range(1, _o.MaxHops).Select(n => new TraceHop(n, _o.Probes)).ToArray();
            _limit = _o.MaxHops;
            _error = 0;
            _end = TraceEnd.Running;
        }
        var pending = new List<Task>();
        try
        {
            // Hop 1 allein und nacheinander; antwortet er nicht, gehen seine übrigen Proben mit den Runden.
            // Die ICMP-Schnittstelle von Windows lässt sich nicht abbrechen: Auf ausstehende Proben wird bei „Abbrechen“ nicht gewartet
            // (WaitAsync), ihre späten Antworten verwirft Probe.
            for (var round = 0; round < _o.Probes; round++)
            {
                cancel.ThrowIfCancellationRequested();
                var first = await Probe(target, 1, round, _o.FirstHopTimeoutMs, cancel).WaitAsync(cancel).ConfigureAwait(false);
                if (!first.Answered && !first.Final) break;
            }
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
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            lock (_gate) _end = TraceEnd.Cancelled;
            Changed?.Invoke();
            return Snapshot();
        }
        lock (_gate)
        {
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
