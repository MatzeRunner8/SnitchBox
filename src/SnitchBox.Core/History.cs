using System.Globalization;
using System.Text.Json;

namespace SnitchBox.Core;

/// <summary>Datenmenge je Tag und Programm (Pfad wie bei <see cref="TrafficStats"/>): für das Diagramm „je Tag“ und die Summen der
/// Programmliste über die Tage des Verlaufs. Tage in Ortszeit.</summary>
public sealed class DailyTraffic
{
    /// <summary>Höchstens so viele Programme je Tag (alles darüber zählt nicht mehr – schützt vor einer aufgeblähten Datei).</summary>
    public const int MaxPathsPerDay = 5000;
    private readonly Dictionary<DateOnly, Dictionary<string, (long Down, long Up)>> _days = [];
    private readonly Lock _gate = new();
    public long Version { get; private set; }

    public void Add(DateOnly day, IEnumerable<(string Path, long Down, long Up)> interval)
    {
        lock (_gate)
        {
            var changed = false;
            foreach (var (path, down, up) in interval)
            {
                if (down <= 0 && up <= 0) continue;
                if (!_days.TryGetValue(day, out var paths)) _days[day] = paths = new Dictionary<string, (long, long)>(StringComparer.OrdinalIgnoreCase);
                if (!paths.TryGetValue(path, out var sum) && paths.Count >= MaxPathsPerDay) continue;
                paths[path] = (sum.Down + Math.Max(0, down), sum.Up + Math.Max(0, up));
                changed = true;
            }
            if (changed) Version++;
        }
    }

    /// <summary>Summen je Programm ab <paramref name="from"/> (einschließlich).</summary>
    public Dictionary<string, (long Down, long Up)> Totals(DateOnly from)
    {
        var result = new Dictionary<string, (long Down, long Up)>(StringComparer.OrdinalIgnoreCase);
        lock (_gate)
            foreach (var (day, paths) in _days)
            {
                if (day < from) continue;
                foreach (var (path, v) in paths)
                {
                    result.TryGetValue(path, out var sum);
                    result[path] = (sum.Down + v.Down, sum.Up + v.Up);
                }
            }
        return result;
    }

    /// <summary>Je Tag von <paramref name="from"/> bis <paramref name="to"/> die Summe – eines Programms, mehrerer (<paramref name="paths"/>)
    /// oder aller (null); Tage ohne Verkehr mit 0.</summary>
    public List<(DateOnly Day, long Down, long Up)> Series(IReadOnlyCollection<string>? paths, DateOnly from, DateOnly to)
    {
        var result = new List<(DateOnly, long, long)>();
        if (to < from || to.DayNumber - from.DayNumber > 3660) return result;
        lock (_gate)
            for (var day = from; day <= to; day = day.AddDays(1))
            {
                long down = 0, up = 0;
                if (_days.TryGetValue(day, out var all))
                {
                    if (paths == null)
                        foreach (var v in all.Values) { down += v.Down; up += v.Up; }
                    else
                        foreach (var p in paths)
                            if (all.TryGetValue(p, out var v)) { down += v.Down; up += v.Up; }
                }
                result.Add((day, down, up));
            }
        return result;
    }

    /// <summary>Tage vor <paramref name="keepFrom"/> vergessen.</summary>
    public void Prune(DateOnly keepFrom)
    {
        lock (_gate)
        {
            var old = _days.Keys.Where(d => d < keepFrom).ToList();
            foreach (var d in old) _days.Remove(d);
            if (old.Count > 0) Version++;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _days.Clear();
            Version++;
        }
    }

    public List<DailyEntry> Export()
    {
        lock (_gate)
            return _days.SelectMany(d => d.Value.Select(p => new DailyEntry
            {
                Day = d.Key.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), Path = p.Key, Down = p.Value.Down, Up = p.Value.Up,
            })).ToList();
    }

    /// <summary>Gespeicherte Tage übernehmen (unbrauchbare Einträge fallen weg); kommt ein Tag doppelt vor, wird addiert.</summary>
    public void Restore(IEnumerable<DailyEntry> entries, DateOnly keepFrom)
    {
        foreach (var group in entries
                     .Where(e => e is { Path: not null } && e.Path.Length <= HistoryFile.MaxText)
                     .Select(e => (Ok: DateOnly.TryParseExact(e.Day, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d), Day: d, e))
                     .Where(x => x.Ok && x.Day >= keepFrom)
                     .GroupBy(x => x.Day))
            Add(group.Key, group.Select(x => (x.e.Path!, x.e.Down, x.e.Up)));
    }
}

/// <summary>Datenmenge einer Zeile an einem Tag (gespeichert).</summary>
public sealed class DayVolume
{
    public string Day { get; set; } = "";
    public long Down { get; set; }
    public long Up { get; set; }
}

/// <summary>Eine gespeicherte Zeile des Netzwerkmonitors.</summary>
public sealed class HistoryEntry
{
    public string ProcessPath { get; set; } = "";
    public string Service { get; set; } = "";
    public string Host { get; set; } = "";
    public string Remote { get; set; } = "";
    public ushort Port { get; set; }
    public Proto Protocol { get; set; }
    public Direction Direction { get; set; }
    public DateTime LastSeen { get; set; }
    public int Count { get; set; }
    public bool? Allowed { get; set; }
    public string Reason { get; set; } = "";
    public long Down { get; set; }
    public long Up { get; set; }
    /// <summary>Zuletzt Verkehr gezählt (eine lange offene Verbindung entscheidet nur einmal, überträgt aber weiter).</summary>
    public DateTime LastActive { get; set; }
    /// <summary>Prozess der letzten Entscheidung – Regeln „bis zum Beenden“ gelten nur für ihn (nach einem Neustart von Windows verworfen).</summary>
    public int Pid { get; set; }
    /// <summary>Namen aus DNS-Antworten (höchstens sechs) – Regeln für Hosts und Domains prüfen alle.</summary>
    public List<string>? Hostnames { get; set; }
    /// <summary>Datenmenge je Tag; die Summe über die aufgehobenen Tage ist die Datenmenge der Zeile.</summary>
    public List<DayVolume>? Days { get; set; }
}

/// <summary>Datenmenge eines Programms an einem Tag (gespeichert).</summary>
public sealed class DailyEntry
{
    public string Day { get; set; } = "";
    public string? Path { get; set; }
    public long Down { get; set; }
    public long Up { get; set; }
}

public sealed class HistoryData
{
    public int Version { get; set; } = 1;
    public List<HistoryEntry> Connections { get; set; } = [];
    public List<DailyEntry> Days { get; set; } = [];
}

/// <summary>Der Verlauf des Netzwerkmonitors über Neustarts hinweg: private\history.json im Datenordner – der Unterordner ist nur für
/// SYSTEM und Administratoren lesbar (der Verlauf zeigt, welches Programm wohin verbunden hat). Geschrieben wird erst in eine
/// Zwischendatei (auf die Platte gebracht), dann ersetzt; eine kaputte oder übergroße Datei wird beiseitegelegt.</summary>
public static class HistoryFile
{
    public const long MaxBytes = 64L << 20;
    public const int MaxText = 1024;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    public static string DefaultPath => Path.Combine(Paths.DataDir, "private", "history.json");

    /// <summary>Legt den Ordner der Datei vor jedem Schreiben an bzw. prüft ihn (die App: nur SYSTEM und Administratoren dürfen lesen);
    /// null = einfach anlegen (Tests).</summary>
    public static Action<string>? PrepareDirectory { get; set; }

    /// <summary>Erster Tag, dessen Daten zum Verlauf gehören: heute und die Tage davor, zusammen <paramref name="days"/> (mindestens heute).
    /// Für Zeilen gilt dieselbe Grenze ab Mitternacht – so stimmen Zeilen, Programmliste und Diagramm überein.</summary>
    public static DateOnly KeepFrom(int days, DateTime now) => DateOnly.FromDateTime(now).AddDays(-(Math.Max(1, days) - 1));

    /// <summary>Zeilen, die seitdem nicht mehr entschieden oder übertragen haben, gehören nicht mehr zum Verlauf: Mitternacht von <see cref="KeepFrom"/>.</summary>
    public static DateTime RowCutoff(int days, DateTime now) => KeepFrom(days, now).ToDateTime(TimeOnly.MinValue);

    /// <summary>false: zu groß – nichts geschrieben (der Aufrufer kürzt und versucht es erneut; Load nähme die Datei nicht).</summary>
    public static bool Save(string path, HistoryData data)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(data, Json);
        if (bytes.Length > MaxBytes) return false;
        var dir = Path.GetDirectoryName(path)!;
        if (PrepareDirectory is { } prepare) prepare(dir);
        else Directory.CreateDirectory(dir);
        var temp = path + ".neu";
        try
        {
            using (var f = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                f.Write(bytes);
                f.Flush(flushToDisk: true); // sonst kann nach einem Absturz eine Datei voller Nullen das Original ersetzen
            }
            File.Move(temp, path, true);
            return true;
        }
        catch
        {
            try { File.Delete(temp); } catch (Exception) { }
            throw;
        }
    }

    /// <summary>Den gespeicherten Verlauf lesen. <paramref name="locked"/>: die Datei ist da, aber gerade nicht lesbar (ein anderes
    /// Programm hält sie offen) – dann nichts beiseitelegen und in dieser Sitzung auch nichts darüber schreiben.</summary>
    public static HistoryData? Load(string path, out bool locked)
    {
        locked = false;
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) return null;
                if (info.Length > MaxBytes) throw new InvalidDataException("Verlauf zu groß: " + info.Length);
                using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                var data = JsonSerializer.Deserialize<HistoryData>(f, Json) ?? throw new InvalidDataException("Verlauf leer");
                data.Connections ??= [];
                data.Days ??= [];
                data.Connections.RemoveAll(e => e == null);
                data.Days.RemoveAll(e => e == null);
                return data;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException && e is not FileNotFoundException)
            {
                if (attempt < 3) { Thread.Sleep(300); continue; }
                Log.Write("Verlauf gerade nicht lesbar: " + e.Message);
                locked = true;
                return null;
            }
            catch (Exception e) when (e is JsonException or InvalidDataException or NotSupportedException)
            {
                SetAside(path, e.Message);
                return null;
            }
        }
    }

    /// <summary>Unbrauchbaren Verlauf beiseitelegen (als .kaputt; „Verlauf leeren“ löscht ihn mit).</summary>
    public static void SetAside(string path, string reason)
    {
        Log.Write("Verlauf unbrauchbar, beiseitegelegt: " + reason);
        try { File.Move(path, path + ".kaputt", true); } catch (Exception) { }
    }

    /// <summary>Verlauf samt Zwischendatei und beiseitegelegter Kopie löschen.</summary>
    public static void Delete(string path)
    {
        foreach (var p in new[] { path, path + ".neu", path + ".kaputt" })
            try { File.Delete(p); } catch (Exception e) { Log.Write("Verlauf löschen: " + e.Message); }
    }
}
