using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace SnitchBox.Core;

/// <summary>Ein Land der eingebetteten Weltkarte: Umrisse (Länge/Breite in Grad, abwechselnd), Punkt für die Markierung und
/// Namen in den Sprachen von SnitchBox. Gebiete ohne Fläche auf der Karte (Gibraltar, Réunion …) haben nur den Punkt.</summary>
public sealed class MapCountry(string code, double lon, double lat, string[] names, float[][] rings)
{
    /// <summary>ISO-3166-Code („DE“), leer bei Gebieten ohne eigenen Code.</summary>
    public string Code { get; } = code;
    public double Lon { get; } = lon;
    public double Lat { get; } = lat;
    public IReadOnlyList<float[]> Rings { get; } = rings;

    public string Name => Localized(Loc.Language);

    public string Localized(string language)
    {
        var i = Array.IndexOf(WorldMap.Languages, language);
        var name = i >= 0 ? names[i] : "";
        return name.Length > 0 ? name : names[1].Length > 0 ? names[1] : Code;
    }
}

/// <summary>Weltkarte aus Natural Earth 1:50 Mio. (gemeinfrei, naturalearthdata.com), vereinfacht und ohne Antarktis; erzeugt von
/// scripts/make_worldmap.py, eingebettet als „worldmap.bin“. Nichts davon wird aus dem Netz geladen.</summary>
public sealed class WorldMap
{
    /// <summary>Reihenfolge der Namen in der Kartendatei.</summary>
    public static readonly string[] Languages = ["de", "en", "es", "fr", "it", "ja", "ko", "pl", "pt", "ru", "tr", "zh"];

    private readonly Dictionary<string, MapCountry> _byCode = new(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<MapCountry> Countries { get; }

    private WorldMap(List<MapCountry> countries)
    {
        Countries = countries;
        foreach (var c in countries)
            if (c.Code.Length == 2) _byCode.TryAdd(c.Code, c);
    }

    public MapCountry? Find(string? code) => code != null && _byCode.TryGetValue(code, out var c) ? c : null;

    private static WorldMap? _default;
    private static readonly Lock Gate = new();

    /// <summary>Die eingebettete Karte (einmal geladen, danach geteilt).</summary>
    public static WorldMap Default
    {
        get
        {
            lock (Gate)
            {
                if (_default != null) return _default;
                using var s = typeof(WorldMap).Assembly.GetManifestResourceStream("worldmap.bin")
                              ?? throw new InvalidOperationException("Weltkarte fehlt in der Anwendung");
                return _default = Read(s);
            }
        }
    }

    /// <summary>Liest die Kartendatei (roher Deflate-Strom; Format in scripts/make_worldmap.py).</summary>
    public static WorldMap Read(Stream deflated)
    {
        using var inflate = new DeflateStream(deflated, CompressionMode.Decompress);
        using var buffer = new MemoryStream();
        inflate.CopyTo(buffer);
        var d = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
        var p = 0;
        ReadOnlySpan<byte> Take(ReadOnlySpan<byte> all, int n)
        {
            if (n < 0 || p + n > all.Length) throw new InvalidDataException("Kartendatei endet zu früh");
            var s = all.Slice(p, n);
            p += n;
            return s;
        }
        if (!Take(d, 4).SequenceEqual("SBWM"u8) || Take(d, 1)[0] != 1) throw new InvalidDataException("Keine Kartendatei");
        var count = BinaryPrimitives.ReadUInt16LittleEndian(Take(d, 2));
        var list = new List<MapCountry>(count);
        for (var c = 0; c < count; c++)
        {
            var code = Encoding.ASCII.GetString(Take(d, 2));
            var lon = BinaryPrimitives.ReadInt16LittleEndian(Take(d, 2)) / 100.0;
            var lat = BinaryPrimitives.ReadInt16LittleEndian(Take(d, 2)) / 100.0;
            var names = new string[Languages.Length];
            for (var i = 0; i < names.Length; i++) names[i] = Encoding.UTF8.GetString(Take(d, Take(d, 1)[0]));
            var rings = new float[BinaryPrimitives.ReadUInt16LittleEndian(Take(d, 2))][];
            for (var r = 0; r < rings.Length; r++)
            {
                var n = BinaryPrimitives.ReadUInt16LittleEndian(Take(d, 2));
                int x = BinaryPrimitives.ReadInt16LittleEndian(Take(d, 2)), y = BinaryPrimitives.ReadInt16LittleEndian(Take(d, 2));
                var pts = new float[n * 2];
                for (var k = 0; k < n; k++)
                {
                    if (k > 0)
                    {
                        x += Zigzag(Varint(d, ref p));
                        y += Zigzag(Varint(d, ref p));
                    }
                    pts[2 * k] = x / 100f;
                    pts[2 * k + 1] = y / 100f;
                }
                rings[r] = pts;
            }
            list.Add(new MapCountry(code == "--" ? "" : code, lon, lat, names, rings));
        }
        return new WorldMap(list);
    }

    private static uint Varint(ReadOnlySpan<byte> d, ref int p)
    {
        uint v = 0;
        for (var shift = 0; shift < 35; shift += 7)
        {
            if (p >= d.Length) throw new InvalidDataException("Kartendatei endet zu früh");
            var b = d[p++];
            v |= (uint)(b & 0x7F) << shift;
            if (b < 0x80) return v;
        }
        throw new InvalidDataException("Zahl in der Kartendatei zu lang");
    }

    private static int Zigzag(uint v) => (int)(v >> 1) ^ -(int)(v & 1);
}

/// <summary>Kartenprojektion „Natural Earth“ (Šavrič, Patterson, Jenny 2011): wirkt wie eine gewohnte Weltkarte, ohne die riesigen
/// Polargebiete der Mercator-Karte. x nach Osten, y nach Norden, in Einheiten des Erdradius (x ±2,74, y ±1,42).</summary>
public static class MapProjection
{
    public const double MaxX = 2.7354, MaxY = 1.4224;

    public static (double X, double Y) Project(double lon, double lat)
    {
        var l = Math.Clamp(lon, -180, 180) * Math.PI / 180;
        var f = Math.Clamp(lat, -90, 90) * Math.PI / 180;
        var f2 = f * f;
        var f4 = f2 * f2;
        var x = l * (0.8707 - 0.131979 * f2 + f4 * (-0.013791 + f4 * (0.003971 * f2 - 0.001529 * f4)));
        var y = f * (1.007226 + f2 * (0.015085 + f4 * (-0.044475 + 0.028874 * f2 - 0.005916 * f4)));
        return (x, y);
    }

    /// <summary>Großkreis von A nach B (kürzester Weg auf der Erde) als Linienzüge in Grad; an der Datumsgrenze (±180°)
    /// aufgeteilt, damit keine Linie quer über die ganze Karte läuft. Etwa ein Punkt je 2°.</summary>
    public static List<List<(double Lon, double Lat)>> GreatCircle(double lon1, double lat1, double lon2, double lat2)
    {
        static (double X, double Y, double Z) Vec(double lon, double lat)
        {
            var l = lon * Math.PI / 180;
            var f = lat * Math.PI / 180;
            return (Math.Cos(f) * Math.Cos(l), Math.Cos(f) * Math.Sin(l), Math.Sin(f));
        }
        var a = Vec(lon1, lat1);
        var b = Vec(lon2, lat2);
        var dot = Math.Clamp(a.X * b.X + a.Y * b.Y + a.Z * b.Z, -1, 1);
        var angle = Math.Acos(dot);
        var steps = Math.Max(1, (int)Math.Ceiling(angle * 180 / Math.PI / 2));
        var points = new List<(double Lon, double Lat)>(steps + 1);
        var sin = Math.Sin(angle);
        for (var i = 0; i <= steps; i++)
        {
            var t = (double)i / steps;
            double x, y, z;
            if (sin < 1e-9)
            {
                // Gleicher Ort (oder genau gegenüber – dann gibt es keinen eindeutigen Großkreis): gerade Linie in Grad.
                points.Add((lon1 + (lon2 - lon1) * t, lat1 + (lat2 - lat1) * t));
                continue;
            }
            var wa = Math.Sin((1 - t) * angle) / sin;
            var wb = Math.Sin(t * angle) / sin;
            x = wa * a.X + wb * b.X;
            y = wa * a.Y + wb * b.Y;
            z = wa * a.Z + wb * b.Z;
            points.Add((Math.Atan2(y, x) * 180 / Math.PI, Math.Atan2(z, Math.Sqrt(x * x + y * y)) * 180 / Math.PI));
        }
        points[0] = (lon1, lat1);
        points[^1] = (lon2, lat2);
        // An der Datumsgrenze teilen: ein Sprung von über 180° Länge zwischen zwei Punkten führt über ±180°.
        var parts = new List<List<(double Lon, double Lat)>> { new() { points[0] } };
        for (var i = 1; i < points.Count; i++)
        {
            var (pl, pf) = points[i - 1];
            var (ql, qf) = points[i];
            if (Math.Abs(ql - pl) > 180)
            {
                var edge = pl > 0 ? 180.0 : -180.0;
                var qShifted = ql + (pl > 0 ? 360 : -360);
                var t = (edge - pl) / (qShifted - pl);
                var lat = pf + (qf - pf) * t;
                parts[^1].Add((edge, lat));
                parts.Add([(-edge, lat)]);
            }
            parts[^1].Add((ql, qf));
        }
        return parts;
    }
}
