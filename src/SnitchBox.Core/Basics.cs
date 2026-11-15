using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SnitchBox.Core;

/// <summary>Oberflächensprache. Deutsch und Englisch stehen direkt im Code (<see cref="T"/>); alle anderen Sprachen kommen aus
/// eingebetteten Tabellen Lang/&lt;code&gt;.json, die den englischen Text auf die Übersetzung abbilden. Fehlt ein Eintrag, gilt Englisch.
/// Neue Texte: scripts/extract_strings.py aktualisiert Lang/_source.json und meldet, was noch übersetzt werden muss.</summary>
public static class Loc
{
    /// <summary>Unterstützte Sprachen (Code, Name in der eigenen Sprache) in der Reihenfolge der Auswahlliste.</summary>
    public static readonly (string Code, string Name)[] Languages =
    [
        ("de", "Deutsch"), ("en", "English"), ("fr", "Français"), ("es", "Español"), ("it", "Italiano"), ("pt", "Português (Brasil)"),
        ("pl", "Polski"), ("tr", "Türkçe"), ("ru", "Русский"), ("ja", "日本語"), ("zh", "中文（简体）"), ("ko", "한국어"),
    ];

    private static string _language = FromCulture(CultureInfo.CurrentUICulture);
    private static Dictionary<string, string>? _table;

    /// <summary>Aktuelle Sprache als zweibuchstabiger Code; Unbekanntes wird Englisch.</summary>
    public static string Language
    {
        get => _language;
        set
        {
            _language = Normalize(value);
            _table = null;
        }
    }

    public static bool German
    {
        get => _language == "de";
        set => Language = value ? "de" : "en";
    }

    /// <summary>Sprache von Windows (Anzeigesprache des Benutzers), soweit unterstützt, sonst Englisch.</summary>
    public static string WindowsLanguage => FromCulture(CultureInfo.CurrentUICulture);

    /// <summary>Name einer Sprache in ihr selbst („Français“).</summary>
    public static string NameOf(string code)
    {
        foreach (var (known, name) in Languages) if (known == code) return name;
        return code;
    }

    public static string FromCulture(CultureInfo culture) => Normalize(culture.TwoLetterISOLanguageName);

    public static string Normalize(string? code)
    {
        var c = (code ?? "").Trim().ToLowerInvariant();
        if (c.Length > 2) c = c[..2]; // „pt-BR“, „zh-Hans“ …
        foreach (var (known, _) in Languages) if (known == c) return c;
        return "en";
    }

    public static string T(string de, string en) => _language switch
    {
        "de" => de,
        "en" => en,
        _ => Lookup(en),
    };

    /// <summary>Wie <see cref="T"/>, aber mit Platzhaltern {0}, {1} … (string.Format), damit sich auch Texte mit Werten übersetzen lassen.</summary>
    public static string F(string de, string en, params object?[] args) => string.Format(CultureInfo.CurrentCulture, T(de, en), args);

    private static string Lookup(string en)
    {
        var table = _table ??= Load(_language);
        return table.TryGetValue(en, out var s) && s.Length > 0 ? s : en;
    }

    /// <summary>Übersetzungstabelle einer Sprache (leer, wenn es keine gibt).</summary>
    public static Dictionary<string, string> Load(string code)
    {
        try
        {
            using var s = typeof(Loc).Assembly.GetManifestResourceStream($"Lang.{code}.json");
            if (s != null) return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(s) ?? [];
        }
        catch { }
        return [];
    }
}

public static class Paths
{
    /// <summary>Überschreibbar für Tests; sonst %ProgramData%\SnitchBox (der Filter gilt für den ganzen Rechner).</summary>
    public static string? Override { get; set; }

    /// <summary>%ProgramData%\SnitchBox, ohne ihn anzulegen (die App legt ihn selbst mit sicheren Rechten an).</summary>
    public static string DefaultDataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SnitchBox");

    public static string DataDir
    {
        get
        {
            var d = Override ?? DefaultDataDir;
            Directory.CreateDirectory(d);
            return d;
        }
    }
}

public static class Log
{
    private static readonly object Gate = new();
    public static string FilePath => Path.Combine(Paths.DataDir, "log.txt");
    /// <summary>Aus, solange der Datenordner nicht als sicher gilt: sonst schriebe das Protokoll womöglich durch eine
    /// untergeschobene Verknüpfung an einen fremden Ort (und löschte dort Dateien über 2 MB).</summary>
    public static bool Enabled { get; set; } = true;

    public static void Write(string line)
    {
        if (!Enabled) return;
        try
        {
            lock (Gate)
            {
                var fi = new FileInfo(FilePath);
                if (fi.Exists && fi.Length > 2_000_000) fi.Delete();
                File.AppendAllText(FilePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {line}{Environment.NewLine}");
            }
        }
        catch { }
    }
}

/// <summary>IP-Adresse als 128-Bit-Wert (IPv4 als ::ffff:a.b.c.d), ohne Speicheranforderung je Paket.</summary>
public readonly record struct IpKey(ulong Hi, ulong Lo) : IComparable<IpKey>
{
    public static IpKey FromV4(ReadOnlySpan<byte> b) => new(0, 0x0000FFFF00000000UL | BinaryPrimitives.ReadUInt32BigEndian(b));
    public static IpKey FromV6(ReadOnlySpan<byte> b) => new(BinaryPrimitives.ReadUInt64BigEndian(b), BinaryPrimitives.ReadUInt64BigEndian(b[8..]));

    public static IpKey From(IPAddress a)
    {
        Span<byte> s = stackalloc byte[16];
        a.MapToIPv6().TryWriteBytes(s, out _);
        return FromV6(s);
    }

    public static bool TryParse(string text, out IpKey key)
    {
        key = default;
        if (!IPAddress.TryParse(text.Trim(), out var a)) return false;
        key = From(a);
        return true;
    }

    public bool IsV4 => Hi == 0 && (Lo >> 32) == 0xFFFF;
    /// <summary>127.0.0.0/8 oder ::1.</summary>
    public bool IsLoopback => IsV4 ? ((Lo >> 24) & 0xFF) == 127 : Hi == 0 && Lo == 1;

    public IPAddress ToAddress()
    {
        Span<byte> s = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(s, Hi);
        BinaryPrimitives.WriteUInt64BigEndian(s[8..], Lo);
        return IsV4 ? new IPAddress(s[12..]) : new IPAddress(s);
    }

    public int CompareTo(IpKey o) => Hi != o.Hi ? Hi.CompareTo(o.Hi) : Lo.CompareTo(o.Lo);
    public override string ToString() => ToAddress().ToString();
}

/// <summary>Adressbereich aus „1.2.3.4“, „10.0.0.0/8“, „fe80::/10“ oder „1.2.3.4-1.2.3.9“.</summary>
public readonly record struct AddressRange(IpKey From, IpKey To)
{
    public bool Contains(IpKey a) => a.CompareTo(From) >= 0 && a.CompareTo(To) <= 0;

    public static bool TryParse(string text, out AddressRange range)
    {
        range = default;
        text = text.Trim();
        var dash = text.IndexOf('-');
        if (dash > 0)
        {
            if (!IpKey.TryParse(text[..dash], out var a) || !IpKey.TryParse(text[(dash + 1)..], out var b)) return false;
            range = a.CompareTo(b) <= 0 ? new(a, b) : new(b, a);
            return true;
        }
        var slash = text.IndexOf('/');
        if (slash > 0)
        {
            if (!IPAddress.TryParse(text[..slash], out var ip) || !int.TryParse(text[(slash + 1)..], out var len)) return false;
            var v4 = ip.AddressFamily == AddressFamily.InterNetwork;
            if (len < 0 || len > (v4 ? 32 : 128)) return false;
            var p = v4 ? len + 96 : len;
            var maskHi = p >= 64 ? ulong.MaxValue : p == 0 ? 0UL : ulong.MaxValue << (64 - p);
            var maskLo = p <= 64 ? 0UL : p == 128 ? ulong.MaxValue : ulong.MaxValue << (128 - p);
            var k = IpKey.From(ip);
            range = new(new(k.Hi & maskHi, k.Lo & maskLo), new(k.Hi | ~maskHi, k.Lo | ~maskLo));
            return true;
        }
        if (!IpKey.TryParse(text, out var single)) return false;
        range = new(single, single);
        return true;
    }

    private static AddressRange P(string s) => TryParse(s, out var r) ? r : throw new FormatException(s);

    /// <summary>Lokales Netz: private Bereiche, Link-Local, Multicast und Broadcast.</summary>
    public static readonly AddressRange[] LocalNet =
    [
        P("10.0.0.0/8"), P("172.16.0.0/12"), P("192.168.0.0/16"), P("169.254.0.0/16"),
        P("224.0.0.0/4"), P("255.255.255.255"), P("fe80::/10"), P("fc00::/7"), P("ff00::/8"),
    ];

    public static bool IsLocal(IpKey a)
    {
        foreach (var r in LocalNet) if (r.Contains(a)) return true;
        return false;
    }
}

/// <summary>Portangabe wie „443“, „80, 443“ oder „8000-8100“; leer oder „any“ = jeder Port.</summary>
public sealed class PortSet
{
    private readonly (ushort From, ushort To)[] _ranges;
    private PortSet((ushort, ushort)[] r) => _ranges = r;
    public bool Any => _ranges.Length == 0;

    public bool Contains(ushort port)
    {
        if (_ranges.Length == 0) return true;
        foreach (var (a, b) in _ranges) if (port >= a && port <= b) return true;
        return false;
    }

    /// <summary>Dieselben Ports, gleich in welcher Schreibweise („443, 80“ = „80,443“).</summary>
    public bool SameAs(PortSet o) =>
        _ranges.Distinct().Order().SequenceEqual(o._ranges.Distinct().Order());

    public static bool TryParse(string? text, out PortSet set)
    {
        var list = new List<(ushort, ushort)>();
        set = new PortSet([]);
        text = (text ?? "").Trim();
        if (text.Length == 0 || text.Equals("any", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var part in text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries))
        {
            var d = part.IndexOf('-');
            if (d > 0)
            {
                if (!ushort.TryParse(part[..d], out var a) || !ushort.TryParse(part[(d + 1)..], out var b) || a > b) return false;
                list.Add((a, b));
            }
            else
            {
                if (!ushort.TryParse(part, out var p)) return false;
                list.Add((p, p));
            }
        }
        set = new PortSet(list.ToArray());
        return true;
    }
}
