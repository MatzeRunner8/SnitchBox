using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SnitchBox.Core;

/// <summary>Liest Datenbanken im MaxMind-DB-Format (.mmdb), wie sie DB-IP und MaxMind anbieten – nur lesend, ganz im Speicher.
/// Die Datei kommt aus dem Netz und SnitchBox läuft als Administrator: Jeder Zugriff prüft seine Grenzen, Verweise und
/// Verschachtelung sind begrenzt, und jede Abfrage hat ein Arbeitsbudget. Eine kaputte Datei liefert keine Treffer, aber
/// nie einen Absturz oder eine Endlosschleife. Format: https://maxmind.github.io/MaxMind-DB/</summary>
public sealed class MaxMindDb
{
    private static readonly byte[] Marker = [0xAB, 0xCD, 0xEF, .. "MaxMind.com"u8];
    private const int MetadataMax = 128 * 1024, MaxDepth = 16, Budget = 20_000;
    private readonly byte[] _data;
    private readonly int _nodeCount, _recordSize, _dataStart, _dataEnd;
    private readonly long _ipv4Start;

    public int IpVersion { get; }
    public string DatabaseType { get; }
    /// <summary>Erstellungszeit laut Datei (UTC).</summary>
    public DateTime BuildTime { get; }

    public MaxMindDb(byte[] data)
    {
        _data = data;
        var from = Math.Max(0, data.Length - MetadataMax - Marker.Length);
        var marker = data.AsSpan(from).LastIndexOf(Marker);
        if (marker < 0) throw new InvalidDataException("Keine MaxMind-DB (Kennung fehlt)");
        var metaStart = from + marker + Marker.Length;
        var pos = metaStart;
        var budget = Budget;
        if (DecodeAt(ref pos, metaStart, data.Length, 0, ref budget) is not Dictionary<string, object?> meta)
            throw new InvalidDataException("Metadaten fehlen");
        long Num(string key) => meta.TryGetValue(key, out var v) && v is long n ? n
            : meta.TryGetValue(key, out v) && v is ulong u && u <= long.MaxValue ? (long)u
            : throw new InvalidDataException("Metadatum fehlt: " + key);
        if (Num("binary_format_major_version") != 2) throw new InvalidDataException("Unbekannte Formatversion");
        var nodes = Num("node_count");
        var recordSize = Num("record_size");
        var ipVersion = Num("ip_version");
        if (recordSize is not (24 or 28 or 32)) throw new InvalidDataException("Unbekannte Datensatzgröße");
        if (ipVersion is not (4 or 6)) throw new InvalidDataException("Unbekannte IP-Version");
        var treeSize = nodes * recordSize / 4; // zwei Datensätze je Knoten
        var markerStart = from + marker;
        if (nodes <= 0 || nodes > int.MaxValue || treeSize + 16 > markerStart) throw new InvalidDataException("Suchbaum passt nicht in die Datei");
        _nodeCount = (int)nodes;
        _recordSize = (int)recordSize;
        _dataStart = (int)treeSize + 16;
        _dataEnd = markerStart;
        IpVersion = (int)ipVersion;
        DatabaseType = meta.TryGetValue("database_type", out var t) && t is string s ? s : "";
        BuildTime = meta.TryGetValue("build_epoch", out var e) && e is long or ulong
            ? DateTime.UnixEpoch.AddSeconds(Math.Clamp(Convert.ToDouble(e), 0, 253_402_300_000)) : DateTime.MinValue;
        // IPv4-Adressen liegen in einer IPv6-Datenbank unter ::/96: der Knoten nach 96 Nullbits.
        long node = 0;
        if (IpVersion == 6)
            for (var i = 0; i < 96 && node < _nodeCount; i++) node = Record((int)node, 0);
        _ipv4Start = node;
    }

    private long Record(int node, int bit)
    {
        var d = _data;
        switch (_recordSize)
        {
            case 24:
            {
                var o = (long)node * 6 + bit * 3;
                return (d[o] << 16) | (d[o + 1] << 8) | d[o + 2];
            }
            case 28:
            {
                var o = (long)node * 7;
                return bit == 0
                    ? ((long)(d[o + 3] & 0xF0) << 20) | ((long)d[o] << 16) | ((long)d[o + 1] << 8) | d[o + 2]
                    : ((long)(d[o + 3] & 0x0F) << 24) | ((long)d[o + 4] << 16) | ((long)d[o + 5] << 8) | d[o + 6];
            }
            default:
                return BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan((int)((long)node * 8 + bit * 4), 4));
        }
    }

    /// <summary>Stelle des Datensatzes zu einer Adresse im Datenbereich (gleiche Stelle = gleicher Datensatz), sonst -1.</summary>
    public int Locate(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out var written)) return -1;
        bytes = bytes[..written];
        long node;
        if (written == 4) node = _ipv4Start;
        else if (IpVersion == 4) return -1;
        else node = 0;
        var bits = written * 8;
        for (var i = 0; i < bits && node < _nodeCount; i++)
            node = Record((int)node, (bytes[i >> 3] >> (7 - (i & 7))) & 1);
        if (node <= _nodeCount) return -1; // = node_count: kein Eintrag; < node_count: Baum zu tief (kaputte Datei)
        var offset = node - _nodeCount - 16;
        return offset >= 0 && _dataStart + offset < _dataEnd ? (int)offset : -1;
    }

    /// <summary>Den Datensatz an einer Stelle aus <see cref="Locate"/> lesen (Map → Dictionary, Array → List, Zahlen als long/ulong/double);
    /// null bei kaputten Daten.</summary>
    public object? Read(int offset)
    {
        if (offset < 0 || _dataStart + (long)offset >= _dataEnd) return null;
        try
        {
            var pos = _dataStart + offset;
            var budget = Budget;
            return DecodeAt(ref pos, _dataStart, _dataEnd, 0, ref budget);
        }
        catch (InvalidDataException) { return null; }
    }

    public object? Find(IPAddress address) => Locate(address) is var o and >= 0 ? Read(o) : null;

    /// <summary>Je angefangene 64 Bytes eine Einheit des Arbeitsbudgets: höchstens etwa 1,3 MB Text je Abfrage – echte Datensätze haben
    /// wenige hundert Bytes.</summary>
    private static void Charge(ref int budget, int bytes)
    {
        if ((budget -= bytes >> 6) < 0) throw new InvalidDataException("Datensatz zu groß");
    }

    // Ein Wert ab pos; Verweise (Typ 1) zählen ab basis, alles muss vor end liegen.
    private object? DecodeAt(ref int pos, int basis, int end, int depth, ref int budget)
    {
        if (depth > MaxDepth || --budget < 0) throw new InvalidDataException("Zu tief verschachtelt");
        var d = _data;
        int Byte(ref int p) => p < end ? d[p++] : throw new InvalidDataException("Datensatz endet zu früh");
        var control = Byte(ref pos);
        var type = control >> 5;
        if (type == 1)
        {
            var ss = (control >> 3) & 3;
            var v = control & 7;
            long target = ss switch
            {
                0 => (v << 8) | Byte(ref pos),
                1 => ((v << 16) | (Byte(ref pos) << 8) | Byte(ref pos)) + 2048L,
                2 => ((long)v << 24 | ((long)Byte(ref pos) << 16) | ((long)Byte(ref pos) << 8) | (long)Byte(ref pos)) + 526_336L,
                _ => ((long)Byte(ref pos) << 24) | ((long)Byte(ref pos) << 16) | ((long)Byte(ref pos) << 8) | (long)Byte(ref pos),
            };
            var at = basis + target;
            if (at < basis || at >= end) throw new InvalidDataException("Verweis außerhalb der Daten");
            var p2 = (int)at;
            return DecodeAt(ref p2, basis, end, depth + 1, ref budget);
        }
        if (type == 0)
        {
            type = 7 + Byte(ref pos);
            if (type is < 8 or > 15) throw new InvalidDataException("Unbekannter Typ");
        }
        var size = control & 0x1F;
        if (size == 29) size = 29 + Byte(ref pos);
        else if (size == 30) size = 285 + ((Byte(ref pos) << 8) | Byte(ref pos));
        else if (size == 31) size = 65_821 + ((Byte(ref pos) << 16) | (Byte(ref pos) << 8) | Byte(ref pos));
        ReadOnlySpan<byte> Take(ref int p, int n)
        {
            if (n < 0 || (long)p + n > end) throw new InvalidDataException("Datensatz endet zu früh");
            var span = d.AsSpan(p, n);
            p += n;
            return span;
        }
        ulong Unsigned(ref int p, int n, int max)
        {
            if (n > max) throw new InvalidDataException("Zahl zu lang");
            ulong v = 0;
            foreach (var b in Take(ref p, n)) v = (v << 8) | b;
            return v;
        }
        switch (type)
        {
            // Große Texte und Byte-Folgen kosten nach Größe: Viele Verweise auf denselben großen Wert erzeugten sonst je Abfrage
            // Gigabytes (das Budget zählt sonst nur Werte).
            case 2: Charge(ref budget, size); return Encoding.UTF8.GetString(Take(ref pos, size));
            case 3:
                if (size != 8) throw new InvalidDataException("double mit falscher Länge");
                return BinaryPrimitives.ReadDoubleBigEndian(Take(ref pos, 8));
            case 4: Charge(ref budget, size); return Take(ref pos, size).ToArray();
            case 5: return (long)Unsigned(ref pos, size, 2);
            case 6: return (long)Unsigned(ref pos, size, 4);
            case 8: return (long)(int)(uint)Unsigned(ref pos, size, 4); // kürzer als 4 Bytes: positiv (wie libmaxminddb)
            case 9: return Unsigned(ref pos, size, 8);
            case 10:
                if (size > 16) throw new InvalidDataException("Zahl zu lang");
                return Take(ref pos, size).ToArray();
            case 7:
            {
                var map = new Dictionary<string, object?>(Math.Min(size, 64));
                for (var k = 0; k < size; k++)
                {
                    if (DecodeAt(ref pos, basis, end, depth + 1, ref budget) is not string key) throw new InvalidDataException("Schlüssel ist kein Text");
                    map[key] = DecodeAt(ref pos, basis, end, depth + 1, ref budget);
                }
                return map;
            }
            case 11:
            {
                var list = new List<object?>(Math.Min(size, 64));
                for (var k = 0; k < size; k++) list.Add(DecodeAt(ref pos, basis, end, depth + 1, ref budget));
                return list;
            }
            case 14:
                if (size > 1) throw new InvalidDataException("Wahrheitswert ungültig");
                return size == 1;
            case 15:
                if (size != 4) throw new InvalidDataException("float mit falscher Länge");
                return (double)BinaryPrimitives.ReadSingleBigEndian(Take(ref pos, 4));
            default: throw new InvalidDataException("Typ " + type + " ist hier nicht erlaubt");
        }
    }
}

/// <summary>Land zu einer IP-Adresse aus einer Länder-Datenbank (DB-IP „IP to Country Lite“ oder GeoLite2-Country). Die Zuordnung
/// geschieht ganz auf diesem PC; sie richtet sich nach der Registrierung der Adresse – Router großer Netze und Anycast-Adressen
/// (z. B. 8.8.8.8) stehen oft woanders.</summary>
public sealed class CountryDb
{
    private readonly MaxMindDb _db;
    private readonly Dictionary<int, string?> _codes = [];
    private readonly Lock _gate = new();

    public CountryDb(byte[] data)
    {
        _db = new MaxMindDb(data);
        if (!_db.DatabaseType.Contains("Country", StringComparison.OrdinalIgnoreCase) && !_db.DatabaseType.Contains("City", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Keine Länder-Datenbank: " + _db.DatabaseType);
    }

    public DateTime BuildTime => _db.BuildTime;
    public string DatabaseType => _db.DatabaseType;

    /// <summary>ISO-3166-Code in Großbuchstaben (z. B. „DE“) oder null (privat, unbekannt, „ZZ“).</summary>
    public string? CountryOf(IPAddress address)
    {
        if (GeoIp.ScopeOf(address) != AddressScope.Public) return null;
        var offset = _db.Locate(address);
        if (offset < 0) return null;
        lock (_gate)
        {
            if (_codes.TryGetValue(offset, out var known)) return known;
            string? code = null;
            if (_db.Read(offset) is Dictionary<string, object?> record)
                code = CodeIn(record, "country") ?? CodeIn(record, "registered_country");
            if (_codes.Count < 100_000) _codes[offset] = code;
            return code;
        }
    }

    private static string? CodeIn(Dictionary<string, object?> record, string key)
    {
        if (!record.TryGetValue(key, out var v) || v is not Dictionary<string, object?> country) return null;
        if (!country.TryGetValue("iso_code", out var c) || c is not string code || code.Length != 2) return null;
        if (!char.IsAsciiLetter(code[0]) || !char.IsAsciiLetter(code[1])) return null;
        code = code.ToUpperInvariant();
        return code == "ZZ" ? null : code;
    }
}

public enum AddressScope { Public, Private, CarrierNat, Loopback, LinkLocal, Multicast, Reserved }

public static class GeoIp
{
    /// <summary>Wohin eine Adresse gehört: nur öffentliche Adressen haben ein Land.</summary>
    public static AddressScope ScopeOf(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        Span<byte> b = stackalloc byte[16];
        if (!address.TryWriteBytes(b, out var n)) return AddressScope.Reserved;
        if (n == 4)
        {
            return b[0] switch
            {
                0 => AddressScope.Reserved,
                10 => AddressScope.Private,
                100 when (b[1] & 0xC0) == 64 => AddressScope.CarrierNat,
                127 => AddressScope.Loopback,
                169 when b[1] == 254 => AddressScope.LinkLocal,
                172 when (b[1] & 0xF0) == 16 => AddressScope.Private,
                192 when b[1] == 168 => AddressScope.Private,
                192 when b[1] == 0 && b[2] is 0 or 2 => AddressScope.Reserved,
                198 when (b[1] & 0xFE) == 18 => AddressScope.Reserved,
                198 when b[1] == 51 && b[2] == 100 => AddressScope.Reserved,
                203 when b[1] == 0 && b[2] == 113 => AddressScope.Reserved,
                >= 224 and < 240 => AddressScope.Multicast,
                >= 240 => AddressScope.Reserved,
                _ => AddressScope.Public,
            };
        }
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return AddressScope.Reserved;
        if (address.Equals(IPAddress.IPv6Loopback)) return AddressScope.Loopback;
        if (b[0] == 0xFF) return AddressScope.Multicast;
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return AddressScope.LinkLocal;
        if ((b[0] & 0xFE) == 0xFC) return AddressScope.Private;
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return AddressScope.Reserved; // Dokumentation
        return (b[0] & 0xE0) == 0x20 ? AddressScope.Public : AddressScope.Reserved; // nur 2000::/3 ist weltweit vergeben
    }
}
