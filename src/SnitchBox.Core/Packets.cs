using System.Buffers.Binary;
using System.Text;

namespace SnitchBox.Core;

/// <summary>Die für die Entscheidung nötigen Felder eines IP-Pakets (IPv4/IPv6 mit TCP oder UDP).</summary>
public struct PacketInfo
{
    public bool V6;
    public byte Protocol; // 6 = TCP, 17 = UDP
    public IpKey Src, Dst;
    public ushort SrcPort, DstPort;
    public bool Syn, Ack;
    public uint Seq;
    public int L4Offset, PayloadOffset;
}

public static class Packet
{
    public const byte Tcp = 6, Udp = 17;

    public static bool TryParse(ReadOnlySpan<byte> p, out PacketInfo info)
    {
        info = default;
        if (p.Length < 20) return false;
        var version = p[0] >> 4;
        int l4;
        byte proto;
        if (version == 4)
        {
            var ihl = (p[0] & 0xF) * 4;
            if (ihl < 20 || p.Length < ihl) return false;
            // Folgefragmente tragen keinen TCP/UDP-Kopf.
            if ((BinaryPrimitives.ReadUInt16BigEndian(p[6..]) & 0x1FFF) != 0) return false;
            proto = p[9];
            info.Src = IpKey.FromV4(p[12..]);
            info.Dst = IpKey.FromV4(p[16..]);
            l4 = ihl;
        }
        else if (version == 6)
        {
            if (p.Length < 40) return false;
            info.V6 = true;
            info.Src = IpKey.FromV6(p[8..]);
            info.Dst = IpKey.FromV6(p[24..]);
            proto = p[6];
            l4 = 40;
            // Erweiterungsköpfe überspringen: Hop-by-Hop, Routing, Fragment, Destination Options.
            for (var i = 0; i < 8 && proto is 0 or 43 or 44 or 60; i++)
            {
                if (p.Length < l4 + 8) return false;
                if (proto == 44)
                {
                    if ((BinaryPrimitives.ReadUInt16BigEndian(p[(l4 + 2)..]) & 0xFFF8) != 0) return false;
                    proto = p[l4];
                    l4 += 8;
                }
                else
                {
                    var len = (p[l4 + 1] + 1) * 8;
                    proto = p[l4];
                    l4 += len;
                }
            }
        }
        else return false;

        info.Protocol = proto;
        info.L4Offset = l4;
        if (proto == Tcp)
        {
            if (p.Length < l4 + 20) return false;
            info.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(p[l4..]);
            info.DstPort = BinaryPrimitives.ReadUInt16BigEndian(p[(l4 + 2)..]);
            info.Seq = BinaryPrimitives.ReadUInt32BigEndian(p[(l4 + 4)..]);
            var flags = p[l4 + 13];
            info.Syn = (flags & 0x02) != 0;
            info.Ack = (flags & 0x10) != 0;
            info.PayloadOffset = l4 + (p[l4 + 12] >> 4) * 4;
            return true;
        }
        if (proto == Udp)
        {
            if (p.Length < l4 + 8) return false;
            info.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(p[l4..]);
            info.DstPort = BinaryPrimitives.ReadUInt16BigEndian(p[(l4 + 2)..]);
            info.PayloadOffset = l4 + 8;
            return true;
        }
        return true;
    }

    /// <summary>Schnelle Vermessung für die Datenmengen: Gesamtlänge des IP-Pakets und, bei TCP/UDP, die Ports.
    /// Gibt 0 zurück, wenn am Anfang kein gültiges IP-Paket steht (dann lässt sich ein Stapel nicht weiter zerlegen).</summary>
    public static int Measure(ReadOnlySpan<byte> p, out bool tcp, out bool counted, out ushort srcPort, out ushort dstPort) =>
        Measure(p, out tcp, out counted, out srcPort, out dstPort, out _, out _);

    /// <summary>Wie oben, dazu Absender- und Zieladresse (für die Datenmengen je Gegenstelle); bei ungültigem Paket default.</summary>
    public static int Measure(ReadOnlySpan<byte> p, out bool tcp, out bool counted, out ushort srcPort, out ushort dstPort, out IpKey src, out IpKey dst)
    {
        tcp = counted = false;
        srcPort = dstPort = 0;
        src = dst = default;
        if (p.Length < 20) return 0;
        int total, l4;
        byte proto;
        var version = p[0] >> 4;
        if (version == 4)
        {
            total = BinaryPrimitives.ReadUInt16BigEndian(p[2..]);
            l4 = (p[0] & 0xF) * 4;
            proto = p[9];
            if (l4 < 20 || total < l4) return 0;
            src = IpKey.FromV4(p[12..]);
            dst = IpKey.FromV4(p[16..]);
            // Folgefragmente haben keine Ports.
            if ((BinaryPrimitives.ReadUInt16BigEndian(p[6..]) & 0x1FFF) != 0) return total <= p.Length ? total : 0;
        }
        else if (version == 6)
        {
            if (p.Length < 40) return 0;
            total = 40 + BinaryPrimitives.ReadUInt16BigEndian(p[4..]);
            l4 = 40;
            proto = p[6];
            src = IpKey.FromV6(p[8..]);
            dst = IpKey.FromV6(p[24..]);
        }
        else return 0;
        if (total > p.Length) return 0;
        if (proto is Tcp or Udp && l4 + 4 <= total)
        {
            tcp = proto == Tcp;
            counted = true;
            srcPort = BinaryPrimitives.ReadUInt16BigEndian(p[l4..]);
            dstPort = BinaryPrimitives.ReadUInt16BigEndian(p[(l4 + 2)..]);
        }
        return total;
    }

    private static uint Sum(ReadOnlySpan<byte> data, uint sum)
    {
        var i = 0;
        for (; i + 1 < data.Length; i += 2) sum += (uint)(data[i] << 8 | data[i + 1]);
        if (i < data.Length) sum += (uint)(data[i] << 8);
        return sum;
    }

    private static ushort Fold(uint sum)
    {
        while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    public static ushort Checksum(ReadOnlySpan<byte> data) => Fold(Sum(data, 0));

    /// <summary>TCP/UDP-Prüfsumme samt Pseudokopf; <paramref name="packet"/> ist das ganze IP-Paket.</summary>
    public static ushort TransportChecksum(ReadOnlySpan<byte> packet, bool v6, int l4Offset, byte protocol)
    {
        var segment = packet[l4Offset..];
        var sum = v6 ? Sum(packet.Slice(8, 32), 0) : Sum(packet.Slice(12, 8), 0);
        sum += protocol;
        sum += (uint)segment.Length;
        return Fold(Sum(segment, sum));
    }

    /// <summary>Antwort auf ein abgelehntes TCP-SYN: ein RST+ACK, als käme es von der Gegenstelle.
    /// Damit scheitert der Verbindungsaufbau sofort statt erst nach rund 20 Sekunden.</summary>
    public static byte[]? BuildReset(ReadOnlySpan<byte> syn)
    {
        if (!TryParse(syn, out var i) || i.Protocol != Tcp) return null;
        var ip = i.V6 ? 40 : 20;
        var r = new byte[ip + 20];
        if (i.V6)
        {
            r[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(4), 20);
            r[6] = Tcp;
            r[7] = 64;
            syn.Slice(24, 16).CopyTo(r.AsSpan(8));
            syn.Slice(8, 16).CopyTo(r.AsSpan(24));
        }
        else
        {
            r[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(2), 40);
            r[8] = 64;
            r[9] = Tcp;
            syn.Slice(16, 4).CopyTo(r.AsSpan(12));
            syn.Slice(12, 4).CopyTo(r.AsSpan(16));
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(10), Checksum(r.AsSpan(0, 20)));
        }
        var t = r.AsSpan(ip);
        BinaryPrimitives.WriteUInt16BigEndian(t, i.DstPort);
        BinaryPrimitives.WriteUInt16BigEndian(t[2..], i.SrcPort);
        BinaryPrimitives.WriteUInt32BigEndian(t[8..], i.Seq + 1);
        t[12] = 5 << 4;
        t[13] = 0x14; // RST | ACK
        BinaryPrimitives.WriteUInt16BigEndian(t[16..], TransportChecksum(r, i.V6, ip, Tcp));
        return r;
    }

    /// <summary>RST-Pakete, die eine bestehende TCP-Verbindung an beiden Enden beenden, gebaut aus einem ihrer Segmente (für IPv6,
    /// wo Windows keine Funktion zum Trennen hat). In Richtung des Segments zwei – Folgenummer vor und nach seinen Daten, je nachdem,
    /// ob das Segment beim Empfänger schon angekommen ist –, zurück an den Absender eines mit dessen Bestätigungsnummer (genau die
    /// Nummer, die er als Nächstes erwartet; Windows nimmt ein RST nur dann sofort an, RFC 5961). ToSender = an den Absender des Segments.
    /// Leer bei einem RST (es soll keine Kette entstehen) und bei anderem als TCP.</summary>
    public static List<(byte[] Packet, bool ToSender)> BuildFlowResets(ReadOnlySpan<byte> segment)
    {
        var result = new List<(byte[], bool)>();
        if (!TryParse(segment, out var i) || i.Protocol != Tcp) return result;
        var l4 = i.L4Offset;
        var flags = segment[l4 + 13];
        if ((flags & 0x04) != 0) return result;
        var ack = BinaryPrimitives.ReadUInt32BigEndian(segment[(l4 + 8)..]);
        var total = i.V6 ? 40 + BinaryPrimitives.ReadUInt16BigEndian(segment[4..]) : BinaryPrimitives.ReadUInt16BigEndian(segment[2..]);
        var payload = Math.Max(0, Math.Min(total, segment.Length) - i.PayloadOffset);
        var advance = (uint)payload + ((flags & 0x02) != 0 ? 1u : 0) + ((flags & 0x01) != 0 ? 1u : 0);
        result.Add((Reset(i, true, i.Seq), false));
        if (advance != 0) result.Add((Reset(i, true, i.Seq + advance), false));
        if ((flags & 0x10) != 0) result.Add((Reset(i, false, ack), true));
        return result;
    }

    /// <summary>Ein RST zu den Adressen und Ports eines Segments: <paramref name="forward"/> in seiner Richtung, sonst zurück.</summary>
    private static byte[] Reset(in PacketInfo i, bool forward, uint seq)
    {
        var ip = i.V6 ? 40 : 20;
        var r = new byte[ip + 20];
        var (src, dst) = forward ? (i.Src, i.Dst) : (i.Dst, i.Src);
        if (i.V6)
        {
            r[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(4), 20);
            r[6] = Tcp;
            r[7] = 64;
            WriteAddress(src, true, r.AsSpan(8));
            WriteAddress(dst, true, r.AsSpan(24));
        }
        else
        {
            r[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(2), 40);
            r[8] = 64;
            r[9] = Tcp;
            WriteAddress(src, false, r.AsSpan(12));
            WriteAddress(dst, false, r.AsSpan(16));
            BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(10), Checksum(r.AsSpan(0, 20)));
        }
        var t = r.AsSpan(ip);
        BinaryPrimitives.WriteUInt16BigEndian(t, forward ? i.SrcPort : i.DstPort);
        BinaryPrimitives.WriteUInt16BigEndian(t[2..], forward ? i.DstPort : i.SrcPort);
        BinaryPrimitives.WriteUInt32BigEndian(t[4..], seq);
        t[12] = 5 << 4;
        t[13] = 0x04; // RST
        BinaryPrimitives.WriteUInt16BigEndian(t[16..], TransportChecksum(r, i.V6, ip, Tcp));
        return r;
    }

    private static void WriteAddress(IpKey a, bool v6, Span<byte> target)
    {
        if (v6)
        {
            BinaryPrimitives.WriteUInt64BigEndian(target, a.Hi);
            BinaryPrimitives.WriteUInt64BigEndian(target[8..], a.Lo);
        }
        else BinaryPrimitives.WriteUInt32BigEndian(target, (uint)a.Lo);
    }
}

/// <summary>Liest aus DNS-Antworten, welcher Name zu welcher Adresse gehört.</summary>
public static class DnsReader
{
    private static bool ReadName(ReadOnlySpan<byte> m, ref int pos, StringBuilder? sb)
    {
        var p = pos;
        var jumped = false;
        for (var hops = 0; hops < 64; hops++)
        {
            if (p >= m.Length) return false;
            int len = m[p];
            if (len == 0)
            {
                if (!jumped) pos = p + 1;
                return true;
            }
            if ((len & 0xC0) == 0xC0)
            {
                if (p + 1 >= m.Length) return false;
                if (!jumped) pos = p + 2;
                jumped = true;
                p = (len & 0x3F) << 8 | m[p + 1];
                continue;
            }
            if ((len & 0xC0) != 0 || p + 1 + len > m.Length) return false;
            if (sb != null)
            {
                if (sb.Length > 0) sb.Append('.');
                foreach (var b in m.Slice(p + 1, len)) sb.Append(b is >= 0x21 and < 0x7F ? (char)b : '?');
                if (sb.Length > 255) return false;
            }
            p += 1 + len;
        }
        return false;
    }

    /// <summary>Gibt den erfragten Namen und alle A/AAAA-Adressen der Antwort zurück (CNAME-Ketten zählen zum erfragten Namen).</summary>
    public static bool TryParseResponse(ReadOnlySpan<byte> m, out string name, List<IpKey> addresses)
    {
        name = "";
        if (m.Length < 12 || (m[2] & 0x80) == 0 || (m[3] & 0x0F) != 0) return false;
        int qd = BinaryPrimitives.ReadUInt16BigEndian(m[4..]), an = BinaryPrimitives.ReadUInt16BigEndian(m[6..]);
        if (qd != 1 || an == 0) return false;
        var pos = 12;
        var sb = new StringBuilder();
        if (!ReadName(m, ref pos, sb)) return false;
        pos += 4;
        name = sb.ToString().ToLowerInvariant();
        for (var i = 0; i < an; i++)
        {
            if (!ReadName(m, ref pos, null) || pos + 10 > m.Length) break;
            var type = BinaryPrimitives.ReadUInt16BigEndian(m[pos..]);
            var len = BinaryPrimitives.ReadUInt16BigEndian(m[(pos + 8)..]);
            pos += 10;
            if (pos + len > m.Length) break;
            if (type == 1 && len == 4) addresses.Add(IpKey.FromV4(m.Slice(pos, 4)));
            else if (type == 28 && len == 16) addresses.Add(IpKey.FromV6(m.Slice(pos, 16)));
            pos += len;
        }
        return name.Length > 0 && addresses.Count > 0;
    }
}

/// <summary>Gedächtnis „Adresse → Namen“ aus beobachteten DNS-Antworten.</summary>
public sealed class HostCache
{
    private const int Max = 30000;
    private readonly Dictionary<IpKey, List<string>> _names = [];
    private readonly Queue<IpKey> _order = new();
    private readonly object _gate = new();

    public void Add(string name, IEnumerable<IpKey> addresses)
    {
        lock (_gate)
        {
            foreach (var a in addresses)
            {
                if (!_names.TryGetValue(a, out var list))
                {
                    _names[a] = list = [];
                    _order.Enqueue(a);
                    if (_order.Count > Max) _names.Remove(_order.Dequeue());
                }
                list.Remove(name);
                list.Insert(0, name);
                if (list.Count > 6) list.RemoveAt(list.Count - 1);
            }
        }
    }

    public IReadOnlyList<string> Lookup(IpKey address)
    {
        lock (_gate) return _names.TryGetValue(address, out var l) ? l.ToArray() : [];
    }
}
