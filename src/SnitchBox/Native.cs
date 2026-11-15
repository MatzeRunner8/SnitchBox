using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Adresse eines WinDivert-Pakets oder -Ereignisses (windivert.h, WINDIVERT_ADDRESS, 80 Byte).</summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
internal struct WinDivertAddress
{
    [FieldOffset(0)] public long Timestamp;
    /// <summary>Bitfeld: Layer 0–7, Event 8–15, Sniffed 16, Outbound 17, Loopback 18, Impostor 19, IPv6 20,
    /// IPChecksum 21, TCPChecksum 22, UDPChecksum 23.</summary>
    [FieldOffset(8)] public uint Flags;
    [FieldOffset(12)] public uint Reserved;
    // Netzwerk-Schicht
    [FieldOffset(16)] public uint IfIdx;
    [FieldOffset(20)] public uint SubIfIdx;
    // Socket-Schicht (EndpointId, ParentEndpointId, ProcessId, LocalAddr[4], RemoteAddr[4], LocalPort, RemotePort, Protocol)
    [FieldOffset(32)] public uint ProcessId;
    // LocalAddr[4] (UINT32, Host-Reihenfolge, niedrigstes Wort zuerst; IPv4 als ::ffff:a.b.c.d, also [0] = IPv4, [1] = 0xFFFF)
    [FieldOffset(36)] public uint LocalAddr0;
    [FieldOffset(40)] public uint LocalAddr1;
    [FieldOffset(44)] public uint LocalAddr2;
    [FieldOffset(48)] public uint LocalAddr3;
    [FieldOffset(68)] public ushort LocalPort;
    [FieldOffset(70)] public ushort RemotePort;
    [FieldOffset(72)] public byte Protocol;

    public const uint OutboundBit = 1u << 17, LoopbackBit = 1u << 18, IPv6Bit = 1u << 20, ChecksumBits = 7u << 21;
    public readonly bool Outbound => (Flags & OutboundBit) != 0;
    public readonly bool Loopback => (Flags & LoopbackBit) != 0;
    /// <summary>Socket auf der Wildcard-Adresse (0.0.0.0 bzw. ::), unabhängig von der Wortreihenfolge.</summary>
    public readonly bool LocalIsWildcard => LocalAddr0 == 0 && LocalAddr2 == 0 && LocalAddr3 == 0
                                           && (IPv6 ? LocalAddr1 == 0 : LocalAddr1 is 0 or 0xFFFF or 0xFFFF0000);
    public readonly bool IPv6 => (Flags & IPv6Bit) != 0;
    public readonly int Event => (int)(Flags >> 8 & 0xFF);
}

internal static unsafe class WinDivert
{
    public const int LayerNetwork = 0, LayerSocket = 3;
    public const ulong FlagSniff = 1, FlagRecvOnly = 4;
    public const int ParamQueueLength = 0, ParamQueueTime = 1, ParamQueueSize = 2;
    public const int EventBind = 3, EventConnect = 4, EventListen = 5, EventAccept = 6, EventClose = 7;
    public static readonly IntPtr Invalid = new(-1);

    [DllImport("WinDivert.dll", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, EntryPoint = "WinDivertOpen")]
    public static extern IntPtr Open(string filter, int layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", SetLastError = true, EntryPoint = "WinDivertRecv")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Recv(IntPtr handle, byte* packet, uint packetLen, uint* recvLen, WinDivertAddress* address);

    /// <summary>Wie Recv, liefert aber bis zu 255 Pakete auf einmal (hintereinander im Puffer, je eine Adresse).</summary>
    [DllImport("WinDivert.dll", SetLastError = true, EntryPoint = "WinDivertRecvEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool RecvEx(IntPtr handle, byte* packet, uint packetLen, uint* recvLen, ulong flags, WinDivertAddress* address, uint* addressLen, IntPtr overlapped);

    [DllImport("WinDivert.dll", SetLastError = true, EntryPoint = "WinDivertSend")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Send(IntPtr handle, byte* packet, uint packetLen, uint* sendLen, WinDivertAddress* address);

    [DllImport("WinDivert.dll", SetLastError = true, EntryPoint = "WinDivertShutdown")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Shutdown(IntPtr handle, int how);

    [DllImport("WinDivert.dll", SetLastError = true, EntryPoint = "WinDivertClose")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Close(IntPtr handle);

    [DllImport("WinDivert.dll", SetLastError = true, EntryPoint = "WinDivertSetParam")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetParam(IntPtr handle, int param, ulong value);
}

internal static unsafe class Native
{
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedTcpTable(byte* table, ref int size, bool order, int family, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedUdpTable(byte* table, ref int size, bool order, int family, int tableClass, uint reserved);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, char* name, ref int size);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr SHGetFileInfoW(string path, uint attributes, ref SHFILEINFOW info, uint size, uint flags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFOW
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
    }

    private const int AfInet = 2, AfInet6 = 23;

    private const int TcpTableOwnerPidAll = 5, TcpTableOwnerPidListener = 3, TcpTableOwnerPidConnections = 4;

    [DllImport("iphlpapi.dll")] private static extern uint SetTcpEntry(byte* row);

    /// <summary>Eine bestehende IPv4-TCP-Verbindung; <see cref="Row"/> ist die Tabellenzeile zum Trennen.</summary>
    public sealed record TcpConnectionV4(int Pid, ushort LocalPort, IpKey Remote, ushort RemotePort, byte[] Row);

    /// <summary>Alle IPv4-TCP-Verbindungen außer Lauschern, mit Besitzer (ohne Loopback und ohne Zeilen ohne Besitzer).</summary>
    public static List<TcpConnectionV4> TcpConnectionsV4()
    {
        var result = new List<TcpConnectionV4>();
        var t = Table(true, AfInet, TcpTableOwnerPidConnections);
        if (t == null) return result;
        var n = BitConverter.ToInt32(t, 0);
        // MIB_TCPROW_OWNER_PID, 24 Byte: Zustand 0, lokale Adresse 4, lokaler Port 8, Gegenadresse 12, Gegenport 16, PID 20
        for (var i = 0; i < n; i++)
        {
            var o = 4 + i * 24;
            if (o + 24 > t.Length) break;
            var pid = BitConverter.ToInt32(t, o + 20);
            if (pid == 0) continue;
            var remote = IpKey.FromV4(t.AsSpan(o + 12, 4));
            if (remote.IsLoopback || remote == IpKey.FromV4([0, 0, 0, 0])) continue;
            result.Add(new TcpConnectionV4(pid, Port(t, o + 8), remote, Port(t, o + 16), t.AsSpan(o, 20).ToArray()));
        }
        return result;
    }

    /// <summary>Trennt eine IPv4-TCP-Verbindung (Windows schickt der Gegenstelle ein RST). Braucht Administratorrechte;
    /// für IPv6 gibt es keine solche Schnittstelle. Liefert den Windows-Fehlercode, 0 = getrennt.</summary>
    public static uint CloseTcpV4(TcpConnectionV4 c)
    {
        var row = (byte[])c.Row.Clone();
        BitConverter.TryWriteBytes(row.AsSpan(0, 4), 12); // MIB_TCP_STATE_DELETE_TCB
        fixed (byte* p = row) return SetTcpEntry(p);
    }

    private static byte[]? Table(bool tcp, int family, int tcpClass = TcpTableOwnerPidAll)
    {
        var size = 0;
        // TCP: TCP_TABLE_OWNER_PID_ALL = 5 bzw. TCP_TABLE_OWNER_PID_LISTENER = 3; UDP_TABLE_OWNER_PID = 1
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var buffer = new byte[Math.Max(size, 16)];
            fixed (byte* b = buffer)
            {
                size = buffer.Length;
                var rc = tcp ? GetExtendedTcpTable(b, ref size, false, family, tcpClass, 0) : GetExtendedUdpTable(b, ref size, false, family, 1, 0);
                if (rc == 0) return buffer;
                if (rc != 122 /*ERROR_INSUFFICIENT_BUFFER*/) return null;
                size += 4096;
            }
        }
        return null;
    }

    private static ushort Port(byte[] t, int offset) => (ushort)(t[offset] << 8 | t[offset + 1]);

    /// <summary>Besitzer eines lokalen Ports laut Windows. Bei TCP mit bekannter Gegenstelle zählt nur die Zeile mit genau
    /// dieser Zieladresse und diesem Zielport – eine andere Verbindung über denselben lokalen Port gehört womöglich einem
    /// anderen Programm. Zeilen ohne Besitzer (TIME_WAIT) zählen nicht. 0 = nicht gefunden.</summary>
    public static int OwnerOfPort(bool tcp, ushort localPort, IpKey? remote, ushort remotePort)
    {
        var fallback = 0;
        foreach (var family in new[] { AfInet, AfInet6 })
        {
            var t = Table(tcp, family);
            if (t == null) continue;
            var n = BitConverter.ToInt32(t, 0);
            var v6 = family == AfInet6;
            // Zeilen: TCPv4 24 Byte (Port 8, Zieladresse 12, Zielport 16, PID 20), TCPv6 56 (Port 20, Zieladresse 24, Zielport 44, PID 52),
            // UDPv4 12 (Port 4, PID 8), UDPv6 28 (Port 20, PID 24)
            var (row, lp, ra, rp, pid) = tcp ? (v6 ? (56, 20, 24, 44, 52) : (24, 8, 12, 16, 20)) : (v6 ? (28, 20, -1, -1, 24) : (12, 4, -1, -1, 8));
            for (var i = 0; i < n; i++)
            {
                var o = 4 + i * row;
                if (o + row > t.Length) break;
                if (Port(t, o + lp) != localPort) continue;
                var owner = BitConverter.ToInt32(t, o + pid);
                if (owner == 0) continue;
                if (rp < 0) return owner; // UDP: nur der lokale Port zählt
                if (Port(t, o + rp) == remotePort)
                {
                    if (remote is not { } r) return owner;
                    var address = v6 ? IpKey.FromV6(t.AsSpan(o + ra, 16)) : IpKey.FromV4(t.AsSpan(o + ra, 4));
                    if (address == r) return owner;
                }
                if (remote == null && fallback == 0) fallback = owner;
            }
        }
        return fallback;
    }

    /// <summary>Alle lokalen Ports mit ihrem Besitzer (IPv4 und IPv6), für die Zuordnung der Datenmengen.</summary>
    public static Dictionary<ushort, int> PortOwners(bool tcp)
    {
        var result = new Dictionary<ushort, int>();
        foreach (var family in new[] { AfInet, AfInet6 })
        {
            var t = Table(tcp, family);
            if (t == null) continue;
            var n = BitConverter.ToInt32(t, 0);
            var v6 = family == AfInet6;
            var (row, lp, pid) = tcp ? (v6 ? (56, 20, 52) : (24, 8, 20)) : (v6 ? (28, 20, 24) : (12, 4, 8));
            for (var i = 0; i < n; i++)
            {
                var o = 4 + i * row;
                if (o + row > t.Length) break;
                var owner = BitConverter.ToInt32(t, o + pid);
                if (owner != 0) result[Port(t, o + lp)] = owner;
            }
        }
        return result;
    }

    /// <summary>Lauschende TCP-Ports mit ihrem Besitzer, je Adressfamilie. Lauscher nur auf 127.x/::1 zählen nicht (von außen
    /// unerreichbar). Ein IPv6-Lauscher auf „::“ kann Dual-Stack sein und gilt daher auch für IPv4, sofern dort kein eigener
    /// IPv4-Lauscher steht. Abgefragt wird die Tabelle nur der Lauscher (TCP_TABLE_OWNER_PID_LISTENER) statt aller Zeilen mit
    /// Zustand LISTEN: auf manchen Windows-Builds (gemessen 26300) steht im Zustandsfeld der Lauscher Unsinn (0, 1, 6) –
    /// eine Prüfung darauf übersah dort fast alle Lauscher und ließ eingehende Verbindungen ungefragt durch.</summary>
    public static Dictionary<(bool V6, ushort Port), int> ListeningTcpPorts()
    {
        var result = new Dictionary<(bool, ushort), int>();
        foreach (var family in new[] { AfInet, AfInet6 })
        {
            var t = Table(true, family, TcpTableOwnerPidListener);
            if (t == null) continue;
            var n = BitConverter.ToInt32(t, 0);
            var v6 = family == AfInet6;
            // Zeilen: TCPv4 24 Byte (lokale Adresse 4, Port 8, PID 20), TCPv6 56 Byte (lokale Adresse 0, Port 20, PID 52)
            var (row, la, lp, pid) = v6 ? (56, 0, 20, 52) : (24, 4, 8, 20);
            for (var i = 0; i < n; i++)
            {
                var o = 4 + i * row;
                if (o + row > t.Length) break;
                var local = v6 ? IpKey.FromV6(t.AsSpan(o + la, 16)) : IpKey.FromV4(t.AsSpan(o + la, 4));
                if (local.IsLoopback) continue;
                var port = Port(t, o + lp);
                var owner = BitConverter.ToInt32(t, o + pid);
                result.TryAdd((v6, port), owner);
                if (v6 && local == default) result.TryAdd((false, port), owner);
            }
        }
        return result;
    }

    public static string? PathOfProcess(int pid)
    {
        if (pid == 4) return SnitchBox.Core.Rule.KernelProcess;
        if (pid == 0) return null;
        var h = OpenProcess(0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var buffer = stackalloc char[1024];
            var size = 1024;
            return QueryFullProcessImageNameW(h, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
        }
        finally { CloseHandle(h); }
    }

    public static bool IsProcessAlive(int pid)
    {
        if (pid is 0 or 4) return true;
        var h = OpenProcess(0x00100000 /*SYNCHRONIZE*/, false, pid);
        if (h == IntPtr.Zero) return Marshal.GetLastWin32Error() == 5; // Zugriff verweigert heißt: es gibt ihn
        try { return WaitForSingleObject(h, 0) == 258 /*WAIT_TIMEOUT*/; }
        finally { CloseHandle(h); }
    }

    private static readonly ConcurrentDictionary<string, ImageSource?> Icons = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Programmsymbol für Listen und Warnfenster; null, wenn die Datei keines hat.</summary>
    public static ImageSource? IconOf(string path)
    {
        if (path.Length == 0 || path == "System") return null;
        return Icons.GetOrAdd(path, static p =>
        {
            try
            {
                var info = new SHFILEINFOW();
                if (SHGetFileInfoW(p, 0, ref info, (uint)Marshal.SizeOf<SHFILEINFOW>(), 0x100 /*SHGFI_ICON, groß*/) == IntPtr.Zero || info.hIcon == IntPtr.Zero) return null;
                try
                {
                    var src = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                    src.Freeze();
                    return src;
                }
                finally { DestroyIcon(info.hIcon); }
            }
            catch { return null; }
        });
    }

    private static readonly ConcurrentDictionary<string, (string Title, string Publisher)> Infos = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Anzeigename (Dateibeschreibung) und Herausgeber laut eingebetteter Signatur. Die Signatur wird nicht geprüft,
    /// nur ausgelesen; Windows-eigene Programme sind über Kataloge signiert und haben hier keinen Eintrag.</summary>
    public static (string Title, string Publisher) InfoOf(string path)
    {
        if (path.Length == 0 || path == "System") return ("", "");
        return Infos.GetOrAdd(path, static p =>
        {
            string title = "", publisher = "";
            try { title = FileVersionInfo.GetVersionInfo(p).FileDescription?.Trim() ?? ""; } catch { }
            try
            {
#pragma warning disable SYSLIB0057
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(p));
#pragma warning restore SYSLIB0057
                publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
            }
            catch { }
            return (title, publisher);
        });
    }
}
