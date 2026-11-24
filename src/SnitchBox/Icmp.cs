using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Proben für die Routenverfolgung über die ICMP-Schnittstelle von Windows (IcmpSendEcho2/Icmp6SendEcho2, wie tracert):
/// ICMP-Echo mit begrenzter Lebensdauer, Antwort über ein Ereignis, ohne einen Thread zu blockieren. Anders als
/// System.Net.NetworkInformation.Ping liefert das auch für „Lebensdauer abgelaufen“ die Laufzeit (Ping meldet dort 0 ms).
/// Der Netzwerkfilter fängt ICMP nicht ab; die Proben gehen also auch bei verbietenden Regeln hinaus.</summary>
internal sealed class IcmpProber : ITraceProber
{
    [StructLayout(LayoutKind.Sequential)]
    private struct IpOptionInformation
    {
        public byte Ttl, Tos, Flags, OptionsSize;
        public IntPtr OptionsData;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern IntPtr IcmpCreateFile();
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern IntPtr Icmp6CreateFile();
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern bool IcmpCloseHandle(IntPtr handle);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint IcmpSendEcho2(IntPtr handle, SafeWaitHandle evt, IntPtr apc, IntPtr apcContext, uint destination,
        IntPtr requestData, ushort requestSize, ref IpOptionInformation options, IntPtr replyBuffer, uint replySize, uint timeout);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint Icmp6SendEcho2(IntPtr handle, SafeWaitHandle evt, IntPtr apc, IntPtr apcContext, byte[] source, byte[] destination,
        IntPtr requestData, ushort requestSize, ref IpOptionInformation options, IntPtr replyBuffer, uint replySize, uint timeout);
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern uint IcmpParseReplies(IntPtr replyBuffer, uint replySize);
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern uint Icmp6ParseReplies(IntPtr replyBuffer, uint replySize);

    private const int ErrorIoPending = 997;
    // Eigene Adressen: Meldet eine davon „nicht erreichbar“, spricht das System selbst (z. B. im eigenen Netz antwortet niemand auf ARP).
    private readonly HashSet<IPAddress> _own = OwnAddresses();

    private static HashSet<IPAddress> OwnAddresses()
    {
        var set = new HashSet<IPAddress>();
        try
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                foreach (var u in nic.GetIPProperties().UnicastAddresses)
                    set.Add(WithoutScope(u.Address.IsIPv4MappedToIPv6 ? u.Address.MapToIPv4() : u.Address));
        }
        catch (Exception) { }
        return set;
    }
    // Wie .NET (Ping): Platz für die größte mögliche Antwort samt zitiertem Originalpaket.
    private const uint ReplySize = 0xFFFF + 256;
    private static readonly byte[] Payload = "abcdefghijklmnopqrstuvwabcdefghi"u8.ToArray(); // wie tracert, 32 Bytes

    public Task<ProbeResult> ProbeAsync(IPAddress target, int ttl, int timeoutMs, CancellationToken cancel)
    {
        if (target.IsIPv4MappedToIPv6) target = target.MapToIPv4();
        var v6 = target.AddressFamily == AddressFamily.InterNetworkV6;
        var done = new TaskCompletionSource<ProbeResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handle = v6 ? Icmp6CreateFile() : IcmpCreateFile();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            return Task.FromResult(new ProbeResult(ProbeStatus.Error, null, 0, Marshal.GetLastPInvokeError()));
        var evt = new ManualResetEvent(false);
        var request = Marshal.AllocHGlobal(Payload.Length);
        var reply = Marshal.AllocHGlobal((int)ReplySize);
        Marshal.Copy(Payload, 0, request, Payload.Length);
        var options = new IpOptionInformation { Ttl = (byte)Math.Clamp(ttl, 1, 255) };
        // Alles bleibt bis zum Signal des Ereignisses bestehen: Windows schreibt die Antwort später in den Puffer.
        void Free()
        {
            IcmpCloseHandle(handle);
            Marshal.FreeHGlobal(request);
            Marshal.FreeHGlobal(reply);
            evt.Dispose();
        }
        uint sent;
        int error;
        if (v6)
        {
            var dest = new byte[28];
            dest[0] = 23; // AF_INET6
            target.GetAddressBytes().CopyTo(dest, 8);
            BitConverter.TryWriteBytes(dest.AsSpan(24), (uint)target.ScopeId);
            sent = Icmp6SendEcho2(handle, evt.SafeWaitHandle, IntPtr.Zero, IntPtr.Zero, new byte[28], dest, request, (ushort)Payload.Length,
                ref options, reply, ReplySize, (uint)timeoutMs);
        }
        else
        {
            var destination = BitConverter.ToUInt32(target.GetAddressBytes()); // Netzwerk-Byte-Reihenfolge wie in in_addr
            sent = IcmpSendEcho2(handle, evt.SafeWaitHandle, IntPtr.Zero, IntPtr.Zero, destination, request, (ushort)Payload.Length,
                ref options, reply, ReplySize, (uint)timeoutMs);
        }
        error = Marshal.GetLastPInvokeError();
        if (sent == 0 && error != ErrorIoPending)
        {
            Free();
            return Task.FromResult(new ProbeResult(error is 1231 or 1232 or 11002 or 11003 ? ProbeStatus.Unreachable : ProbeStatus.Error, null, 0, error));
        }
        // Normalerweise ERROR_IO_PENDING; meldet Windows das Ergebnis sofort, ist das Ereignis schon gesetzt.
        RegisteredWaitHandle? registration = null;
        var gate = new object();
        var finished = false;
        void OnSignal(object? _, bool timedOut)
        {
            lock (gate)
            {
                if (finished) return;
                if (timedOut)
                {
                    // Windows hat nicht geantwortet (sollte nach timeoutMs nie vorkommen): als Zeitüberschreitung melden, den Puffer aber
                    // erst freigeben, wenn das Ereignis doch noch kommt (sonst schriebe Windows in freigegebenen Speicher).
                    done.TrySetResult(new ProbeResult(ProbeStatus.Timeout, null, 0, 11010));
                    registration?.Unregister(null);
                    registration = ThreadPool.RegisterWaitForSingleObject(evt, OnSignal, null, Timeout.Infinite, true);
                    return;
                }
                finished = true;
                registration?.Unregister(null);
            }
            try
            {
                var result = Parse(v6, reply);
                // Ohne Absender = Meldung des Systems (siehe Tracer.Probe); eine Echo-Antwort an sich selbst bleibt, wie sie ist.
                if (result is { Status: ProbeStatus.Unreachable, From: { } from } && _own.Contains(WithoutScope(from))) result = result with { From = null };
                done.TrySetResult(result);
            }
            catch (Exception e) { done.TrySetResult(new ProbeResult(ProbeStatus.Error, null, 0, e.HResult)); }
            finally { Free(); }
        }
        lock (gate) registration = ThreadPool.RegisterWaitForSingleObject(evt, OnSignal, null, timeoutMs + 10_000, true);
        return done.Task;
    }

    private static IPAddress WithoutScope(IPAddress a) => a.AddressFamily == AddressFamily.InterNetworkV6 && a.ScopeId != 0 ? new IPAddress(a.GetAddressBytes()) : a;

    private static ProbeResult Parse(bool v6, IntPtr reply)
    {
        uint status;
        int rtt;
        IPAddress? from;
        if (v6)
        {
            var count = Icmp6ParseReplies(reply, ReplySize);
            var error = Marshal.GetLastPInvokeError();
            // ICMPV6_ECHO_REPLY: IPV6_ADDRESS_EX (gepackt, 26 Bytes: Port 2, Flowinfo 4, Adresse 16, Scope 4), Status @28, Laufzeit @32.
            status = (uint)Marshal.ReadInt32(reply, 28);
            rtt = Marshal.ReadInt32(reply, 32);
            var bytes = new byte[16];
            Marshal.Copy(reply + 6, bytes, 0, 16);
            from = new IPAddress(bytes);
            if (count == 0 && status == 0) status = (uint)error;
        }
        else
        {
            var count = IcmpParseReplies(reply, ReplySize);
            var error = Marshal.GetLastPInvokeError();
            // ICMP_ECHO_REPLY: Adresse @0, Status @4, Laufzeit @8.
            var bytes = new byte[4];
            Marshal.Copy(reply, bytes, 0, 4);
            from = new IPAddress(bytes);
            status = (uint)Marshal.ReadInt32(reply, 4);
            rtt = Marshal.ReadInt32(reply, 8);
            if (count == 0 && status == 0) status = (uint)error;
        }
        var kind = Classify(status);
        if (kind is ProbeStatus.Timeout or ProbeStatus.Error || from.Equals(IPAddress.Any) || from.Equals(IPAddress.IPv6Any)) from = null;
        return new ProbeResult(kind, from, from == null ? 0 : Math.Max(0, rtt), (int)status);
    }

    /// <summary>Statuswerte aus ipexport.h.</summary>
    internal static ProbeStatus Classify(uint status) => status switch
    {
        0 => ProbeStatus.Reply,
        11013 or 11014 or 11041 => ProbeStatus.TimeExceeded,                       // TTL/Hop-Limit abgelaufen, Zusammensetzen
        11002 or 11003 or 11004 or 11005 or 11040 or 11045 => ProbeStatus.Unreachable, // Netz/Host/Protokoll/Port, IPv6-Varianten
        11010 => ProbeStatus.Timeout,
        _ => ProbeStatus.Error,
    };

    /// <summary>Verständlicher Text zu einem Statuswert (Spalte „Zeiten“, Tooltip).</summary>
    public static string Describe(int code) => code switch
    {
        11002 => Loc.T("Netz nicht erreichbar", "Network unreachable"),
        11003 => Loc.T("Ziel nicht erreichbar", "Host unreachable"),
        11004 => Loc.T("Verboten (Protokoll/Filter)", "Prohibited (protocol/filter)"),
        11005 => Loc.T("Port nicht erreichbar", "Port unreachable"),
        11040 or 11045 => Loc.T("Ziel nicht erreichbar", "Host unreachable"),
        1231 => Loc.T("Kein Netz zum Ziel", "No network to the destination"),
        1232 => Loc.T("Ziel nicht erreichbar", "Host unreachable"),
        11010 => Loc.T("Keine Antwort", "No reply"),
        _ => Loc.F("Fehler {0}", "Error {0}", code),
    };
}
