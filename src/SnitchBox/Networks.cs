using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Die gerade verbundenen Netzwerke laut Netzwerkliste von Windows (Network List Manager): Name und Kennung, wie sie auch
/// die Windows-Einstellungen zeigen. Windows erkennt ein Netz am Router wieder; die Kennung bleibt also beim nächsten Verbinden gleich.</summary>
internal static class Networks
{
    [ComImport, Guid("DCB00000-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetworkListManager
    {
        IEnumNetworks GetNetworks(int flags);
    }

    [ComImport, Guid("DCB00003-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IEnumNetworks
    {
        [DispId(-4)]
        object NewEnum { [return: MarshalAs(UnmanagedType.IUnknown)] get; }
        [PreserveSig] int Next(int count, [MarshalAs(UnmanagedType.Interface)] out INetwork? network, out int fetched);
    }

    [ComImport, Guid("DCB00002-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetwork
    {
        [return: MarshalAs(UnmanagedType.BStr)] string GetName();
        void SetName([MarshalAs(UnmanagedType.BStr)] string name);
        [return: MarshalAs(UnmanagedType.BStr)] string GetDescription();
        void SetDescription([MarshalAs(UnmanagedType.BStr)] string description);
        Guid GetNetworkId();
    }

    private static readonly Guid NetworkListManager = new("DCB00C01-570F-4A9B-8D69-199FDBA5723B");
    private const int ConnectedOnly = 1; // NLM_ENUM_NETWORK_CONNECTED

    public static List<ConnectedNetwork> Connected()
    {
        var result = new List<ConnectedNetwork>();
        object? manager = null;
        try
        {
            manager = Activator.CreateInstance(Type.GetTypeFromCLSID(NetworkListManager, true)!)!;
            var networks = ((INetworkListManager)manager).GetNetworks(ConnectedOnly);
            try
            {
                for (var i = 0; i < 64; i++)
                {
                    if (networks.Next(1, out var net, out var fetched) != 0 || fetched == 0 || net == null) break;
                    try
                    {
                        var id = net.GetNetworkId().ToString("B");
                        result.Add(new ConnectedNetwork(id, net.GetName(), HasProfile(id)));
                    }
                    finally { Marshal.ReleaseComObject(net); }
                }
            }
            finally { Marshal.ReleaseComObject(networks); }
        }
        catch (Exception e) { Log.Write("Netzwerkliste lesen: " + e.Message); }
        finally { if (manager != null) Marshal.ReleaseComObject(manager); }
        return result;
    }

    /// <summary>Führt Windows ein Profil für dieses Netz (es ist identifiziert)? Das Übergangsnetz beim Verbinden und ein „Nicht
    /// identifiziertes Netzwerk“ haben keins. Im Zweifel ja – dann gilt nur die kurze Wartezeit.</summary>
    private static bool HasProfile(string id)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\" + id);
            return key != null;
        }
        catch (Exception) { return true; }
    }
}

/// <summary>Schaltet das Profil um, wenn du ein anderes Netzwerk betrittst (Zuordnung unter Einstellungen → Profile; was als Wechsel
/// zählt, entscheidet <see cref="NetworkProfiles.Observe"/>). Ein von Hand gewähltes Profil bleibt bis dahin, auch über einen Neustart
/// von SnitchBox hinweg. Es zählen nur Netze, die seit <see cref="StableNetworks.After"/> verbunden sind (Übergangsnetz beim Verbinden).
/// Geprüft wird 2 s nach dem letzten Netzwerkereignis (bei Ereignissen im Sekundentakt spätestens 5 s nach dem ersten), 6 s danach noch
/// einmal (Windows erkennt ein Netz oft erst dann), sobald ein neues Netz lange genug verbunden ist, und sonst alle 30 s – falls Windows
/// einen Wechsel gar nicht meldet und für die Frist eines weggefallenen Netzes.</summary>
internal sealed class NetworkProfileWatcher : IDisposable
{
    private const int Debounce = 2000, MaxDelay = 5000, SecondCheck = 6000, Periodic = 30_000;
    private readonly FirewallEngine _engine;
    // Prüfung nach Netzwerkereignissen (entprellt), Nachprüfungen (zweite Prüfung, neues Netz lange genug da), regelmäßige Prüfung.
    private readonly Timer _eventTimer, _followUp, _periodic;
    private readonly object _gate = new();
    private readonly StableNetworks _stable = new();
    private int _generation;
    private bool _eventPending, _secondCheckDue;
    private long _burstStart = -1, _followUpAt = long.MaxValue, _placeMissingSince = -1, _lastTick = -1;

    /// <summary>Nach jeder Prüfung (für die Einstellungen), mit den verbundenen Netzwerken.</summary>
    public event Action<IReadOnlyList<ConnectedNetwork>>? Checked;
    /// <summary>Die verbundenen Netze, die zählen (schon lange genug verbunden).</summary>
    public IReadOnlyList<ConnectedNetwork> Current { get; private set; } = [];

    public NetworkProfileWatcher(FirewallEngine engine)
    {
        _engine = engine;
        _eventTimer = new Timer(_ =>
        {
            lock (_gate)
            {
                _eventPending = false;
                _burstStart = -1;
                // Erst hier, nicht schon beim Ereignis: Eine Nachprüfung in der Entprellzeit soll die zweite Prüfung nicht vorwegnehmen.
                _secondCheckDue = true;
            }
            Tick();
        }, null, Timeout.Infinite, Timeout.Infinite);
        _followUp = new Timer(_ =>
        {
            lock (_gate) _followUpAt = long.MaxValue;
            Tick();
        }, null, Timeout.Infinite, Timeout.Infinite);
        // Die regelmäßige Prüfung läuft auf eigenem Timer und verdrängt keine geplante (nur eine Ereignisprüfung kommt ohnehin gleich).
        // Sie muss auch laufen, während eine lange Nachprüfung aussteht (ein nicht identifiziertes Netz wartet 90 s): Die Frist für
        // ein fehlendes Netz läuft weiter, und mehr als 70 s ohne Prüfung gelten als Standby.
        _periodic = new Timer(_ =>
        {
            lock (_gate) if (_eventPending) return;
            Tick();
        }, null, Periodic, Periodic);
        NetworkChange.NetworkAddressChanged += OnChanged;
        NetworkChange.NetworkAvailabilityChanged += OnChanged;
        Microsoft.Win32.SystemEvents.PowerModeChanged += OnPowerModeChanged;
        OnEvent(500);
    }

    private void OnChanged(object? sender, EventArgs e) => OnEvent(Debounce);

    /// <summary>Nach dem Aufwachen beginnt die Frist für ein fehlendes Netz neu: Die Zeit im Standby zählt nicht (sonst schaltete die
    /// erste Prüfung nach dem Aufwachen sofort um, noch bevor das WLAN wieder da ist).</summary>
    private void OnPowerModeChanged(object? sender, Microsoft.Win32.PowerModeChangedEventArgs e)
    {
        if (e.Mode != Microsoft.Win32.PowerModes.Resume) return;
        lock (_gate) _placeMissingSince = -1;
        OnEvent(Debounce);
    }

    private void OnEvent(int ms)
    {
        lock (_gate)
        {
            var now = Environment.TickCount64;
            if (_burstStart < 0) _burstStart = now;
            var due = Math.Max(0, Math.Min(ms, _burstStart + MaxDelay - now));
            _generation++;
            _eventPending = true;
            try { _eventTimer.Change(due, Timeout.Infinite); } catch (ObjectDisposedException) { }
        }
    }

    /// <summary>Nachprüfung in <paramref name="ms"/> Millisekunden, sofern nicht schon eine frühere geplant ist (unter <see cref="_gate"/>).
    /// false: es bleibt bei der früheren – wer eine Prüfung genau dann braucht, plant bei ihr neu.</summary>
    private bool FollowUpIn(long ms)
    {
        var at = Environment.TickCount64 + ms;
        if (at >= _followUpAt) return false;
        _followUpAt = at;
        try { _followUp.Change(ms, Timeout.Infinite); } catch (ObjectDisposedException) { }
        return true;
    }

    private void Tick()
    {
        try
        {
            int generation;
            lock (_gate) generation = _generation;
            var all = Networks.Connected();
            IReadOnlyList<ConnectedNetwork> connected;
            lock (_gate)
            {
                // Während des Lesens kam ein Netzwerkereignis: Dieser Lauf hat womöglich noch den alten Stand gesehen, der nächste prüft ohnehin.
                if (generation != _generation) return;
                var (stable, next) = _stable.Update(all, Environment.TickCount64);
                Current = connected = stable;
                // Zweite Prüfung 6 s nach einer Prüfung wegen eines Ereignisses; ist schon eine frühere Nachprüfung geplant, plant diese neu.
                if (next is { } wait) FollowUpIn(wait + 250);
                if (_secondCheckDue && FollowUpIn(SecondCheck)) _secondCheckDue = false;
            }
            // Wie lange fehlt das ausschlaggebende Netz schon, während andere verbunden sind? Ist es gerade wieder da (nur noch nicht
            // lange genug), fehlt es nicht – sonst schaltete der Ablauf der Frist kurz vor seiner Bestätigung noch um.
            var now = Environment.TickCount64;
            var placeConnected = _engine.Read(s => NetworkProfiles.PlaceConnected(all, s.Settings));
            bool placeGone;
            lock (_gate)
            {
                // Lange keine Prüfung (sonst spätestens alle 30 s): Der Rechner schlief – die Frist beginnt neu, falls das Aufwachen
                // nicht gemeldet wurde.
                if (_lastTick >= 0 && now - _lastTick > 2 * Periodic + 10_000 && _placeMissingSince >= 0) _placeMissingSince = now;
                _lastTick = now;
                if (placeConnected) _placeMissingSince = -1;
                else if (_placeMissingSince < 0) _placeMissingSince = now;
                placeGone = _placeMissingSince >= 0 && now - _placeMissingSince >= (long)NetworkProfiles.PlaceGrace.TotalMilliseconds;
            }
            if (_engine.Read(s => NetworkProfiles.Observe(connected, s.Settings, placeGone)) != null) Apply(connected, generation, placeGone);
            Checked?.Invoke(connected);
        }
        catch (Exception e) { Log.Write("Profil je Netzwerk: " + e.Message); }
    }

    private void Apply(IReadOnlyList<ConnectedNetwork> connected, int generation, bool placeGone)
    {
        string? log = null;
        _engine.Mutate(s =>
        {
            // Unter der Sperre noch einmal: Ein neuerer Lauf kann inzwischen alles erledigt haben.
            lock (_gate) if (generation != _generation) return;
            if (NetworkProfiles.Observe(connected, s.Settings, placeGone) is not { } seen) return;
            s.Settings.NetworkPlace = seen.Place;
            s.Settings.NetworkExtras = seen.Extras;
            if (!seen.Changed) return;
            var (change, profile, network) = NetworkProfiles.Choose(connected, s.Settings);
            if (!change || s.Settings.ActiveProfile == profile) return;
            s.Settings.ActiveProfile = profile;
            log = $"Profil je Netzwerk: „{profile ?? "Kein Profil"}“ für Netzwerk „{network}“";
        });
        if (log != null) Log.Write(log);
    }

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnChanged;
        Microsoft.Win32.SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        lock (_gate)
        {
            _periodic.Dispose();
            _followUp.Dispose();
            _eventTimer.Dispose();
        }
    }
}
