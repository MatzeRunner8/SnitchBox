namespace SnitchBox.Core;

/// <summary>Zuordnung eines Netzwerks zu einem Profil. <see cref="NetworkId"/> ist die Kennung, die Windows einem Netzwerk gibt
/// (bleibt gleich, solange es dasselbe Netz ist – etwa am selben Router), <see cref="Name"/> sein Anzeigename.</summary>
public sealed class NetworkProfile
{
    public string NetworkId { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>null = „Kein Profil“.</summary>
    public string? Profile { get; set; }
    /// <summary>In diesem Netzwerk nie automatisch umschalten (auch nicht auf das Profil für andere Netzwerke).</summary>
    public bool NoSwitch { get; set; }
}

/// <summary>Ein gerade verbundenes Netzwerk (unter Windows aus der Netzwerkliste). <paramref name="Known"/>: Windows führt ein Profil
/// dafür, es ist also schon identifiziert (nicht das Übergangsnetz beim Verbinden oder ein „Nicht identifiziertes Netzwerk“).</summary>
public readonly record struct ConnectedNetwork(string Id, string Name, bool Known = true);

/// <summary>Nur Netze, die schon eine Weile verbunden sind, zählen. Beim Verbinden meldet Windows zuerst ein Übergangsnetz
/// („Netzwerkidentifizierung…“, „Nicht identifiziertes Netzwerk“, je Verbindung mit neuer Kennung) und erst Sekunden später das
/// eigentliche – das Übergangsnetz darf nicht als neues Netz gelten und das Profil umschalten. Ein noch nicht identifiziertes Netz
/// (<see cref="ConnectedNetwork.Known"/> false) muss länger bleiben: Nach einem Neustart des Routers hält es sich oft eine Minute.</summary>
public sealed class StableNetworks
{
    public static readonly TimeSpan After = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan AfterUnknown = TimeSpan.FromSeconds(90);
    private readonly Dictionary<string, long> _firstSeen = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Neuer Stand der verbundenen Netze (<paramref name="nowMs"/>: fortlaufende Millisekunden). Liefert die Netze, die seit
    /// mindestens <see cref="After"/> (unbekannte: <see cref="AfterUnknown"/>) ohne Unterbrechung verbunden sind, und wann das nächste so
    /// weit ist (Millisekunden ab jetzt, sonst null).</summary>
    public (List<ConnectedNetwork> Stable, long? NextInMs) Update(IReadOnlyList<ConnectedNetwork> connected, long nowMs)
    {
        foreach (var gone in _firstSeen.Keys.Where(id => !connected.Any(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase))).ToList())
            _firstSeen.Remove(gone);
        var stable = new List<ConnectedNetwork>();
        long? next = null;
        foreach (var net in connected)
        {
            if (!_firstSeen.TryGetValue(net.Id, out var since)) _firstSeen[net.Id] = since = nowMs;
            var wait = since + (long)(net.Known ? After : AfterUnknown).TotalMilliseconds - nowMs;
            if (wait <= 0) stable.Add(net);
            else next = Math.Min(next ?? long.MaxValue, wait);
        }
        return (stable, next);
    }
}

/// <summary>Entscheidet, welches Profil zu den verbundenen Netzwerken gehört.</summary>
public static class NetworkProfiles
{
    /// <summary>Ergebnis: <c>Switch</c> = umschalten auf <c>Profile</c> (null = „Kein Profil“); <c>Network</c> nennt das Netzwerk, das
    /// den Ausschlag gab. Netzwerke mit „Nicht automatisch wechseln“ zählen gar nicht – sind nur solche verbunden, bleibt alles, wie es ist;
    /// neben einem anderen Netz (etwa ein Gast-WLAN oder VPN neben dem LAN) entscheidet das andere. Sonst gewinnt die erste passende
    /// Zuordnung (in der Reihenfolge, in der sie angelegt wurden), dann das Profil für andere Netzwerke. Ohne verbundenes Netzwerk, ohne
    /// passende Zuordnung und ohne Profil für andere Netzwerke bleibt alles, wie es ist. Zuordnungen zu gelöschten Profilen zählen nicht.</summary>
    public static (bool Switch, string? Profile, string Network) Choose(IReadOnlyList<ConnectedNetwork> connected, Settings s)
    {
        var d = Decide(connected, s);
        return (d.Switch, d.Profile, d.Network);
    }

    /// <summary>Wie <see cref="Choose"/>, dazu die Kennung des ausschlaggebenden zugeordneten Netzes (null: kein zugeordnetes, dann gilt
    /// das Profil für andere Netzwerke) und die Kennungen aller zählenden Netze (ohne „Nicht automatisch wechseln“), klein geschrieben.</summary>
    private static (bool Switch, string? Profile, string Network, string? Decider, List<string> Relevant) Decide(IReadOnlyList<ConnectedNetwork> connected, Settings s)
    {
        if (connected.Count == 0) return (false, null, "", null, []);
        bool Exists(string? profile) => profile == null || s.Profiles.Contains(profile);
        bool Is(ConnectedNetwork net, NetworkProfile b) => net.Id.Equals(b.NetworkId, StringComparison.OrdinalIgnoreCase);
        var relevant = connected.Where(net => !s.NetworkProfiles.Any(b => b.NoSwitch && Is(net, b))).ToList();
        var ids = relevant.Select(n => n.Id.ToLowerInvariant()).Distinct().ToList();
        if (relevant.Count == 0) return (false, null, connected[0].Name, null, ids);
        foreach (var binding in s.NetworkProfiles)
        {
            if (binding.NoSwitch || !Exists(binding.Profile)) continue;
            foreach (var net in relevant)
                if (Is(net, binding)) return (true, binding.Profile, net.Name, net.Id.ToLowerInvariant(), ids);
        }
        return s.SwitchOnUnknownNetwork && Exists(s.UnknownNetworkProfile)
            ? (true, s.UnknownNetworkProfile, relevant[0].Name, null, ids)
            : (false, null, "", null, ids);
    }

    /// <summary>Wie lange das ausschlaggebende Netz fehlen darf, während andere verbunden bleiben, bevor das als Wechsel zählt
    /// (Aufwachen, WLAN-Aussetzer).</summary>
    public static readonly TimeSpan PlaceGrace = TimeSpan.FromSeconds(60);
    private const int MaxExtras = 32;

    /// <summary>Netzwerkwechsel erkennen. Gemerkt sind der „Ort“ (<see cref="Settings.NetworkPlace"/>: die Netze, die beim letzten Wechsel
    /// den Ausschlag gaben) und die Netze, die danach nur dazukamen (<see cref="Settings.NetworkExtras"/>, etwa ein VPN). Ein Wechsel ist
    /// es, wenn ein neu verbundenes Netz entscheidet (es ist zugeordnet und hat Vorrang), wenn ein neues Netz kommt, während vom bisherigen
    /// Ort keines (bei einem Ort aus mehreren nicht zugeordneten Netzen: nicht mehr jedes) verbunden ist, oder wenn der Ort länger als
    /// <see cref="PlaceGrace"/> fehlt (<paramref name="placeGone"/>), während andere Netze verbunden sind. Netze, die nur kurz wegfallen,
    /// und Netze mit „Nicht automatisch wechseln“ lösen nie etwas aus; sind nur solche länger verbunden, wird der Ort vergessen (ohne
    /// umzuschalten), damit die Rückkehr wieder zählt. Zum Ort werden nur neu erschienene Netze oder das entscheidende zugeordnete, nie
    /// schon vorher verbundene (etwa ein virtueller Adapter von WSL oder Hyper-V) – fehlt der Ort und kommt kein neues Netz, bleibt er
    /// leer, und das nächste neue Netz zählt. Entscheidet inzwischen ein Netz des Orts per Zuordnung, schrumpft der Ort auf dieses.
    /// Liefert null, wenn sich nichts ändert, sonst den neuen Stand; <c>Changed</c> = das Profil neu bestimmen.</summary>
    public static (bool Changed, List<string> Place, List<string> Extras)? Observe(IReadOnlyList<ConnectedNetwork> connected, Settings s, bool placeGone)
    {
        var d = Decide(connected, s);
        var place = s.NetworkPlace;
        var extras = s.NetworkExtras;
        if (d.Relevant.Count == 0)
            return placeGone && connected.Count > 0 && (place.Count > 0 || extras.Count > 0) ? (false, [], []) : null;
        var placeConnected = place.Any(d.Relevant.Contains);
        // Nur wirklich getrennte Mitglieder zählen als fehlend, nicht verbundene mit „Nicht automatisch wechseln“.
        var placePartlyMissing = d.Decider == null && place.Any(id => !connected.Any(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase)));
        var fresh = d.Relevant.Where(id => !place.Contains(id) && !extras.Contains(id)).ToList();
        var deciderIsNew = d.Decider != null && fresh.Contains(d.Decider);
        List<string> Others(List<string> p) => d.Relevant.Where(id => !p.Contains(id)).Take(MaxExtras).ToList();
        if (deciderIsNew || (fresh.Count > 0 && (!placeConnected || placePartlyMissing)) || (place.Count > 0 && !placeConnected && placeGone))
        {
            List<string> newPlace = d.Decider != null ? [d.Decider] : fresh;
            return (true, newPlace, Others(newPlace));
        }
        // Kein Wechsel. Entscheidet ein Netz des Orts inzwischen per Zuordnung, gehören die übrigen nicht mehr zum Ort.
        if (d.Decider != null && place.Contains(d.Decider) && place.Count > 1)
            return (false, [d.Decider], Others([d.Decider]));
        // Neu dazugekommene Netze merken, nicht mehr verbundene vergessen (der Ort bleibt, bis gewechselt wird) – im Zustand „unterwegs“
        // (leerer Ort) erst nach der Frist: Sonst zählte ein WLAN nach einem kurzen Aussetzer bei seiner Rückkehr als neues Netz.
        var kept = place.Count == 0 && !placeGone ? extras : extras.Where(d.Relevant.Contains);
        var newExtras = kept.Concat(fresh).Take(MaxExtras).ToList();
        return newExtras.SequenceEqual(extras) ? null : (false, place.ToList(), newExtras);
    }

    /// <summary>Ist vom gemerkten Ort noch ein Netz verbunden? Ganz ohne Netz (Aufwachen, unterwegs) fehlt nichts. Sind nur Netze mit
    /// „Nicht automatisch wechseln“ verbunden, fehlt der gemerkte Stand, sobald einer da ist (Ort oder Extras) – nach der Frist wird er
    /// vergessen. Bei leerem Ort („unterwegs“) fehlt etwas, solange eines der gemerkten Extras weg ist; nach der Frist wird es vergessen.</summary>
    public static bool PlaceConnected(IReadOnlyList<ConnectedNetwork> connected, Settings s)
    {
        if (connected.Count == 0) return true;
        var relevant = Decide(connected, s).Relevant;
        if (relevant.Count == 0) return s.NetworkPlace.Count == 0 && s.NetworkExtras.Count == 0;
        if (s.NetworkPlace.Count == 0) return s.NetworkExtras.All(relevant.Contains);
        return s.NetworkPlace.Any(relevant.Contains);
    }

    /// <summary>Wie <see cref="Choose"/> für die verbundenen Netze – fehlt der gemerkte Ort aber gerade (die Frist läuft), zählen seine
    /// Netze noch mit: Kommt er zurück, stimmt das Ergebnis; läuft die Frist ab, schaltet der Watcher.</summary>
    public static (bool Switch, string? Profile, string Network) ChooseHere(IReadOnlyList<ConnectedNetwork> connected, Settings s) =>
        Choose(Here(connected, s), s);

    private static IReadOnlyList<ConnectedNetwork> Here(IReadOnlyList<ConnectedNetwork> connected, Settings s) =>
        !HasRelevant(connected, s) || PlaceConnected(connected, s)
            ? connected
            : connected.Concat(s.NetworkPlace.Where(id => !connected.Any(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase)))
                .Select(id => new ConnectedNetwork(id, id))).ToList();

    /// <summary>Ist ein Netz verbunden, das zählt (also nicht nur Netze mit „Nicht automatisch wechseln“)?</summary>
    public static bool HasRelevant(IReadOnlyList<ConnectedNetwork> connected, Settings s) => Decide(connected, s).Relevant.Count > 0;

    /// <summary>Profil von Hand wählen. Ist man dabei nicht am gemerkten Ort (er fehlt, oder nur Netze mit „Nicht automatisch wechseln“
    /// sind verbunden), gilt die Wahl dem Netz, in dem man gerade ist: Der Ort wird vergessen (die verbundenen Netze bleiben als Extras
    /// bekannt), damit die Rückkehr an den Ort oder das nächste neue Netz wieder umschaltet – sonst bliebe die Wahl etwa vom Heimnetz
    /// am nächsten Tag im Café aktiv, wenn man zu Hause nur kurz war.</summary>
    public static void ChooseByHand(IReadOnlyList<ConnectedNetwork> connected, Settings s, string? profile)
    {
        s.ActiveProfile = profile;
        if (PlaceConnected(connected, s)) return;
        s.NetworkPlace = [];
        s.NetworkExtras = Decide(connected, s).Relevant.Take(MaxExtras).ToList();
    }

    /// <summary>Gemerkten Ort vergessen: Die nächste Netzwerkprüfung bestimmt das Profil neu.</summary>
    public static void Forget(Settings s)
    {
        s.NetworkPlace.Clear();
        s.NetworkExtras.Clear();
    }

    /// <summary>Ändert die Zuordnungen (<paramref name="change"/>) und schaltet das aktive Profil nur dann um, wenn sich dadurch das
    /// Ergebnis für die verbundenen Netzwerke ändert. Betrifft die Änderung sie nicht (ein anderes Netz, „Andere Netzwerke“ bei
    /// zugeordnetem Netz), bleibt ein von Hand gewähltes Profil. Danach passt der gemerkte Ort zu den neuen Zuordnungen – sonst hielte
    /// die nächste Prüfung die Änderung für einen Netzwerkwechsel (aber nur, wenn kein echter Wechsel mehr aussteht, den der Watcher noch
    /// anwenden muss). Zählt kein verbundenes Netz (keins oder nur „Nicht automatisch wechseln“), zählt der gemerkte Ort: Ändert sich
    /// dessen Ergebnis, wird er vergessen, damit die Änderung beim nächsten Verbinden gilt. Liefert true, wenn umgeschaltet wurde.</summary>
    public static bool ChangeBindings(IReadOnlyList<ConnectedNetwork> connected, Settings s, Action<Settings> change)
    {
        // Der gemerkte Stand als Netze (Ort und Extras: bei leerem Ort „unterwegs“ sind die Extras das Einzige, was zählt).
        IReadOnlyList<ConnectedNetwork> remembered = s.NetworkPlace.Concat(s.NetworkExtras).Distinct().Select(id => new ConnectedNetwork(id, id)).ToList();
        // Fehlt der Ort gerade (die Frist läuft), gilt er für die Entscheidung als noch da: Kommt er zurück, stimmt das Ergebnis; läuft
        // die Frist ab, schaltet der Watcher. Steht ein Wechsel aus oder fehlt der Ort, wird der gemerkte Stand nicht nachgezogen.
        var placeMissing = HasRelevant(connected, s) && !PlaceConnected(connected, s);
        var here = Here(connected, s);
        var beforeHere = Choose(here, s);
        var beforeRemembered = Choose(remembered, s);
        var inSync = !placeMissing && Observe(connected, s, placeGone: false) is not { Changed: true };
        change(s);
        if (!HasRelevant(connected, s))
        {
            if (Choose(remembered, s) != beforeRemembered) Forget(s);
            return false;
        }
        bool IsConnected(string id) => connected.Any(c => c.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (inSync) Settle(connected, s);
        if (placeMissing && Decide(here, s).Decider is { } decider && !s.NetworkPlace.Contains(decider) && IsConnected(decider))
        {
            // Entscheidet jetzt ein verbundenes Netz außerhalb des fehlenden Orts, ist es der Ort (wie ein neu verbundenes entscheidendes Netz).
            s.NetworkPlace = [decider];
            s.NetworkExtras = Decide(connected, s).Relevant.Where(id => id != decider).Take(MaxExtras).ToList();
        }
        if (!placeMissing && s.NetworkPlace.Count > 1)
        {
            // Ort aus mehreren Netzen: Ein gerade getrenntes Mitglied, das jetzt zugeordnet ist, gehört nicht mehr dazu – seine Rückkehr
            // ist dann ein neues entscheidendes Netz und schaltet um.
            bool Bound(string id) => s.NetworkProfiles.Any(b => !b.NoSwitch && (b.Profile == null || s.Profiles.Contains(b.Profile))
                                                                && b.NetworkId.Equals(id, StringComparison.OrdinalIgnoreCase));
            var leave = s.NetworkPlace.Where(id => !IsConnected(id) && Bound(id)).ToList();
            if (leave.Count > 0 && leave.Count < s.NetworkPlace.Count) s.NetworkPlace = s.NetworkPlace.Except(leave).ToList();
        }
        var after = Choose(here, s);
        if (!after.Switch || (beforeHere.Switch && beforeHere.Profile == after.Profile) || s.ActiveProfile == after.Profile) return false;
        s.ActiveProfile = after.Profile;
        return true;
    }

    /// <summary>Die verbundenen Netze als bekannt merken, ohne das Profil zu ändern: Ort = das entscheidende zugeordnete Netz, sonst
    /// der bisherige Ort unverändert, solange eines seiner Netze noch zählt – sonst leer (nie ein Extra wie ein virtueller Adapter, sonst
    /// zählte das nächste neue Netz nicht; und nicht verkleinert, sonst bliebe ein Dauer-Adapter allein als Ort übrig); der Rest wird zu Extras.</summary>
    private static void Settle(IReadOnlyList<ConnectedNetwork> connected, Settings s)
    {
        var d = Decide(connected, s);
        if (d.Relevant.Count == 0) return;
        List<string> place = d.Decider != null ? [d.Decider] : s.NetworkPlace.Any(d.Relevant.Contains) ? s.NetworkPlace.ToList() : [];
        s.NetworkPlace = place;
        s.NetworkExtras = d.Relevant.Where(id => !place.Contains(id)).Take(MaxExtras).ToList();
    }

    /// <summary>Zuordnung eines Netzwerks setzen, ohne ihre Stelle in der Liste (ihren Vorrang) zu ändern; null entfernt sie
    /// („Wie andere Netzwerke“).</summary>
    public static void SetBinding(Settings s, string networkId, NetworkProfile? binding)
    {
        bool Same(NetworkProfile b) => b.NetworkId.Equals(networkId, StringComparison.OrdinalIgnoreCase);
        var i = s.NetworkProfiles.FindIndex(Same);
        if (binding == null) s.NetworkProfiles.RemoveAll(Same);
        else if (i < 0) s.NetworkProfiles.Add(binding);
        else
        {
            s.NetworkProfiles[i] = binding;
            for (var j = s.NetworkProfiles.Count - 1; j > i; j--)
                if (Same(s.NetworkProfiles[j])) s.NetworkProfiles.RemoveAt(j); // doppelte Einträge (von Hand bearbeitete Datei)
        }
    }
}
