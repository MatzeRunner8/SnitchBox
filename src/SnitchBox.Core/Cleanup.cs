namespace SnitchBox.Core;

/// <summary>Ergebnis von <see cref="RuleCleanup.Plan"/>: die aufgeräumte Regelliste (Kopien, Kennungen bleiben) und was sich ändert.</summary>
public sealed record CleanupPlan(List<Rule> Rules, int Before, int Generalized, int Vanished, int Redundant, int MergedFrom, int MergedInto)
{
    public bool Empty => Generalized + Vanished + Redundant + MergedFrom == 0;
}

/// <summary>Hält die Regelliste klein, ohne eine Entscheidung zu ändern: Regeln gleicher Art (nur andere Gegenstellen) werden
/// zu einer zusammengefasst, und Regeln entfallen, die eine umfassendere Regel überflüssig macht.</summary>
public static class RuleCleanup
{
    private static string Norm(string t) => t.Trim().TrimEnd('.').ToLowerInvariant();

    private static bool SameLifetime(Rule a, Rule b) =>
        a.Lifetime == b.Lifetime && a.Expires == b.Expires && a.BootId == b.BootId && a.QuitPid == b.QuitPid;

    private static bool SamePorts(string a, string b) =>
        PortSet.TryParse(a, out var pa) && PortSet.TryParse(b, out var pb) ? pa.SameAs(pb) : a.Trim() == b.Trim();

    /// <summary>Lassen sich zwei Regeln zu einer mit beiden Gegenstellen-Listen zusammenfassen? Nur wenn sie sich allein
    /// in den Hosts, Domains bzw. Adressen unterscheiden – dann entscheidet die gemeinsame Regel genau wie die beiden.</summary>
    public static bool Mergeable(Rule a, Rule b) =>
        a.Enabled && b.Enabled && !a.Factory && !b.Factory && a.Action == b.Action && a.Direction == b.Direction
        && a.Remote == b.Remote && a.Remote is RemoteKind.Hosts or RemoteKind.Domains or RemoteKind.Addresses
        && a.Process.Equals(b.Process, StringComparison.OrdinalIgnoreCase) && a.Protocol == b.Protocol && a.Profile == b.Profile
        && a.HighPriority == b.HighPriority && SamePorts(a.Ports, b.Ports) && SameLifetime(a, b)
        && (a.Notes == b.Notes || a.Notes.Length == 0 || b.Notes.Length == 0);

    /// <summary>Kopie von <paramref name="a"/> (gleiche Kennung) mit den Gegenstellen beider Regeln.</summary>
    public static Rule Merge(Rule a, Rule b)
    {
        var r = a.Clone();
        var seen = r.Targets.Select(Norm).ToHashSet();
        foreach (var t in b.Targets)
            if (seen.Add(Norm(t))) r.Targets.Add(a.Remote == RemoteKind.Addresses ? t.Trim() : Norm(t));
        if (r.Notes.Length == 0) r.Notes = b.Notes;
        if (b.Created < r.Created) r.Created = b.Created;
        return r;
    }

    private static bool ProcessCovers(string wide, string narrow)
    {
        if (wide.Equals(narrow, StringComparison.OrdinalIgnoreCase)) return true;
        if (wide.Length == 0 || narrow.Length == 0 || (narrow.Contains('*') && !WindowsComponents.IsComponent(wide))) return false;
        if (WindowsComponents.IsComponent(wide)) return WindowsComponents.Of(narrow) == wide;
        if (WindowsComponents.IsComponent(narrow)) return false;
        var nameOnly = wide.IndexOfAny(['\\', '/']) < 0;
        if (nameOnly && wide.Equals(Rule.KernelProcess, StringComparison.OrdinalIgnoreCase)) return false;
        var subject = nameOnly ? Rule.NameOf(narrow) : narrow;
        return RuleSet.ProcessGlob(wide) is { } glob ? glob.IsMatch(subject) : nameOnly && subject.Equals(wide, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Könnte eine Regel mit <paramref name="o"/> als Prozess für dasselbe Programm gelten wie <paramref name="n"/>? Großzügig
    /// geschätzt über den Dateinamen: verschiedene Dateinamen schließen sich aus, ein Muster im Dateinamen nur, wenn es nicht passt.</summary>
    private static bool ProcessMayOverlap(Rule o, Rule n)
    {
        if (o.AnyProcess || n.AnyProcess || WindowsComponents.IsComponent(o.Process) || WindowsComponents.IsComponent(n.Process)) return true;
        string a = Rule.NameOf(o.Process), b = Rule.NameOf(n.Process);
        if (a.Contains('*') && b.Contains('*')) return true;
        if (a.Contains('*')) return RuleSet.ProcessGlob(a)!.IsMatch(b);
        if (b.Contains('*')) return RuleSet.ProcessGlob(b)!.IsMatch(a);
        return a.Equals(b, StringComparison.OrdinalIgnoreCase);
    }

    private static bool RemoteCovers(Rule w, Rule n)
    {
        if (w.Remote == RemoteKind.Any) return true;
        if (w.Remote != n.Remote)
            return w.Remote == RemoteKind.Domains && n.Remote == RemoteKind.Hosts && n.Targets.Count > 0
                   && n.Targets.All(h => !IpKey.TryParse(Norm(h), out _) && w.Targets.Any(d => RuleSet.DomainMatches(Norm(h), Norm(d))));
        return w.Remote switch
        {
            RemoteKind.LocalNet or RemoteKind.DnsServers => true,
            RemoteKind.Domains => n.Targets.All(t => w.Targets.Any(d => RuleSet.DomainMatches(Norm(t), Norm(d)))),
            _ => n.Targets.All(t => w.Targets.Any(x => Norm(x) == Norm(t))),
        };
    }

    private static bool Outlives(Rule w, Rule n) => w.Lifetime switch
    {
        LifetimeKind.Forever => true,
        LifetimeKind.Timed => n.Lifetime == LifetimeKind.Timed && n.Expires <= w.Expires,
        LifetimeKind.UntilRestart => n.Lifetime == LifetimeKind.UntilRestart && n.BootId == w.BootId,
        _ => n.Lifetime == LifetimeKind.UntilQuit && n.QuitPid == w.QuitPid,
    };

    /// <summary>Nimmt die Regel Verbindungen von Blocklisten aus? (wie in <see cref="RuleSet.Evaluate"/>, „DNS-Server“ vorsichtshalber nicht)</summary>
    private static bool Exempts(Rule r) => r.Action == RuleAction.Allow && (r.HighPriority || r.Remote is RemoteKind.Addresses or RemoteKind.Domains or RemoteKind.Hosts);

    /// <summary>Macht <paramref name="w"/> die Regel <paramref name="n"/> überflüssig? Das gilt, wenn w dieselbe Aktion hat, mindestens
    /// dieselben Verbindungen erfasst, mindestens so lange gilt und nach dem Entfernen von n keine Regel mit der Gegen-Aktion an ihre
    /// Stelle treten kann (keine liegt in der Rangfolge zwischen w und n). Dann entscheidet SnitchBox ohne n genau wie mit ihr.</summary>
    public static bool MakesRedundant(Rule w, Rule n, IReadOnlyList<Rule> all)
    {
        if (ReferenceEquals(w, n) || w.Id == n.Id || !w.Enabled || !n.Enabled || w.Factory || n.Factory) return false;
        if (w.Action != n.Action || w.Direction != n.Direction || (w.Profile != null && w.Profile != n.Profile)) return false;
        if (w.Protocol != Proto.Any && w.Protocol != n.Protocol) return false;
        if (!PortSet.TryParse(w.Ports, out var wp) || !PortSet.TryParse(n.Ports, out var np) || (!wp.Any && !wp.SameAs(np))) return false;
        if (!ProcessCovers(w.Process, n.Process) || !RemoteCovers(w, n) || !Outlives(w, n)) return false;
        if (Exempts(n) && !Exempts(w)) return false; // n hielte eine Blockliste fern, w nicht
        int sw = RuleSet.Score(w, wp), sn = RuleSet.Score(n, np);
        if (sw > sn) return true; // w schlägt n ohnehin überall, wo n gilt
        foreach (var o in all)
        {
            if (!o.Enabled || o.Action == n.Action || o.Direction != n.Direction || !ProcessMayOverlap(o, n)) continue;
            if (!PortSet.TryParse(o.Ports, out var op)) continue;
            var so = RuleSet.Score(o, op);
            if (so > sw && so < sn) return false;
        }
        return true;
    }

    /// <summary>Nimmt eine neue Regel auf: passt sie zu einer bestehenden gleicher Art (nur andere Gegenstellen), kommen ihre
    /// Gegenstellen dorthin; danach entfallen eigene Regeln, die die stehende Regel überflüssig macht. Liefert die stehende Regel.</summary>
    public static Rule Absorb(List<Rule> rules, Rule added)
    {
        Rule standing;
        var host = rules.FindIndex(r => r.Id != added.Id && Mergeable(r, added));
        if (host >= 0)
        {
            standing = Merge(rules[host], added);
            rules[host] = standing; // Kopie statt Änderung: die alte Regel steckt noch im bisherigen Regelstand
            rules.RemoveAll(r => r.Id == added.Id);
        }
        else
        {
            if (!rules.Any(r => r.Id == added.Id)) rules.Add(added);
            standing = added;
        }
        var snapshot = rules.ToList();
        rules.RemoveAll(n => MakesRedundant(standing, n, snapshot));
        return standing;
    }

    /// <summary>Plan zum Aufräumen der ganzen Liste: Programme in Temp-Ordnern verallgemeinern (<see cref="AlertRules.ProcessPattern"/>),
    /// Regeln für nicht mehr vorhandene Programme (<paramref name="vanished"/>, volle Pfade) entfernen, überflüssige Regeln entfernen,
    /// gleichartige zusammenfassen. Werksregeln bleiben unberührt.</summary>
    public static CleanupPlan Plan(IReadOnlyList<Rule> rules, ISet<string> vanished)
    {
        var list = rules.Select(r => r.Clone()).ToList();
        var generalized = 0;
        foreach (var r in list)
        {
            if (r.Factory) continue;
            var p = AlertRules.ProcessPattern(r.Process);
            if (p != r.Process) { r.Process = p; generalized++; }
        }
        var gone = list.RemoveAll(r => !r.Factory && r.Process.Length > 0 && vanished.Contains(r.Process));
        var redundant = 0;
        for (var i = 0; i < list.Count; i++)
        {
            var n = list[i];
            if (!list.Any(w => !ReferenceEquals(w, n) && MakesRedundant(w, n, list))) continue;
            list.RemoveAt(i--);
            redundant++;
        }
        int mergedFrom = 0, mergedInto = 0;
        for (var i = 0; i < list.Count; i++)
        {
            var a = list[i];
            var joined = 0;
            for (var j = i + 1; j < list.Count; j++)
            {
                if (!Mergeable(a, list[j])) continue;
                a = Merge(a, list[j]);
                list.RemoveAt(j--);
                joined++;
            }
            if (joined == 0) continue;
            list[i] = a;
            mergedFrom += joined + 1;
            mergedInto++;
        }
        return new CleanupPlan(list, rules.Count, generalized, gone, redundant, mergedFrom, mergedInto);
    }
}
