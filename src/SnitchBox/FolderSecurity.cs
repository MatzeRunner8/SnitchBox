using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Der Datenordner ließ sich nicht sicher herrichten; SnitchBox startet dann nicht.</summary>
internal sealed class UnsafeDataDirException(string dir, Exception? inner)
    : Exception(Loc.F("Der Datenordner {0} ließ sich nicht absichern, deshalb startet SnitchBox nicht.\n\n" +
                      "Möglicherweise hält ein anderes Programm Dateien darin offen oder hat ihn vorbereitet. Ursache: {1}",
                      "The data folder {0} could not be secured, so SnitchBox does not start.\n\n" +
                      "Another program may be holding files in it open or may have prepared it. Cause: {1}", dir, inner?.Message ?? "?"), inner);

/// <summary>Zugriffsrechte rund um SnitchBox. Das Programm läuft mit Administratorrechten; alles, was es liest oder startet,
/// darf daher nur von Administratoren änderbar sein – sonst könnte ein gewöhnliches Programm über SnitchBox an
/// Administratorrechte kommen oder die Firewall-Regeln umschreiben.</summary>
internal static class FolderSecurity
{
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);
    private static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>Richtet %ProgramData%\SnitchBox so her, dass nur SYSTEM und Administratoren schreiben dürfen (Benutzer lesen).
    /// Der Ordner erbt sonst von %ProgramData% „Benutzer dürfen Dateien anlegen“; ein gewöhnliches Programm könnte z. B.
    /// config.json.tmp vorab anlegen (die beim Speichern zu config.json wird) oder den Ordner vor dem ersten Start als
    /// Verknüpfung anlegen. Fremdes wird deshalb nicht an Ort und Stelle übernommen (geöffnete Handles behielten ihre
    /// Rechte) und auch nicht rekursiv gelöscht (der Angreifer könnte währenddessen Unterordner gegen Verknüpfungen tauschen),
    /// sondern ohne Rekursion beiseitegeschoben; Verknüpfungen werden selbst entfernt. Gelingt etwas nicht, bricht der Start
    /// ab (<see cref="UnsafeDataDirException"/>). Bis zum Erfolg schreibt auch das Protokoll nichts in den Ordner.</summary>
    public static void HardenDataDir(string dir)
    {
        var notes = new List<string>();
        Log.Enabled = false;
        try
        {
            var root = new DirectoryInfo(dir);
            var aside = dir + ".unsicher-" + Guid.NewGuid().ToString("N")[..8];
            if (File.Exists(dir))
            {
                // Eine Datei an Stelle des Ordners: beiseiteschieben, sonst scheiterte jeder Start.
                File.Move(dir, aside);
                notes.Add($"An Stelle des Datenordners lag eine Datei; beiseitegeschoben nach {aside}");
            }
            else if (root.Exists && (root.Attributes.HasFlag(FileAttributes.ReparsePoint) || !IsTrustedOwner(root)))
            {
                // Verknüpfung oder fremder Ordner: umbenennen (bei einer Verknüpfung nur die Verknüpfung, nicht ihr Ziel).
                Directory.Move(dir, aside);
                notes.Add($"Datenordner war eine Verknüpfung oder gehörte nicht den Administratoren; beiseitegeschoben nach {aside}");
            }
            var secure = SecureDescriptor();
            if (!Directory.Exists(dir)) secure.CreateDirectory(dir); // gleich mit den richtigen Rechten anlegen
            root = new DirectoryInfo(dir);
            if (root.Attributes.HasFlag(FileAttributes.ReparsePoint) || !IsTrustedOwner(root))
                throw new InvalidOperationException(Loc.T("Der Ordner wurde gerade von jemand anderem angelegt.", "The folder was just created by someone else."));
            root.SetAccessControl(secure);
            CleanTree(root, notes);
            root.SetAccessControl(secure); // reicht die Rechte an alles darunter weiter
            // Unterordner für den Verlauf des Netzwerkmonitors: erst jetzt (Ordner geprüft und aufgeräumt), nur SYSTEM und Administratoren lesen.
            // Scheitert das, startet SnitchBox trotzdem (der Verlauf ist eine Zugabe) – vor jedem Schreiben wird erneut geprüft.
            try { EnsurePrivateDir(Path.Combine(dir, PrivateName)); }
            catch (Exception e) { notes.Add("Ordner für den Verlauf: " + e.Message); }
        }
        catch (Exception e)
        {
            throw new UnsafeDataDirException(dir, e);
        }
        Log.Enabled = true;
        foreach (var n in notes) Log.Write(n);
    }

    /// <summary>Name der Unterordner, die nur SYSTEM und Administratoren lesen dürfen (Verlauf: welches Programm wohin verbunden hat).</summary>
    public const string PrivateName = "private";

    /// <summary>Vor jedem Schreiben des Verlaufs (und beim Start): Fehlt der Ordner, wird er gleich mit den strengen Rechten angelegt – sonst
    /// erbte er „Benutzer lesen“ vom Datenordner (etwa wenn ein Administrator ihn bei laufendem SnitchBox löscht). Hat er die Rechte
    /// verloren, bekommt er sie zurück; eine Verknüpfung oder ein fremder Eigentümer: nichts schreiben.</summary>
    public static void EnsurePrivateDir(string dir)
    {
        var info = new DirectoryInfo(dir);
        if (!info.Exists)
        {
            if (File.Exists(dir)) throw new IOException($"{dir}: an Stelle des Ordners liegt eine Datei");
            Directory.CreateDirectory(Path.GetDirectoryName(dir)!); // Datenordner (im Demo-Modus „demo“) mit seinen Rechten
            PrivateDescriptor().CreateDirectory(dir); // tut nichts, falls ihn gerade jemand anders angelegt hat – deshalb unten prüfen
            info.Refresh();
        }
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint) || !IsTrustedOwner(info))
            throw new IOException($"{dir}: Verknüpfung oder fremder Eigentümer");
        var acl = info.GetAccessControl();
        var strict = acl.AreAccessRulesProtected && acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .All(r => r.AccessControlType == AccessControlType.Deny || r.IdentityReference.Equals(SystemSid) || r.IdentityReference.Equals(Admins));
        if (!strict) info.SetAccessControl(PrivateDescriptor());
    }

    private static DirectorySecurity PrivateDescriptor()
    {
        var sec = new DirectorySecurity();
        sec.SetOwner(Admins);
        sec.SetAccessRuleProtection(true, false);
        const InheritanceFlags all = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        return sec;
    }

    private static DirectorySecurity SecureDescriptor()
    {
        var sec = new DirectorySecurity();
        sec.SetOwner(Admins);
        sec.SetAccessRuleProtection(true, false);
        const InheritanceFlags all = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, all, PropagationFlags.None, AccessControlType.Allow));
        return sec;
    }

    /// <summary>Eigene Einträge (Eigentümer Administratoren) behalten nur die geerbten Rechte. Verknüpfungen, Einträge fremder
    /// Eigentümer und Namen mit Punkt oder Leerzeichen am Ende (legt SnitchBox nie an; Windows schnitte sie bei normalen
    /// Pfaden ab und träfe dann womöglich die echte Nachbardatei) kommen weg – SnitchBox legt alles selbst mit
    /// Administratorrechten an.</summary>
    private static void CleanTree(DirectoryInfo root, List<string> notes)
    {
        var asideDir = Path.GetDirectoryName(root.FullName)!;
        var pending = new Stack<DirectoryInfo>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            foreach (var item in pending.Pop().EnumerateFileSystemInfos())
            {
                try
                {
                    if (item.Attributes.HasFlag(FileAttributes.ReparsePoint) || item.Name.EndsWith('.') || item.Name.EndsWith(' ') || !IsTrustedOwner(item))
                    {
                        RemoveForeign(item, asideDir, notes);
                        continue;
                    }
                    // Ein Ordner „private“ bekommt die strengeren Rechte (ohne Benutzer); sein Inhalt erbt sie.
                    if (item is DirectoryInfo { Name: PrivateName } priv) priv.SetAccessControl(PrivateDescriptor());
                    else ResetToInherited(item);
                    if (item is DirectoryInfo d) pending.Push(d);
                }
                catch (Exception e)
                {
                    // Den betroffenen Eintrag nennen: das Protokoll ist bis zum Erfolg aus, die Meldung ist der einzige Hinweis.
                    throw new IOException($"{item.FullName}: {e.Message}", e);
                }
            }
        }
    }

    /// <summary>Entfernt einen fremden Eintrag aus dem Datenordner, ohne in ihn abzusteigen: eine Verknüpfung wird selbst
    /// gelöscht (ihrem Ziel wird nie gefolgt), alles andere samt Inhalt unter einem Zufallsnamen nach %ProgramData%
    /// verschoben (Umbenennen folgt keinen Verknüpfungen). Alle Zugriffe über „\\?\“, damit Windows Punkte und Leerzeichen
    /// am Namensende nicht abschneidet; danach wird geprüft, dass der Name wirklich frei ist.</summary>
    private static void RemoveForeign(FileSystemInfo item, string asideDir, List<string> notes)
    {
        var source = Extended(item.FullName);
        var isDir = item is DirectoryInfo;
        if (item.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            if (isDir) Directory.Delete(source, false);
            else File.Delete(source);
            notes.Add("Verknüpfung im Datenordner entfernt: " + item.FullName);
        }
        else
        {
            var name = item.Name.TrimEnd('.', ' ');
            var target = Path.Combine(asideDir, "SnitchBox.unsicher-" + Guid.NewGuid().ToString("N")[..8] + "-" + (name.Length > 0 ? name[..Math.Min(name.Length, 150)] : "_"));
            if (isDir) Directory.Move(source, Extended(target));
            else File.Move(source, Extended(target));
            notes.Add($"Fremder Eintrag aus dem Datenordner verschoben: {item.FullName} → {target}");
        }
        if (File.Exists(source) || Directory.Exists(source))
            throw new IOException(Loc.T("Der fremde Eintrag ließ sich nicht entfernen.", "The foreign entry could not be removed."));
    }

    private static string Extended(string path) => path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path : @"\\?\" + path;

    private static bool IsTrusted(SecurityIdentifier? sid) => sid != null && (sid == Admins || sid == SystemSid || sid == TrustedInstaller);

    /// <summary>Gehört der Eintrag Administratoren, SYSTEM oder TrustedInstaller? Lässt sich der Eigentümer nicht lesen, gilt er als fremd.</summary>
    private static bool IsTrustedOwner(FileSystemInfo item)
    {
        try { return IsTrusted(OwnerOf(item)); }
        catch { return false; }
    }

    private static FileSystemSecurity SecurityOf(FileSystemInfo item, AccessControlSections sections) =>
        item is DirectoryInfo d ? d.GetAccessControl(sections) : ((FileInfo)item).GetAccessControl(sections);

    private static SecurityIdentifier? OwnerOf(FileSystemInfo item) =>
        SecurityOf(item, AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;

    /// <summary>Eigene Regeln eines Eintrags entfernen; danach gelten nur die vom Ordner geerbten.</summary>
    private static void ResetToInherited(FileSystemInfo item)
    {
        var s = SecurityOf(item, AccessControlSections.Access);
        var rules = s.GetAccessRules(true, false, typeof(SecurityIdentifier));
        if (rules.Count == 0 && !s.AreAccessRulesProtected) return;
        foreach (FileSystemAccessRule r in rules) s.RemoveAccessRuleSpecific(r);
        s.SetAccessRuleProtection(false, false);
        if (item is DirectoryInfo dir) dir.SetAccessControl((DirectorySecurity)s);
        else ((FileInfo)item).SetAccessControl((FileSecurity)s);
    }

    /// <summary>Wer außer Administratoren, SYSTEM und TrustedInstaller das Programm austauschen kann: die .exe (und DLLs
    /// daneben) beschreiben, im Ordner Dateien ablegen oder den Ordner samt Inhalt ersetzen (umbenennen und neu anlegen,
    /// auch über einen übergeordneten Ordner). Leer, wenn nur Administratoren. Mit Autostart startet die Datei bei jeder
    /// Anmeldung ohne Rückfrage mit Administratorrechten.</summary>
    public static List<string> WritersOtherThanAdmins(string exePath)
    {
        var result = new List<string>();
        try
        {
            const FileSystemRights fileRights = FileSystemRights.WriteData | FileSystemRights.AppendData
                                                | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            var exe = new FileInfo(exePath);
            var dir = exe.Directory!;
            result.AddRange(Grants(SecurityOf(exe, AccessControlSections.Access | AccessControlSections.Owner), fileRights));
            // Auch jede andere .exe im Ordner: Der Starter SnitchBoxStart.exe startet SnitchBox.exe aus seinem Ordner mit
            // Administratorrechten – ist das Ziel des Autostarts der Starter, muss auch SnitchBox.exe geschützt sein.
            foreach (var file in dir.EnumerateFiles("*.dll").Concat(dir.EnumerateFiles("*.exe")))
                result.AddRange(Grants(SecurityOf(file, AccessControlSections.Access | AccessControlSections.Owner), fileRights));
            result.AddRange(Grants(SecurityOf(dir, AccessControlSections.Access | AccessControlSections.Owner),
                FileSystemRights.CreateFiles | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership));
            // Ordner ersetzen: ihn (oder einen übergeordneten) umbenennen und unter altem Namen neu anlegen.
            for (var d = dir; d.Parent != null; d = d.Parent)
            {
                var parent = SecurityOf(d.Parent, AccessControlSections.Access | AccessControlSections.Owner);
                var create = Grants(parent, FileSystemRights.CreateDirectories | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);
                if (create.Count == 0) continue;
                var remove = Grants(parent, FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)
                    .Concat(Grants(SecurityOf(d, AccessControlSections.Access | AccessControlSections.Owner), FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership))
                    .ToList();
                // Verschiedene Gruppen zählen zusammen: der angemeldete Benutzer gehört praktisch allen nicht vertrauenswürdigen an.
                if (remove.Count > 0) result.AddRange(create.Concat(remove));
            }
        }
        catch (Exception e) { Log.Write("Rechte des Programmordners: " + e.Message); }
        return result.Distinct().ToList();
    }

    /// <summary>Konten außer den vertrauenswürdigen, denen eines der Rechte zusteht; ein fremder Eigentümer zählt immer
    /// (er darf sich jedes Recht selbst geben). Nur vererbbare Einträge (für Unterobjekte) und ERSTELLER-BESITZER zählen nicht.</summary>
    private static List<string> Grants(FileSystemSecurity sec, FileSystemRights rights)
    {
        const int genericWrite = 0x40000000, genericAll = 0x10000000;
        var found = new List<string>();
        if (sec.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && !IsTrusted(owner)) found.Add(Name(owner));
        foreach (FileSystemAccessRule r in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (r.AccessControlType != AccessControlType.Allow || r.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue;
            if (r.IdentityReference is not SecurityIdentifier sid || IsTrusted(sid) || sid == CreatorOwner) continue;
            if ((r.FileSystemRights & rights) != 0 || ((int)r.FileSystemRights & (genericWrite | genericAll)) != 0) found.Add(Name(sid));
        }
        return found;
    }

    private static string Name(SecurityIdentifier sid)
    {
        try { return sid.Translate(typeof(NTAccount)).Value; }
        catch { return sid.Value; }
    }
}
