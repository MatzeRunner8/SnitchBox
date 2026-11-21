namespace SnitchBox.Core;

/// <summary>Bekannte Windows-Bestandteile, die als eigene Programme (nicht in svchost.exe) ins Netz gehen: Windows Update und der
/// Viren- &amp; Bedrohungsschutz (Microsoft Defender). Ihre Dateinamen sagen wenig („SIHClient.exe“, „MpCmdRun.exe“), wer sie verbietet,
/// verhindert leicht unbemerkt Updates oder neue Virensignaturen. Erkannt werden sie am Dateinamen und am Ort – nur in Ordnern, in die
/// allein Windows und Administratoren schreiben dürfen, sonst könnte sich jedes Programm per Dateiname als Windows Update ausgeben.
/// Eine Regel mit <see cref="Update"/> bzw. <see cref="Defender"/> als Prozess gilt für alle Programme des Bestandteils.</summary>
public static class WindowsComponents
{
    public const string Update = "@windows-update", Defender = "@defender";

    private static readonly HashSet<string> UpdateFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "MoUsoCoreWorker.exe", "SIHClient.exe", "WaaSMedicAgent.exe", "UsoClient.exe", "wuauclt.exe",
        "TiWorker.exe", "TrustedInstaller.exe", "MusNotification.exe", "MusNotificationUx.exe",
    };
    private static readonly HashSet<string> DefenderFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "MpDefenderCoreService.exe", "MpCopyAccelerator.exe",
        "MsSense.exe", "SenseCncProxy.exe",
    };

    // Windows Update: direkt in System32/SysWOW64 (deren Unterordner sind teils für alle beschreibbar) oder irgendwo unter
    // UUS, WinSxS, servicing, SoftwareDistribution. Defender: unter Platform\<Version>\ bzw. den Programmordnern.
    private static string[] _updateExact = [], _updateTrees = [], _defenderTrees = [];

    /// <summary>Orte festlegen (unter Windows beim Start aus den Systemordnern).</summary>
    public static void Configure(string windowsDir, string programFiles, string programFilesX86, string programData)
    {
        static string D(string p) => p.TrimEnd('\\') + "\\";
        var win = D(windowsDir);
        _updateExact = [win + @"System32\", win + @"SysWOW64\"];
        _updateTrees = [win + @"UUS\", win + @"WinSxS\", win + @"servicing\", win + @"SoftwareDistribution\"];
        _defenderTrees =
        [
            D(programData) + @"Microsoft\Windows Defender\Platform\", D(programFiles) + @"Windows Defender\",
            D(programFilesX86) + @"Windows Defender\", D(programFiles) + @"Windows Defender Advanced Threat Protection\",
        ];
    }

    public static bool IsComponent(string process) => process.StartsWith('@');

    /// <summary>Der Bestandteil, zu dem ein Programm (voller Pfad, auch ein Muster) gehört, sonst null.</summary>
    public static string? Of(string processPath)
    {
        if (processPath.Length == 0 || IsComponent(processPath) || processPath.Contains("..") || processPath.IndexOf('\\') < 0
            || processPath.IndexOf(':', 2) >= 0) return null; // alternativer Datenstrom („Ordner:datei.exe“) zählt nie
        var name = Rule.NameOf(processPath);
        var dir = processPath[..^name.Length];
        if (UpdateFiles.Contains(name)
            && (_updateExact.Any(d => dir.Equals(d, StringComparison.OrdinalIgnoreCase)) || _updateTrees.Any(d => dir.StartsWith(d, StringComparison.OrdinalIgnoreCase))))
            return Update;
        if (DefenderFiles.Contains(name) && _defenderTrees.Any(d => dir.StartsWith(d, StringComparison.OrdinalIgnoreCase)))
            return Defender;
        return null;
    }

    /// <summary>Name des Bestandteils, wie ihn die Windows-Sicherheit bzw. die Einstellungen zeigen.</summary>
    public static string Title(string component) => component switch
    {
        Update => "Windows Update",
        Defender => Loc.T("Viren- & Bedrohungsschutz", "Virus & threat protection"),
        _ => component,
    };

    /// <summary>Name des Bestandteils zu einer Prozessangabe (Bestandteil selbst oder eines seiner Programme), sonst null.</summary>
    public static string? TitleOf(string process) =>
        IsComponent(process) ? Title(process) : Of(process) is { } c ? Title(c) : null;
}
