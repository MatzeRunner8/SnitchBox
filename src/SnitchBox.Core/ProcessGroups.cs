namespace SnitchBox.Core;

/// <summary>Gruppen, nach denen Regelliste und Programmliste des Netzwerkmonitors sortiert und mit Überschriften getrennt werden;
/// die Reihenfolge hier ist die in den Listen.</summary>
public enum ProcessGroup { AllPrograms, AI, Browser, Office, Development, Vpn, Windows, Other }

/// <summary>Ordnet Programme einer Gruppe zu – aus der Erkennung bekannter Apps, der Windows-Bestandteile und Windows-Programme.
/// Nur Anzeige: Nichts wird ausgeblendet, und die Gruppierung lässt sich in den Einstellungen abschalten (Settings.GroupLists).</summary>
public static class ProcessGroups
{
    /// <summary>Gruppe eines Programms (voller Pfad oder Regel-Muster). <paramref name="emptyMeansAll"/>: leerer Pfad steht für
    /// „jeder Prozess“ (Regeln) statt für einen unbekannten Prozess (Netzwerkmonitor).</summary>
    public static ProcessGroup Of(string processPath, string service = "", bool emptyMeansAll = false)
    {
        if (service.Length > 0) return ProcessGroup.Windows; // Windows-Dienst, auch eine Dienst-Regel ohne Programm
        if (processPath.Length == 0) return emptyMeansAll ? ProcessGroup.AllPrograms : ProcessGroup.Other;
        if (processPath == Rule.KernelProcess || WindowsComponents.IsComponent(processPath)
            || WindowsComponents.Of(processPath) != null) return ProcessGroup.Windows;
        if (KnownApps.Of(processPath) is { } app) return app.App.Group;
        return WindowsProcesses.Of(processPath) != null ? ProcessGroup.Windows : ProcessGroup.Other;
    }

    /// <summary>Überschrift der Gruppe.</summary>
    public static string Title(ProcessGroup group) => group switch
    {
        ProcessGroup.AllPrograms => Loc.T("Alle Programme", "All Programs"),
        ProcessGroup.AI => Loc.T("KI", "AI"),
        ProcessGroup.Browser => Loc.T("Browser", "Browsers"),
        ProcessGroup.Office => Loc.T("Office und Kreativ", "Office and creative"),
        ProcessGroup.Development => Loc.T("Entwicklung", "Development"),
        ProcessGroup.Vpn => Loc.T("VPN und Sicherheit", "VPN and security"),
        ProcessGroup.Windows => "Windows",
        _ => Loc.T("Andere Programme", "Other programs"),
    };
}
