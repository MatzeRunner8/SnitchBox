using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Regel anlegen oder ändern. <see cref="Result"/> ist eine Kopie; die Vorlage bleibt bis zum Sichern unberührt.</summary>
public partial class RuleEditorWindow : Window
{
    private static readonly AlertLifetime[] Lifetimes =
    [
        AlertLifetime.Forever, AlertLifetime.UntilRestart, AlertLifetime.Minutes10, AlertLifetime.Hours2,
        AlertLifetime.Day1, AlertLifetime.Days7, AlertLifetime.Days30,
    ];

    private readonly Rule _source;
    internal Rule Result { get; private set; }

    internal RuleEditorWindow(Rule rule, bool isNew)
    {
        InitializeComponent();
        _source = rule;
        Result = rule;
        Title = isNew ? Loc.T("Neue Regel", "New Rule") : Loc.T("Regel bearbeiten", "Edit Rule");
        if (Ui.AppIcon() is { } icon) Icon = icon;

        AllowRadio.IsChecked = rule.Action == RuleAction.Allow;
        DenyRadio.IsChecked = rule.Action == RuleAction.Deny;
        ProcessBox.Text = rule.Process;
        ServiceBox.Text = rule.Service;
        ProcessBox.ToolTip = Loc.T("Voller Pfad der .exe, nur ein Dateiname wie chrome.exe, oder leer für jedes Programm. * steht für einen beliebigen Teil eines Ordner- oder Dateinamens, z. B. C:\\Temp\\*\\setup.exe",
                                   "Full path of the .exe, just a file name like chrome.exe, or empty for any program. * stands for any part of a folder or file name, e.g. C:\\Temp\\*\\setup.exe");
        DirectionBox.Items.Add(Loc.T("Ausgehende Verbindungen", "Outgoing connections"));
        DirectionBox.Items.Add(Loc.T("Eingehende Verbindungen", "Incoming connections"));
        DirectionBox.SelectedIndex = (int)rule.Direction;
        foreach (var t in new[]
                 {
                     Loc.T("Jeder Server", "Any server"), Loc.T("Lokales Netzwerk", "Local network"), Loc.T("IP-Adressen", "IP addresses"),
                     Loc.T("Domains (mit Subdomains)", "Domains (with subdomains)"), Loc.T("Hostnamen", "Hostnames"),
                     Loc.T("DNS-Server des Systems", "System DNS servers"), // Position = RemoteKind
                 }) RemoteBox.Items.Add(t);
        TargetsBox.Text = string.Join(", ", rule.Targets);
        RemoteBox.SelectedIndex = (int)rule.Remote;
        PortsBox.Text = rule.Ports;
        ProtocolBox.Items.Add(Loc.T("TCP und UDP", "TCP and UDP"));
        ProtocolBox.Items.Add("TCP");
        ProtocolBox.Items.Add("UDP");
        ProtocolBox.SelectedIndex = (int)rule.Protocol;

        // Eine laufende Frist („bis 14:30“, „bis zum Beenden“) bleibt als eigener Eintrag erhalten.
        if (rule.Lifetime is LifetimeKind.Timed or LifetimeKind.UntilQuit) LifetimeBox.Items.Add(Loc.T("Unverändert: ", "Unchanged: ") + rule.DescribeLifetime());
        foreach (var l in Lifetimes) LifetimeBox.Items.Add(AlertRules.Title(l));
        LifetimeBox.SelectedIndex = rule.Lifetime == LifetimeKind.UntilRestart ? 1 : 0;

        ProfileBox.Items.Add(Loc.T("In allen Profilen", "In all profiles"));
        var profiles = App.Engine.Read(s => s.Settings.Profiles.ToList());
        foreach (var p in profiles) ProfileBox.Items.Add(p);
        ProfileBox.SelectedIndex = rule.Profile == null ? 0 : Math.Max(0, profiles.IndexOf(rule.Profile) + 1);
        PriorityBox.IsChecked = rule.HighPriority;
        NotesBox.Text = rule.Notes;
    }

    private void RemoteBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var kind = (RemoteKind)Math.Max(0, RemoteBox.SelectedIndex);
        var needs = kind is RemoteKind.Addresses or RemoteKind.Domains or RemoteKind.Hosts;
        TargetsBox.IsEnabled = needs;
        TargetsLabel.Text = kind switch
        {
            RemoteKind.Addresses => Loc.T("Adressen", "Addresses"),
            RemoteKind.Domains => Loc.T("Domains", "Domains"),
            RemoteKind.Hosts => Loc.T("Hostnamen", "Hostnames"),
            _ => "",
        };
        TargetsBox.ToolTip = kind == RemoteKind.Addresses
            ? Loc.T("Zum Beispiel 203.0.113.7, 10.0.0.0/8 oder 192.168.1.1-192.168.1.50; mehrere durch Komma trennen", "For example 203.0.113.7, 10.0.0.0/8 or 192.168.1.1-192.168.1.50; separate several with commas")
            : Loc.T("Mehrere Einträge durch Komma trennen", "Separate several entries with commas");
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = Loc.T("Programm wählen", "Choose Program"), Filter = Loc.T("Programme", "Programs") + "|*.exe|" + Loc.T("Alle Dateien", "All files") + "|*.*" };
        if (dialog.ShowDialog(this) == true) ProcessBox.Text = dialog.FileName;
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        void Fail(string text, Control focus)
        {
            MessageBox.Show(this, text, Title, MessageBoxButton.OK, MessageBoxImage.Warning);
            focus.Focus();
        }

        var remote = (RemoteKind)Math.Max(0, RemoteBox.SelectedIndex);
        var needsTargets = remote is RemoteKind.Addresses or RemoteKind.Domains or RemoteKind.Hosts;
        var targets = !needsTargets
            ? []
            : TargetsBox.Text.Split([',', ';', '\n', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        if (needsTargets && targets.Count == 0)
        {
            Fail(Loc.T("Bitte mindestens eine Gegenstelle eintragen.", "Please enter at least one remote."), TargetsBox);
            return;
        }
        if (remote == RemoteKind.Addresses && targets.FirstOrDefault(t => !AddressRange.TryParse(t, out _)) is { } bad)
        {
            Fail(Loc.F("„{0}“ ist keine gültige Adresse oder kein gültiger Bereich.", "“{0}” is not a valid address or range.", bad), TargetsBox);
            return;
        }
        var service = ServiceBox.Text.Trim();
        var process = ProcessBox.Text.Trim().Trim('"');
        if (service.Length > 0 && process.Length > 0 && !Rule.NameOf(process).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            Fail(Loc.T("Einen Windows-Dienst gibt es nur bei svchost.exe. Trage dort svchost.exe ein (oder lass das Programm leer) – oder lass den Dienst leer.",
                       "Windows services only exist with svchost.exe. Enter svchost.exe as the program (or leave it empty) – or leave the service empty."), ServiceBox);
            return;
        }
        if (!PortSet.TryParse(PortsBox.Text, out _))
        {
            Fail(Loc.T("Die Portangabe ist ungültig. Beispiele: 443 · 80, 443 · 8000-8100", "The port entry is invalid. Examples: 443 · 80, 443 · 8000-8100"), PortsBox);
            return;
        }

        var r = _source.Clone();
        r.Action = AllowRadio.IsChecked == true ? RuleAction.Allow : RuleAction.Deny;
        r.Process = process;
        r.Service = service;
        r.Direction = (Direction)Math.Max(0, DirectionBox.SelectedIndex);
        r.Remote = remote;
        r.Targets = remote is RemoteKind.Domains or RemoteKind.Hosts ? targets.Select(t => t.TrimEnd('.').ToLowerInvariant()).ToList() : targets;
        r.Ports = PortsBox.Text.Trim();
        r.Protocol = (Proto)Math.Max(0, ProtocolBox.SelectedIndex);
        r.HighPriority = PriorityBox.IsChecked == true;
        r.Profile = ProfileBox.SelectedIndex <= 0 ? null : ProfileBox.SelectedItem as string;
        r.Notes = NotesBox.Text.Trim();

        var keeps = _source.Lifetime is LifetimeKind.Timed or LifetimeKind.UntilQuit;
        var index = LifetimeBox.SelectedIndex - (keeps ? 1 : 0);
        if (index >= 0)
        {
            var choice = Lifetimes[index];
            r.QuitPid = 0;
            r.BootId = null;
            r.Expires = null;
            switch (choice)
            {
                case AlertLifetime.Forever: r.Lifetime = LifetimeKind.Forever; break;
                case AlertLifetime.UntilRestart: r.Lifetime = LifetimeKind.UntilRestart; r.BootId = App.Engine.BootId; break;
                default:
                    r.Lifetime = LifetimeKind.Timed;
                    r.Expires = DateTime.Now + choice switch
                    {
                        AlertLifetime.Minutes10 => TimeSpan.FromMinutes(10),
                        AlertLifetime.Hours2 => TimeSpan.FromHours(2),
                        AlertLifetime.Day1 => TimeSpan.FromDays(1),
                        AlertLifetime.Days7 => TimeSpan.FromDays(7),
                        _ => TimeSpan.FromDays(30),
                    };
                    break;
            }
        }
        Result = r;
        DialogResult = true;
    }
}
