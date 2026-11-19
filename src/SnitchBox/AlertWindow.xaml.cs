using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Warnfenster: ein Programm will eine Verbindung, für die es noch keine Regel gibt.
/// Die Verbindung bleibt angehalten, bis hier entschieden ist.</summary>
public partial class AlertWindow : Window
{
    // Die zuletzt gewählte Dauer und Reichweite gelten als Vorschlag für die nächste Nachfrage.
    private static AlertLifetime _lastLifetime = AlertLifetime.Forever;
    private static AlertScope _lastScope = AlertScope.AnyConnection;

    private readonly List<(AlertScope Scope, RadioButton Button)> _scopes = [];
    private readonly bool _remember;
    private bool _silent;

    internal PendingAlert Alert { get; }

    internal AlertWindow(PendingAlert alert, int waiting)
    {
        InitializeComponent();
        Alert = alert;
        var c = alert.Connection;
        Title = Loc.T("Verbindungswarnung – ", "Connection Alert – ") + "SnitchBox";
        if (Ui.AppIcon() is { } icon) Icon = icon;
        IconImage.Source = Ui.IconFor(c.ProcessPath, false);

        var info = Native.InfoOf(c.ProcessPath);
        NameText.Text = info.Title.Length > 0 ? info.Title : c.ProcessName;
        if (WindowsComponents.Of(c.ProcessPath) is { } component)
        {
            NameText.Text = WindowsComponents.Title(component) + " · " + c.ProcessName;
            ComponentHint.Text = "ⓘ " + (component == WindowsComponents.Update
                ? Loc.T("Teil von Windows: Verbietest du das, bekommt Windows keine Updates mehr.", "Part of Windows: if you deny this, Windows no longer gets updates.")
                : Loc.T("Teil von Windows: Verbietest du das, bekommt der Virenschutz keine neuen Signaturen und keinen Cloud-Schutz mehr.",
                        "Part of Windows: if you deny this, virus protection no longer gets new signatures or cloud protection."));
            ComponentHint.Visibility = Visibility.Visible;
        }
        else if (KnownApps.Of(c.ProcessPath) is { } app)
        {
            // Bekannte App: Name und Rolle statt „updater.exe“; ob die Datei wirklich vom Hersteller stammt, zeigt die Signaturzeile.
            NameText.Text = app.Label(c.ProcessPath);
            var hint = app.Role switch
            {
                AppRole.Updater => Loc.F("Updater von {0}: Verbietest du das, bekommt {0} keine Updates mehr – auch keine Sicherheitsupdates.",
                                         "Updater of {0}: if you deny this, {0} no longer gets updates – including security updates.", app.App.Title),
                AppRole.Helper => Loc.F("Hilfsprogramm von {0}.", "Helper program of {0}.", app.App.Title),
                _ => null,
            };
            if (hint != null)
            {
                ComponentHint.Text = "ⓘ " + hint;
                ComponentHint.Visibility = Visibility.Visible;
            }
        }
        var port =$"{c.Port} ({(c.Protocol == Proto.Tcp ? "TCP" : "UDP")})";
        // Der Satz nennt die Gegenstelle fett, damit das Wichtigste sofort ins Auge fällt.
        var (before, after) = c.Direction == Direction.Outgoing
            ? (Loc.T("möchte sich mit ", "wants to connect to "), Loc.F(" auf Port {0} verbinden", " on port {0}", port))
            : (Loc.T("möchte eine eingehende Verbindung von ", "wants to accept an incoming connection from "), Loc.F(" auf Port {0} annehmen", " on port {0}", port));
        SummaryText.Inlines.Add(new Run(before));
        SummaryText.Inlines.Add(new Run(c.Host) { FontWeight = FontWeights.Bold });
        SummaryText.Inlines.Add(new Run(after));

        AddressText.Text = c.Remote + (AddressRange.IsLocal(c.Remote) ? Loc.T("  (lokales Netz)", "  (local network)") : "")
                           + (c.Hostnames.Count == 0 ? Loc.T("  – kein Name bekannt", "  – no name known") : "");
        PathText.Text = (c.ProcessPath.Length > 0 ? c.ProcessPath : Loc.T("unbekannt", "unknown")) + (c.Service.Length > 0 ? " · " + c.Service : "")
                        + (c.Pid > 0 ? $"  (PID {c.Pid})" : "");
        if (c.Service.Length > 0) NameText.Text = Loc.F("Windows-Dienst: {0}", "Windows service: {0}", Rule.ServiceTitle(c.Service) ?? c.Service);
        PathText.ToolTip = c.ProcessPath;
        // Signatur mit Windows prüfen (bei Katalog-Signaturen einige zehn Millisekunden): nicht im Fenster-Aufbau, sondern danach.
        if (c.ProcessPath == Rule.KernelProcess) PublisherText.Text = "Microsoft Windows";
        else
        {
            PublisherText.Text = Loc.T("Signatur wird geprüft …", "Checking signature…");
            var path = c.ProcessPath;
            Task.Run(() => Signature.Check(path)).ContinueWith(t => Dispatcher.BeginInvoke(() => ShowSignature(t.Result, info.Publisher)), TaskScheduler.Default);
        }
        if (c.Hostnames.Count > 1) NamesText.Text = string.Join(", ", c.Hostnames.Skip(1));
        else NamesLabel.Visibility = NamesText.Visibility = Visibility.Collapsed;

        foreach (var l in Enum.GetValues<AlertLifetime>()) LifetimeBox.Items.Add(AlertRules.Title(l));
        LifetimeBox.SelectedIndex = (int)_lastLifetime;

        var outgoing = c.Direction == Direction.Outgoing;
        var domain = c.Hostnames.Count > 0 ? AlertRules.DomainOf(c.Hostnames[0]) : "";
        AddScope(AlertScope.AnyConnection, Loc.T("Jede Verbindung", "Any connection"));
        AddScope(AlertScope.Port, Loc.F("Nur Port {0}", "Only port {0}", port));
        if (domain.Length > 0 && !domain.Equals(c.Host, StringComparison.OrdinalIgnoreCase))
        {
            AddScope(AlertScope.Domain, outgoing ? Loc.F("Nur Domain {0}", "Only domain {0}", domain) : Loc.F("Nur von Domain {0}", "Only from domain {0}", domain));
            AddScope(AlertScope.DomainAndPort, outgoing ? Loc.F("Nur Domain {0} und Port {1}", "Only domain {0} and port {1}", domain, port)
                                                         : Loc.F("Nur von Domain {0} und Port {1}", "Only from domain {0} and port {1}", domain, port));
        }
        AddScope(AlertScope.Host, outgoing ? Loc.F("Nur {0}", "Only {0}", c.Host) : Loc.F("Nur von {0}", "Only from {0}", c.Host));
        AddScope(AlertScope.HostAndPort, outgoing ? Loc.F("Nur {0} und Port {1}", "Only {0} and port {1}", c.Host, port)
                                                  : Loc.F("Nur von {0} und Port {1}", "Only from {0} and port {1}", c.Host, port));
        (_scopes.FirstOrDefault(s => s.Scope == _lastScope).Button ?? _scopes[0].Button).IsChecked = true;

        // Ohne bekanntes Programm gälte eine gemerkte Regel für jedes Programm: dann nur für diesen einen Versuch.
        _remember = AlertRules.CanRemember(c);
        if (!_remember)
        {
            ScopePanel.IsEnabled = false;
            LifetimeBox.SelectedIndex = (int)AlertLifetime.Once;
            LifetimeBox.IsEnabled = false;
            UnknownHint.Text = Loc.T("Das Programm ließ sich nicht ermitteln. Die Entscheidung gilt deshalb nur für diesen Versuch – eine Regel ohne Programm würde für alle Programme gelten.",
                                     "The program could not be determined, so the decision applies to this attempt only – a rule without a program would apply to every program.");
            UnknownHint.Visibility = Visibility.Visible;
        }

        SetWaiting(waiting);
        var area = SystemParameters.WorkArea;
        Left = area.Right - Width - 24;
        Top = area.Top + 24;
    }

    /// <summary>Ergebnis der Signaturprüfung in der Zeile „Herausgeber“: grün bei gültiger Signatur, rot bei ungültiger
    /// (Datei verändert oder Zertifikat nicht vertrauenswürdig).</summary>
    private void ShowSignature(SignatureInfo sig, string readPublisher)
    {
        switch (sig.State)
        {
            case SignatureState.Valid:
                var signer = sig.Signer.Length > 0 ? sig.Signer : readPublisher;
                PublisherText.Text = "✓ " + signer + " – " + Loc.T("Signatur gültig", "valid signature")
                                     + (sig.Catalog ? " (" + Loc.T("Windows-Katalog", "Windows catalog") + ")" : "");
                PublisherText.Foreground = Ui.Allow;
                break;
            case SignatureState.Invalid:
                PublisherText.Text = "⚠ " + Loc.T("Signatur ungültig – die Datei wurde verändert oder das Zertifikat ist nicht vertrauenswürdig",
                                                  "Invalid signature – the file was modified or the certificate is not trusted") + $" (0x{sig.Code:X8})";
                PublisherText.Foreground = Ui.Deny;
                PublisherText.FontWeight = FontWeights.SemiBold;
                break;
            case SignatureState.Unsigned:
                PublisherText.Text = Loc.T("nicht signiert", "not signed");
                break;
            default:
                PublisherText.Text = Loc.T("nicht prüfbar", "could not be checked");
                break;
        }
        PublisherText.ToolTip = PublisherText.Text;
    }

    private void AddScope(AlertScope scope, string text)
    {
        var b = new RadioButton { Content = text, GroupName = "scope", Margin = new Thickness(2, 1, 0, 1) };
        _scopes.Add((scope, b));
        ScopePanel.Children.Add(b);
    }

    internal void SetWaiting(int waiting) =>
        WaitingText.Text = waiting <= 0 ? "" : waiting == 1
            ? Loc.T("1 weitere Nachfrage wartet", "1 more alert waiting")
            : Loc.F("{0} weitere Nachfragen warten", "{0} more alerts waiting", waiting);

    private void Decide(bool allow)
    {
        var lifetime = (AlertLifetime)Math.Max(0, LifetimeBox.SelectedIndex);
        var scope = _scopes.FirstOrDefault(s => s.Button.IsChecked == true).Scope;
        if (_remember)
        {
            // Nur echte Wahlen dienen als Vorschlag für die nächste Nachfrage (nicht das erzwungene „Einmal“).
            _lastLifetime = lifetime;
            _lastScope = scope;
        }
        // Regeln aus dem Warnfenster gelten in allen Profilen; ein Profil lässt sich in der Regelliste zuweisen.
        var rule = AlertRules.Create(Alert.Connection, allow, scope, lifetime, App.Engine.BootId, null, DateTime.Now);
        _silent = true;
        Close();
        App.Engine.Resolve(Alert.Id, allow, rule);
    }

    private void Allow_Click(object sender, RoutedEventArgs e) => Decide(true);
    private void Deny_Click(object sender, RoutedEventArgs e) => Decide(false);

    /// <summary>Schließen ohne Entscheidung (die Nachfrage hat sich anders erledigt).</summary>
    internal void CloseSilently()
    {
        _silent = true;
        if (!_closed) Close();
    }

    private bool _closed;

    protected override void OnClosed(EventArgs e)
    {
        _closed = true;
        base.OnClosed(e);
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        base.OnClosing(e);
        // Fenster weggeklickt: diesen einen Versuch ablehnen, ohne Regel.
        if (!_silent) Dispatcher.BeginInvoke(() => App.Engine.Resolve(Alert.Id, false, null));
    }
}
