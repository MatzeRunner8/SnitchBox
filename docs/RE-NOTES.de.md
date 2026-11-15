# Befunde am Original und Technik-Entscheidungen

[English](RE-NOTES.md) · **Deutsch**

Vorlage: Little Snitch 6.5 (Build 7303), /Applications/Little Snitch.app. Untersucht mit REA (statisch) und den mitgelieferten Textdateien.
Es wurde kein Code und keine Grafik übernommen; übernommen sind Bedienkonzept und das offene .lsrules-Format.

## Aufbau des Originals (beobachtet)
- Hauptprogramm (Regeln/Einstellungen), dazu Components/: „Little Snitch Agent.app“ (Warnfenster, Menüleiste),
  „Little Snitch Network Monitor.app“, „Software Update.app“, Kommandozeile `littlesnitch`.
- Filter: Systemerweiterungen at.obdev.littlesnitch.networkextension und …endpointsecurity; Daemon in /Library/Application Support.
- Warnfenster (Agent, ConnectionAlert.strings): „… wants to connect to %host on %port“, Reichweiten „Any Connection“, „Only port“,
  „Only %host“, „Only %host and %port“, „domain %@“, „Only local network“; ein-/ausgehend getrennt.
- Gültigkeit (RuleLifetimeOption.strings): Once, Until Quit, Until Logout, Until Restart, 1 Minute, 10 Minutes, 2 Hours, 1 Day, 7 Days, 30 Days, Forever.
- Betriebsarten: Alert Mode, Silent Mode (allow/deny); Profile; Regelgruppen und Blocklisten mit Abo.
- Regel-Rangfolge laut Texten: hohe Priorität, genauere Regeln überdecken allgemeinere („redundant/overridden“).

## .lsrules (REA search_strings im Hauptprogramm, Evidence ev_abb2d20a…)
Schlüssel im Programm vorhanden: name, description, rules, action (allow/deny/ask), process, via, direction (incoming/outgoing),
priority, disabled, ports, protocol, remote (any, local-net, multicast, broadcast, bonjour, bpf), remote-hosts, remote-domains,
remote-addresses, notes, lifetime, creationDate/modificationDate, owner, denied-remote-domains/-hosts/-addresses/-notes.
SnitchBox liest und schreibt davon: action, process, direction, priority, disabled, ports, protocol, remote* (any, local-net, dns-servers;
multicast/broadcast/bonjour werden als local-net gelesen), notes, denied-remote-domains/-hosts.

## Umsetzung unter Windows
- Abfangen: WinDivert-Handle auf der Netzwerk-Schicht mit Filter
  `!loopback and ((outbound and ((tcp.Syn and !tcp.Ack) or udp)) or (inbound and ((tcp.Syn and !tcp.Ack) or udp.SrcPort == 53)))`.
  Nur diese Pakete laufen durch das Programm; bestehende TCP-Verbindungen bleiben im Kernel.
- Prozess zum Paket: zweites Handle auf der Socket-Schicht (nur mitlesen) liefert PID je lokalem Port; Rückfall GetExtendedTcpTable/UdpTable.
- Anhalten: unentschiedene Pakete werden zurückgehalten und nach der Antwort wieder eingespeist. TCP wiederholt das SYN selbst rund 20 s lang.
- Verbieten: SYN verwerfen und dem Programm ein RST+ACK zustellen (schlägt sofort fehl statt nach Zeitüberschreitung). Eingehend: still verwerfen.
- Datenmengen: drittes Handle (nur mitlesen, Priorität −1, Filter `!loopback and (tcp or udp)`) holt Pakete stapelweise per WinDivertRecvEx;
  gezählt wird je lokalem Port, einmal je Sekunde dem Programm zugeordnet (TrafficStats im Kern). Bei Überlast fehlen nur Zahlen.
- Hostnamen: DNS-Antworten (UDP von Port 53) werden mitgelesen, aber nur von den DNS-Servern des Systems und passend zu einer
  beobachteten Anfrage; beim Start wird der DNS-Zwischenspeicher geleert.
- Fehlersicher: Fehler in der Auswertung lassen das Paket durch; öffnet das Warnfenster nicht, wechselt SnitchBox in „alles erlauben“.
- Geprüft per REA inspect_pe_resources: dist/SnitchBox.exe enthält Manifest (RT_MANIFEST, requireAdministrator), Icon-Gruppe mit 9 Größen, Versionsangabe.
- WinDivert-Prüfsummen (build-windows.sh prüft sie): Release-Zip 63cb4176…3f15, WinDivert.dll c1e060ee…d9a2, WinDivert64.sys 8da08533…ddc2.

## Review und Korrekturen (1.0.1, Build 13)
- Unbekannter Prozess: Antworten werden nicht mehr als Regel gemerkt (leeres Programmfeld hieße „jeder Prozess“).
- Prozess zum Port: Socket-Ereignis „geschlossen“ entfernt die Zuordnung, sonst konnte nach Wiedervergabe eines Ports das alte Programm entscheiden.
- Wartende Verbindungen: jede wird je Nachfrage vermerkt (nicht nur die mit aufgehobenem Paket); vorher hingen Verbindungen über
  der 64-Paket-Grenze für immer.
- Eingehend ohne lauschendes Programm: durchlassen statt nachfragen, ohne 15-ms-Wartezeit (Portscans erzeugten bis zu 100 Warnfenster).
- DNS: Antworten zählen nur, wenn sie von einem DNS-Server des Systems kommen und eine beobachtete Anfrage (Server, Port, Kennung)
  beantworten. Werksregel DNS nur noch zu diesen Servern (neue Gegenstelle „dns-servers“), DHCP nur ins lokale Netz; Werksregel-Stand 2
  passt bestehende Regeln beim Start an.
- Speichern: Stand unter der Sperre aufnehmen, außerhalb schreiben, nacheinander und nie älter über neuer; Blocklisten-Dateien außerhalb der Sperre.
- Blocklisten gelten auch gegen allgemeine Erlauben-Regeln (siehe README).
- Rechte: %ProgramData%\SnitchBox nur für Administratoren beschreibbar (fremde Einträge übernommen, Verknüpfungen entfernt); Treiberdateien
  per SHA-256 mit dem eingebetteten Original verglichen; ipconfig/schtasks/notepad mit vollem Pfad; Aufgaben-XML im Datenordner;
  Warnung beim Autostart aus einem für alle beschreibbaren Ordner; Build ohne Auspacken nach %TEMP%\.net.
- Loopback-Pakete werden auch beim Ausweichfilter (ohne „!loopback“) sofort durchgelassen.
- Zweite Runde nach adversarialer Prüfung (6 Blickwinkel, Gegenprüfung je Fund, 19 bestätigte Funde):
  - Datenordner: Verknüpfung oder fremder Eigentümer → beiseiteschieben und mit fertiger DACL neu anlegen; fremde Einträge löschen statt
    übernehmen (geöffnete Handles behielten sonst ihre Rechte); jeder Fehlschlag bricht den Start ab; vorher kein Protokoll (Log.Enabled).
  - Treiberdateien bleiben nach der Hash-Prüfung bis nach WinDivertOpen geöffnet (nur Lesen freigegeben).
  - „System“ (Rule.KernelProcess) wird nie als Dateiname verglichen, nur genau so (PID 4).
  - csproj: StartupHookSupport=false, AppHostDotNetSearch=Global (keine Hooks, kein DOTNET_ROOT aus der Benutzerumgebung).
  - DNS: leere Serverliste behält den letzten Stand; lokaler Resolver auch unter eigener Adresse erkannt, Werksregel dann nur zu ihm;
    Anfragen nur nach erlaubendem Urteil gemerkt; bei Flut die ältesten verdrängt; unbekannter DNS-Server löst gedrosseltes Neulesen aus;
    nach Adressänderung nach 3 s erneut lesen; Einlesen nacheinander. Blocklisten: DnsServers zählt nur bei bekannter Liste als Ausnahme.
  - Prozess zum Port: Ereigniszeit (QPC, wie WinDivert-Timestamp) gespeichert; älter als 2 s → Gegenprobe mit der Port-Tabelle;
    geschlossene Sockets bleiben 5 s (Pakete) bzw. 10 s (Datenmengen) als Rückfall; eingehend zählen nur lauschende TCP-Ports
    (Lauscher-Tabelle, ergänzt um LISTEN-Ereignisse; Einzelheiten unten in Runde 4).
  - Autostart: bestehende Aufgabe wird geprüft (Befehl aus schtasks /XML), Warnung einmal je Build und als Hinweis in den Einstellungen;
    Prüfung als Erlaubt-Liste (nur Administratoren, SYSTEM, TrustedInstaller) inkl. DLLs daneben und übergeordneter Ordner.
  - Demo-Modus nutzt %ProgramData%\SnitchBox\demo (gehärtet) statt %TEMP%.
  - Vor Werksregel-Stand 2 Sicherung config.json.vor-werksregeln-2; „.defekt“-Sicherungen mit Zeitstempel.
  - build-windows.ps1 bricht bei jedem Fehler ab; EditRule verwirft abgelaufene „bis zum Beenden“-Regeln mit ehrlichem Hinweis.
- Dritte Runde nach zweiter Prüfung (5 Blickwinkel, 11 bestätigte Funde, alle niedrig):
  - Datenordner: Datei an Stelle des Ordners und unlesbarer Eigentümer gelten als fremd (beiseiteschieben); fremde Einträge zuerst ohne
    Übernahme löschen, sonst nach Übernahme – scheitert das Löschen, bekommen sie wieder einen fremden Eigentümer; Fehlermeldung nennt den Eintrag.
  - Zwischendateien (config.json.tmp, Blocklisten) werden gelöscht und neu angelegt, nie überschrieben.
  - Prozess zum Port: Rückstand der Socket-Ereignisse gemessen; über 100 ms gilt nur die Port-Tabelle. Ausgehendes TCP nur über die Zeile
    mit genau dieser Gegenstelle (Adresse und Port), Zeilen ohne Besitzer ausgelassen. Lauscher je Adressfamilie, Loopback-Lauscher zählen
    nicht, Neulesen nach 25 ms bei unbekanntem Port.
  - DNS-Server zusätzlich aus der NRPT (Split-DNS); Neulesen bei unbekanntem Server höchstens alle 3 s.
  - Autostart: Befehl aus %SystemRoot%\System32\Tasks\SnitchBox (UTF-16) statt aus der schtasks-Ausgabe; Warnung auch bei fehlender Zieldatei.
  - Bewusst offen: Laufzeit-Variablen der Benutzerumgebung (CORECLR_*, DOTNET_DiagnosticPorts, DOTNET_ADDITIONAL_DEPS) – bräuchte einen
    nativen Starter mit bereinigter Umgebung; eine Flut erlaubter DNS-Anfragen zwischen Anfrage und Antwort kann einen Namen verdrängen.
- Vierte Runde nach gezielter Prüfung der dritten (3 Blickwinkel, 5 bestätigte Funde):
  - Lauscher: GetExtendedTcpTable mit TCP_TABLE_OWNER_PID_LISTENER (3) statt Zustandsfeld = 2. Auf Windows 26300 (am Testrechner
    gemessen) steht bei Lauschern meist 0, 1 oder 6 im Zustandsfeld, auch netstat zeigt sie falsch – die Prüfung übersah fast alle
    Lauscher und hätte eingehende Verbindungen ungefragt durchgelassen.
  - LISTEN-Ereignisse tragen nur Wildcard-Lauscher (0.0.0.0/::) direkt ein, sonst Tabelle neu lesen (WinDivertAddress.LocalAddr*).
  - Fremde Einträge im Datenordner: nicht mehr rekursiv löschen (Junction-Tausch während des Löschens hätte Löschungen umgelenkt),
    sondern ohne Rekursion nach %ProgramData%\SnitchBox.unsicher-… verschieben; Verknüpfungen selbst löschen; alles über „\\?\“-Pfade,
    Namen mit Punkt/Leerzeichen am Ende gelten als fremd; danach prüfen, dass der Name frei ist. Eigentumsübernahme entfällt.
  - NRPT: auch DirectAccessDNSServers.

## Build 14
- Rotes Schild (ShieldIcon.cs, zur Laufzeit gezeichnet: Schildform aus make_win_icon.swift, rot, weißes Kreuz) im Infobereich und als
  Fenstersymbol, solange App.Filtering() falsch ist (Netzwerkfilter aus oder Treiber läuft nicht); Tooltip nennt den Grund.

## Build 15
- Installer installer/Setup.cs → dist/SnitchBox-Setup.exe (~0,95 MB): .NET Framework 4.x, C# 5, übersetzt mit dem Windows-eigenen
  csc.exe (läuft auf jedem Windows 10/11 ohne Vorbereitung); enthält dist/SnitchBox.exe; Runtime-Download per aka.ms-Kanal-Link mit
  WinVerifyTrust + Herausgeber „Microsoft Corporation“; Datei und Aufgaben-XML nur im Programmordner (Admin-only); /quiet, /uninstall.
  Bauteile ohne Adminrechte per Reflection getestet; die eigentliche Installation braucht UAC.

## Build 16
- 12 Sprachen (de, en, fr, es, it, pt-BR, pl, tr, ru, ja, zh-Hans, ko): Loc.T/Loc.F im Code (de/en), übrige Sprachen in
  src/SnitchBox.Core/Lang/<code>.json (englischer Text → Übersetzung, eingebettet); Texte mit Werten über Platzhalter (Loc.F);
  Auswahl unter Einstellungen → Sprache (Settings.Language, sofort wirksam) oder --lang; Installer mit denselben Tabellen
  (nur seine Texte, DataContractJsonSerializer). scripts/extract_strings.py erzeugt Lang/_source.json und prüft Vollständigkeit,
  Platzhalter, Zeilenumbrüche und Zugriffstasten; Build-Skripte und Kern-Tests brechen bei Lücken ab. Übersetzt von KI-Agenten
  (je zwei Sprachen), von Muttersprachlern nicht gegengelesen.

## Build 17
- Installer-Fenster: fließendes Layout (TableLayoutPanel/AutoSize, Segoe UI 9 pt, umbrechende Texte, mitwachsende Knöpfe) statt fester
  Koordinaten mit SystemFonts.MessageBoxFont – bei 175 % lief der Untertitel aus dem Fenster; dazu erzwungenes Neuzeichnen nach dem
  Erscheinen (nach der UAC-Rückfrage fehlten Teile des Fensters). Geprüft bei 100 % und 175 % in de/fr/ru/ja;
  echter Installationslauf bestätigt (Installer funktioniert, Anzeige korrekt).

## Build 18
- Bereichs-Schaltflächen (Regeln, Netzwerkmonitor, Blocklisten, Einstellungen) im Dunkelmodus lesbar: der eigene Stil NavButton
  ersetzt den Fluent-Stil, ohne Textfarbe galt die klassische dunkle Systemfarbe (schwarz auf dunkelgrau). Jetzt Textfarbe des
  Fensters (Bindung an Window.Foreground: dunkel weiß, hell #E4000000); gewählter Bereich weiter weiß auf Blau. Geprüft per
  Render-Test mit dem echten Styles.xaml in beiden Themes.

## Build 19
- Netzwerkmonitor „Erlauben …“/„Verbieten …“ schienen wirkungslos (Nutzer-Meldung): die Regel wurde angelegt (stand in
  config.json), die Zeile zeigte aber den alten Zustand, bis das Programm erneut verbindet – bei SystemSettings.exe womöglich nie.
  Jetzt passt die Engine nach jeder Regeländerung (Mutate, Warnfenster mit Regel, abgelaufene Regeln, DNS-Server) alle Zeilen an
  die geltenden Regeln an (ConnectionLog.Reevaluate). Ohne passende Regel: Zustand „Ohne Regel“ (grau, „der nächste Versuch
  fragt nach“) statt „Fragt …“; „Fragt …“ nur noch bei offenem Warnfenster (ConnectionRecord.Pending).
- Gleicher Geltungsbereich (Rule.SameScope: Prozess, Richtung, Gegenstelle, Ports, Protokoll, Profil): beim Speichern im
  Regel-Editor ersetzt die neue Regel eine eigene Regel mit gleichem Bereich – bei Gleichstand gewänne sonst „Verbieten“,
  ein „Erlauben“ für eine verbotene Verbindung bliebe wirkungslos. Werksregeln bleiben.
- Nach „Erlauben …“/„Verbieten …“ im Monitor prüft SnitchBox, ob die Regel bei dieser Verbindung greift, und nennt sonst die
  vorrangige Regel bzw. Blockliste.
- Bestehende IPv4-TCP-Verbindungen, die erst eine Regeländerung verbietet, werden getrennt (SetTcpEntry mit DELETE_TCB,
  FilterService.OnRulesApplied; Engine.RulesApplied liefert Regeln davor/danach). Der Filter sieht nur den Verbindungsaufbau,
  ohne das liefe z. B. eine offene Browserverbindung weiter. IPv6-TCP lässt sich so nicht trennen (keine Windows-Schnittstelle):
  dort wirkt die Regel ab dem nächsten Verbindungsaufbau. UDP ist sofort betroffen (Flusszwischenspeicher je Regelstand).
  Trennen im echten Lauf noch ungetestet (braucht Adminrechte).

## Build 20
- Einstellungen: Abschnitt „SnitchBox unterstützen“ mit Ko-fi-Knopf (Link ko-fi.com/C5H12AP4UV; das offizielle Ko-fi-Knopfbild ist als
  WPF-Resource src/SnitchBox/kofi.png eingebettet, Stil ImageButton – die Einstellungen laden nichts aus dem Netz).
  Weil SnitchBox immer als Administrator läuft, öffnet DesktopShell.cs Webadressen über die Desktop-Shell
  (ShellWindows → IShellDispatch2.ShellExecute, Verfahren nach Raymond Chen): der Browser läuft mit den normalen Rechten des Benutzers
  statt erhöht; getestet: der gestartete Prozess hat explorer.exe als Elternprozess.

## Build 21
- Ko-fi-Knopf rechts neben die Sprachauswahl verlegt (unten in den Einstellungen war er erst nach Scrollen sichtbar); der Hinweistext
  ist jetzt ein Tooltip, der eigene Abschnitt entfällt.

## Build 22
- Zu viele Regeln für dasselbe Programm (Nutzer-Meldung, 17 Regeln für BackgroundDownload.exe): Der Visual-Studio-Installer kopiert
  sich bei jedem Start in einen neuen Zufallsordner (R:\Temp\obkz3fue.blc\…\BackgroundDownload.exe), eine Regel mit vollem Pfad passte
  also nie wieder; dazu legte jede Nachfrage (Reichweite „Host“) eine eigene Regel an.
- Prozess-Muster: `*` in der Prozessangabe steht für einen beliebigen Teil eines Ordner- oder Dateinamens (nie für „\“; passt nie auf
  einen unbekannten Prozess). AlertRules.ProcessPattern macht wechselnde Ordnernamen zu `*`: den ersten Unterordner eines Temp-Ordners
  (%TEMP%, %SystemRoot%\Temp, …\AppData\Local\Temp; nie ein ganzes Laufwerk), Versionsordner (2.1.325, v1.2, app-1.0.3), GUID- und
  Hash-Ordner sowie die Version in Store-Paketordnern (Claude_*_x64__pzs8sxrjxfjjc). Regeln aus Warnfenster und Monitor nutzen das und
  gelten so auch nach dem nächsten Start oder Update. Vom Benutzer beschreibbare Ordner sind damit nicht schwächer geschützt als vorher
  (wer so einen Ordner anlegen kann, hätte auch die Datei am alten Ort ersetzen können).
- RuleCleanup (Cleanup.cs): Regeln, die sich nur in Hosts, Domains oder Adressen unterscheiden, werden zu einer zusammengefasst (eine
  neue Antwort mit Reichweite „Host“ kommt in die bestehende Regel); eine Regel entfällt, wenn eine umfassendere mit gleicher Aktion sie
  überflüssig macht – gleicher oder weiterer Prozess, Gegenstelle, Ports, Protokoll und Profil, mindestens gleiche Gültigkeit, und keine
  Regel mit der Gegen-Aktion liegt in der Rangfolge dazwischen (dann entscheidet SnitchBox mit und ohne sie gleich); Erlauben-Regeln,
  die einen Host von Blocklisten ausnehmen, ersetzt nur eine Regel, die das auch tut. Angewandt beim Anlegen einer Regel (Warnfenster,
  Regel-Editor).
- Regeln → „Aufräumen …“: zeigt, was sich ändert, und wendet es nach Bestätigung an – Temp- und Versionspfade verallgemeinern,
  überflüssige Regeln entfernen, gleichartige zusammenfassen, Regeln für nicht mehr vorhandene Programme entfernen (nur volle Pfade,
  geprüft außerhalb der Sperre der Engine). Werksregeln bleiben unberührt. Probelauf mit den Regeln des Testrechners: 90 → 43,
  BackgroundDownload.exe 17 → 3.

## Build 23
- Windows Update und Viren- & Bedrohungsschutz als Regel erkennbar (Wunsch des Nutzers): Ihre Programme außerhalb von svchost.exe haben
  nichtssagende Namen (SIHClient.exe, MoUsoCoreWorker.exe, MpCmdRun.exe …) und wurden leicht versehentlich verboten – auf dem Testrechner
  gab es eine Regel gegen SIHClient.exe und eine, die MpCmdRun.exe definitionupdates.microsoft.com (Virensignaturen) verbot.
- WindowsComponents (Components.cs): erkennt sie an Dateiname und Ort – Windows Update direkt in System32/SysWOW64 oder unter UUS, WinSxS,
  servicing, SoftwareDistribution; Defender unter ProgramData\Microsoft\Windows Defender\Platform\ und den Programmordnern von Windows
  Defender. Nur Ordner, in die allein Windows und Administratoren schreiben, damit sich kein Programm per Dateiname als Windows Update
  ausgeben kann (Unterordner von System32 zählen nicht, manche sind für alle beschreibbar).
- Prozess „@windows-update“ / „@defender“ in einer Regel = alle Programme des Bestandteils. Werksregel-Stand 3 ergänzt „Windows Update“ und
  „Viren- & Bedrohungsschutz“ (ausgehend erlauben, abschaltbar); eigene Verbieten-Regeln für einzelne Programme gehen weiter vor
  (gleiche Rangstufe, bei Gleichstand gewinnt „Verbieten“).
- Anzeige: Die Regelliste zeigt „Windows Update“ / „Viren- & Bedrohungsschutz“ als Prozess bzw. „Windows Update · SIHClient.exe“ bei Regeln
  für einzelne Programme, mit dem Symbol der Einstellungen bzw. der Windows-Sicherheit; ebenso im Netzwerkmonitor; das Warnfenster nennt
  den Bestandteil und sagt, was ein Verbot bewirkt.

## Build 24
- Warnung, bevor der Schutz endet (Wunsch des Nutzers): Ausschalten des Netzwerkfilters (Schalter im Hauptfenster, Menü im Infobereich)
  und „Beenden (Filter aus)“ im Infobereich fragen jetzt erst nach – danach geht jede Verbindung ungefragt durch. Vorauswahl ist „Nein“,
  ein versehentliches Enter ändert also nichts. Beenden fragt nur, solange SnitchBox wirklich filtert; Einschalten fragt nie.
  App.SetFilterEnabled / App.QuitAsked; bei Abbruch springt der Schalter auf den tatsächlichen Stand zurück.

## Offen
- Datenmengen je Gegenstelle, Dienstnamen hinter svchost.exe, Signaturprüfung (WinVerifyTrust), SNI-Auswertung bei DoH, Schutz ohne laufendes Programm.
