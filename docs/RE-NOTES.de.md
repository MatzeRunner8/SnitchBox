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

## Build 25
- Windows-Dienste einzeln: Alle Dienste in svchost.exe teilten sich eine Werksregel „jede Verbindung erlauben“, auch die Telemetrie
  (DiagTrack, „Benutzererfahrungen und Telemetrie im verbundenen Modus“). Jetzt bestimmt die Prozess-Zuordnung auch den Dienst:
  Native.Services liest die laufenden Win32-Dienste mit Prozessnummer (EnumServicesStatusEx, ohne Adminrechte), FilterService.ServiceOf
  ordnet einer svchost-PID ihren Dienst zu – nur wenn der Prozess genau einen beherbergt (Testrechner: 91 von 95 Dienst-Prozessen;
  geteilte wie RpcSs + RpcEptMapper lassen sich nicht unterscheiden und fallen unter die svchost-Regel). Benutzerdienst-Instanzen
  verlieren ihre je Anmeldung wechselnde Endung (CDPUserSvc_4396b → CDPUserSvc).
- Connection/ConnectionRecord/ProcessInfo tragen den Dienst; Rule.Service beschränkt eine Regel auf einen Dienst (Rangstufe zwischen
  Prozess und Gegenstelle, „DiagTrack verbieten“ schlägt also die svchost-Werksregel); Warnfenster und Monitor-Knöpfe übernehmen ihn;
  Feld „Windows-Dienst“ im Regel-Editor; .lsrules-Export/-Import behält ihn unter „snitchbox-service“; Aufräumen behandelt eine Regel
  ohne Dienst als für jeden Dienst geltend. Neu verbotene IPv4-TCP-Verbindungen eines Dienstes werden ebenfalls getrennt.
- Anzeige: Der Netzwerkmonitor zeigt jeden Dienst als eigene Zeile („Windows-Dienst: Benutzererfahrungen und Telemetrie …“; die
  Datenmengen bleiben bei der svchost-Zeile, weil sie je Programm gezählt werden), Regelliste und Warnfenster zeigen den Anzeigenamen
  in der Sprache von Windows (Native.ServiceDisplayName).
- Hinweis: Ältere Builds kennen Rule.Service nicht – zurück zu ihnen würde aus „DiagTrack verbieten“ „svchost.exe verbieten“.

## Build 26
- Echte Signaturprüfung (Signature.cs): Das Warnfenster las den Herausgeber bisher nur aus einer eingebetteten Signatur. Jetzt prüft
  Windows die Signatur (WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2) – eingebettete Signaturen und, wenn es keine gibt,
  Katalog-Signaturen (CryptCATAdmin…: Hash der Datei → Katalog → WinVerifyTrust mit WTD_CHOICE_CATALOG; SHA256, dann SHA1). Ohne
  Netzzugriff (WTD_REVOCATION_CHECK_NONE, WTD_CACHE_ONLY_URL_RETRIEVAL), Ergebnis je Pfad, Größe und Änderungszeit gemerkt; läuft,
  nachdem das Warnfenster offen ist. Anzeige: „✓ Google LLC – Signatur gültig“ (grün, „Windows-Katalog“ bei Katalog-Signaturen),
  „⚠ Signatur ungültig – die Datei wurde verändert oder das Zertifikat ist nicht vertrauenswürdig (0x…)“ (rot), „nicht signiert“.
- Geprüft auf dem Testrechner: svchost.exe/SIHClient.exe (Microsoft Windows Publisher), chrome.exe (Google LLC), devenv.exe (Microsoft
  Corporation), eine Kopie von notepad.exe (Katalog, Microsoft Windows), eine unsignierte exe und devenv.exe mit einem geänderten Byte
  (ungültig, TRUST_E_BAD_DIGEST); höchstens 42 ms je Datei.

## Build 27
- Nativer Starter SnitchBoxStart.exe (launcher\SnitchBoxStart.cpp, C++, statische Laufzeit, ~205 KB, Manifest requireAdministrator, nur
  kernel32/user32): entfernt alle Umgebungsvariablen, die mit CORECLR_, COR_, COMPlus_ oder DOTNET_ beginnen, und startet SnitchBox.exe aus
  seinem Ordner mit der übrigen Umgebung und den eigenen Argumenten, dann beendet er sich. Schließt die Lücke „Laufzeit-Variablen aus der
  Benutzerumgebung“ (jedes Programm darf sie in HKCU\Environment setzen; beim nächsten Anmelden hätte der Autostart fremden Code mit
  Administratorrechten geladen).
- Installer: legt den Starter neben SnitchBox.exe; Startmenü-/Desktop-Verknüpfung, Autostart-Aufgabe und der Start nach der Installation
  nutzen ihn; die Deinstallation entfernt ihn. SnitchBox: Der Autostart zeigt auf den Starter, wenn er neben SnitchBox.exe liegt; ein
  bestehender Autostart, der noch SnitchBox.exe direkt startet, wird beim Start umgestellt; mit bedenklichen Variablen gestartet
  (CORECLR_*, COR_PROFILER*, DOTNET_DiagnosticPorts, DOTNET_ADDITIONAL_DEPS, DOTNET_SHARED_STORE, DOTNET_STARTUP_HOOKS) warnt SnitchBox.
- Build: build-windows.ps1 findet Visual Studio über vswhere und baut den Starter mit launcher\build-launcher.cmd (rc + cl /O1 /MT /GS
  /guard:cf, Linker /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT); auch in SnitchBox-Standalone\ und im Installer eingebettet.
- Getestet mit einer Fassung ohne Admin-Manifest und cmd.exe als „SnitchBox.exe“: CORECLR_ENABLE_PROFILING, CORECLR_PROFILER_PATH,
  COR_PROFILER, DOTNET_DiagnosticPorts und COMPlus_EnableDiagnostics waren weg, andere Variablen (PATH, eigene Testvariable) und die
  Argumente kamen an. Die echte Startkette (UAC, Autostart) ist beim Nutzer noch ungetestet.

## Build 28
- Bestehende IPv6-TCP-Verbindungen trennen (Windows hat für IPv6 keine Funktion wie SetTcpEntry): Nach einer Regeländerung liest
  FilterService.OnRulesApplied auch die IPv6-TCP-Tabelle (Native.TcpConnectionsV6) und merkt neu verbotene Verbindungen vor (dieselbe
  Vorher/Nachher-Prüfung wie bei IPv4); IPv4-Verbindungen, bei denen SetTcpEntry scheitert, ebenso. Der Zähl-Thread, der ohnehin jedes
  TCP-Paket mitliest, sieht sich ein Paket nur genauer an, solange Verbindungen vorgemerkt sind: Für eine vorgemerkte baut er aus dem
  beobachteten Segment RSTs (Packet.BuildFlowResets: zum Empfänger des Segments mit der Folgenummer vor und nach seinen Daten, zurück an den
  Absender mit dessen Bestätigungsnummer – genau der Nummer, die er als Nächstes erwartet; Windows nimmt so ein RST sofort an, RFC 5961) und
  speist sie über das Netzwerk-Handle ein, ausgehend oder eingehend mit der beobachteten Schnittstelle. Höchstens zweimal je Sekunde und
  Verbindung; ein neues SYN auf denselben Ports oder fünf Minuten ohne Paket heben die Vormerkung auf.
- Kern-Tests: RSTs für IPv6 und IPv4 (Richtungen, Ports, Folgenummern mit Daten/FIN, nur RST-Flag, IP- und TCP-Prüfsummen, kein RST auf ein
  RST). Live auf dem Testrechner nicht prüfbar: Dort ist IPv6 ganz abgeschaltet (keine IPv6-Verbindungen, nicht einmal Link-lokal).

## Build 29 – Prüfung der Builds 25–28
Adversariale Prüfung mit mehreren Agenten (5 Prüfer, ein Gegenprüfer je Fund), danach zwei Nachprüfungen der Korrekturen. Behoben:
- Hoch: Der Starter entfernte COREHOST_TRACE/COREHOST_TRACEFILE nicht (der .NET-Host liest sie weiterhin; über TRACEFILE hätte ein Programm ohne
  Adminrechte das erhöht laufende SnitchBox Dateien an beliebiger Stelle anlegen lassen können, etwa eine falsche hostfxr.dll im Programmordner)
  – COREHOST_ wird jetzt entfernt; IsRiskyVariable warnt auch bei COREHOST_*, DOTNET_HOST_* und DiagnosticPorts/ADDITIONAL_DEPS/SHARED_STORE/
  STARTUP_HOOKS unter DOTNET_ und COMPlus_.
- Hoch (durch einen ersten Korrekturversuch entstanden, von der Nachprüfung gefunden): Beim Umstellen des Autostarts auf den Starter wurde der
  Inhalt von %SystemRoot%\System32\Tasks\SnitchBox neu registriert – dort dürfen Nicht-Administratoren Dateien anlegen, deren Aufgabe (Konto
  SYSTEM, weitere Befehle) wäre also mit Adminrechten registriert worden. Jetzt wird die Aufgabe immer aus der festen Vorlage neu angelegt; nur
  „abgeschaltet“ bleibt erhalten.
- Mittel: Eine Dienst-Regel mit leerem Programm verlor gegen die svchost-Werksregel (kein Prozess-Bonus) – ein Dienst zählt in der Rangfolge
  jetzt als bestimmter Prozess.
- Die Prüfung des Autostart-Ziels erfasst auch SnitchBox.exe (jede .exe neben dem Ziel), weil der Starter es mit Adminrechten startet.
- Dienst-Zuordnung: Cache-Einträge mit Startzeit des Prozesses (neu vergebene PIDs), unbekannte PIDs werden sofort neu gelesen (insgesamt
  höchstens alle 100 ms, je PID erst nach einem echten Neulesen gedrosselt), vollständig alle 15 s.
- Signaturprüfung ohne Zwischenspeicher (Größe und Änderungszeit kann der Besitzer nach einer Manipulation zurücksetzen).
- IPv6-Trennen: Vormerkungen werden vor jedem RST gegen die aktuellen Regeln, den Netzwerkfilter und die Überwachung eingehender Verbindungen
  geprüft, nur unverändert entfernt, einmal je Sekunde nach fünf Minuten ohne Paket aufgeräumt und bei abgeschaltetem Filter verworfen; ein
  eingehendes SYN hebt keine Vormerkung mehr auf; Stop wartet auf alle Threads, bevor es die WinDivert-Handles schließt.
- build-windows.ps1 verschluckt keine Compiler-Meldungen des Starters mehr.

## Build 30 – Profil je Netzwerk, Datenmengen je Gegenstelle
- Profil je Netzwerk (Einstellungen → Profile, „Profil je Netzwerk“): Die verbundenen Netzwerke kommen aus der Netzwerkliste von Windows
  (COM INetworkListManager, NLM_ENUM_NETWORK_CONNECTED – dieselben Namen und Netzwerkkennungen wie in den Windows-Einstellungen; Windows
  erkennt ein Netz am Gateway wieder, die Kennung bleibt also beim nächsten Verbinden gleich). Je Netzwerk: „Wie andere Netzwerke“,
  „Nicht automatisch wechseln“, „Kein Profil“ oder ein Profil; dazu eine Auswahl für alle anderen Netzwerke (Standard „Profil unverändert
  lassen“). NetworkProfileWatcher hört auf NetworkChange (Adressen/Verfügbarkeit) und prüft 2 s nach dem letzten Ereignis (spätestens
  5 s nach dem ersten eines Schubs), weitere 6 s später (Windows erkennt ein frisch verbundenes Netz oft erst dann), sobald ein neues Netz
  lange genug verbunden ist, und alle 30 s, wenn sonst nichts ansteht; ein Generationszähler verwirft eine Prüfung, die ein neueres
  Ereignis überholt hat. Es zählen nur Netze, die seit mindestens 5 s ohne Unterbrechung verbunden sind (StableNetworks): Beim Verbinden
  meldet Windows zuerst ein Übergangsnetz („Netzwerkidentifizierung…“, „Nicht identifiziertes Netzwerk“, jedes Mal mit neuer Kennung),
  das nicht als neues Netz gelten darf; ein Netz ohne Netzwerkprofil von Windows (Registry NetworkList\Profiles, also noch nicht
  identifiziert – etwa eine Minute lang nach einem Neustart des Routers) zählt erst nach 90 s. Mehrere Netze zugleich (LAN an der
  Dockingstation und WLAN, VPN): Netze mit „Nicht automatisch wechseln“ zählen nicht, dann gewinnt die älteste passende Zuordnung (eine
  geänderte behält ihre Stelle), dann das Profil für andere Netzwerke.
  Was als Netzwerkwechsel zählt (NetworkProfiles.Observe): SnitchBox merkt sich den „Ort“ (die Netze, die beim letzten Wechsel den
  Ausschlag gaben, Settings.NetworkPlace) und Netze, die danach nur dazukamen (Settings.NetworkExtras, etwa ein VPN). Umgeschaltet wird,
  wenn ein neu verbundenes Netz entscheidet (es ist zugeordnet und hat Vorrang, etwa ein Firmen-VPN), wenn ein neues Netz kommt, während
  vom Ort keines mehr verbunden ist, oder wenn der Ort 60 s lang fehlt, während andere Netze verbunden bleiben. Netze, die nur kurz
  wegfallen (Aufwachen, WLAN-Aussetzer, VPN verbindet neu), schalten nie um – ein von Hand gewähltes Profil gilt also, bis du wirklich ein
  anderes Netz betrittst, auch über einen Neustart von SnitchBox hinweg. Zum Ort werden nur neu erschienene Netze oder das entscheidende
  zugeordnete, nie schon vorher verbundene (ein dauerhaft verbundener virtueller Adapter von WSL/Hyper-V bleibt ein Extra); fehlt der Ort
  und kommt kein neues Netz, bleibt er leer, und das nächste neue Netz zählt. Bei einem Ort aus mehreren nicht zugeordneten Netzen zählt
  ein neues Netz, sobald eines davon fehlt. Sind länger als 60 s nur Netze mit „Nicht automatisch wechseln“ verbunden, werden Ort und
  Extras vergessen (ohne umzuschalten), damit die Rückkehr wieder zählt. Ein Profil, das man von Hand wählt, während man nicht am
  gemerkten Ort ist, gilt dem Netz, in dem man gerade ist: Der Ort wird vergessen, die Rückkehr schaltet wieder um. Zeit im Standby
  zählt nicht zu den 60 s (PowerModeChanged/Resume und eine Lücke von über 70 s zwischen zwei Prüfungen); ein Netz des Orts, das wieder
  da, aber noch nicht bestätigt ist, gilt nicht als fehlend. Im Zustand „unterwegs“ (leerer Ort) werden gemerkte Netze, die wegfallen,
  ebenfalls erst nach den 60 s vergessen. Entscheidet ein Netz des Orts per Zuordnung, schrumpft der Ort auf
  dieses. Eine geänderte Zuordnung schaltet nur um, wenn sie das Ergebnis für die verbundenen Netzwerke ändert, und zieht den gemerkten
  Ort nach (NetworkProfiles.ChangeBindings – außer ein Netzwechsel steht noch aus; während einer laufenden 60-s-Frist entscheidet sie,
  als wäre der fehlende Ort noch da); solange kein zählendes
  Netz verbunden ist (keins oder nur „Nicht automatisch wechseln“), sorgt eine Änderung, die den
  gemerkten Ort betrifft, dafür, dass beim nächsten Verbinden neu entschieden wird. In den Einstellungen gilt eine Auswahl aus der aufgeklappten Liste sofort, mit
  den Pfeiltasten im zugeklappten Feld erst mit der Eingabetaste oder beim Verlassen des Feldes (keine Zwischenwerte); das Mausrad über
  einem zugeklappten Feld rollt die Seite; solange eine Liste offen ist, werden die Zeilen nicht neu aufgebaut, und der Fokus kehrt auf
  dasselbe Feld zurück. Der Tooltip im Infobereich zeigt das aktive Profil.
- Datenmengen je Gegenstelle: Der Zähl-Thread (WinDivert-Sniff-Handle) zählt jetzt auch je Verbindung (Gegenadresse, lokaler Port,
  Gegenport, Protokoll); jede Verbindung, die SnitchBox selbst erlaubt hat (gleich oder nach einer Nachfrage), wird ihrer Zeile im
  Netzwerkmonitor zugeordnet (ConnectionLog, bis 50.000 Verbindungen; ist es voll, fällt das am längsten untätige Zehntel heraus, Zeilen mit
  laufendem Verkehr bleiben, verdrängte Zeilen nehmen ihre Verbindungen mit; höchstens 65.536 neue Verbindungen je Sekundenabschnitt).
  Neue Spalte „Daten“ mit den Summen, die aktuelle Rate als Tooltip; Dienst-Zeilen in der Programmliste summieren ihre Gegenstellen.
  Verbotene Verbindungen werden nicht zugeordnet (sonst zählte der Zähler das eigene RST). Verbindungen, die schon vor dem Start von
  SnitchBox bestanden, zählen nur beim Programm.
- Spalten des Netzwerkmonitors neu vermessen (Segoe UI 14, alle 12 Sprachen), damit bei Standardgröße des Fensters (1280 px) alles
  hineinpasst; zu lange Spaltenköpfe enden mit „…“ und Tooltip; kürzere Köpfe in es/pt/it/ru („Veces“, „Última“, „Volte“, „Кол-во“, „Время“);
  Datenmengen mit höchstens fünf Zeichen vor der Einheit („999,9 MB“, „12,3 GB“, „1000 GB“, „1,23 TB“).
- Mehragenten-Prüfung beider Funktionen (16 bestätigte Befunde, alle behoben – darunter „Nicht automatisch wechseln“, das vom Profil für
  andere Netzwerke übergangen wurde, eine Wahl von Hand, die unbeteiligte Änderungen zurücksetzten, FIFO-Verdrängung langlebiger
  Verbindungen und die Spaltenbreite bei Standardgröße des Fensters), danach sechs Prüfrunden der Korrekturen (Simulatoren mit
  Tagesabläufen und Fuzzing gegen den echten Code; 35 weitere Befunde
  behoben, darunter: Vorrang ging beim Ändern verloren, VPN, Übergangsnetz oder kurzer Aussetzer zählte als Netzwechsel, ein dauerhaft
  verbundener virtueller Adapter verhinderte spätere Wechsel, ein „Nicht wechseln“-Netz dazwischen zählte nicht als Verlassen,
  Änderungen ohne Netz oder während der Frist, Zwischenwerte bei Tastaturauswahl, Mausrad änderte
  die Auswahl, Netzwerkereignisse in schneller Folge schoben die Prüfung beliebig auf, die 30-s-Prüfung verdrängte die zweite Prüfung,
  abgeschnittene Zellen und Köpfe).

## Build 31 – bekannte Apps mit Namen und Symbol
- KnownApps (Kern): Claude (Store-Paket Claude_pzs8sxrjxfjjc, ältere Squirrel-Installation unter AppData\Local\AnthropicClaude), Claude
  Code (Kommandozeile: AppData\Local\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\…\claude.exe, ~\.local\bin\claude.exe), ChatGPT
  (Store-Pakete OpenAI.Codex / OpenAI.ChatGPT-Desktop, Herausgeber 2p2nqsd0c76g0), Google Chrome, Brave, Firefox (auch als Store-Paket
  und mit Wartungsdienst) und Microsoft Edge samt WebView2. Jedes Programm bekommt eine Rolle: die App selbst, Updater (GoogleUpdater,
  Google Update, BraveUpdate/BraveUpdater, EdgeUpdate, updater.exe und Wartungsdienst von Firefox, der Installer-Ordner der
  Chromium-Browser, Squirrel-Update.exe), Hilfsprogramm (alles Übrige im Ordner der App, etwa elevation_service.exe, codex.exe, WebView2)
  oder Kommandozeile. Erkannt wird am Ort über Vorlagen für beide Programmordner, WindowsApps, AppData\Local, den Benutzerordner und
  ProgramData; Versions-, Hash- und Paketversions-Ordner sind variabel, deshalb passen auch Regel-Muster mit „*“. Ein Store-Paket muss
  die richtige Herausgeber-Kennung haben. Namen: „Google Chrome“, „Brave · Updater“, „Google Updater“, „ChatGPT · codex.exe“, „Microsoft
  Edge WebView2“ – in der Regelliste, der Programmliste des Netzwerkmonitors und im Warnfenster (mit Hinweis bei Updatern: Verbieten
  stoppt die Updates, auch die Sicherheitsupdates). Die schmale Prozess-Spalte der Verbindungsliste zeigt Symbol und Dateiname, den Namen
  im Tooltip.
- Nur Anzeige: Die Erkennung ändert nie, welche Regel greift. Name und Symbol einer Datei kann ihr Hersteller ohnehin frei wählen, eine
  neue Möglichkeit zum Verkleiden entsteht also nicht; maßgeblich ist die geprüfte Signatur im Warnfenster.
- Symbole (AppIcons): Bekannte Apps zeigen das Symbol ihres Hauptprogramms (Store-Pakete über GetPackagesByPackageFamily /
  GetPackagePathByFullName aufgelöst, denn WindowsApps lässt sich nicht auflisten), Updater, Hilfsprogramme und Kommandozeile zusätzlich
  ein Abzeichen unten rechts (blauer Kreis mit Pfeilen, graues Zahnrad, dunkle Eingabeaufforderung); ist die App nicht installiert, eine
  Buchstabenkachel in ihrer Farbe. Allgemein bekommen Regel-Muster mit „*“ und Pfade alter, schon gelöschter Versionen jetzt das Symbol
  der aktuell installierten Datei (neuester Treffer, höchstens 400 Ordner durchsucht) statt des grauen Fragezeichens. Geprüft mit den
  48 Regeln des Nutzers: Alle 46 aufgeführten Programme haben ein Symbol.

## Build 32 – Visual Studio Code, Visual Studio, NordVPN
- KnownApps erweitert: Visual Studio Code (Benutzerinstallation unter AppData\Local\Programs und Systeminstallation; Updater
  inno_updater.exe im Hash-Ordner, etwa …\e646868227\tools\; das heruntergeladene Update %TEMP%\vscode-stable-…\CodeSetup-….exe;
  Erweiterungen unter ~\.vscode\extensions wie rust-analyzer; VS Code Insiders getrennt), Visual Studio (Ordner 18/2022 und Ausgabe:
  devenv.exe als App, alles Übrige im Installationsordner und in „Shared“ als Hilfsprogramm, etwa PerfWatson2.exe; der Visual Studio
  Installer als Updater, auch seine Kopie in einem Zufallsordner unter Temp, die BackgroundDownload.exe ausführt) und NordVPN (NordVPN.exe
  und NordVPNApp.exe im Versionsordner als App, Dienst und Threat Protection als Hilfsprogramme, NordUpdater als Updater).
- Neuer Platzhalter {TEMP} in den Vorlagen: die eingestellten Temp-Ordner (wie bei Regel-Mustern, nie ein ganzes Laufwerk) und
  AppData\Local\Temp jedes Benutzers. Das Symbol einer App mit wechselndem Ordner (devenv.exe) wird per Muster gefunden.

## Build 33 – Update-Prozesse von Microsoft Office und Adobe
- Microsoft Office (Klick-und-Los): der Dienst OfficeClickToRun.exe (lädt und installiert die Updates, während eines Updates auch aus
  einem Unterordner) als „Microsoft Office Click-to-Run“ und OfficeC2RClient.exe (von der Aufgabe „Office Automatic Updates 2.0“
  gestartet) als „Microsoft Office · Updater“, beide mit Updater-Abzeichen; alles Übrige unter ClickToRun und Microsoft Office als
  Hilfsprogramm; Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher, Visio, Project und Skype for Business mit Namen
  (Klick-und-Los- und MSI-Ordner). Das neue Outlook (Store-Paket Microsoft.OutlookForWindows) und Teams (MSTeams) als eigene Apps,
  OneDrive (je Benutzer und für alle) mit OneDriveStandaloneUpdater.exe und OneDriveSetup.exe als Updater.
- Adobe: Acrobat und Reader mit ihrem Updater unter Common Files\Adobe\ARM (Adobe Acrobat Update Service armsvc.exe, AdobeARM.exe);
  Creative Cloud mit dem Adobe Update Service (Adobe Desktop Common\ElevationManager\AdobeUpdateService.exe) und dem
  Installationsprogramm (ElevationManager, HDBox, OOBE) als Updater, Hintergrunddienste (Adobe Desktop Service, CoreSync, Adobe Genuine
  Service) als Hilfsprogramme und die Programme der Suite mit Namen (Photoshop, Illustrator, InDesign, Premiere Pro, After Effects, Media
  Encoder, Audition, Bridge, Animate, Dreamweaver, Lightroom, Character Animator, Substance 3D Painter).
- Ein Programm mit eigenem Namen zeigt sein eigenes Symbol (Word, Photoshop); ist es nicht installiert, eine Buchstabenkachel mit seinem
  Anfangsbuchstaben statt dem der Suite.
- Office (Klick-und-Los) und Adobe sind auf dem Entwicklungsrechner nicht installiert: Ihre Vorlagen folgen den Standard-Installationsorten
  der Hersteller und sind durch Kern-Tests abgedeckt, aber nicht mit echten Dateien geprüft. OneDrive und das neue Outlook wurden mit den
  installierten Apps geprüft.

## Offen
- SNI-Auswertung bei DoH, Verlauf über Neustarts.
- Bewusst nicht umgesetzt (Entscheidung des Nutzers): Schutz ohne laufendes SnitchBox (dauerhafte WFP-Filter beim Hochfahren).
