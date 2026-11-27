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

## Build 34 – Windows-Programme mit Namen und Symbol
- WindowsProcesses (Kern): rund 60 Windows-Programme bekommen einen verständlichen Namen und eine Art – System (Diensthost, Anmeldung
  LSASS, Hintergrundaufgaben, Aufgabenhost, WMI, Geräteverbindungen, Druckwarteschlange, App-Verknüpfungen prüfen …), Oberfläche
  (Datei-Explorer, Startmenü, Sperrbildschirm, Smartphone-Link, Remotedesktop), Suche, Einstellungen, Sicherheit (Windows-Sicherheit,
  SmartScreen, Microsoft-Konto-Anmeldung), Telemetrie (CompatTelRunner, DeviceCensus, wsqmcons, Fehlerberichterstattung), Tipps/Hinweise/
  Werbung (SoftLandingTask, RUXIM-Hinweise von Windows Update, Widgets und ihr Nachrichten-Feed), Installation (Windows Installer, WinGet,
  App-Installer, Microsoft Store) und Kommandozeile (PowerShell, Eingabeaufforderung, curl, OpenSSH). Andere Programme in geschützten
  Windows-Ordnern heißen „Windows · name.exe“.
- Erkannt am Dateinamen, aber nur in Ordnern, in die allein Windows und Administratoren schreiben: System32 und SysWOW64 selbst (dazu
  wbem, WindowsPowerShell\<Version>, OpenSSH, ruxim), der Windows-Ordner, ImmersiveControlPanel, SystemApps und Store-Pakete mit den
  Herausgeber-Kennungen von Microsoft (8wekyb3d8bbwe, cw5n1h2txyewy). Unterordner wie System32\spool\drivers\color oder Tasks sind für
  alle beschreibbar und zählen nicht, der DriverStore (Treiber anderer Hersteller, etwa NVIDIA) auch nicht. Windows Update und der
  Viren- & Bedrohungsschutz behalten ihre eigene Erkennung (WindowsComponents), Dienst-Zeilen bleiben „Windows-Dienst: …“. Nur Anzeige.
- Symbole: Die meisten Windows-Programme enthalten kein Symbol (ExtractIconEx liefert 0 – svchost, lsass, Startmenü, Suche, Telemetrie),
  Windows zeigte dann das leere Standardsymbol. Programme mit eigenem Symbol behalten es (Datei-Explorer, Einstellungen, cmd,
  Druckwarteschlange), die übrigen bekommen eine Kachel nach ihrer Art mit einem Zeichen aus Segoe Fluent Icons: Bildschirm (System),
  Raster (Oberfläche), Lupe (Suche), Zahnrad (Einstellungen), Schild (Sicherheit), Pulslinie (Telemetrie), Megafon (Tipps/Werbung),
  Paket (Installation), Eingabeaufforderung (Kommandozeile).
- Warnfenster: Name und Hinweis – bei Telemetrie und Tipps/Werbung, dass Windows auch funktioniert, wenn man es verbietet, sonst „Teil
  von Windows.“
- 43 neue Texte in allen 12 Sprachen.

## Build 35 – Git und GitHub
- KnownApps: GitHub CLI (MSI-Installation unter Programme\GitHub CLI, sonst ZIP-Paket oder Scoop mit …\bin\gh.exe – auch portabel an
  beliebigem Ort, etwa C:\Tools\GitHubCLI\bin\gh.exe) als Kommandozeile; Git für Windows und MinGit an beliebigem Ort – git.exe in cmd\
  oder <arch>\bin\ als Kommandozeile, die Helfer (git-remote-https.exe, git-credential-manager.exe …) in <arch>\bin\ und
  <arch>\libexec\git-core\ (arch = mingw64, ucrt64, clangarm64, mingw32), alles Übrige unter Programme\Git als Hilfsprogramm; GitHub
  Desktop (Squirrel, je Benutzer) mit Update.exe als Updater – das mitgelieferte Git zählt zu GitHub Desktop, ebenso das von Visual Studio.
- Neue Platzhalter {DRIVE}{DIRS} („irgendwo“), nur für portable Werkzeuge mit unverwechselbarer Ordnerstruktur und ganz am Ende der
  Liste, damit bestimmte Apps vorgehen.
- Symbole: gh.exe und die Git-Programme enthalten kein Symbol. Git zeigt das von Git Bash, GitHub CLI das von GitHub Desktop, wenn
  installiert; sonst eine gezeichnete Kachel – orangefarbene Raute mit Verzweigung für Git, dunkelgraue Kachel mit „GH“ für GitHub.
  Korrektur: Updater, Hilfsprogramme und Kommandozeile nehmen jetzt immer das Hauptprogramm der App (oder die gezeichnete Kachel), nie
  das Symbol der gerade gezeigten Datei (bisher lieh der erste Helfer mit Symbol – git-credential-manager.exe – es allen anderen, und
  Dateien ohne Symbol zeigten das leere Standardsymbol); ein Hauptprogramm oder die eigene Datei einer App zählt nur, wenn sie
  wirklich ein Symbol enthält.

## Build 36 – Programme nach Art gruppiert
- ProcessGroups (Kern): Jedes Programm gehört zu einer Gruppe – Alle Programme (Regeln für jeden Prozess), KI (Claude, Claude Code,
  ChatGPT), Browser (Chrome, Brave, Firefox, Edge samt WebView2 und ihren Updatern), Office und Kreativ (Office, OneDrive, Outlook, Teams,
  Adobe), Entwicklung (VS Code, Visual Studio, Git, GitHub), VPN und Sicherheit (NordVPN), Windows (Windows Update, Defender,
  Windows-Programme, Dienste, auch eine Dienst-Regel ohne Programm, der Kern), Andere Programme. Die Gruppe kommt aus der Erkennung
  bekannter Apps (KnownApp.Group), der Windows-Bestandteile und Windows-Programme; Updater und Hilfsprogramme bleiben bei ihrer App.
- Regelliste und Programmliste des Netzwerkmonitors: nach Gruppe sortiert, darin wie bisher (eigene vor Werksregeln, nach Name); jede
  Gruppe bekommt eine Überschrift mit Name, Anzahl und feiner Linie (WPF-CollectionView-Gruppierung, GroupStyle ohne Expander – nichts
  klappt zu oder wird ausgeblendet). Die Zeile „Alle Programme“ oben in der Programmliste gehört zu einer Gruppe ohne Überschrift. Die
  Programmliste aktualisiert sich weiter an Ort und Stelle und wird nur neu aufgebaut, wenn sich ein Programm oder seine Gruppe ändert;
  Auswahl und Rollposition bleiben.
- Einstellungen → Allgemein: „Programme nach Art gruppieren (KI, Browser, Windows …)“, Settings.GroupLists, standardmäßig an (auch bei
  einer älteren config.json ohne den Eintrag); ausgeschaltet gibt es die bisherigen flachen Listen.
- 8 neue Texte in allen 12 Sprachen.

## Build 37 – NVIDIA und Steam
- NVIDIA (neue Gruppe „Treiber und Hardware“): der Grafiktreiber im DriverStore – nur die NVIDIA-Pakete (nv_disp…, nvhda…, nvpcf…),
  nicht jeder „nv…“-Ordner (nvdimm, nvmedisk gehören zu Microsoft) – mit NVDisplay.Container.exe als Hilfsprogramm, dem NGX/DLSS-Updater
  nvngx_update.exe („NVIDIA NGX Updater (DLSS)“) und der Treiber-Installation als Updater; nvidia-smi.exe („NVIDIA SMI“), nvidia-pcc.exe
  und nvdebugdump.exe in System32; NVIDIA App und GeForce Experience mit Namen, Installer2, der Downloader unter ProgramData und der nach
  C:\NVIDIA\DisplayDriver entpackte Treiber als Updater. Symbol: NVIDIA App, wenn installiert, sonst NVDisplay.Container.exe aus dem
  DriverStore (das einzige Treiberprogramm mit Symbol; Hauptprogramme werden jetzt auch im Windows-Ordner gesucht). Neuer Platzhalter {WIN}.
- Steam (neue Gruppe „Spiele“): steam.exe, steamwebhelper und der Steam Client Service; Spiele in jeder Bibliothek auf jedem Laufwerk
  (…\steamapps\common\<Spiel>\…) mit der neuen Rolle „Spiel“, benannt nach dem Ordner des Spiels („Steam · Portal 2“), mit eigenem Symbol
  oder dem Steam-Symbol samt Gamepad-Abzeichen. Steam ist auf dem Entwicklungsrechner nicht installiert: durch Kern-Tests abgedeckt,
  Symbol nur als Buchstabenkachel.

## Build 38 – Discord, Spotify, Apple Music
- Discord (neue Gruppe „Kommunikation“): Squirrel-Installation je Benutzer unter AppData\Local\Discord – die App in
  app-<Version>\Discord.exe, Update.exe als Updater, Module als Hilfsprogramme; Discord PTB und Discord Canary als eigene Apps.
- Spotify (neue Gruppe „Musik und Medien“): klassische Installation unter AppData\Roaming\Spotify (neuer Platzhalter {ROAMING};
  Hauptprogramme werden jetzt auch unter Roaming gesucht), heruntergeladene Updates unter AppData\Local\Spotify\Update als Updater,
  Store-App SpotifyAB.SpotifyMusic (Herausgeber zpdnekdrzrea0).
- Apple („Musik und Medien“): Apple Music als Store-App AppleInc.AppleMusicWin (Herausgeber-Kennung von Apple nzyj5cx40ttqa) samt
  Hilfsprogrammen (etwa AMPLibraryAgent.exe); iTunes als Store-App und klassisch, Apple Software Update als Updater, Bonjour
  (mDNSResponder.exe) und Apple Mobile Device Support.
- Keins der drei ist auf dem Entwicklungsrechner installiert: Die Vorlagen folgen den Standard-Installationsorten und sind durch Kern-Tests
  abgedeckt; Symbole bis zur Installation nur als Buchstabenkachel.

## Build 39 – Prüfrunde der Builds 31–38
Drei unabhängige Prüfer (Erkennung im Kern, Symbole/Win32, Einbindung in die Oberfläche) haben den Code der Builds 31–38 gelesen; jeder
Befund wurde vor der Korrektur am Code nachgeprüft. Bestätigt und behoben:
- Von SnitchBox selbst angelegte Regeln wurden teils nicht erkannt: AlertRules.ProcessPattern macht „app-1.0.9213“ und den ersten
  Temp-Unterordner zu „*“, die Vorlagen erwarteten aber wörtlich „app-“ (Discord, PTB, Canary, altes Claude, GitHub Desktop) bzw.
  „vscode-stable-“. Die Vorlagen nutzen jetzt {V}; neuer Platzhalter {STAR} (passt nur auf das „*“ eines gespeicherten Musters) für das
  VS-Code-Update. Neuer Test: Für 25 Beispielpfade wird das gespeicherte Muster genauso erkannt wie der echte Pfad.
- Beruhigende Hinweise im Warnfenster ohne Prüfung: „Updater von …“, „Hilfsprogramm von …“ und „Teil von Windows“ erschienen für jede
  Datei an einem Ort, den jeder Benutzer beschreiben kann (AppData, Temp, ProgramData, „irgendwo“-Vorlagen), und für jedes Programm in
  System32. Jetzt wissen die Vorlagen, ob ihr Ort beschreibbar ist (AppMatch.Writable); dort und bei allen Windows-Programmen erscheint
  der Hinweis erst nach der Signaturprüfung und nur, wenn der Unterzeichner zum Hersteller passt (KnownApps.MakersOf – NVIDIA-Treiber
  sind etwa von „Microsoft Windows Hardware Compatibility Publisher“ signiert, Git von „Johannes Schindelin“, Windows-Programme von
  Microsoft); sonst ein roter Vorsichtshinweis („liegt im Ordner von …, ist aber nicht von dessen Hersteller signiert“).
  Kommandozeilen-Werkzeuge (PowerShell, cmd, curl, OpenSSH) bekommen eine Warnung statt einer Beruhigung, Verbindungen eines
  svchost-Dienstes keinen allgemeinen Hinweis. An beschreibbaren Orten verbergen feste Namen und „· Updater“ den Dateinamen nicht mehr
  („Discord · Updater (Update.exe)“, „Visual Studio Installer (BackgroundDownload.exe)“).
- Alternative Datenströme („C:\Windows\Tasks:evil.exe“ – Tasks und Tracing sind für alle beschreibbar) zählten als Windows-Programm: Ein
  „:“ nach dem Laufwerk weisen jetzt KnownApps, WindowsProcesses, WindowsComponents und die Symbolsuche ab.
- Symbole: Die neueste Store-Paketversion wurde durch Vergleich eines Paketnamens mit einem Pfad gewählt (jetzt nach Version);
  Zwischenspeicher hielten Fehlschläge und veraltete Ergebnisse für die ganze Laufzeit (nach einem Store-Update konnte die
  Buchstabenkachel für immer bleiben) – jetzt Speicher mit Verfallszeit (TimedCache: vorhandene Datei 1 min, Paketordner 5 min, echte
  Symbole 30 min, Ersatz 2 min) und Größengrenze; Native.IconOf merkt sich keine Fehlschläge mehr; nicht mehr jede Listenaktualisierung
  prüft jede Zeile auf der Platte; bei einem gelöschten Programm werden nur Versionsordner zu „*“ (AlertRules.VersionPattern) – vorher
  konnte „C:\Windows\Temp\{GUID}\setup.exe“ das Symbol eines beliebigen anderen Installers zeigen; nur lokale Laufwerke (keine
  Netzfreigabe – eine nicht erreichbare würde die Oberfläche anhalten); die Ordnersuche überspringt Verknüpfungen (Junctions, symbolische
  Links – auch zu \\server-Freigaben) und ausgelagerte Ordner; die Paketabfrage wiederholt, wenn sich die Paketzahl zwischen ihren beiden
  Aufrufen ändert.
- Tempo: KnownApps.Of und WindowsProcesses.Of merken sich das Ergebnis je Pfad (sie prüften ~190 reguläre Ausdrücke je Aufruf, mehrmals je
  Zeile und Sekunde); der Netzwerkmonitor berechnet die Gruppe je Zeile nur einmal.
- Kleinere Korrekturen: Der Tooltip der Verbindungsliste benennt Windows-Update-Programme wie die Programmliste (gemeinsame
  Namensfunktion); die Regelsuche findet auch die angezeigten Namen und Dienste („Google Updater“, „Telemetrie: Kompatibilität“); die
  Programmliste behält beim Neuaufbau ihre Rollposition; „system“ in Kleinschreibung wird wie bei den Regeln zu Windows gruppiert;
  Steamworks Shared ist kein Spiel; der Platzhalter {WIN} fällt nicht mehr auf „jedes Laufwerk“ zurück.
- Geprüft und in Ordnung: Die Erkennung ändert nie, welche Regel greift; die Reihenfolge (Dienst, Windows Update/Defender, bekannte Apps,
  Windows-Programme) ist überall gleich; Aufbau der regulären Ausdrücke und Store-Herausgeberkennungen; P/Invoke-Signaturen und Puffer;
  Threads (nur Oberflächen-Thread, eingefrorene Bilder); Gruppierung, Auswahl und Speichern der Einstellung. Bekannte Grenzen: Programme
  auf Netzfreigaben oder UNC-Pfaden bekommen kein Symbol; bei Erhöhung über ein anderes Administratorkonto zeigen Apps des angemeldeten
  Benutzers Buchstabenkacheln.
- 11 neue Kern-Tests (322 insgesamt), 4 neue Texte in allen 12 Sprachen.

## Build 40 – Route verfolgen mit Weltkarte
Wunsch des Nutzers: den Weg zu einer Gegenstelle verfolgen und auf Wunsch auf einer Karte zeigen.
- Netzwerkmonitor: Knopf „Route verfolgen …“ und derselbe Eintrag im Kontextmenü der Verbindungsliste; ohne Auswahl öffnet das Fenster mit
  leerem Ziel (Adresse oder Name). Mehrere Fenster gleichzeitig gehen.
- Proben (IcmpProber): ICMP-Echo mit begrenzter TTL über die ICMP-Schnittstelle von Windows (IcmpSendEcho2/Icmp6SendEcho2, wie tracert),
  Abschluss über ein Ereignis und den Thread-Pool – kein blockierter Thread. Anders als System.Net.NetworkInformation.Ping liefert das
  auch bei „TTL abgelaufen“ die Laufzeit (Ping meldet dort 0 ms). Der WinDivert-Filter fängt ICMP nicht ab; der Trace geht also auch bei
  verbietenden Regeln.
- Ablauf (Tracer, Kern): drei Proben je Hop. Hop 1 zuerst und allein, dann Runden im Sekundenabstand, die TTL 2…30 im Abstand von 15 ms
  abschicken, statt Hop für Hop zu warten; sobald das Ziel antwortet, gehen spätere Runden nur noch bis zu seinem Hop. Ein Trace dauert
  etwa 2 s (tracert bei stummen Routern bis zu zwei Minuten). Gemessen am Anschluss des Nutzers: Eine FRITZ!Box beantwortet TTL 1 nicht,
  solange weitergeleitete Proben zum selben Ziel unterwegs sind (vermutlich NAT-Zustand) – daher Hop 1 zuerst; wer dasselbe Ziel
  innerhalb weniger Sekunden erneut verfolgt, kann dort trotzdem „*“ sehen. Endzustände: erreicht, nicht erreichbar (Meldung eines
  Routers), ab Hop N keine Antwort (Ziel beantwortet keinen Ping), abgebrochen.
- Hop-Liste: Adresse(n) (mehrere bei Lastverteilung), Routername per Rückwärts-DNS (abschaltbar, wie tracert), drei Zeiten, Land
  (private Netze, CGNAT, verbindungslokale Adressen werden benannt).
- Weltkarte (MapView, auf Wunsch): Natural Earth 1:50 Mio. (gemeinfrei) als eingebettete Datei mit 114 KB (scripts/make_worldmap.py,
  Projektion „Natural Earth“, ohne Antarktis, 13 kleine Gebiete als Punkt, Namen in allen 12 Sprachen). Länder der Route hervorgehoben,
  Stationen (aufeinanderfolgende Hops in einem Land) mit ihrem ersten Hop nummeriert, Start grün, Ziel orange, Großkreise mit
  Richtungspfeil, an der Datumsgrenze geteilt. Mausrad zoomt um den Mauszeiger, Ziehen verschiebt, Doppelklick zoomt hinein; Tooltip je
  Station mit ihren Hops; Farben für Hell und Dunkel.
- Länder: DB-IP „IP to Country Lite“ (CC BY 4.0, Namensnennung „IP Geolocation by DB-IP“ mit Link im Fenster). Heruntergeladen erst nach
  Rückfrage (rund 4 MB von download.db-ip.com, aktueller Monat, sonst der vorige), Größengrenzen für Download und Entpacken, geprüft, bevor
  sie die alte Tabelle in %ProgramData%\SnitchBox\geo ersetzt; Link „aktualisieren“ mit dem Stand der Tabelle. Die Zuordnung geschieht auf
  dem PC (eigener Leser für das MaxMind-DB-Format: jeder Zugriff mit Grenzprüfung, Tiefen- und Arbeitsgrenze; getestet mit eigenem
  Schreiber, 4000 zufällig beschädigten Dateien und 20.000 Abfragen gegen eine Python-Referenz an der echten Datei). Länder nach
  Registrierung der Adresse – Anycast-Adressen (1.1.1.1 → Australien) und Router großer Netze können woanders stehen; das Fenster sagt das.
- Einstellungen: „Namen auflösen“ (an) und „Weltkarte“ (aus) werden gemerkt.
- Prüfung (vier unabhängige Prüfer – ICMP/Ablauf, Daten- und Download-Sicherheit, Fensterabläufe, Kartenzeichnung –, jeder Befund von
  einem Gegenprüfer nachgeprüft; 16 bestätigt, 1 widerlegt, 1 offen, alle bestätigten behoben): „Abbrechen“ wirkte spät im Trace erst
  nach bis zu 3 s (die ICMP-Schnittstelle lässt sich nicht abbrechen; RunAsync wartet jetzt nicht mehr und verwirft späte Antworten); eine
  präparierte Ländertabelle konnte über viele Verweise auf einen großen Text Gigabytes je Abfrage anfordern (das Arbeitsbudget rechnet jetzt
  auch nach Größe ab); die Download-Adresse nutzte den Kalender der Regionaleinstellung (thailändisch ergab 2569-11 und immer 404); ein
  hängender Download hing bis zum Schließen des Fensters (Gesamtfrist 120 s); zwei Fenster, die zugleich luden, kamen sich in die Quere
  (nur ein Download zur Zeit, eigene Zwischendatei); das Ende an der Höchstzahl der Hops (Routing-Schleife, Weg länger als 30 Hops) hieß
  „ab Hop 31 keine Antwort“ (eigener Endzustand); nach einem gescheiterten Neustart kam ein älteres Ergebnis zurück; Rückwärts-DNS-
  Ergebnisse kamen nach dem Abschalten von „Namen auflösen“ zurück; Länder in der Liste ohne die Quellenangabe von DB-IP; ein DNS-Fehler
  genau beim Abbrechen entkam als unbehandelte Ausnahme; feste Spalten schnitten die Länderspalte in schmalen Fenstern ab (die Namensspalte
  gibt jetzt nach, Mindestbreite 840); der Teiler vergaß die Kartengröße nach dem Ausblenden; Trace-Fenster gingen mit dem Netzwerkmonitor
  zu (jetzt eigenständig); die Karte behielt nach einer Größenänderung den alten Zoom und folgte nach einem Klick mit 1 Pixel Zittern der
  Route nicht mehr (Ziehschwelle).
- Gefunden im Live-Test: Ein totes Ziel im eigenen Netz ergab 30 Zeilen „*“ und an Hop 30 zuletzt „nicht erreichbar“ von der eigenen
  Adresse (ARP braucht rund 3 s). Ein „nicht erreichbar“ vom PC selbst gilt jetzt für Hop 1 – eine Zeile, wie bei tracert.
- Nachprüfung der Korrekturen (zwei weitere Prüfer: Vollständigkeit und neue Fehler, mit Mutationsläufen): Die Regel „nicht erreichbar
  vom PC selbst“ darf nicht mehr greifen, sobald ein Router geantwortet hat (ein kurzer WLAN-Aussetzer mitten im Trace hätte ihn sonst
  auf Hop 1 gekürzt – jetzt zählt eine solche Probe als Fehler, und eine späte Antwort des ersten Routers nimmt eine frühere
  Systemmeldung zurück); Trace-Fenster öffnen wieder per CenterOwner (bleiben im Arbeitsbereich des Bildschirms mit dem Hauptfenster,
  passend zu dessen Größe) und lösen sich danach vom Besitzer; die Quellenangabe von DB-IP erscheint auch, wenn ein anderes Fenster die
  Tabelle geladen hat; nach „Abbrechen“ nicht mehr abgewartete Proben zeigen „–“ statt „…“; der Status nach einem Download holt keine
  veraltete Zeile mehr zurück; zwei Tests prüfen jetzt wirklich das späte Abbrechen und die Reihenfolge der Systemmeldung.
- 65 neue Kern-Tests (387 insgesamt), 61 neue Texte in allen 12 Sprachen.

## Build 42 – wohin sendet ein Programm?
Wunsch des Nutzers: anzeigen, wohin ein Programm wie Claude gerade sendet.
- Netzwerkmonitor: links ein Programm wählen (keine Verbindung gewählt) und „Route verfolgen …“, oder Rechtsklick auf das Programm
  („Wohin sendet das Programm? Ziele verfolgen …“). „Alle Programme“ verfolgt die Ziele aller Programme.
- Ziele (TraceTargets): je Gegenadresse eins aus den Zeilen des Monitors seit dem Start von SnitchBox, das zuletzt benutzte zuerst,
  höchstens 20 (ältere werden als ausgelassen gezählt); Name aus DNS/SNI, Zahl der Verbindungen und Datenmenge zusammengezählt; Loopback,
  Multicast, Broadcast, unbestimmte und verbindungslokale Adressen fallen weg (verbindungslokalen fehlt die Schnittstelle).
- Fenster: Liste mit Ziel, Adresse, Land, Hops, Zeit und Datenmenge; Tooltip mit allen Hops; Doppelklick öffnet die Hop-Liste dieses
  Ziels; „Erneut verfolgen“. Die Karte zeigt einen Punkt je Land (orange mit der Zahl der Ziele, grüner Start, kleiner Punkt für
  Durchgangsländer), die Wege als Stücke zwischen Ländern, gestrichelt zum Land des Ziels, wenn es keinen Ping beantwortet; ein gewähltes
  Ziel wird kräftig mit Pfeilen gezeichnet, die übrigen blass.
- Gemessen am Anschluss des Nutzers (FRITZ!Box): Ganze Traces parallel verloren bis zu 10 von 18 Antworten von Hop 1, und selbst Hop 1
  aller Ziele nacheinander verlor 26 von 45 – der Router beantwortet nach einem Schub von rund sechs nur etwa eine Probe je Sekunde.
  Daher TraceGroup: Hop 1 wird einmal je Gateway abgefragt (GetBestRoute2: Schnittstelle + nächster Hop; Ziele im eigenen Netz und VPNs
  mit eigenem Gateway einzeln) und von den übrigen Zielen übernommen (Tracer.TryAdoptFirstHop – nur wenn Hop 1 als Router antwortete und
  dort nichts endete), danach laufen die Runden von bis zu sechs Zielen gleichzeitig. Ergebnis: keine Antwort von Hop 1 verloren, 6 Ziele
  in 4,9 s, 15 in 7,3 s; gemeinsame Router des Providers drosseln einzelne Proben, wenn viele Ziele zugleich laufen (sie zeigen „*“).
- Antwortpuffer je Probe 8 KB statt 64 KB (eine ICMP-Fehlermeldung zitiert höchstens 576/1280 Bytes; jetzt laufen Hunderte zugleich).
- Prüfung (drei unabhängige Prüfer – Gruppe/Kern, Fensterabläufe, Karte –, jeder Befund von einem Gegenprüfer nachgeprüft; 11 bestätigt,
  2 widerlegt, alle behoben): Ein erster Router, der nie antwortet, kostete je Ziel 1 s, bevor irgendetwas geschah (jetzt warten nur zwei
  Ziele je Gateway auf ihn, die übrigen schicken ihre Proben für Hop 1 mit den Runden; Ziele ohne Gateway fragen Hop 1 gleichzeitig ab);
  VPN-Tunnel und PPP (Standardrouten wie 0.0.0.0/1 ohne nächsten Hop) bekamen keinen gemeinsamen Hop 1 (jetzt ein Schlüssel je
  Tunnel-Schnittstelle); ein Ziel, das eine andere Adresse des Routers selbst ist (seine WAN-Adresse), hatte nach der Übernahme von Hop 1
  zwei Hops (eine Probe mit TTL 1 nach den Runden korrigiert das); Broadcast-Adressen der eigenen Netze (192.168.178.255) wurden verfolgt
  (fallen weg); „Alle Programme“ ergab ungrammatische Texte (eigener Titel, Stand ohne Programmnamen); „Erneut verfolgen“ nahm nie neue
  Ziele dazu (das Fenster holt sie bei jedem Start); der Schlussstand zählte „nicht erreichbar“, „über 30 Hops“ und Sendefehler als „ohne
  Antwort“ (getrennt gezählt, „kein Netz“, wenn nichts von außen kam); abgebrochene Traces bekamen eine gestrichelte „vermutete“ Linie;
  Ländernamen verdeckten Punkte (in der Übersicht nur dort, wo sie nichts verdecken, Länder mit den meisten Zielen zuerst); eine
  durchgezogene und eine gestrichelte Linie für dasselbe Länderpaar überdeckten sich (eine Linie je Paar, gestrichelt nur, wenn jeder Weg
  darüber vermutet ist); der Tooltip nahm den letzten Punkt im Umkreis von 13 Pixeln statt des Punkts unter der Maus.
- Nachprüfung der Korrekturen (zwei weitere Prüfer): IPv4- und IPv6-Ziele über einen Tunnel mit beiden Familien teilten einen Schlüssel,
  der IPv6-Trace übernahm so den Hop 1 von IPv4 (Schlüssel je Adressfamilie, TryAdoptFirstHop vergleicht die Familien); Split-Tunnel-Routen
  wie 10.0.0.0/8 galten als eigenes Netz (eine Route ohne nächsten Hop gilt jetzt nur als LAN, wenn das Ziel im Netz einer eigenen Adresse
  dieser Schnittstelle liegt – Tunnel-Adressen haben meist /32); dasselbe Länderpaar in beide Richtungen ergab noch zwei Linien übereinander
  (eine Linie je Paar ohne Richtung, kein Pfeil, wenn Wege in beide Richtungen laufen); die Gegenstelle eines /31-Punkt-zu-Punkt-Netzes galt
  als Broadcast-Adresse.
- Die Platzhalterprüfung der Kern-Tests nimmt Texte mit bis zu sechs Zahlen. 16 neue Kern-Tests (403 insgesamt), 33 neue Texte in allen
  12 Sprachen.

## Build 43 – Verlauf, Suche und Weltkarte im Netzwerkmonitor
Wunsch des Nutzers: Punkte 1–3 der Liste fehlender Funktionen.
- **Verlauf über Neustarts** (HistoryFile, private\history.json im Datenordner): Die Zeilen des Netzwerkmonitors (Programm, Dienst,
  Gegenstelle samt aller DNS-Namen, Port, Zustand, Anzahl, Datenmenge je Tag, zuletzt übertragen; auch noch offene Rückfragen) und die
  Datenmenge je Tag und Programm (DailyTraffic, gespeist aus derselben Zählung je Programm wie bisher) werden alle fünf Minuten gesichert,
  wenn sich etwas geändert hat (im Hintergrund), außerdem beim Beenden und beim Abmelden von Windows; geladen wird beim Start, bevor der
  Filter läuft; geladene Zeilen zeigen, wie die geltenden Regeln entscheiden. Einstellungen → „Verlauf des Netzwerkmonitors aufheben“: nur
  bis zum Beenden, 7, 30 (Standard), 90 Tage oder ein Jahr; Kürzen wirkt sofort, „nur bis zum Beenden“ löscht die Datei, „Verlauf leeren“
  löscht nach einer Rückfrage alles. Ein Tag zählt ab Mitternacht (Ortszeit); „30 Tage“ heißt heute und die 29 Tage davor – überall gleich
  (Zeilen, Programmliste, Diagramm). Mit Verlauf zeigt die Programmliste die Datenmenge über die aufgehobenen Tage (die Rate bleibt die
  aktuelle), die Datenmenge einer Zeile ist die Summe ihrer aufgehobenen Tage; Programme, von denen nur noch Datenmengen aufgehoben sind
  (Verbindung von vor dem Start, Filter aus, Zeile verdrängt), bleiben in der Liste („Nur Datenmenge aus dem Verlauf“) – so stimmt „Alle
  Programme“ mit dem Diagramm überein. Eine lange offene Verbindung (Netzlaufwerk, Download) bleibt, solange sie überträgt, auch wenn sie vor
  Wochen entschieden wurde; die Spalte „Zuletzt“ zeigt heute die Uhrzeit, sonst das Datum. Die Prozessnummer wird mitgespeichert: Regeln „bis
  zum Beenden“ gelten nach einem Neustart von SnitchBox weiter für die geladenen Zeilen des noch laufenden Programms (nach einem Neustart von
  Windows wird sie verworfen).
- **Schutz der Datei:** Der Unterordner private\ ist nur für SYSTEM und Administratoren lesbar (der Verlauf zeigt, welches Programm wohin
  verbunden hat; die Einstellungen daneben bleiben für Benutzer lesbar). Angelegt wird er erst, nachdem der Datenordner geprüft und
  aufgeräumt ist, und vor jedem Schreiben wird er geprüft: fehlt er (etwa von Hand gelöscht), entsteht er gleich mit diesen Rechten, hat er
  sie verloren, bekommt er sie zurück, eine Verknüpfung oder ein fremder Eigentümer verhindert das Schreiben. Geschrieben wird in eine Zwischendatei, die auf die Platte gebracht und dann ersetzt wird (nach einem Absturz keine Datei voller
  Nullen). Der Leser überspringt ungültige Einträge (null, Adresse, Aufzählungswerte, Textlängen), nimmt höchstens 4000 Zeilen (die neuesten)
  und 5000 Programme je Tag und legt eine kaputte Datei als .kaputt beiseite – eine gerade gesperrte (ein anderes Programm hält sie offen)
  dagegen nicht, und SnitchBox schreibt in dieser Sitzung nicht darüber. Über 64 MB werden die ältesten Tage weggelassen. Ein Fehler im
  Verlauf hält den Start nie auf; ein Sichern, das vor „Verlauf leeren“ begann, schreibt danach nichts mehr zurück (Generationszähler).
- **Datenmenge je Tag:** Der Umschalter „Je Tag“ im Kopf zeigt Balken für das gewählte Programm (Windows-Dienste: alle Dienste zusammen, wie
  die Zählung je Programm; bei einer Suche und „Alle Programme“ die gefundenen Programme), höchstens 60 Tage, Tooltip mit Datum und Mengen;
  der Kopf zeigt die Summe des Zeitraums.
- **Suche** unter den Listen: filtert Programmliste, Verbindungen und Karte nach Programmname, Pfad, Dienst, Gegenstelle, Adresse, Port,
  Protokoll, Land, Zustand und Richtung; mehrere Wörter müssen alle passen, Groß-/Kleinschreibung und Akzente zählen nicht („osterreich“
  findet „Österreich“). Mit Suche zeigt „Alle Programme“ die Summen der gefundenen Programme.
- **Weltkarte** statt der Verbindungsliste (Umschalter „Weltkarte“, gemerkt): je Land ein Punkt mit der Zahl der Gegenstellen, rot, wenn
  alle Verbindungen dorthin verboten sind, Linien von deinem Land aus (Regionseinstellung von Windows, keine Netzabfrage) – Linien gerade
  übertragender Verbindungen kräftig, die übrigen blass; Tooltip mit Datenmenge und den größten Gegenstellen; Doppelklick auf ein Land
  setzt die Suche „land:XX“ (genau dieses Land, nicht jeder Text mit diesen Buchstaben; „country:XX“ geht auch). Gegenstellen im eigenen Netz und ohne bekanntes Land werden unter der Karte gezählt. Ohne Ländertabelle bietet die
  Karte das Herunterladen an (dieselbe Rückfrage wie im Trace-Fenster); die Quellenangabe von DB-IP steht auf der Karte.
- Testprogramm für das echte Hauptfenster (Monitor mit erfundenem Verlauf, Karte, Suche, Tagesdiagramm, hell und dunkel).
- Prüfung mit Gegenprüfern (30 bestätigte Befunde, alle behoben): u. a. Verlauf lesbar für jeden Benutzer, lange Verbindungen nach der Frist
  gelöscht, Datenmengen alter Tage in den Zeilen, verlorene DNS-Namen (Regeln für Hosts griffen nach dem Neustart nicht), gesperrte Datei
  beiseitegelegt, Wettlauf zwischen Sichern und Löschen, Absturz beim Start durch null in der Datei, Tagesgrenzen uneinheitlich, Länder-Suche
  per Doppelklick traf auch Hostnamen, Tooltip der Karte nach dem Neuzeichnen falsch. Eine zweite Prüfung der Fixes fand 7 weitere Fehler
  (alle behoben): ein von Hand gelöschter Ordner private\ wäre mit „Benutzer lesen“ neu entstanden (und beim Start vor der Prüfung des
  Datenordners angelegt worden), Programme nur mit aufgehobener Datenmenge fehlten in der Liste, Regeln „bis zum Beenden“ griffen für geladene
  Zeilen nicht, Zeilen nutzten noch eine rollende Grenze (jetzt Mitternacht wie die Tage), das Tagesdiagramm blieb nach der Suche beim vorigen
  Programm, die Karte zählte im eigenen Netz Adressen statt Zeilen, der Tooltip der Trace-Karte konnte zu einem anderen Hop springen. Die
  Gegenprüfung dieser Fixes fand noch 6 Kleinigkeiten (behoben): eine Datei namens „private“ hätte den Start verhindert (der Verlaufsordner
  hält den Start jetzt nie auf), ein gerade von jemand anderem angelegter Ordner wurde nicht geprüft, Verkehr dieser Sitzung von vor dem
  Zeitraum zählte noch in der Programmliste, eine Regel „bis zum Beenden“ eines inzwischen beendeten Programms galt beim Laden noch,
  Sommerzeit verschob die Grenze für Prozessnummern, und die Grenze der Zeilen war nicht durch einen Test gesichert.
- 38 neue Kern-Tests (441 insgesamt), 32 neue Texte in allen 12 Sprachen.

## Build 44 – Ko-fi-Knopf in der Kopfzeile
Wunsch des Nutzers: den Ko-fi-Knopf dauerhaft sichtbar machen. Er steht jetzt in der Kopfzeile hinter „Profil“ (vorher in den
Einstellungen neben der Sprache). Nur wenn das Fenster so schmal ist, dass der Zustand rechts (etwa „Treiber läuft nicht“) keinen Platz mehr
hätte, tritt der Knopf zurück; gerechnet wird ohne den Knopf selbst, damit nichts hin und her springt. Keine neuen Texte.

## Offen
- SNI-Auswertung bei DoH.
- Bewusst nicht umgesetzt (Entscheidung des Nutzers): Schutz ohne laufendes SnitchBox (dauerhafte WFP-Filter beim Hochfahren).
