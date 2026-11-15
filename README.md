# SnitchBox für Windows

Firewall nach dem Vorbild von Little Snitch (macOS) für Windows 11 x64 – WPF/.NET 10, ohne Installation.
Sie zeigt, welches Programm sich wohin verbinden will, hält die Verbindung an und lässt dich erlauben oder verbieten.

*An application firewall for Windows 11 x64 in the spirit of Little Snitch: it shows which program wants to connect where,
holds the connection and lets you allow or deny it. The user interface is available in 12 languages, including English.*

**Download:** unter [Releases](../../releases) – `SnitchBox-Setup.exe` (Installer, richtet bei Bedarf die .NET Desktop Runtime 10 ein)
oder `SnitchBox.exe` (eine Datei, braucht die .NET Desktop Runtime 10). Beide brauchen Administratorrechte und sind nicht signiert
(Windows SmartScreen: „Weitere Informationen“ → „Trotzdem ausführen“).

<a href="https://ko-fi.com/C5H12AP4UV"><img src="src/SnitchBox/kofi.png" alt="Buy me a coffee (Ko-fi)" width="200"></a>

- Warnfenster je neuer Verbindung: Programm, Hostname, Port; Gültigkeit (Einmal … Für immer) und Reichweite (jede Verbindung, Port, Domain, Host)
- Betriebsarten: Warnmodus, Stiller Modus „alles erlauben“ / „alles verbieten“; Netzwerkfilter ein/aus
- Regeln je Programm: Erlauben/Verbieten, aus-/eingehend, Hosts, Domains, Adressbereiche, lokales Netz, DNS-Server des Systems, Ports, TCP/UDP, Priorität, Gültigkeit, Profile
- Netzwerkmonitor: jeder Verbindungsaufbau je Programm und Gegenstelle, Datenmengen und aktuelle Rate je Programm, Gesamtdatenrate, Regel direkt aus einer Zeile
- Blocklisten abonnieren (.lsrules, hosts-Dateien, Domainlisten), tägliche Aktualisierung; Import/Export von .lsrules
- Symbol im Infobereich, Start beim Anmelden über die Aufgabenplanung (ohne UAC-Rückfrage)
- Solange nicht gefiltert wird (Netzwerkfilter aus oder Treiber läuft nicht), zeigen Infobereich und Taskleiste ein rotes Schild mit weißem Kreuz

Technik: Der Treiber WinDivert 2.2.2 (third_party/windivert, unverändert aus dem offiziellen Release, LGPLv3) leitet TCP-Verbindungsaufbau
und UDP durch das Programm. Die Entscheidung trifft der plattformunabhängige Kern (src/SnitchBox.Core).
Der Filter wirkt nur, solange SnitchBox läuft; endet das Programm, läuft der Verkehr ungefiltert weiter.

## Bauen und ablegen

- Windows: `powershell -ExecutionPolicy Bypass -File build-windows.ps1` · Mac: `./build-windows.sh` (zeichnet zusätzlich das Symbol neu).
  Beide zählen BUILD_NUMBER hoch und führen vorher die Kern-Tests aus (`dotnet run --project tests/SnitchBox.Tests`).
- `dist/SnitchBox.exe` – eine Datei, braucht die „.NET Desktop Runtime“ 10 oder neuer (fehlt sie, bietet Windows den Download an). Empfohlen.
- `dist/SnitchBox-Standalone/` – läuft ohne .NET-Installation; die WPF-Bibliotheken liegen neben der .exe.
- `dist/SnitchBox-Setup.exe` – kleiner Installer (unter 1 MB, nur von build-windows.ps1 gebaut) für andere PCs, siehe unten.

## Installer für andere PCs

`SnitchBox-Setup.exe` läuft auf jedem Windows 10/11 x64 ohne Vorbereitung (.NET Framework 4.x ist dort eingebaut) und fragt nach
Administratorrechten. Er
- legt SnitchBox nach `C:\Program Files\SnitchBox` (nur für Administratoren beschreibbar),
- lädt bei Bedarf die .NET Desktop Runtime 10 von Microsoft (`aka.ms/dotnet/10.0/…`, neuester Patch) und installiert sie still – nur wenn
  die Datei gültig von Microsoft signiert ist; ohne Internet bietet er die Download-Seite an,
- legt wahlweise Verknüpfungen im Startmenü und auf dem Desktop an, richtet den Autostart ein und startet SnitchBox,
- beendet ein laufendes SnitchBox für die Aktualisierung und startet es danach wieder,
- trägt sich in „Apps“ ein; dort (oder mit dem Knopf „Deinstallieren“) wird SnitchBox wieder entfernt, auf Wunsch samt Regeln.

Ohne Fenster (z. B. Softwareverteilung): `SnitchBox-Setup.exe /quiet` installiert mit Startmenü-Verknüpfung und Autostart,
`SnitchBox-Setup.exe /uninstall /quiet` entfernt SnitchBox (Regeln bleiben); Protokoll in `%TEMP%\SnitchBox-Setup.log`, Rückgabe 0 = Erfolg.
Läuft der Installer als SYSTEM, gilt der Autostart für jedes Administratorkonto.
Der Installer ist nicht signiert: aus dem Internet geladen, warnt Windows SmartScreen beim ersten Start („Weitere Informationen“ → „Trotzdem ausführen“).
- Beide entpacken beim Start nichts nach %TEMP%. (Bis Build 12 tat die eigenständige Fassung das; was dort unter `%TEMP%\.net\SnitchBox` liegt, kann weg.)
- Ablage: am besten `C:\Program Files\SnitchBox`. SnitchBox läuft mit Administratorrechten; liegt die .exe in einem Ordner, in den auch
  gewöhnliche Programme schreiben dürfen (z. B. Dokumente, Downloads, `C:\Tools`), könnten diese sie austauschen. SnitchBox warnt davor beim
  Einrichten des Autostarts, einmal je Build beim Start (wenn ein bestehender Autostart so eine Datei startet) und in den Einstellungen.
  Nach dem Umzug den Autostart aus- und wieder einschalten, damit er die neue Datei startet.

Sprachen: Deutsch, Englisch, Französisch, Spanisch, Italienisch, Portugiesisch (Brasilien), Polnisch, Türkisch, Russisch, Japanisch,
Chinesisch (vereinfacht), Koreanisch – Standard ist die Windows-Sprache, umstellbar unter Einstellungen → Sprache (wirkt sofort).
Deutsch und Englisch stehen im Code (`Loc.T`/`Loc.F`), die übrigen in `src/SnitchBox.Core/Lang/<code>.json` (englischer Text → Übersetzung).
Neue oder geänderte Texte: `python scripts/extract_strings.py` erneuert die Vorlage `Lang/_source.json` und listet fehlende Übersetzungen;
die Build-Skripte brechen ab, solange eine Sprache unvollständig ist.

Start-Parameter: `--appearance light|dark`, `--lang de|en|fr|es|it|pt|pl|tr|ru|ja|zh|ko`, `--tray`, `--demo` (erfundene Verbindungen ohne Treiber, Daten getrennt in `%ProgramData%\SnitchBox\demo`).
Daten und Protokoll: `%ProgramData%\SnitchBox\` (config.json, log.txt, blocklists\, driver\). Der Ordner ist nur für Administratoren beschreibbar;
SnitchBox stellt das bei jedem Start sicher: Fremde Einträge (von anderen Programmen angelegt) werden als `%ProgramData%\SnitchBox.unsicher-…`
beiseitegeschoben, Verknüpfungen entfernt. Lässt sich der Ordner nicht absichern (z. B. weil ein anderes Programm Dateien darin offen hält),
startet SnitchBox nicht und nennt den betroffenen Eintrag.
Zurück zu Build 12: Build 13 stellt die Werksregeln um, was Build 12 nicht lesen kann; der vorherige Stand liegt in `config.json.vor-werksregeln-2`.

## Verhalten, das man kennen sollte

- Lässt sich das Programm einer Verbindung nicht ermitteln, gilt die Antwort im Warnfenster nur für diesen Versuch: eine Regel ohne Programm gälte für alle Programme.
- Werksregeln: DNS darf jedes Programm nur zu den DNS-Servern des Systems (aus den Netzwerkeinstellungen), DHCP nur ins lokale Netz.
  Die Regel für den Windows-Kern („System“) gilt nur für ihn selbst, nicht für Dateien, die zufällig System heißen.
  Alle Windows-Dienste laufen als svchost.exe und sind über eine Werksregel gemeinsam erlaubt.
- Lokaler DNS-Resolver (als DNS-Server ist 127.0.0.1, ::1 oder eine eigene Adresse eingetragen, z. B. dnscrypt-proxy, AdGuard):
  Seine Anfragen nach draußen fragt SnitchBox einmal nach (die Werksregel öffnet Port 53 dann nicht für jeden Server).
- Blocklisten sperren auch Programme, denen „jede Verbindung“ erlaubt ist. Vorrang haben nur Erlauben-Regeln mit hoher Priorität
  oder für genau diesen Host, diese Domain oder Adresse.
- Hostnamen stammen nur aus DNS-Antworten auf erlaubte, beobachtete Anfragen – und, ohne lokalen Resolver, nur von den DNS-Servern
  des Systems –, damit kein Programm einer Adresse einen falschen Namen geben kann. Bei verschlüsseltem DNS (DoH) erscheint die IP-Adresse.

## Grenzen

- Nicht gefiltert: ICMP, Verkehr am eigenen Rechner (Loopback), eingehendes UDP sowie eingehende Verbindungen auf Ports, auf denen kein
  Programm lauscht (Portscans, Weiterleitungen an virtuelle Maschinen) – darüber entscheidet die Windows-Firewall.
- Das Programm zu einer Verbindung ermittelt SnitchBox über den lokalen Port (Socket-Ereignisse, Port-Tabellen von Windows). Gegen
  Schadsoftware, die schon als derselbe Benutzer läuft und Ports gezielt neu belegt, ist das kein vollständiger Schutz.
- Der Autostart läuft mit der Umgebung des Benutzers. Startup-Hooks und `DOTNET_ROOT` sind abgeschaltet, andere Laufzeit-Variablen
  aus der Benutzerumgebung beachtet die .NET-Laufzeit aber noch und könnten darüber Code mit Administratorrechten ausführen: Profiler
  (`CORECLR_*`), Diagnose-Ports (`DOTNET_DiagnosticPorts`) und bei `SnitchBox.exe` (framework-abhängig) `DOTNET_ADDITIONAL_DEPS`/`DOTNET_SHARED_STORE`.
  Vollständig schlösse das erst ein Start mit bereinigter Umgebung (kleiner nativer Starter oder Dienst) – noch nicht umgesetzt.
- Die Herausgeber-Angabe im Warnfenster wird ausgelesen, nicht kryptografisch geprüft.

Details zum Original und zur Technik: docs/RE-NOTES.md.

## Lizenz

Eigener Code: MIT-Lizenz (siehe [LICENSE](LICENSE)). WinDivert 2.2.2 in `third_party/windivert` behält seine eigene Lizenz
(LGPLv3 oder GPLv2, siehe [third_party/windivert/LICENSE](third_party/windivert/LICENSE)).
Little Snitch ist eine Marke der Objective Development Software GmbH. SnitchBox ist ein unabhängiges Projekt; übernommen sind nur
das Bedienkonzept und das offene `.lsrules`-Format, kein Code und keine Grafik.
