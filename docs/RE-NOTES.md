# Findings on the original and technical decisions

**English** · [Deutsch](RE-NOTES.de.md)

Model: Little Snitch 6.5 (build 7303), /Applications/Little Snitch.app. Examined with REA (static analysis) and the bundled text files.
No code and no graphics were taken over; adopted are the user interface concept and the open .lsrules format.

## Structure of the original (observed)
- Main app (rules/settings), plus Components/: “Little Snitch Agent.app” (alert window, menu bar),
  “Little Snitch Network Monitor.app”, “Software Update.app”, command line tool `littlesnitch`.
- Filter: system extensions at.obdev.littlesnitch.networkextension and …endpointsecurity; daemon in /Library/Application Support.
- Alert window (Agent, ConnectionAlert.strings): “… wants to connect to %host on %port”, scopes “Any Connection”, “Only port”,
  “Only %host”, “Only %host and %port”, “domain %@”, “Only local network”; incoming and outgoing handled separately.
- Lifetime (RuleLifetimeOption.strings): Once, Until Quit, Until Logout, Until Restart, 1 Minute, 10 Minutes, 2 Hours, 1 Day, 7 Days, 30 Days, Forever.
- Modes: Alert Mode, Silent Mode (allow/deny); profiles; rule groups and blocklists with subscriptions.
- Rule precedence according to the texts: high priority; more specific rules override more general ones (“redundant/overridden”).

## .lsrules (REA search_strings in the main app, evidence ev_abb2d20a…)
Keys present in the app: name, description, rules, action (allow/deny/ask), process, via, direction (incoming/outgoing),
priority, disabled, ports, protocol, remote (any, local-net, multicast, broadcast, bonjour, bpf), remote-hosts, remote-domains,
remote-addresses, notes, lifetime, creationDate/modificationDate, owner, denied-remote-domains/-hosts/-addresses/-notes.
SnitchBox reads and writes: action, process, direction, priority, disabled, ports, protocol, remote* (any, local-net, dns-servers;
multicast/broadcast/bonjour are read as local-net), notes, denied-remote-domains/-hosts.

## Implementation on Windows
- Interception: a WinDivert handle on the network layer with the filter
  `!loopback and ((outbound and ((tcp.Syn and !tcp.Ack) or udp)) or (inbound and ((tcp.Syn and !tcp.Ack) or udp.SrcPort == 53)))`.
  Only these packets pass through the program; established TCP connections stay in the kernel.
- Process per packet: a second handle on the socket layer (sniff only) provides the PID per local port; fallback GetExtendedTcpTable/UdpTable.
- Holding: undecided packets are held back and re-injected after the answer. TCP retransmits the SYN on its own for about 20 s.
- Deny: drop the SYN and deliver an RST+ACK to the program (it fails immediately instead of after a timeout). Incoming: drop silently.
- Data volume: a third handle (sniff only, priority −1, filter `!loopback and (tcp or udp)`) fetches packets in batches via WinDivertRecvEx;
  counted per local port and assigned to the program once per second (TrafficStats in the core). Under overload only numbers go missing.
- Host names: DNS answers (UDP from port 53) are read along, but only from the system’s DNS servers and only when they match an
  observed query; the DNS cache is flushed at startup.
- Fail-safe: errors during evaluation let the packet pass; if the alert window does not open, SnitchBox switches to “allow all”.
- Checked with REA inspect_pe_resources: dist/SnitchBox.exe contains a manifest (RT_MANIFEST, requireAdministrator), an icon group with 9 sizes and version info.
- WinDivert checksums (build-windows.sh verifies them): release zip 63cb4176…3f15, WinDivert.dll c1e060ee…d9a2, WinDivert64.sys 8da08533…ddc2.

## Review and fixes (1.0.1, build 13)
- Unknown process: answers are no longer remembered as a rule (an empty program field would mean “any process”).
- Process per port: the socket event “closed” removes the mapping; otherwise, after a port was reassigned, the old program could decide.
- Waiting connections: each one is recorded per alert (not only those with a held packet); before, connections beyond
  the 64-packet limit hung forever.
- Incoming without a listening program: let through instead of asking, without the 15 ms wait (port scans produced up to 100 alert windows).
- DNS: answers only count if they come from a system DNS server and answer an observed query (server, port, ID).
  Factory rule DNS only to these servers (new remote kind “dns-servers”), DHCP only into the local network; factory rule revision 2
  adapts existing rules at startup.
- Saving: the state is captured under the lock and written outside it, sequentially and never older over newer; blocklist files outside the lock.
- Blocklists also apply against general allow rules (see README).
- Permissions: %ProgramData%\SnitchBox writable by administrators only (foreign entries taken over, links removed); driver files
  compared by SHA-256 with the embedded original; ipconfig/schtasks/notepad called with full path; task XML in the data folder;
  warning for autostart from a world-writable folder; build without extraction to %TEMP%\.net.
- Loopback packets are let through immediately even with the fallback filter (without “!loopback”).
- Second round after an adversarial review (6 perspectives, cross-check per finding, 19 confirmed findings):
  - Data folder: link or foreign owner → move aside and recreate with a finished DACL; delete foreign entries instead of
    taking them over (open handles would otherwise keep their rights); every failure aborts the start; no logging before that (Log.Enabled).
  - Driver files stay open after the hash check until after WinDivertOpen (read sharing only).
  - “System” (Rule.KernelProcess) is never compared as a file name, only literally (PID 4).
  - csproj: StartupHookSupport=false, AppHostDotNetSearch=Global (no hooks, no DOTNET_ROOT from the user environment).
  - DNS: an empty server list keeps the last known state; a local resolver is also recognized under one of the machine’s own addresses,
    the factory rule then allows only it; queries are remembered only after an allowing verdict; under flooding the oldest are evicted;
    an unknown DNS server triggers a throttled re-read; re-read 3 s after an address change; reads run sequentially.
    Blocklists: DnsServers only counts as an exception when the server list is known.
  - Process per port: event time stored (QPC, like the WinDivert timestamp); older than 2 s → cross-check with the port table;
    closed sockets remain as a fallback for 5 s (packets) or 10 s (data volume); for incoming connections only listening TCP ports
    count (listener table, supplemented by LISTEN events; details in round 4 below).
  - Autostart: an existing task is checked (command from schtasks /XML), warning once per build and as a hint in the settings;
    the check works as an allow list (only Administrators, SYSTEM, TrustedInstaller) including DLLs next to the file and parent folders.
  - Demo mode uses %ProgramData%\SnitchBox\demo (hardened) instead of %TEMP%.
  - Before factory rule revision 2, a backup config.json.vor-werksregeln-2 is written; “.defekt” backups get a timestamp.
  - build-windows.ps1 aborts on any error; EditRule discards expired “until quit” rules with an honest notice.
- Third round after the second review (5 perspectives, 11 confirmed findings, all low):
  - Data folder: a file in place of the folder and an unreadable owner count as foreign (moved aside); foreign entries are first
    deleted without taking ownership, otherwise after taking it – if deletion fails, they get a foreign owner again; the error message names the entry.
  - Temporary files (config.json.tmp, blocklists) are deleted and recreated, never overwritten.
  - Process per port: the backlog of socket events is measured; above 100 ms only the port table counts. Outgoing TCP only via the row
    with exactly this remote (address and port), rows without an owner are skipped. Listeners per address family, loopback listeners
    don’t count, re-read after 25 ms for an unknown port.
  - DNS servers additionally from the NRPT (split DNS); re-read for an unknown server at most every 3 s.
  - Autostart: command read from %SystemRoot%\System32\Tasks\SnitchBox (UTF-16) instead of from the schtasks output; warning also when the target file is missing.
  - Deliberately open: runtime variables from the user environment (CORECLR_*, DOTNET_DiagnosticPorts, DOTNET_ADDITIONAL_DEPS) – would need a
    native launcher with a sanitized environment; a flood of allowed DNS queries between query and answer can evict a name.
- Fourth round after a targeted review of the third (3 perspectives, 5 confirmed findings):
  - Listeners: GetExtendedTcpTable with TCP_TABLE_OWNER_PID_LISTENER (3) instead of checking the state field for 2. On Windows build 26300
    (measured on the test machine) the state field of listeners mostly contains 0, 1 or 6, and netstat shows them wrongly too – the check missed
    almost all listeners and would have let incoming connections through without asking.
  - LISTEN events enter only wildcard listeners (0.0.0.0/::) directly, otherwise the table is re-read (WinDivertAddress.LocalAddr*).
  - Foreign entries in the data folder: no longer deleted recursively (swapping in a junction during deletion would have redirected deletions),
    but moved without recursion to %ProgramData%\SnitchBox.unsicher-…; links themselves are deleted; everything via “\\?\” paths,
    names with a trailing dot or space count as foreign; afterwards it is checked that the name is free. Taking ownership is no longer needed.
  - NRPT: DirectAccessDNSServers as well.

## Build 14
- Red shield (ShieldIcon.cs, drawn at runtime: shield shape from make_win_icon.swift, red, white cross) in the tray and as the
  window icon as long as App.Filtering() is false (network filter off or driver not running); the tooltip names the reason.

## Build 15
- Installer installer/Setup.cs → dist/SnitchBox-Setup.exe (~0.95 MB): .NET Framework 4.x, C# 5, compiled with Windows’ own
  csc.exe (runs on any Windows 10/11 without preparation); contains dist/SnitchBox.exe; runtime download via the aka.ms channel link with
  WinVerifyTrust + publisher “Microsoft Corporation”; file and task XML only in the program folder (admin-only); /quiet, /uninstall.
  Components tested without admin rights via reflection; the actual installation needs UAC.

## Build 16
- 12 languages (de, en, fr, es, it, pt-BR, pl, tr, ru, ja, zh-Hans, ko): Loc.T/Loc.F in the code (de/en), other languages in
  src/SnitchBox.Core/Lang/<code>.json (English text → translation, embedded); texts with values use placeholders (Loc.F);
  selection under Settings → Language (Settings.Language, effective immediately) or --lang; the installer uses the same tables
  (only its own texts, DataContractJsonSerializer). scripts/extract_strings.py generates Lang/_source.json and checks completeness,
  placeholders, line breaks and access keys; build scripts and core tests abort on gaps. Translated by AI agents
  (two languages each), not proofread by native speakers.

## Build 17
- Installer window: fluid layout (TableLayoutPanel/AutoSize, Segoe UI 9 pt, wrapping texts, growing buttons) instead of fixed
  coordinates with SystemFonts.MessageBoxFont – at 175 % the subtitle ran out of the window; plus a forced repaint after it
  appears (parts of the window were missing after the UAC prompt). Checked at 100 % and 175 % in de/fr/ru/ja;
  a real installation run was confirmed (installer works, display correct).

## Build 18
- Section buttons (Rules, Network Monitor, Blocklists, Settings) readable in dark mode: the custom NavButton style replaces
  the Fluent style, and without a text color the classic dark system color applied (black on dark gray). Now they use the window’s
  text color (binding to Window.Foreground: white in dark mode, #E4000000 in light mode); the selected section stays white on blue.
  Checked with a render test using the real Styles.xaml in both themes.

## Build 19
- Network Monitor “Allow…”/“Deny…” seemed to have no effect (user report): the rule was created (it was in
  config.json), but the row kept showing the old state until the program connected again – for SystemSettings.exe possibly never.
  Now the engine updates all rows to the current rules after every rule change (Mutate, alert with rule, expired rules, DNS servers)
  (ConnectionLog.Reevaluate). Without a matching rule the state is “No rule” (gray, “the next attempt will ask”)
  instead of “Asking…”; “Asking…” only while an alert window is open (ConnectionRecord.Pending).
- Same scope (Rule.SameScope: process, direction, remote, ports, protocol, profile): when saving in the
  rule editor, the new rule replaces an own rule with the same scope – on a tie “Deny” would win,
  so an “Allow” for a denied connection would have no effect. Factory rules stay.
- After “Allow…”/“Deny…” in the monitor, SnitchBox checks whether the rule takes effect for this connection and otherwise names
  the rule or blocklist that takes precedence.
- Established IPv4 TCP connections that a rule change newly denies are cut (SetTcpEntry with DELETE_TCB,
  FilterService.OnRulesApplied; Engine.RulesApplied provides the rules before and after). The filter only sees connection setup;
  without this, an open browser connection, for example, would keep running. IPv6 TCP cannot be cut this way (no Windows API):
  there the rule takes effect from the next connection setup. UDP is affected immediately (flow cache per rule revision).
  Cutting is not yet tested in a real run (needs admin rights).

## Build 20
- Settings: section “Support SnitchBox” with a Ko-fi button (link ko-fi.com/C5H12AP4UV; the official Ko-fi button image is
  embedded as a WPF resource src/SnitchBox/kofi.png, style ImageButton – the settings load nothing from the network).
  Because SnitchBox always runs as administrator, DesktopShell.cs opens web addresses via the desktop shell
  (ShellWindows → IShellDispatch2.ShellExecute, Raymond Chen’s method), so the browser runs with the user’s normal rights instead of
  elevated; tested: the started process has explorer.exe as its parent.

## Build 21
- Ko-fi button moved next to the language selection (at the bottom of the settings it was only visible after scrolling); the hint
  text is now a tooltip, the separate section is gone.

## Build 22
- Too many rules for the same program (user report, 17 rules for BackgroundDownload.exe): the Visual Studio installer copies itself
  to a new random folder on every start (R:\Temp\obkz3fue.blc\…\BackgroundDownload.exe), so a rule with the full path never matched
  again; each alert (scope “host”) also created a rule of its own.
- Process patterns: `*` in the process field stands for any part of a folder or file name (never for “\”; never matches an unknown
  process). AlertRules.ProcessPattern turns changing folder names into `*`: the first subfolder of a temp folder (%TEMP%,
  %SystemRoot%\Temp, …\AppData\Local\Temp; never a whole drive), version folders (2.1.325, v1.2, app-1.0.3), GUID and hash folders,
  and the version in Store package folders (Claude_*_x64__pzs8sxrjxfjjc). Rules from the alert window and the monitor use it, so
  they keep matching after the next start or update. Folders writable by the user stay just as protected as before (anyone who can
  create such a folder could also have replaced the file at the old location).
- RuleCleanup (Cleanup.cs): rules that differ only in their hosts, domains or addresses are combined into one rule (a new alert
  answer with scope “host” adds the host to the existing rule); a rule is removed when a broader rule with the same action makes it
  superfluous – same or wider process, remote, ports, protocol and profile, at least the same lifetime, and no rule with the opposite
  action ranks between the two (then the decision is identical with or without it); allow rules that exempt a host from blocklists
  are only replaced by rules that do the same. Applied when a rule is created (alert window, rule editor).
- Rules → “Clean Up…”: shows what changes and applies it after confirmation – generalize temp/version paths, remove superfluous
  rules, combine rules of the same kind, remove rules for programs that no longer exist (full paths only, checked outside the engine
  lock). Factory rules stay untouched. Dry run on the test machine’s rules: 90 → 43, BackgroundDownload.exe 17 → 3.

## Build 23
- Windows Update and Virus & threat protection recognizable as rules (user request): their programs outside svchost.exe have
  meaningless names (SIHClient.exe, MoUsoCoreWorker.exe, MpCmdRun.exe …) and were easily denied by accident – the test machine had a
  rule denying SIHClient.exe and one denying MpCmdRun.exe access to definitionupdates.microsoft.com (virus signatures).
- WindowsComponents (Components.cs): recognizes them by file name and location – Windows Update directly in System32/SysWOW64 or below
  UUS, WinSxS, servicing, SoftwareDistribution; Defender below ProgramData\Microsoft\Windows Defender\Platform\ and the Windows Defender
  program folders. Only folders writable by Windows and administrators alone, so no program can pose as Windows Update by its file name
  (subfolders of System32 don’t count, some are writable by everyone).
- Process “@windows-update” / “@defender” in a rule = all programs of the component. Factory rule revision 3 adds “Windows Update” and
  “Virus & threat protection” (allow outgoing, can be switched off); own deny rules for single programs still take precedence
  (same rank, deny wins a tie).
- Display: the rule list shows “Windows Update” / “Virus & threat protection” as the process, or “Windows Update · SIHClient.exe” for
  rules of single programs, with the icon of Settings or Windows Security; the same in the Network Monitor; the alert window names the
  component and says what denying it does.

## Build 24
- Warning before protection ends (user request): turning off the network filter (switch in the main window, tray menu) and
  “Quit (Filter Off)” in the tray menu now ask first – afterwards every connection passes without asking. The default button is “No”,
  so an accidental Enter changes nothing. Quitting only asks while SnitchBox is actually filtering; turning the filter on never asks.
  App.SetFilterEnabled / App.QuitAsked; if cancelled, the switch returns to the actual state.

## Build 25
- Windows services individually: all services in svchost.exe shared one factory rule “allow any”, including telemetry (DiagTrack,
  “Connected User Experiences and Telemetry”). Now the process lookup also determines the service: Native.Services enumerates the
  running Win32 services with their process ID (EnumServicesStatusEx, no admin rights needed), FilterService.ServiceOf maps a svchost
  PID to its service – only if the process hosts exactly one (test machine: 91 of 95 service processes; shared ones such as
  RpcSs + RpcEptMapper can’t be told apart and fall under the svchost rule). User service instances lose their per-logon suffix
  (CDPUserSvc_4396b → CDPUserSvc).
- Connection/ConnectionRecord/ProcessInfo carry the service; Rule.Service restricts a rule to one service (rank between process and
  remote, so “deny DiagTrack” beats the svchost factory rule); the alert window and the monitor buttons fill it in; rule editor field
  “Windows service”; .lsrules export/import keeps it under “snitchbox-service”; Cleanup treats a rule without service as covering
  every service. Newly denied IPv4 TCP connections of a service are cut as well.
- Display: the Network Monitor lists each service as its own row (“Windows service: Connected User Experiences and Telemetry”, data
  volumes stay on the svchost row because traffic is counted per program), the rule list and alert window show the localized
  display name (Native.ServiceDisplayName).
- Note: older builds ignore Rule.Service – going back would turn “deny DiagTrack” into “deny svchost.exe”.

## Build 26
- Real signature check (Signature.cs): the alert window used to only read the publisher from an embedded signature. Now Windows checks
  the signature (WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2) – embedded signatures and, if there is none, catalog signatures
  (CryptCATAdmin…: file hash → catalog → WinVerifyTrust with WTD_CHOICE_CATALOG; SHA256, then SHA1). No network access
  (WTD_REVOCATION_CHECK_NONE, WTD_CACHE_ONLY_URL_RETRIEVAL), results cached per path, size and modification time; runs after the alert
  window has opened. Display: “✓ Google LLC – valid signature” (green, “Windows catalog” for catalog signatures), “⚠ Invalid signature
  – the file was modified or the certificate is not trusted (0x…)” (red), “not signed”.
- Checked on the test machine: svchost.exe/SIHClient.exe (Microsoft Windows Publisher), chrome.exe (Google LLC), devenv.exe (Microsoft
  Corporation), a copy of notepad.exe (catalog, Microsoft Windows), an unsigned exe, and devenv.exe with one changed byte
  (invalid, TRUST_E_BAD_DIGEST); at most 42 ms per file.

## Open
- Data volume per remote, service names behind svchost.exe, signature check (WinVerifyTrust), SNI evaluation with DoH, protection while the program is not running.
