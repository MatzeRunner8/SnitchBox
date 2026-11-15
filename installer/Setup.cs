// SnitchBox-Setup: kleiner Installer für andere PCs.
// Bewusst für das .NET Framework 4.x geschrieben (C# 5, übersetzt mit dem in Windows mitgelieferten csc.exe): das ist auf
// jedem Windows 10/11 vorhanden, der Installer braucht also nichts vorab. Er bringt SnitchBox.exe (framework-abhängig) als
// Ressource mit, installiert bei Bedarf die .NET Desktop Runtime von Microsoft (mit Signaturprüfung), legt SnitchBox nach
// C:\Program Files\SnitchBox (nur für Administratoren beschreibbar), Verknüpfungen, die Autostart-Aufgabe und einen Eintrag
// in „Apps“ an (Deinstallation). Aufruf: SnitchBox-Setup.exe [/quiet] · SnitchBox-Setup.exe /uninstall [/quiet]
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("SnitchBox Setup")]
[assembly: AssemblyProduct("SnitchBox")]
[assembly: AssemblyCompany("justbox")]

namespace SnitchBoxSetup
{
    /// <summary>Sprache wie in SnitchBox: Deutsch/Englisch im Code, sonst Tabellen Lang.&lt;code&gt;.json (englischer Text → Übersetzung).</summary>
    internal static class L
    {
        static readonly string[] Supported = { "de", "en", "fr", "es", "it", "pt", "pl", "tr", "ru", "ja", "zh", "ko" };
        public static readonly string Language = Detect();
        static Dictionary<string, string> _table;

        static string Detect()
        {
            var c = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.ToLowerInvariant();
            return Supported.Contains(c) ? c : "en";
        }

        public static string T(string de, string en)
        {
            if (Language == "de") return de;
            if (Language == "en") return en;
            if (_table == null) _table = Load(Language);
            string s;
            return _table.TryGetValue(en, out s) && !string.IsNullOrEmpty(s) ? s : en;
        }

        public static string F(string de, string en, params object[] args) { return string.Format(CultureInfo.CurrentCulture, T(de, en), args); }

        static Dictionary<string, string> Load(string code)
        {
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("Lang." + code + ".json"))
                {
                    if (s == null) return new Dictionary<string, string>();
                    var json = new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(Dictionary<string, string>),
                        new System.Runtime.Serialization.Json.DataContractJsonSerializerSettings { UseSimpleDictionaryFormat = true });
                    return (Dictionary<string, string>)json.ReadObject(s) ?? new Dictionary<string, string>();
                }
            }
            catch { return new Dictionary<string, string>(); }
        }
    }

    internal sealed class Options
    {
        public bool StartMenu = true;
        public bool Desktop;
        public bool Autostart = true;
        public bool Launch = true;
    }

    internal static class Installer
    {
        public const string TaskName = "SnitchBox";
        public const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SnitchBox";
        // Kanal-Link von Microsoft: zeigt immer auf den neuesten Patch der .NET Desktop Runtime 10.
        public const string RuntimeUrl = "https://aka.ms/dotnet/10.0/windowsdesktop-runtime-win-x64.exe";
        public const string RuntimePage = "https://dotnet.microsoft.com/download/dotnet/10.0";

        public static readonly string InstallDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SnitchBox");
        public static string AppExe { get { return Path.Combine(InstallDir, "SnitchBox.exe"); } }
        public static string SetupCopy { get { return Path.Combine(InstallDir, "SnitchBox-Setup.exe"); } }
        public static string StartMenuLink { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "SnitchBox.lnk"); } }
        public static string DesktopLink { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "SnitchBox.lnk"); } }
        public static string DataDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SnitchBox"); } }
        public static string Self { get { return Assembly.GetExecutingAssembly().Location; } }
        static string System32(string exe) { return Path.Combine(Environment.SystemDirectory, exe); }

        static bool IsSystem { get { using (var id = WindowsIdentity.GetCurrent()) return id.IsSystem; } }

        // ------------------------------------------------------------------ Prüfungen

        /// <summary>SnitchBox gibt es nur für Windows x64 (der Treiber lässt sich auf ARM64 nicht laden).</summary>
        public static string ArchitectureProblem()
        {
            var arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432") ?? Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ?? "";
            return arch.Equals("AMD64", StringComparison.OrdinalIgnoreCase) ? null
                : L.F("SnitchBox läuft nur auf Windows x64 (dieser PC: {0}).", "SnitchBox runs on Windows x64 only (this PC: {0}).", arch);
        }

        /// <summary>Neueste systemweit installierte .NET Desktop Runtime ab Version 10 (dort sucht SnitchBox sie), sonst null.</summary>
        public static string DesktopRuntimeVersion()
        {
            var roots = new List<string>();
            try
            {
                using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
                using (var k = hklm.OpenSubKey(@"SOFTWARE\dotnet\Setup\InstalledVersions\x64"))
                {
                    var location = k == null ? null : k.GetValue("InstallLocation") as string;
                    if (!string.IsNullOrEmpty(location)) roots.Add(location);
                }
            }
            catch { }
            roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet"));
            string best = null;
            Version bestVersion = null;
            foreach (var root in roots)
            {
                var dir = Path.Combine(root, @"shared\Microsoft.WindowsDesktop.App");
                if (!Directory.Exists(dir)) continue;
                foreach (var sub in Directory.GetDirectories(dir))
                {
                    var name = Path.GetFileName(sub);
                    Version v;
                    if (!Version.TryParse(name.Split('-')[0], out v) || v.Major < 10) continue;
                    if (bestVersion == null || v > bestVersion) { bestVersion = v; best = name; }
                }
            }
            return best;
        }

        public static string InstalledVersion()
        {
            try { return File.Exists(AppExe) ? FileVersionInfo.GetVersionInfo(AppExe).ProductVersion : null; }
            catch { return null; }
        }

        public static bool AppRunning() { return Process.GetProcessesByName("SnitchBox").Length > 0; }

        // ------------------------------------------------------------------ Installieren

        public static void Install(Options o, Action<string, int> progress)
        {
            var wasRunning = StopApp(progress);
            if (DesktopRuntimeVersion() == null) InstallRuntime(progress);

            progress(L.T("Kopiere SnitchBox …", "Copying SnitchBox …"), -1);
            Directory.CreateDirectory(InstallDir); // erbt die Rechte von C:\Program Files: nur Administratoren dürfen schreiben
            ReplaceFile(AppExe, s => CopyResource("SnitchBox.exe", s));
            if (!SamePath(Self, SetupCopy)) ReplaceFile(SetupCopy, s => { using (var f = File.OpenRead(Self)) f.CopyTo(s); });

            progress(L.T("Lege Verknüpfungen an …", "Creating shortcuts …"), -1);
            SetShortcut(StartMenuLink, o.StartMenu);
            SetShortcut(DesktopLink, o.Desktop);

            progress(L.T("Richte den Autostart ein …", "Setting up autostart …"), -1);
            if (o.Autostart) CreateTask(); else DeleteTask();
            Register();

            if ((o.Launch || wasRunning) && !IsSystem)
            {
                progress(L.T("Starte SnitchBox …", "Starting SnitchBox …"), -1);
                Process.Start(new ProcessStartInfo(AppExe) { UseShellExecute = true, WorkingDirectory = InstallDir });
            }
            progress(L.T("Fertig. SnitchBox ist installiert.", "Done. SnitchBox is installed."), 100);
        }

        /// <summary>Beendet laufende SnitchBox-Fenster (der Netzwerkfilter ist dann kurz aus). true, wenn eines lief.</summary>
        static bool StopApp(Action<string, int> progress)
        {
            var running = Process.GetProcessesByName("SnitchBox");
            if (running.Length == 0) return false;
            progress(L.T("Beende das laufende SnitchBox …", "Stopping the running SnitchBox …"), -1);
            foreach (var p in running)
            {
                try { p.Kill(); p.WaitForExit(10000); }
                catch { }
                finally { p.Dispose(); }
            }
            System.Threading.Thread.Sleep(500); // Treiber-Handles freigeben lassen
            return true;
        }

        /// <summary>Lädt die .NET Desktop Runtime von Microsoft, prüft die Signatur und installiert sie still.</summary>
        static void InstallRuntime(Action<string, int> progress)
        {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // TLS 1.2
            Directory.CreateDirectory(InstallDir);
            // Im Programmordner (nur Administratoren dürfen schreiben), damit niemand die Datei zwischen Prüfen und Starten tauscht.
            var file = Path.Combine(InstallDir, "windowsdesktop-runtime-setup.exe");
            try
            {
                using (var web = new WebClient())
                {
                    web.DownloadProgressChanged += (s, e) =>
                        progress(string.Format(L.T("Lade .NET Desktop Runtime von Microsoft … {0:0.0} von {1:0.0} MB", "Downloading .NET Desktop Runtime from Microsoft … {0:0.0} of {1:0.0} MB"),
                            e.BytesReceived / 1048576.0, e.TotalBytesToReceive / 1048576.0), e.ProgressPercentage);
                    try { web.DownloadFileTaskAsync(new Uri(RuntimeUrl), file).Wait(); }
                    catch (AggregateException e) { throw new InvalidOperationException(L.T("Download der .NET Desktop Runtime fehlgeschlagen: ", "Downloading the .NET Desktop Runtime failed: ") + e.InnerException.Message, e.InnerException); }
                }
                progress(L.T("Prüfe die Signatur …", "Checking the signature …"), -1);
                if (!SignedByMicrosoft(file))
                    throw new SecurityException(L.T("Die heruntergeladene Datei ist nicht von Microsoft signiert; sie wird nicht ausgeführt.", "The downloaded file is not signed by Microsoft; it will not be run."));
                progress(L.T("Installiere .NET Desktop Runtime …", "Installing .NET Desktop Runtime …"), -1);
                using (var p = Process.Start(new ProcessStartInfo(file, "/install /quiet /norestart") { UseShellExecute = false, CreateNoWindow = true }))
                {
                    p.WaitForExit();
                    // 3010/1641: Neustart nötig; 1638: schon eine (neuere) Fassung da
                    if (p.ExitCode != 0 && p.ExitCode != 3010 && p.ExitCode != 1641 && p.ExitCode != 1638)
                        throw new InvalidOperationException(string.Format(L.T("Die Installation der .NET Desktop Runtime ist fehlgeschlagen (Code {0}).", "Installing the .NET Desktop Runtime failed (code {0})."), p.ExitCode));
                }
                if (DesktopRuntimeVersion() == null)
                    throw new InvalidOperationException(L.T("Die .NET Desktop Runtime 10 ist nach der Installation nicht zu finden.", "The .NET Desktop Runtime 10 cannot be found after installation."));
            }
            finally { try { File.Delete(file); } catch { } }
        }

        static void CopyResource(string name, Stream target)
        {
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            {
                if (s == null) throw new FileNotFoundException(L.T("Im Installer fehlt: ", "Missing from the installer: ") + name);
                s.CopyTo(target);
            }
        }

        /// <summary>Schreibt eine Datei neu. Ist die alte in Benutzung, wird sie umbenannt und beim nächsten Neustart gelöscht.</summary>
        static void ReplaceFile(string target, Action<Stream> write)
        {
            var fresh = target + ".neu";
            DeleteIfExists(fresh);
            using (var f = new FileStream(fresh, FileMode.CreateNew, FileAccess.Write)) write(f);
            if (File.Exists(target))
            {
                try { File.Delete(target); }
                catch (Exception)
                {
                    var old = target + "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".alt";
                    File.Move(target, old);
                    DeleteLater(old);
                }
            }
            File.Move(fresh, target);
        }

        static void DeleteIfExists(string path) { if (File.Exists(path)) File.Delete(path); }

        static void SetShortcut(string link, bool wanted)
        {
            if (!wanted) { try { DeleteIfExists(link); } catch { } return; }
            var type = Type.GetTypeFromProgID("WScript.Shell");
            var shell = Activator.CreateInstance(type);
            try
            {
                var lnk = type.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { link });
                var t = lnk.GetType();
                t.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { AppExe });
                t.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { InstallDir });
                t.InvokeMember("IconLocation", BindingFlags.SetProperty, null, lnk, new object[] { AppExe + ",0" });
                t.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { L.T("Firewall: zeigt, welches Programm sich wohin verbinden will", "Firewall: shows which program wants to connect where") });
                t.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
                Marshal.FinalReleaseComObject(lnk);
            }
            finally { Marshal.FinalReleaseComObject(shell); }
        }

        /// <summary>Dieselbe Aufgabe, die SnitchBox unter Einstellungen → „Beim Anmelden starten“ anlegt: startet ohne
        /// UAC-Rückfrage mit Administratorrechten. Läuft der Installer als SYSTEM (Softwareverteilung), gilt sie für jedes
        /// Administratorkonto, sonst für den angemeldeten Benutzer.</summary>
        static void CreateTask()
        {
            string trigger, principal;
            if (IsSystem)
            {
                trigger = "";
                principal = "<GroupId>S-1-5-32-544</GroupId>";
            }
            else
            {
                string user;
                using (var id = WindowsIdentity.GetCurrent()) user = SecurityElement.Escape(id.Name);
                trigger = "<UserId>" + user + "</UserId>";
                principal = "<UserId>" + user + "</UserId><LogonType>InteractiveToken</LogonType>";
            }
            var xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
                      "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
                      "  <Triggers><LogonTrigger><Enabled>true</Enabled>" + trigger + "</LogonTrigger></Triggers>\r\n" +
                      "  <Principals><Principal id=\"Author\">" + principal + "<RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n" +
                      "  <Settings>\r\n" +
                      "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n" +
                      "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n" +
                      "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n" +
                      "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n" +
                      "    <Enabled>true</Enabled>\r\n" +
                      "  </Settings>\r\n" +
                      "  <Actions Context=\"Author\"><Exec><Command>" + SecurityElement.Escape(AppExe) + "</Command><Arguments>--tray</Arguments></Exec></Actions>\r\n" +
                      "</Task>\r\n";
            // Im Programmordner (nur Administratoren), nicht in %TEMP%: dort ließe sich die Datei vor dem Einlesen austauschen.
            var file = Path.Combine(InstallDir, "autostart-task.xml");
            try
            {
                File.WriteAllText(file, xml, Encoding.Unicode);
                if (Schtasks("/Create /F /TN \"" + TaskName + "\" /XML \"" + file + "\"") != 0)
                    throw new InvalidOperationException(L.T("Die Autostart-Aufgabe ließ sich nicht anlegen.", "The autostart task could not be created."));
            }
            finally { try { File.Delete(file); } catch { } }
        }

        static void DeleteTask() { Schtasks("/Delete /F /TN \"" + TaskName + "\""); }

        static int Schtasks(string arguments)
        {
            using (var p = Process.Start(new ProcessStartInfo(System32("schtasks.exe"), arguments)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }))
            {
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit(30000);
                return p.ExitCode;
            }
        }

        static void Register()
        {
            var info = FileVersionInfo.GetVersionInfo(AppExe);
            long size = new FileInfo(AppExe).Length + (File.Exists(SetupCopy) ? new FileInfo(SetupCopy).Length : 0);
            using (var k = Registry.LocalMachine.CreateSubKey(UninstallKey))
            {
                k.SetValue("DisplayName", "SnitchBox");
                k.SetValue("DisplayVersion", info.FileVersion ?? "");
                k.SetValue("Publisher", info.CompanyName ?? "");
                k.SetValue("DisplayIcon", AppExe + ",0");
                k.SetValue("InstallLocation", InstallDir);
                k.SetValue("UninstallString", "\"" + SetupCopy + "\" /uninstall");
                k.SetValue("QuietUninstallString", "\"" + SetupCopy + "\" /uninstall /quiet");
                k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                k.SetValue("EstimatedSize", (int)(size / 1024), RegistryValueKind.DWord);
            }
        }

        // ------------------------------------------------------------------ Deinstallieren

        public static void Uninstall(bool removeData, Action<string, int> progress)
        {
            StopApp(progress);
            progress(L.T("Entferne SnitchBox …", "Removing SnitchBox …"), -1);
            DeleteTask();
            SetShortcut(StartMenuLink, false);
            SetShortcut(DesktopLink, false);
            try { Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, false); } catch { }
            DeleteNowOrLater(AppExe);
            foreach (var leftover in Directory.Exists(InstallDir) ? Directory.GetFiles(InstallDir, "*.alt") : new string[0]) DeleteNowOrLater(leftover);
            if (removeData && Directory.Exists(DataDir))
            {
                progress(L.T("Lösche Einstellungen und Regeln …", "Deleting settings and rules …"), -1);
                try { Directory.Delete(DataDir, true); }
                catch
                {
                    // Gesperrtes (etwa der noch geladene Treiber) beim nächsten Neustart löschen.
                    foreach (var f in Directory.GetFiles(DataDir, "*", SearchOption.AllDirectories)) DeleteNowOrLater(f);
                    foreach (var d in Directory.GetDirectories(DataDir, "*", SearchOption.AllDirectories).OrderByDescending(x => x.Length)) DeleteDirLater(d);
                    DeleteDirLater(DataDir);
                }
            }
            if (SamePath(Self, SetupCopy))
            {
                // Läuft gerade selbst aus dem Programmordner: kurz nach dem Beenden löschen lassen.
                var cmd = string.Format("/c \"\"{0}\" -n 3 127.0.0.1 >nul & del /f /q \"{1}\" & rmdir \"{2}\"\"", System32("PING.EXE"), SetupCopy, InstallDir);
                Process.Start(new ProcessStartInfo(System32("cmd.exe"), cmd) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Environment.SystemDirectory });
                DeleteLater(SetupCopy);
            }
            else
            {
                DeleteNowOrLater(SetupCopy);
                try { if (Directory.Exists(InstallDir) && !Directory.EnumerateFileSystemEntries(InstallDir).Any()) Directory.Delete(InstallDir); } catch { }
            }
            DeleteDirLater(InstallDir); // falls noch etwas übrig ist: beim Neustart, sobald der Ordner leer ist
            progress(L.T("SnitchBox wurde entfernt.", "SnitchBox has been removed."), 100);
        }

        static void DeleteNowOrLater(string path)
        {
            try { DeleteIfExists(path); }
            catch { DeleteLater(path); }
        }

        static void DeleteDirLater(string path)
        {
            try { if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any()) { Directory.Delete(path); return; } }
            catch { }
            if (Directory.Exists(path)) DeleteLater(path);
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool MoveFileEx(string existing, string replacement, int flags);

        /// <summary>Beim nächsten Windows-Start löschen (MOVEFILE_DELAY_UNTIL_REBOOT).</summary>
        static void DeleteLater(string path) { MoveFileEx(path, null, 4); }

        static bool SamePath(string a, string b)
        {
            try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }

        // ------------------------------------------------------------------ Signaturprüfung (WinVerifyTrust)

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WinTrustFileInfo
        {
            public int cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WinTrustData
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public IntPtr pFile;
            public int dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, [In] ref Guid action, [In] ref WinTrustData data);

        /// <summary>Gültige Authenticode-Signatur (Kette bis zu einer vertrauenswürdigen Stelle) und Herausgeber Microsoft Corporation.</summary>
        public static bool SignedByMicrosoft(string path)
        {
            var file = new WinTrustFileInfo { cbStruct = Marshal.SizeOf(typeof(WinTrustFileInfo)), pcwszFilePath = path };
            var pFile = Marshal.AllocHGlobal(file.cbStruct);
            try
            {
                Marshal.StructureToPtr(file, pFile, false);
                try
                {
                    var data = new WinTrustData
                    {
                        cbStruct = Marshal.SizeOf(typeof(WinTrustData)),
                        dwUIChoice = 2,          // WTD_UI_NONE
                        fdwRevocationChecks = 0, // WTD_REVOKE_NONE
                        dwUnionChoice = 1,       // WTD_CHOICE_FILE
                        pFile = pFile,
                        dwStateAction = 0,       // WTD_STATEACTION_IGNORE
                        dwProvFlags = 0x10,      // WTD_REVOCATION_CHECK_NONE
                    };
                    var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
                    if (WinVerifyTrust(IntPtr.Zero, ref action, ref data) != 0) return false;
                }
                finally { Marshal.DestroyStructure(pFile, typeof(WinTrustFileInfo)); }
            }
            finally { Marshal.FreeHGlobal(pFile); }
            try { return X509Certificate.CreateFromSignedFile(path).Subject.Contains("O=Microsoft Corporation"); }
            catch { return false; }
        }

        /// <summary>Passendes Bild aus der mitgelieferten app.ico (PNG-Einträge, kleinster ≥ size).</summary>
        public static Image IconImage(int size)
        {
            try
            {
                byte[] ico;
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.ico"))
                using (var m = new MemoryStream()) { s.CopyTo(m); ico = m.ToArray(); }
                int count = BitConverter.ToUInt16(ico, 4), best = -1, bestSize = int.MaxValue;
                for (var i = 0; i < count; i++)
                {
                    var w = ico[6 + 16 * i] == 0 ? 256 : ico[6 + 16 * i];
                    if (w >= size && w < bestSize) { best = i; bestSize = w; }
                }
                if (best < 0) best = count - 1;
                var len = BitConverter.ToInt32(ico, 6 + 16 * best + 8);
                var off = BitConverter.ToInt32(ico, 6 + 16 * best + 12);
                using (var png = new MemoryStream(ico, off, len))
                using (var img = Image.FromStream(png))
                    return new Bitmap(img, size, size);
            }
            catch { return null; }
        }
    }

    internal sealed class SetupForm : Form
    {
        readonly CheckBox _startMenu, _desktop, _autostart, _launch;
        readonly Label _info, _status;
        readonly ProgressBar _progress;
        readonly Button _install, _cancel, _uninstall;
        bool _busy, _done;

        // Inhaltsbreite bei 100 %; alles andere richtet sich nach dem Inhalt (Texte brechen um, das Fenster wächst mit),
        // damit auch längere Übersetzungen und jede Bildschirmskalierung passen.
        const int ContentWidth = 520;

        public SetupForm()
        {
            SuspendLayout();
            // Schrift fest in Punkt; skaliert wird nach DPI (Manifest: dpiAware).
            Font = new Font("Segoe UI", 9F);
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = L.T("SnitchBox installieren", "Install SnitchBox");
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            var root = new TableLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 1, Padding = new Padding(18, 16, 18, 14) };

            // Kopf: Symbol links, Titel und Beschreibung rechts
            var header = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Margin = new Padding(0, 0, 0, 12) };
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var picture = new PictureBox { Size = new Size(48, 48), SizeMode = PictureBoxSizeMode.Zoom, Image = Installer.IconImage(48), Margin = new Padding(0, 2, 14, 0) };
            var titles = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Margin = Padding.Empty };
            titles.Controls.Add(new Label { AutoSize = true, Text = "SnitchBox " + Info.Version, Font = new Font("Segoe UI", 14F, FontStyle.Bold), Margin = new Padding(0, 0, 0, 4) });
            titles.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(ContentWidth - 62, 0), Margin = Padding.Empty,
                Text = L.T("Firewall für Windows: zeigt, welches Programm sich wohin verbinden will, und lässt dich erlauben oder verbieten.",
                           "Firewall for Windows: shows which program wants to connect where and lets you allow or deny it."),
            });
            header.Controls.Add(picture, 0, 0);
            header.Controls.Add(titles, 1, 0);

            var installed = Installer.InstalledVersion();
            var runtime = Installer.DesktopRuntimeVersion();
            _info = new Label { AutoSize = true, MaximumSize = new Size(ContentWidth, 0), Margin = new Padding(0, 0, 0, 12) };
            _info.Text = L.T("Zielordner: ", "Folder: ") + Installer.InstallDir + "\n"
                + (installed != null ? L.F("Installiert: {0} – wird aktualisiert", "Installed: {0} – will be updated", installed) + "\n" : "")
                + (runtime != null
                    ? L.F(".NET Desktop Runtime {0} ist vorhanden.", ".NET Desktop Runtime {0} is present.", runtime)
                    : L.T(".NET Desktop Runtime 10 fehlt – wird bei der Installation von Microsoft geladen (ca. 60 MB).",
                          ".NET Desktop Runtime 10 is missing – it will be downloaded from Microsoft during installation (about 60 MB)."));

            var checks = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Margin = new Padding(2, 0, 0, 10) };
            _startMenu = Check(checks, L.T("Verknüpfung im Startmenü", "Start menu shortcut"), true);
            _desktop = Check(checks, L.T("Verknüpfung auf dem Desktop", "Desktop shortcut"), installed != null && File.Exists(Installer.DesktopLink));
            _autostart = Check(checks, L.T("Beim Anmelden starten (Autostart, ohne UAC-Rückfrage)", "Start at sign-in (autostart, without UAC prompt)"), true);
            _launch = Check(checks, L.T("SnitchBox nach der Installation starten", "Start SnitchBox after installation"), true);

            // Fortschritt und Status mit fester Höhe, damit das Fenster nicht springt, wenn sie erscheinen.
            var progressArea = new Panel { Size = new Size(ContentWidth, 18), Margin = new Padding(0, 0, 0, 4) };
            _progress = new ProgressBar { Dock = DockStyle.Top, Height = 16, Visible = false };
            progressArea.Controls.Add(_progress);
            _status = new Label { AutoSize = true, MinimumSize = new Size(ContentWidth, 40), MaximumSize = new Size(ContentWidth, 0), Margin = new Padding(0, 0, 0, 8) };

            // Knöpfe: Deinstallieren links, Installieren/Abbrechen rechts; sie wachsen mit längeren Übersetzungen.
            var buttons = new TableLayoutPanel { ColumnCount = 4, RowCount = 1, Size = new Size(ContentWidth, 34), Margin = Padding.Empty };
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            buttons.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            _uninstall = MakeButton(L.T("Deinstallieren", "Uninstall"), 0);
            _uninstall.Visible = installed != null;
            _install = MakeButton(installed != null ? L.T("Aktualisieren", "Update") : L.T("Installieren", "Install"), 8);
            _cancel = MakeButton(L.T("Abbrechen", "Cancel"), 8);
            _cancel.DialogResult = DialogResult.Cancel;
            buttons.Controls.Add(_uninstall, 0, 0);
            buttons.Controls.Add(_install, 2, 0);
            buttons.Controls.Add(_cancel, 3, 0);
            _install.Click += OnInstall;
            _uninstall.Click += OnUninstall;
            _cancel.Click += (s, e) => Close();
            AcceptButton = _install;
            CancelButton = _cancel;

            root.Controls.AddRange(new Control[] { header, _info, checks, progressArea, _status, buttons });
            Controls.Add(root);
            ResumeLayout(false);
            PerformLayout();
        }

        static CheckBox Check(Control parent, string text, bool value)
        {
            var box = new CheckBox { AutoSize = true, Text = text, Checked = value, Margin = new Padding(0, 3, 0, 3) };
            parent.Controls.Add(box);
            return box;
        }

        static Button MakeButton(string text, int left)
        {
            return new Button { Text = text, AutoSize = true, MinimumSize = new Size(96, 30), Padding = new Padding(8, 0, 8, 0), Margin = new Padding(left, 0, 0, 0) };
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            // Nach der UAC-Rückfrage (Wechsel vom sicheren Desktop) kommt das erste Zeichnen nicht immer vollständig an:
            // gleich und in den ersten Sekunden noch einmal alles neu zeichnen.
            Invalidate(true);
            Update();
            var timer = new System.Windows.Forms.Timer { Interval = 400 };
            var ticks = 0;
            timer.Tick += (s, a) =>
            {
                Invalidate(true);
                if (++ticks >= 4) { timer.Stop(); timer.Dispose(); }
            };
            timer.Start();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (_busy) e.Cancel = true; // nicht mitten in der Installation abbrechen
            base.OnFormClosing(e);
        }

        void Progress(string text, int percent)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string, int>(Progress), text, percent); return; }
            _status.Text = text;
            _progress.Visible = true;
            if (percent < 0) _progress.Style = ProgressBarStyle.Marquee;
            else { _progress.Style = ProgressBarStyle.Continuous; _progress.Value = Math.Max(0, Math.Min(100, percent)); }
        }

        void SetBusy(bool busy)
        {
            _busy = busy;
            foreach (Control c in new Control[] { _startMenu, _desktop, _autostart, _launch, _install, _uninstall, _cancel }) c.Enabled = !busy;
            UseWaitCursor = busy;
        }

        async void OnInstall(object sender, EventArgs e)
        {
            if (_done) { Close(); return; }
            if (Installer.AppRunning() && MessageBox.Show(this,
                    L.T("SnitchBox läuft gerade. Es wird für die Installation beendet (der Netzwerkfilter ist kurz aus) und danach wieder gestartet.\n\nFortfahren?",
                        "SnitchBox is running. It will be stopped for the installation (the network filter is briefly off) and started again afterwards.\n\nContinue?"),
                    Text, MessageBoxButtons.OKCancel, MessageBoxIcon.Information) != DialogResult.OK) return;
            var o = new Options { StartMenu = _startMenu.Checked, Desktop = _desktop.Checked, Autostart = _autostart.Checked, Launch = _launch.Checked };
            SetBusy(true);
            try
            {
                await Task.Run(() => Installer.Install(o, Progress));
                _done = true;
                _install.Text = L.T("Schließen", "Close");
                _uninstall.Visible = false;
            }
            catch (Exception ex)
            {
                Progress(L.T("Abgebrochen.", "Cancelled."), 0);
                ShowError(this, ex);
            }
            finally
            {
                SetBusy(false);
                if (_done) { _cancel.Visible = false; _startMenu.Enabled = _desktop.Enabled = _autostart.Enabled = _launch.Enabled = false; }
            }
        }

        void OnUninstall(object sender, EventArgs e)
        {
            if (Program.Uninstall(this)) Close();
        }

        public static void ShowError(IWin32Window owner, Exception ex)
        {
            var text = ex.Message;
            if (ex is InvalidOperationException && text.Contains(".NET Desktop Runtime"))
            {
                if (MessageBox.Show(owner, text + "\n\n" + L.T("Download-Seite von Microsoft öffnen?", "Open Microsoft's download page?"),
                        "SnitchBox", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                    // Über den Explorer, damit der Browser nicht mit den Administratorrechten des Installers läuft.
                    try { Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), Installer.RuntimePage); } catch { }
                return;
            }
            MessageBox.Show(owner, text, "SnitchBox", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    internal static class Program
    {
        static string _logFile;

        [STAThread]
        static int Main(string[] args)
        {
            var flags = new HashSet<string>(args.Select(a => a.Trim().TrimStart('/', '-').ToLowerInvariant()));
            var quiet = flags.Contains("quiet") || flags.Contains("silent") || flags.Contains("q");
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var problem = Installer.ArchitectureProblem();
            if (problem != null)
            {
                if (!quiet) MessageBox.Show(problem, "SnitchBox", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 2;
            }
            if (flags.Contains("uninstall"))
                return quiet ? Quiet(() => Installer.Uninstall(false, Log)) : (Uninstall(null) ? 0 : 1);
            if (quiet)
                return Quiet(() => Installer.Install(new Options { Launch = false }, Log));
            Application.Run(new SetupForm());
            return 0;
        }

        /// <summary>Ohne Fenster (Softwareverteilung): Standardauswahl, Protokoll in %TEMP%\SnitchBox-Setup.log, Rückgabe 0 = Erfolg.</summary>
        static int Quiet(Action run)
        {
            _logFile = Path.Combine(Path.GetTempPath(), "SnitchBox-Setup.log");
            Log("SnitchBox-Setup " + Info.Version + " " + string.Join(" ", Environment.GetCommandLineArgs().Skip(1)), -1);
            try { run(); return 0; }
            catch (Exception e) { Log(L.T("FEHLER: ", "ERROR: ") + e, -1); return 1; }
        }

        static void Log(string text, int percent)
        {
            if (_logFile == null || percent > 0 && percent < 100) return; // Download-Fortschritt nicht zeilenweise protokollieren
            try { File.AppendAllText(_logFile, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + text + Environment.NewLine); } catch { }
        }

        /// <summary>Deinstallation mit Rückfragen; true, wenn entfernt.</summary>
        public static bool Uninstall(IWin32Window owner)
        {
            if (MessageBox.Show(owner,
                    L.T("SnitchBox wirklich entfernen? Der Netzwerkfilter ist danach aus.", "Really remove SnitchBox? The network filter will then be off."),
                    "SnitchBox", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return false;
            var removeData = Directory.Exists(Installer.DataDir) && MessageBox.Show(owner,
                    L.F("Auch Einstellungen und Regeln löschen ({0})?\n\nNein behält sie für eine spätere Installation.",
                        "Also delete settings and rules ({0})?\n\nNo keeps them for a later installation.", Installer.DataDir),
                    "SnitchBox", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
            try
            {
                Cursor.Current = Cursors.WaitCursor;
                Installer.Uninstall(removeData, (t, p) => { });
                MessageBox.Show(owner, L.T("SnitchBox wurde entfernt.", "SnitchBox has been removed."), "SnitchBox", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return true;
            }
            catch (Exception e)
            {
                SetupForm.ShowError(owner, e);
                return false;
            }
            finally { Cursor.Current = Cursors.Default; }
        }
    }
}
