using System.Runtime.InteropServices;
using System.Windows;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Öffnet Webadressen im Standardbrowser des Benutzers – aber nicht mit den Administratorrechten von SnitchBox.
/// Ein gewöhnliches ShellExecute aus diesem Prozess startete den Browser ebenfalls als Administrator. Stattdessen führt die
/// Shell des Desktops (explorer.exe, läuft mit normalen Rechten) den Aufruf aus: ShellWindows → Desktop-Fenster →
/// IShellBrowser → aktive Ansicht → IShellFolderViewDual.Application → IShellDispatch2.ShellExecute.
/// Verfahren nach Raymond Chen, „How can I launch an unelevated process from my elevated process and vice versa?“.</summary>
internal static class DesktopShell
{
    private const int SWC_DESKTOP = 8;
    private const int SWFO_NEEDDISPATCH = 1;
    private const int CSIDL_DESKTOP = 0;
    private const uint SVGIO_BACKGROUND = 0;
    private const int SW_SHOWNORMAL = 1;

    private static readonly Guid CLSID_ShellWindows = new("9BA05972-F6A8-11CF-A442-00A0C90A8F39");
    private static readonly Guid SID_STopLevelBrowser = new("4C96BE40-915C-11CF-99D3-00AA004AE837");
    private static readonly Guid IID_IShellBrowser = new("000214E2-0000-0000-C000-000000000046");
    private static readonly Guid IID_IDispatch = new("00020400-0000-0000-C000-000000000046");

    /// <summary>Nur https-Adressen; bei einem Fehler steht die Adresse in einer Meldung (zum Abschreiben oder Kopieren mit Strg+C).</summary>
    public static void OpenUrl(Window? owner, string url)
    {
        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                throw new ArgumentException("Nur https-Adressen", nameof(url));
            ShellExecuteAsDesktopUser(uri.AbsoluteUri);
        }
        catch (Exception ex)
        {
            Log.Write($"Webadresse nicht geöffnet ({url}): {ex.Message}");
            var text = Loc.F("Der Browser ließ sich nicht öffnen. Die Adresse lautet:\n{0}", "The browser could not be opened. The address is:\n{0}", url);
            if (owner != null) MessageBox.Show(owner, text, App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
            else MessageBox.Show(text, App.Title, MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    /// <summary>Lässt explorer.exe die Datei oder Adresse öffnen (im STA-Thread der Oberfläche aufrufen).</summary>
    internal static void ShellExecuteAsDesktopUser(string file, string arguments = "")
    {
        var type = Type.GetTypeFromCLSID(CLSID_ShellWindows, throwOnError: true)!;
        var windows = (IShellWindows)Activator.CreateInstance(type)!;
        object? location = CSIDL_DESKTOP, root = null;
        var desktop = windows.FindWindowSW(ref location, ref root, SWC_DESKTOP, out var hwnd, SWFO_NEEDDISPATCH)
                      ?? throw new InvalidOperationException("Kein Desktop der Shell gefunden (läuft explorer.exe?)");
        var sid = SID_STopLevelBrowser;
        var iid = IID_IShellBrowser;
        var browser = (IShellBrowser)((IOleServiceProvider)desktop).QueryService(ref sid, ref iid);
        var dispatchIid = IID_IDispatch;
        dynamic folderView = browser.QueryActiveShellView().GetItemObject(SVGIO_BACKGROUND, ref dispatchIid);
        dynamic shell = folderView.Application;
        // Der Explorer ist nicht im Vordergrund; ohne diese Erlaubnis bliebe ein neu startender Browser womöglich dahinter.
        if (GetWindowThreadProcessId(new IntPtr(hwnd), out var explorerPid) != 0) AllowSetForegroundWindow(explorerPid);
        shell.ShellExecute(file, arguments, "", "open", SW_SHOWNORMAL);
    }

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(uint processId);

    // Nur die benötigten Methoden; die Platzhalter davor halten die Reihenfolge der vtable (exdisp.h, shobjidl.h, servprov.h).

    [ComImport, Guid("85CB6900-4D95-11CF-960C-0080C7F4EE85"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IShellWindows
    {
        void _Count(); void _Item(); void _NewEnum(); void _Register(); void _RegisterPending(); void _Revoke(); void _OnNavigate(); void _OnActivated();
        [return: MarshalAs(UnmanagedType.IDispatch)]
        object? FindWindowSW(ref object? pvarLoc, ref object? pvarLocRoot, int swClass, out int phwnd, int swfwOptions);
    }

    [ComImport, Guid("6D5140C1-7436-11CE-8034-00AA006009FA"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IOleServiceProvider
    {
        [return: MarshalAs(UnmanagedType.IUnknown)]
        object QueryService(ref Guid guidService, ref Guid riid);
    }

    [ComImport, Guid("000214E2-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellBrowser
    {
        void _GetWindow(); void _ContextSensitiveHelp(); void _InsertMenusSB(); void _SetMenuSB(); void _RemoveMenusSB(); void _SetStatusTextSB();
        void _EnableModelessSB(); void _TranslateAcceleratorSB(); void _BrowseObject(); void _GetViewStateStream(); void _GetControlWindow(); void _SendControlMsg();
        IShellView QueryActiveShellView();
    }

    [ComImport, Guid("000214E3-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellView
    {
        void _GetWindow(); void _ContextSensitiveHelp(); void _TranslateAccelerator(); void _EnableModeless(); void _UIActivate(); void _Refresh();
        void _CreateViewWindow(); void _DestroyViewWindow(); void _GetCurrentInfo(); void _AddPropertySheetPages(); void _SaveViewState(); void _SelectItem();
        [return: MarshalAs(UnmanagedType.IUnknown)]
        object GetItemObject(uint uItem, ref Guid riid);
    }
}
