// SnitchBoxStart.exe – startet SnitchBox.exe (aus demselben Ordner) mit bereinigter Umgebung.
//
// Warum: SnitchBox läuft mit Administratorrechten, beim Anmelden über die Aufgabenplanung sogar ohne UAC-Rückfrage – aber mit den
// Umgebungsvariablen des Benutzers. Die .NET-Laufzeit wertet einige davon aus, bevor auch nur eine Zeile SnitchBox läuft
// (Profiler über CORECLR_*/COR_*, Diagnose-Ports, zusätzliche Abhängigkeiten über DOTNET_*). Jedes gewöhnliche Programm darf sie
// ohne Adminrechte setzen (HKCU\Environment) und hätte so beim nächsten Anmelden eigenen Code mit Administratorrechten.
// Dieser Starter ist ein natives Programm ohne .NET (für ihn bedeuten die Variablen nichts), entfernt alle Variablen, die mit
// CORECLR_, COR_, COMPlus_ oder DOTNET_ beginnen, startet SnitchBox.exe und beendet sich sofort.
//
// Er braucht selbst Administratorrechte (Manifest), damit SnitchBox.exe – das sie ebenfalls verlangt – ohne zweite Rückfrage startet.
// Er lädt nur kernel32 und user32 (bekannte System-DLLs, nie aus dem Programmordner oder PATH).

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>

static const wchar_t* const Blocked[] = { L"CORECLR_", L"COR_", L"COMPLUS_", L"DOTNET_" };

static bool IsBlocked(const wchar_t* entry)
{
    // Einträge „NAME=Wert“; die verborgenen „=C:=C:\…“ (Arbeitsverzeichnis je Laufwerk) beginnen mit „=“ und bleiben.
    for (const wchar_t* prefix : Blocked)
        if (_wcsnicmp(entry, prefix, wcslen(prefix)) == 0) return true;
    return false;
}

static void Fail(const wchar_t* german, const wchar_t* english, DWORD error, const wchar_t* path)
{
    wchar_t text[2048];
    const bool de = PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_GERMAN;
    _snwprintf_s(text, _TRUNCATE, L"%s (%s %lu)\n\n%s", de ? german : english, de ? L"Fehler" : L"error", error, path);
    MessageBoxW(nullptr, text, L"SnitchBox", MB_ICONERROR | MB_OK);
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    wchar_t dir[32768];
    const DWORD n = GetModuleFileNameW(nullptr, dir, ARRAYSIZE(dir));
    if (n == 0 || n >= ARRAYSIZE(dir)) return 1;
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash == nullptr) return 1;
    *slash = L'\0';

    static wchar_t target[32768];
    if (_snwprintf_s(target, _TRUNCATE, L"%s\\SnitchBox.exe", dir) < 0) return 1;

    // Kommandozeile: "SnitchBox.exe" und die eigenen Argumente (z. B. --tray aus dem Autostart) unverändert dahinter.
    const wchar_t* args = GetCommandLineW();
    if (*args == L'"')
    {
        ++args;
        while (*args != L'\0' && *args != L'"') ++args;
        if (*args == L'"') ++args;
    }
    else
        while (*args != L'\0' && *args != L' ' && *args != L'\t') ++args;
    while (*args == L' ' || *args == L'\t') ++args;
    const size_t lineLength = wcslen(target) + wcslen(args) + 4;
    wchar_t* line = static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, lineLength * sizeof(wchar_t)));
    if (line == nullptr || swprintf_s(line, lineLength, L"\"%s\" %s", target, args) < 0) return 1;

    // Umgebung ohne die Variablen der .NET-Laufzeit. Block: Einträge mit je einer Null, am Ende eine zweite.
    wchar_t* env = GetEnvironmentStringsW();
    if (env == nullptr) return 1;
    size_t total = 0;
    for (const wchar_t* p = env; *p != L'\0'; p += wcslen(p) + 1) total += wcslen(p) + 1;
    wchar_t* clean = static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, (total + 2) * sizeof(wchar_t)));
    if (clean == nullptr) return 1;
    wchar_t* out = clean;
    for (const wchar_t* p = env; *p != L'\0'; p += wcslen(p) + 1)
    {
        const size_t length = wcslen(p);
        if (IsBlocked(p)) continue;
        memcpy(out, p, (length + 1) * sizeof(wchar_t));
        out += length + 1;
    }
    *out++ = L'\0';
    if (out == clean + 1) *out++ = L'\0'; // ganz leerer Block braucht zwei Nullen
    FreeEnvironmentStringsW(env);

    STARTUPINFOW si;
    GetStartupInfoW(&si); // Fensterzustand (z. B. minimiert) durchreichen
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(target, line, nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, clean, dir, &si, &pi))
    {
        Fail(L"SnitchBox ließ sich nicht starten", L"SnitchBox could not be started", GetLastError(), target);
        return 2;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
