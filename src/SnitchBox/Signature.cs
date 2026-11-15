using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace SnitchBox;

internal enum SignatureState { Unknown, Valid, Invalid, Unsigned }

/// <summary>Ergebnis der Signaturprüfung: Zustand, Unterzeichner (bei gültiger Signatur), ob über einen Windows-Katalog signiert,
/// und der Windows-Fehlercode bei ungültiger Signatur.</summary>
internal readonly record struct SignatureInfo(SignatureState State, string Signer, bool Catalog, int Code);

/// <summary>Prüft die digitale Signatur einer Datei mit Windows (WinVerifyTrust), wie es auch der Explorer tut – eingebettete
/// Signaturen und Katalog-Signaturen (fast alle Windows-Programme sind über Kataloge signiert). Ohne Netzzugriff: keine Sperrlisten-
/// Abfrage (sie hielte das Warnfenster auf und ginge selbst durch den Filter). Bewusst ohne Zwischenspeicher: Größe und Änderungszeit
/// kann der Besitzer einer Datei nach einer Manipulation zurücksetzen – ein gemerktes „gültig“ würde dann ausgerechnet die veränderte
/// Datei als gültig zeigen. Eine Prüfung dauert höchstens einige zehn Millisekunden und läuft nur einmal je Warnfenster.</summary>
internal static unsafe class Signature
{
    public static SignatureInfo Check(string path)
    {
        if (path.Length == 0 || path.IndexOf('\\') < 0) return default;
        try { return File.Exists(path) ? Verify(path) : default; }
        catch { return default; }
    }

    // ---- WinVerifyTrust

    private static Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint UiNone = 2, ChoiceFile = 1, ChoiceCatalog = 2, StateVerify = 1, StateClose = 2;
    private const uint RevocationCheckNone = 0x10, CacheOnlyUrlRetrieval = 0x1000;
    private const int NoSignature = unchecked((int)0x800B0100), SubjectFormUnknown = unchecked((int)0x800B0003), ProviderUnknown = unchecked((int)0x800B0001);

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll")] private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WintrustData data);
    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, IntPtr file, ref uint hashSize, byte* hash, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte* hash, uint hashSize, uint flags, IntPtr prevCatInfo);
    [DllImport("wintrust.dll", SetLastError = true)] private static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CatalogInfo info, uint flags);
    [DllImport("wintrust.dll")] private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);
    [DllImport("wintrust.dll")] private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

    private static int Trust(uint choice, IntPtr info)
    {
        var data = new WintrustData
        {
            cbStruct = (uint)sizeof(WintrustData), dwUIChoice = UiNone, fdwRevocationChecks = 0, dwUnionChoice = choice, pInfo = info,
            dwStateAction = StateVerify, dwProvFlags = RevocationCheckNone | CacheOnlyUrlRetrieval,
        };
        var result = WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, ref data);
        data.dwStateAction = StateClose;
        WinVerifyTrust(IntPtr.Zero, ref GenericVerifyV2, ref data);
        return result;
    }

    private static string SignerOf(string signedFile)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
#pragma warning restore SYSLIB0057
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch { return ""; }
    }

    private static SignatureInfo Verify(string path)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        try
        {
            var file = new WintrustFileInfo { cbStruct = (uint)sizeof(WintrustFileInfo), pcwszFilePath = pathPtr };
            var code = Trust(ChoiceFile, (IntPtr)(&file));
            if (code == 0) return new SignatureInfo(SignatureState.Valid, SignerOf(path), false, 0);
            if (code is not (NoSignature or SubjectFormUnknown or ProviderUnknown)) return new SignatureInfo(SignatureState.Invalid, "", false, code);
            // Keine eingebettete Signatur: Windows-Programme stehen in einem Katalog (Hash der Datei, vom Katalog signiert).
            foreach (var algorithm in new[] { "SHA256", "SHA1" })
                if (VerifyCatalog(path, pathPtr, algorithm) is { } result) return result;
            return new SignatureInfo(SignatureState.Unsigned, "", false, code);
        }
        catch { return default; }
        finally { Marshal.FreeHGlobal(pathPtr); }
    }

    /// <summary>Prüft die Datei gegen einen Windows-Katalog; null, wenn kein Katalog ihren Hash enthält.</summary>
    private static SignatureInfo? VerifyCatalog(string path, IntPtr pathPtr, string algorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) return null;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var handle = stream.SafeFileHandle.DangerousGetHandle();
            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, null, 0);
            if (size == 0 || size > 256) return null;
            var hash = new byte[size];
            fixed (byte* h = hash)
            {
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, h, 0)) return null;
                var catInfo = CryptCATAdminEnumCatalogFromHash(admin, h, size, 0, IntPtr.Zero);
                if (catInfo == IntPtr.Zero) return null;
                try
                {
                    var info = new CatalogInfo { cbStruct = (uint)Marshal.SizeOf<CatalogInfo>(), wszCatalogFile = "" };
                    if (!CryptCATCatalogInfoFromContext(catInfo, ref info, 0)) return null;
                    var catalogPtr = Marshal.StringToHGlobalUni(info.wszCatalogFile);
                    var tagPtr = Marshal.StringToHGlobalUni(Convert.ToHexString(hash));
                    try
                    {
                        var cat = new WintrustCatalogInfo
                        {
                            cbStruct = (uint)sizeof(WintrustCatalogInfo), pcwszCatalogFilePath = catalogPtr, pcwszMemberTag = tagPtr,
                            pcwszMemberFilePath = pathPtr, hMemberFile = handle, pbCalculatedFileHash = (IntPtr)h, cbCalculatedFileHash = size,
                            hCatAdmin = admin,
                        };
                        var code = Trust(ChoiceCatalog, (IntPtr)(&cat));
                        return code == 0
                            ? new SignatureInfo(SignatureState.Valid, SignerOf(info.wszCatalogFile), true, 0)
                            : new SignatureInfo(SignatureState.Invalid, "", true, code);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(catalogPtr);
                        Marshal.FreeHGlobal(tagPtr);
                    }
                }
                finally { CryptCATAdminReleaseCatalogContext(admin, catInfo, 0); }
            }
        }
        catch { return null; }
        finally { CryptCATAdminReleaseContext(admin, 0); }
    }
}
