using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Media;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Symbole für Programme, deren Datei nicht (mehr) unter dem angezeigten Pfad liegt, und für bekannte Apps.
/// Regel-Muster („…\GoogleUpdater\*\updater.exe“, „WindowsApps\Claude_*_x64__pzs8sxrjxfjjc\…“) und Pfade alter Versionen werden zur
/// aktuell installierten Datei aufgelöst; Store-Pakete über ihre Paketfamilie (den Ordner WindowsApps darf man nicht auflisten).
/// Bekannte Apps (<see cref="KnownApps"/>) zeigen das Symbol ihres Hauptprogramms, Updater, Hilfsprogramme und Kommandozeile
/// zusätzlich ein Abzeichen unten rechts – so gehören „updater.exe“ und „chrome.exe“ auf einen Blick zusammen.</summary>
internal static class AppIcons
{
    private static readonly ConcurrentDictionary<string, string?> Resolved = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, ImageSource> Composed = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Symbol einer bekannten App in ihrer Rolle: das Programm selbst zeigt sein eigenes Symbol (Word, Photoshop, ChatGPT),
    /// Updater, Hilfsprogramme und Kommandozeile das des Hauptprogramms mit Abzeichen (zwischengespeichert je App und Rolle).</summary>
    public static ImageSource For(AppMatch match, string processPath)
    {
        if (match.Role == AppRole.App)
        {
            if (ExistingFile(processPath) is { } own && Native.IconOf(own) is { } ownIcon) return ownIcon;
            // Programm mit eigenem Namen, aber nicht (mehr) installiert (Word, Photoshop): sein Anfangsbuchstabe, nicht der der Suite.
            if (match.FixedLabel != null) return Composed.GetOrAdd(match.App.Id + "|" + match.FixedLabel, _ => LetterTile(match.App, match.FixedLabel));
        }
        return Composed.GetOrAdd(match.App.Id + "|" + match.Role, _ =>
        {
            var main = MainFile(match.App) ?? ExistingFile(processPath);
            var baseIcon = (main != null ? Native.IconOf(main) : null) ?? LetterTile(match.App);
            return match.Role == AppRole.App ? baseIcon : WithBadge(baseIcon, match.Role);
        });
    }

    /// <summary>Symbol eines Windows-Programms: sein eigenes, wenn die Datei eines enthält (Explorer, Einstellungen, cmd), sonst das
    /// Symbol seiner Art – die meisten Windows-Programme (svchost, lsass, Startmenü, Suche, Telemetrie) bringen keines mit, Windows
    /// zeigte dann nur das leere Standardsymbol.</summary>
    public static ImageSource ForWindows(WinMatch match, string processPath)
    {
        if (ExistingFile(processPath) is { } file && HasOwnIcon(file) && Native.IconOf(file) is { } own) return own;
        return Composed.GetOrAdd("windows|" + match.Category, _ => CategoryTile(match.Category));
    }

    private static readonly ConcurrentDictionary<string, bool> OwnIcons = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Enthält die Datei ein Symbol? (Sonst liefert Windows für sie das allgemeine Programmsymbol.)</summary>
    private static bool HasOwnIcon(string file) => OwnIcons.GetOrAdd(file, static f =>
    {
        try { return ExtractIconExW(f, -1, null, null, 0) > 0; }
        catch { return false; }
    });

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint ExtractIconExW(string file, int index, IntPtr[]? large, IntPtr[]? small, uint count);

    /// <summary>Kachel je Art: Bildschirm (System), Raster (Oberfläche), Lupe (Suche), Zahnrad (Einstellungen), Schild (Sicherheit),
    /// Pulslinie (Telemetrie), Megafon (Tipps, Hinweise, Werbung), Paket (Installation), Eingabeaufforderung (Kommandozeile).</summary>
    private static ImageSource CategoryTile(WinCategory category)
    {
        var (color, glyph) = category switch
        {
            WinCategory.Shell => (0x0067C0u, ""),
            WinCategory.Search => (0x0067C0u, ""),
            WinCategory.Settings => (0x5D6B7Au, ""),
            WinCategory.Security => (0x107C10u, ""),
            WinCategory.Telemetry => (0xCA5010u, ""),
            WinCategory.Content => (0x8764B8u, ""),
            WinCategory.Install => (0x038387u, ""),
            WinCategory.CommandLine => (0x2B2F36u, ""),
            _ => (0x0078D4u, ""),
        };
        var group = new DrawingGroup();
        group.Children.Add(new GeometryDrawing(Brush(color), null, new RectangleGeometry(new Rect(2, 2, 28, 28), 7, 7)));
        if (Glyph(glyph, "Segoe Fluent Icons, Segoe MDL2 Assets", FontWeights.Normal, new Rect(8, 8, 16, 16)) is { } g)
            group.Children.Add(new GeometryDrawing(Brushes.White, null, g));
        return Freeze(group);
    }

    /// <summary>Hauptprogramm einer bekannten App: Store-Paket, sonst die Programmordner und AppData\Local des Benutzers.</summary>
    private static string? MainFile(KnownApp app)
    {
        foreach (var (family, exe) in app.Packages)
            if (PackageRoot(family) is { } root && File.Exists(Path.Combine(root, exe))) return Path.Combine(root, exe);
        foreach (var dir in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.LocalApplicationData })
        foreach (var file in app.Files)
        {
            var p = Path.Combine(Environment.GetFolderPath(dir), file);
            var found = p.Contains('*') ? ExistingFile(p) : File.Exists(p) ? p : null;
            if (found != null) return found;
        }
        return null;
    }

    /// <summary>Vorhandene Datei zu einer Prozessangabe: der Pfad selbst, sonst die neueste Datei, auf die das Muster passt (ein Pfad
    /// einer alten Version wird dazu erst zum Muster, wie es auch eine Regel bekäme); null, wenn nichts passt.</summary>
    public static string? ExistingFile(string path)
    {
        if (path.Length < 4 || path[1] != ':' || path.Contains("..") || path.StartsWith('@')) return null;
        if (!path.Contains('*') && File.Exists(path)) return path;
        return Resolved.GetOrAdd(path, static p =>
        {
            try
            {
                var pattern = p.Contains('*') ? p : AlertRules.ProcessPattern(p);
                return pattern.Contains('*') ? FromPackage(pattern) ?? Glob(pattern) : null;
            }
            catch { return null; }
        });
    }

    // WindowsApps\Name_*_x64__Herausgeber\Rest: Paketfamilie „Name_Herausgeber“.
    private static readonly Regex PackageSegment = new(@"\\WindowsApps\\([^\\_]+)_\*_[^\\_]*__([a-z0-9]+)\\(.+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static string? FromPackage(string pattern)
    {
        var m = PackageSegment.Match(pattern);
        if (!m.Success || m.Groups[3].Value.Contains('*')) return null;
        var root = PackageRoot(m.Groups[1].Value + "_" + m.Groups[2].Value);
        var file = root == null ? null : Path.Combine(root, m.Groups[3].Value);
        return file != null && File.Exists(file) ? file : null;
    }

    /// <summary>Muster mit „*“ in Ordnernamen auflösen; höchstens einige hundert Ordner (ein Temp-Ordner kann sehr voll sein).</summary>
    private static string? Glob(string pattern)
    {
        var parts = pattern.Split('\\');
        if (parts.Length < 2 || parts[^1].Contains('*')) return null;
        var dirs = new List<string> { parts[0] + "\\" };
        for (var i = 1; i < parts.Length - 1 && dirs.Count > 0; i++)
        {
            var next = new List<string>();
            foreach (var d in dirs)
            {
                if (!parts[i].Contains('*')) { next.Add(Path.Combine(d, parts[i])); continue; }
                try { next.AddRange(Directory.EnumerateDirectories(d, parts[i]).Take(400 - next.Count)); } catch { }
                if (next.Count >= 400) break;
            }
            dirs = next;
        }
        return dirs.Select(d => Path.Combine(d, parts[^1])).Where(File.Exists)
            .OrderByDescending(f => { try { return File.GetLastWriteTimeUtc(f); } catch { return DateTime.MinValue; } })
            .FirstOrDefault();
    }

    private static readonly ConcurrentDictionary<string, string?> PackageRoots = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Installationsordner eines Store-Pakets des Benutzers (neueste Version), sonst null.</summary>
    private static string? PackageRoot(string family) => PackageRoots.GetOrAdd(family, static f =>
    {
        try
        {
            uint count = 0, bufferLength = 0;
            var rc = GetPackagesByPackageFamily(f, ref count, null, ref bufferLength, IntPtr.Zero);
            if (rc != 122 /*ERROR_INSUFFICIENT_BUFFER*/ || count == 0 || bufferLength == 0) return null;
            var names = new IntPtr[count];
            // Die Namen-Zeiger zeigen in diesen Puffer; deshalb fester, nicht verschiebbarer Speicher.
            var buffer = Marshal.AllocHGlobal((int)bufferLength * 2);
            try
            {
                if (GetPackagesByPackageFamily(f, ref count, names, ref bufferLength, buffer) != 0) return null;
                string? best = null;
                foreach (var namePtr in names.Take((int)count))
                {
                    var fullName = Marshal.PtrToStringUni(namePtr);
                    if (fullName == null) continue;
                    uint len = 0;
                    if (GetPackagePathByFullName(fullName, ref len, null) != 122) continue;
                    var sb = new StringBuilder((int)len);
                    if (GetPackagePathByFullName(fullName, ref len, sb) != 0) continue;
                    var path = sb.ToString();
                    if (Directory.Exists(path) && (best == null || string.CompareOrdinal(fullName, best) > 0)) best = path;
                }
                return best;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        catch { return null; }
    });

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetPackagesByPackageFamily(string packageFamilyName, ref uint count, [Out] IntPtr[]? packageFullNames, ref uint bufferLength, IntPtr buffer);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetPackagePathByFullName(string packageFullName, ref uint pathLength, StringBuilder? path);

    // ------------------------------------------------------------------ Zeichnen (32×32-Fläche wie die übrigen Symbole)

    private static SolidColorBrush Brush(uint rgb)
    {
        var b = new SolidColorBrush(Color.FromRgb((byte)(rgb >> 16), (byte)(rgb >> 8), (byte)rgb));
        b.Freeze();
        return b;
    }

    /// <summary>Ersatz, solange die App nicht installiert ist (etwa eine Regel von früher): Anfangsbuchstabe auf ihrer Farbe.</summary>
    private static ImageSource LetterTile(KnownApp app, string? label = null)
    {
        var color = app.Id switch
        {
            "claude" or "claude-code" => 0xD97757u, "chatgpt" => 0x10A37Fu, "chrome" => 0x4285F4u, "brave" => 0xFB542Bu,
            "firefox" => 0xFF7139u, "edge" => 0x0C59A4u, "vscode" => 0x007ACCu, "vscode-insiders" => 0x24BFA5u,
            "visualstudio" => 0x5C2D91u, "nordvpn" => 0x4687FFu, "office" => 0xD83B01u, "onedrive" => 0x0364B8u,
            "outlook" => 0x0F6CBDu, "teams" => 0x4B53BCu,
            "adobe-cc" => 0xDA1F26u, "acrobat" => 0xB30B00u, _ => 0x8A939Eu,
        };
        // Anfangsbuchstabe ohne Herstellernamen: „O“ für Microsoft Office, „C“ für Adobe Creative Cloud.
        var name = label ?? app.Title;
        foreach (var vendor in new[] { "Microsoft ", "Adobe " })
            if (name.StartsWith(vendor, StringComparison.Ordinal) && name.Length > vendor.Length) name = name[vendor.Length..];
        var group = new DrawingGroup();
        group.Children.Add(new GeometryDrawing(Brush(color), null, new RectangleGeometry(new Rect(2, 2, 28, 28), 7, 7)));
        if (Glyph(name[..1], "Segoe UI", FontWeights.Bold, new Rect(8, 7, 16, 18)) is { } letter)
            group.Children.Add(new GeometryDrawing(Brushes.White, null, letter));
        return Freeze(group);
    }

    /// <summary>Abzeichen unten rechts: Pfeile im Kreis (Updater), Zahnrad (Hilfsprogramm), Eingabeaufforderung (Kommandozeile).</summary>
    private static ImageSource WithBadge(ImageSource icon, AppRole role)
    {
        var (fill, glyph) = role switch
        {
            AppRole.Updater => (Brush(0x1F7AE0), ""),
            AppRole.CommandLine => (Brush(0x2B2F36), ""),
            _ => (Brush(0x6E7781), ""),
        };
        var group = new DrawingGroup();
        group.Children.Add(new GeometryDrawing(Brushes.Transparent, null, new RectangleGeometry(new Rect(0, 0, 32, 32))));
        group.Children.Add(new ImageDrawing(icon, new Rect(0, 0, 32, 32)));
        // In den Listen ist das Symbol nur 16–18 px groß; kleiner wäre das Abzeichen nicht mehr zu erkennen.
        var center = new Point(23, 23);
        group.Children.Add(new GeometryDrawing(Brushes.White, null, new EllipseGeometry(center, 9.6, 9.6)));
        group.Children.Add(new GeometryDrawing(fill, null, new EllipseGeometry(center, 8.2, 8.2)));
        if (Glyph(glyph, "Segoe Fluent Icons, Segoe MDL2 Assets", FontWeights.Normal, new Rect(18, 18, 10, 10)) is { } g)
            group.Children.Add(new GeometryDrawing(Brushes.White, null, g));
        return Freeze(group);
    }

    /// <summary>Zeichen als Fläche, in das Rechteck eingepasst und mittig; null ohne passende Schrift (dann eben ohne Zeichen).</summary>
    private static Geometry? Glyph(string text, string font, FontWeight weight, Rect box)
    {
        try
        {
            var geometry = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                new Typeface(new FontFamily(font), FontStyles.Normal, weight, FontStretches.Normal), 32, Brushes.White, 1.0).BuildGeometry(new Point(0, 0));
            var b = geometry.Bounds;
            if (b.IsEmpty || b.Width <= 0 || b.Height <= 0) return null;
            var scale = Math.Min(box.Width / b.Width, box.Height / b.Height);
            var t = new TransformGroup();
            t.Children.Add(new TranslateTransform(-b.X - b.Width / 2, -b.Y - b.Height / 2));
            t.Children.Add(new ScaleTransform(scale, scale));
            t.Children.Add(new TranslateTransform(box.X + box.Width / 2, box.Y + box.Height / 2));
            geometry.Transform = t;
            geometry.Freeze();
            return geometry;
        }
        catch { return null; }
    }

    private static ImageSource Freeze(DrawingGroup group)
    {
        var image = new DrawingImage(group);
        image.Freeze();
        return image;
    }
}
