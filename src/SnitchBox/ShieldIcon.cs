using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace SnitchBox;

/// <summary>Symbol für „es wird nicht gefiltert“ (Netzwerkfilter aus oder Treiber läuft nicht): dieselbe Schildform wie das
/// App-Symbol (scripts/make_win_icon.swift), aber rot und mit weißem Kreuz – im Infobereich und auf der Taskleiste sofort als
/// „Schutz aus“ zu erkennen. Zur Laufzeit gezeichnet, damit es bei jeder Skalierung scharf ist.</summary>
internal static class ShieldIcon
{
    private static readonly Color Ink = Color.FromRgb(0x12, 0x21, 0x42); // Umrissfarbe des App-Symbols
    private static readonly Color RedLight = Color.FromRgb(0xEF, 0x53, 0x50), RedDark = Color.FromRgb(0xC6, 0x28, 0x28);
    private static ImageSource? _windowIcon;

    /// <summary>Zeichnung auf einer Fläche von 256×256. Wie beim App-Symbol wird jede Größe eigens abgestimmt: Linien bleiben
    /// mindestens so breit, dass sie in <paramref name="size"/> Pixeln sichtbar sind.</summary>
    public static Drawing Off(int size)
    {
        double W(double units, double minPx) => Math.Max(units, minPx * 256 / size);
        var outline = W(12, 1.2);
        var inset = outline / 2 + 4;
        // Schild: oben breite Kante mit leichter Wölbung, unten spitz zulaufend (Koordinaten wie im Swift-Skript, y nach unten).
        var shield = new StreamGeometry();
        using (var c = shield.Open())
        {
            c.BeginFigure(new Point(128, inset), true, true);
            c.BezierTo(new Point(160, 24), new Point(206, 44), new Point(242 - inset, 52), true, true);
            c.BezierTo(new Point(248 - inset, 160), new Point(192, 220), new Point(128, 256 - inset), true, true);
            c.BezierTo(new Point(64, 220), new Point(inset + 8, 160), new Point(inset + 14, 52), true, true);
            c.BezierTo(new Point(50, 44), new Point(96, 24), new Point(128, inset), true, true);
        }
        shield.Freeze();

        var group = new DrawingGroup();
        // Feste Fläche 256×256, auch wo sie durchsichtig ist – sonst rechnete WPF auf die Grenzen der Zeichnung um.
        group.Children.Add(new GeometryDrawing(Brushes.Transparent, null, new RectangleGeometry(new Rect(0, 0, 256, 256))));
        group.Children.Add(new GeometryDrawing(new LinearGradientBrush(RedLight, RedDark, new Point(0.5, 0), new Point(0.5, 1)), null, shield));
        if (size > 32)
        {
            // Rechte Hälfte etwas dunkler: wirkt plastisch wie beim App-Symbol, verschmiert aber klein nicht.
            var shade = new DrawingGroup { ClipGeometry = shield };
            shade.Children.Add(new GeometryDrawing(new SolidColorBrush(Color.FromArgb(31, 0, 64, 115)), null, new RectangleGeometry(new Rect(128, 0, 128, 256))));
            group.Children.Add(shade);
        }
        group.Children.Add(new GeometryDrawing(null, new Pen(new SolidColorBrush(Ink), outline) { LineJoin = PenLineJoin.Round }, shield));

        // Weißes Kreuz für „aus“; klein etwas größer und kräftiger, damit es auch mit 16 px lesbar bleibt.
        var r = size <= 20 ? 46.0 : 40.0;
        const double cx = 128, cy = 122;
        var cross = new Pen(Brushes.White, W(30, 2.0)) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
        group.Children.Add(new GeometryDrawing(null, cross, new LineGeometry(new Point(cx - r, cy - r), new Point(cx + r, cy + r))));
        group.Children.Add(new GeometryDrawing(null, cross, new LineGeometry(new Point(cx + r, cy - r), new Point(cx - r, cy + r))));
        group.Freeze();
        return group;
    }

    /// <summary>Das Symbol als PNG in genau dieser Größe.</summary>
    public static byte[] Png(int size)
    {
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            dc.PushTransform(new ScaleTransform(size / 256.0, size / 256.0));
            dc.DrawDrawing(Off(size));
        }
        var bitmap = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(visual);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = new MemoryStream();
        encoder.Save(stream);
        return stream.ToArray();
    }

    /// <summary>Symbol-Handle für den Infobereich (vom Aufrufer mit DestroyIcon freizugeben).</summary>
    public static IntPtr CreateHIcon(int size)
    {
        var png = Png(size);
        return TrayNative.CreateIconFromResourceEx(png, (uint)png.Length, true, 0x00030000, size, size, 0);
    }

    /// <summary>Fenstersymbol (Titelleiste, Taskleiste) mit allen üblichen Größen, damit Windows für jede Stelle die passend
    /// gezeichnete wählt.</summary>
    public static ImageSource WindowIcon => _windowIcon ??= BitmapFrame.Create(new MemoryStream(Ico([16, 20, 24, 32, 40, 48, 64, 256])),
        BitmapCreateOptions.None, BitmapCacheOption.OnLoad);

    /// <summary>.ico-Datei mit PNG-Einträgen (wie scripts/make_ico.py).</summary>
    private static byte[] Ico(int[] sizes)
    {
        var images = sizes.Select(Png).ToArray();
        using var stream = new MemoryStream();
        using var w = new BinaryWriter(stream);
        w.Write((ushort)0);
        w.Write((ushort)1);
        w.Write((ushort)sizes.Length);
        var offset = 6 + 16 * sizes.Length;
        for (var i = 0; i < sizes.Length; i++)
        {
            w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
            w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
            w.Write((byte)0);
            w.Write((byte)0);
            w.Write((ushort)1);
            w.Write((ushort)32);
            w.Write(images[i].Length);
            w.Write(offset);
            offset += images[i].Length;
        }
        foreach (var image in images) w.Write(image);
        w.Flush();
        return stream.ToArray();
    }
}
