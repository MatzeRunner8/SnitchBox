using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using SnitchBox.Core;

namespace SnitchBox;

public enum StopKind { Start, Hop, End }

/// <summary>Eine Station der Route auf der Karte: ein Land mit den Hops, die nacheinander dort liegen.</summary>
public sealed record MapStop(MapCountry Country, string Label, string Tip, StopKind Kind);

/// <summary>Weltkarte mit dem Weg der Routenverfolgung: Länder der Route hervorgehoben, Stationen als nummerierte Punkte, dazwischen
/// Großkreise mit Pfeil in Wegrichtung. Mausrad zoomt (um den Mauszeiger), Ziehen verschiebt, Doppelklick zoomt hinein; über einer
/// Station zeigt ein Tooltip ihre Hops. Alles wird hier gezeichnet – ohne Kartendienst, ohne Netz.</summary>
public sealed class MapView : FrameworkElement
{
    // Kartenraum: Projektion mit y nach unten (wie der Bildschirm), damit die Ansicht nur skaliert und verschiebt.
    private static readonly Lock Gate = new();
    private static StreamGeometry? _land;
    private static readonly Dictionary<string, StreamGeometry> CountryShapes = [];
    private static readonly Rect World = WorldBounds();

    private IReadOnlyList<MapStop> _stops = [];
    private List<List<Point>> _lines = [];
    private double _scale = -1, _cx, _cy;
    private bool _userMoved, _dragging, _panning;
    private Point _dragFrom, _pressAt;
    private readonly ToolTip _tip = new() { Placement = PlacementMode.Relative };
    private MapStop? _tipFor;

    public MapView()
    {
        ClipToBounds = true;
        Focusable = true;
        FocusVisualStyle = null;
        Cursor = Cursors.Hand;
        _tip.PlacementTarget = this;
    }

    private static Point P(double lon, double lat)
    {
        var (x, y) = MapProjection.Project(lon, lat);
        return new Point(x, -y);
    }

    private static Rect WorldBounds()
    {
        var top = P(0, 84).Y;
        var bottom = P(0, -58).Y;
        return new Rect(-MapProjection.MaxX, top, 2 * MapProjection.MaxX, bottom - top);
    }

    private static void AddRings(StreamGeometryContext g, MapCountry c)
    {
        foreach (var r in c.Rings)
        {
            var pts = new List<Point>(r.Length / 2);
            for (var i = 0; i < r.Length; i += 2) pts.Add(P(r[i], r[i + 1]));
            g.BeginFigure(pts[0], true, true);
            g.PolyLineTo(pts.Skip(1).ToList(), true, false);
        }
    }

    private static StreamGeometry Land()
    {
        lock (Gate)
        {
            if (_land != null) return _land;
            var geo = new StreamGeometry { FillRule = FillRule.EvenOdd };
            using (var g = geo.Open())
                foreach (var c in WorldMap.Default.Countries) AddRings(g, c);
            geo.Freeze();
            return _land = geo;
        }
    }

    private static StreamGeometry? Shape(MapCountry c)
    {
        if (c.Rings.Count == 0 || c.Code.Length == 0) return null;
        lock (Gate)
        {
            if (CountryShapes.TryGetValue(c.Code, out var known)) return known;
            var geo = new StreamGeometry { FillRule = FillRule.EvenOdd };
            using (var g = geo.Open()) AddRings(g, c);
            geo.Freeze();
            return CountryShapes[c.Code] = geo;
        }
    }

    /// <summary>Neue Stationen zeigen; solange niemand die Ansicht verschoben oder gezoomt hat, passt sie sich der Route an.</summary>
    public void SetStops(IReadOnlyList<MapStop> stops)
    {
        _stops = stops;
        _lines = [];
        for (var i = 1; i < stops.Count; i++)
        {
            var a = stops[i - 1].Country;
            var b = stops[i].Country;
            if (a == b) continue;
            foreach (var part in MapProjection.GreatCircle(a.Lon, a.Lat, b.Lon, b.Lat))
                _lines.Add(part.Select(p => P(p.Lon, p.Lat)).ToList());
        }
        if (_tipFor != null && !stops.Contains(_tipFor)) CloseTip();
        if (!_userMoved) Fit(false);
        InvalidateVisual();
    }

    public void FitRoute() { _userMoved = false; Fit(false); InvalidateVisual(); }

    /// <summary>Für einen neuen Trace: keine Stationen, die Ansicht folgt wieder der Route.</summary>
    public void ResetView()
    {
        _userMoved = false;
        SetStops([]);
    }
    public void FitWorld() { _userMoved = true; Fit(true); InvalidateVisual(); }

    public void ZoomBy(double factor) => ZoomAt(new Point(ActualWidth / 2, ActualHeight / 2), factor);

    private double MinScale => ActualWidth <= 0 || ActualHeight <= 0 ? 1 : Math.Min(ActualWidth / World.Width, ActualHeight / World.Height) * 0.8;
    private double MaxScale => MinScale / 0.8 * 40;

    private void Fit(bool world)
    {
        if (ActualWidth <= 0 || ActualHeight <= 0) { _scale = -1; return; }
        var box = World;
        if (!world && _stops.Count > 0)
        {
            var pts = _stops.Select(s => P(s.Country.Lon, s.Country.Lat)).Concat(_lines.SelectMany(l => l)).ToList();
            double x0 = pts.Min(p => p.X), x1 = pts.Max(p => p.X), y0 = pts.Min(p => p.Y), y1 = pts.Max(p => p.Y);
            // Mindestens etwa ein Drittel Europas, damit eine Route im Inland nicht bis zur Unkenntlichkeit vergrößert wird.
            const double min = 0.35;
            if (x1 - x0 < min) { var m = (x0 + x1) / 2; x0 = m - min / 2; x1 = m + min / 2; }
            if (y1 - y0 < min * 0.6) { var m = (y0 + y1) / 2; y0 = m - min * 0.3; y1 = m + min * 0.3; }
            box = new Rect(x0, y0, x1 - x0, y1 - y0);
            box.Inflate(box.Width * 0.15 + 0.05, box.Height * 0.15 + 0.05);
        }
        _scale = Math.Clamp(Math.Min(ActualWidth / box.Width, ActualHeight / box.Height), MinScale, MaxScale);
        _cx = box.X + box.Width / 2;
        _cy = box.Y + box.Height / 2;
        ClampCenter();
    }

    private void ClampCenter()
    {
        _cx = Math.Clamp(_cx, World.Left, World.Right);
        _cy = Math.Clamp(_cy, World.Top, World.Bottom);
    }

    private Point ToScreen(Point p) => new((p.X - _cx) * _scale + ActualWidth / 2, (p.Y - _cy) * _scale + ActualHeight / 2);
    private Point ToMap(Point s) => new((s.X - ActualWidth / 2) / _scale + _cx, (s.Y - ActualHeight / 2) / _scale + _cy);

    private void ZoomAt(Point screen, double factor)
    {
        if (_scale <= 0) return;
        var before = ToMap(screen);
        _scale = Math.Clamp(_scale * factor, MinScale, MaxScale);
        _cx = before.X - (screen.X - ActualWidth / 2) / _scale;
        _cy = before.Y - (screen.Y - ActualHeight / 2) / _scale;
        ClampCenter();
        _userMoved = true;
        InvalidateVisual();
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo info)
    {
        base.OnRenderSizeChanged(info);
        if (_scale <= 0 || !_userMoved) Fit(false);
        else _scale = Math.Clamp(_scale, MinScale, MaxScale);
        // WPF hat für die neue Größe schon mit den alten Werten gezeichnet.
        InvalidateVisual();
    }

    // ---- Farben (hell/dunkel nach der Textfarbe des Fensters)
    private bool Dark
    {
        get
        {
            var c = (TextElement.GetForeground(this) as SolidColorBrush)?.Color ?? Colors.Black;
            return 0.299 * c.R + 0.587 * c.G + 0.114 * c.B > 140;
        }
    }

    private static SolidColorBrush Brush(uint argb)
    {
        var b = new SolidColorBrush(Color.FromArgb((byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb));
        b.Freeze();
        return b;
    }

    private static readonly SolidColorBrush OceanLight = Brush(0xFFD9E7F4), LandLight = Brush(0xFFF6F3EC), BorderLight = Brush(0xFFB3AEA3),
        OceanDark = Brush(0xFF101A26), LandDark = Brush(0xFF2B3038), BorderDark = Brush(0xFF4D5560),
        RouteLight = Brush(0xFF1F7AE0), RouteDark = Brush(0xFF4DA3FF), VisitedLight = Brush(0xFFFFE3BF), VisitedDark = Brush(0xFF4A3A22),
        VisitedBorder = Brush(0xFFE08A2E), StartFill = Brush(0xFF2EA043), EndFill = Brush(0xFFE08A2E), HaloLight = Brush(0xC0FFFFFF), HaloDark = Brush(0xC0101A26);

    protected override void OnRender(DrawingContext dc)
    {
        var dark = Dark;
        var size = new Rect(0, 0, ActualWidth, ActualHeight);
        dc.DrawRectangle(dark ? OceanDark : OceanLight, null, size);
        if (_scale <= 0) Fit(false);
        if (_scale <= 0) return;
        dc.PushTransform(new MatrixTransform(_scale, 0, 0, _scale, ActualWidth / 2 - _cx * _scale, ActualHeight / 2 - _cy * _scale));
        dc.DrawGeometry(dark ? LandDark : LandLight, new Pen(dark ? BorderDark : BorderLight, 0.7 / _scale), Land());
        var visitedPen = new Pen(VisitedBorder, 1.2 / _scale);
        foreach (var c in _stops.Select(s => s.Country).Distinct())
            if (Shape(c) is { } shape) dc.DrawGeometry(dark ? VisitedDark : VisitedLight, visitedPen, shape);
        dc.Pop();

        // Linien und Punkte in Bildschirmpixeln (gleich dick bei jedem Zoom).
        var route = dark ? RouteDark : RouteLight;
        var halo = new Pen(dark ? HaloDark : HaloLight, 5.5) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round };
        var line = new Pen(route, 2.4) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round };
        foreach (var l in _lines)
        {
            var geo = new StreamGeometry();
            using (var g = geo.Open())
            {
                g.BeginFigure(ToScreen(l[0]), false, false);
                g.PolyLineTo(l.Skip(1).Select(ToScreen).ToList(), true, true);
            }
            geo.Freeze();
            dc.DrawGeometry(null, halo, geo);
            dc.DrawGeometry(null, line, geo);
        }
        foreach (var l in _lines) Arrow(dc, l, route);
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var face = new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);
        var markers = Markers();
        foreach (var (stop, at) in markers)
        {
            var fill = stop.Kind switch { StopKind.Start => StartFill, StopKind.End => EndFill, _ => route };
            dc.DrawEllipse(fill, new Pen(dark ? HaloDark : Brushes.White, 2), at, 11, 11);
            var text = new FormattedText(stop.Label, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, face, stop.Label.Length > 2 ? 9.5 : 11.5, Brushes.White, dpi);
            dc.DrawText(text, new Point(at.X - text.Width / 2, at.Y - text.Height / 2));
        }
        // Namen von Start und Ziel rechts neben dem letzten Punkt im selben Land (dort können mehrere nebeneinander stehen).
        foreach (var (stop, at) in markers)
        {
            if (stop.Kind == StopKind.Hop) continue;
            var right = markers.Where(m => m.Stop.Country == stop.Country).Max(m => m.At.X);
            var name = new FormattedText(stop.Country.Name, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, face, 12, dark ? Brushes.White : Brushes.Black, dpi);
            var box = new Rect(right + 15, at.Y - name.Height / 2 - 1, name.Width + 10, name.Height + 2);
            dc.DrawRoundedRectangle(dark ? HaloDark : HaloLight, null, box, 5, 5);
            dc.DrawText(name, new Point(box.X + 5, box.Y + 1));
        }
    }

    /// <summary>Pfeil in der Mitte eines Großkreises, in Wegrichtung.</summary>
    private void Arrow(DrawingContext dc, List<Point> l, Brush brush)
    {
        if (l.Count < 2) return;
        var pts = l.Select(ToScreen).ToList();
        var total = 0.0;
        for (var i = 1; i < pts.Count; i++) total += (pts[i] - pts[i - 1]).Length;
        if (total < 60) return; // zu kurz – der Pfeil verdeckte die Punkte
        var half = total / 2;
        for (var i = 1; i < pts.Count; i++)
        {
            var seg = pts[i] - pts[i - 1];
            if (seg.Length < half) { half -= seg.Length; continue; }
            seg.Normalize();
            var tip = pts[i - 1] + seg * half + seg * 6;
            var side = new Vector(-seg.Y, seg.X);
            var geo = new StreamGeometry();
            using (var g = geo.Open())
            {
                g.BeginFigure(tip, true, true);
                g.PolyLineTo([tip - seg * 12 + side * 6, tip - seg * 12 - side * 6], true, true);
            }
            geo.Freeze();
            dc.DrawGeometry(brush, null, geo);
            return;
        }
    }

    /// <summary>Bildschirmposition je Station; mehrere Stationen im selben Land rücken nebeneinander.</summary>
    private List<(MapStop Stop, Point At)> Markers()
    {
        var used = new Dictionary<MapCountry, int>();
        var result = new List<(MapStop, Point)>(_stops.Count);
        foreach (var s in _stops)
        {
            var n = used.GetValueOrDefault(s.Country);
            used[s.Country] = n + 1;
            var p = ToScreen(P(s.Country.Lon, s.Country.Lat));
            result.Add((s, new Point(p.X + n * 20, p.Y)));
        }
        return result;
    }

    // ---- Maus
    protected override void OnMouseWheel(MouseWheelEventArgs e)
    {
        ZoomAt(e.GetPosition(this), Math.Pow(1.25, e.Delta / 120.0));
        e.Handled = true;
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        Focus();
        if (e.ClickCount == 2)
        {
            ZoomAt(e.GetPosition(this), 2);
            e.Handled = true;
            return;
        }
        _dragging = CaptureMouse();
        _panning = false;
        _dragFrom = _pressAt = e.GetPosition(this);
        e.Handled = true;
    }

    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        if (_dragging) ReleaseMouseCapture();
        _dragging = false;
    }

    protected override void OnLostMouseCapture(MouseEventArgs e) => _dragging = false;

    protected override void OnMouseMove(MouseEventArgs e)
    {
        var pos = e.GetPosition(this);
        if (_dragging && _scale > 0)
        {
            // Erst ab der Ziehschwelle von Windows verschieben: Ein Klick mit einem Pixel Zittern schaltete sonst das Mitführen ab.
            if (!_panning && Math.Abs(pos.X - _pressAt.X) < SystemParameters.MinimumHorizontalDragDistance
                && Math.Abs(pos.Y - _pressAt.Y) < SystemParameters.MinimumVerticalDragDistance) return;
            _panning = true;
            var d = pos - _dragFrom;
            _dragFrom = pos;
            if (d.X == 0 && d.Y == 0) return;
            _cx -= d.X / _scale;
            _cy -= d.Y / _scale;
            ClampCenter();
            _userMoved = true;
            CloseTip();
            InvalidateVisual();
            return;
        }
        MapStop? hit = null;
        foreach (var (stop, at) in Markers())
            if ((at - pos).Length <= 13) hit = stop; // die zuletzt gezeichnete liegt oben
        if (hit == null) { CloseTip(); return; }
        if (hit != _tipFor)
        {
            _tipFor = hit;
            _tip.Content = hit.Tip;
            _tip.IsOpen = false;
        }
        _tip.HorizontalOffset = pos.X + 16;
        _tip.VerticalOffset = pos.Y + 18;
        _tip.IsOpen = true;
    }

    protected override void OnMouseLeave(MouseEventArgs e) => CloseTip();

    private void CloseTip()
    {
        _tipFor = null;
        _tip.IsOpen = false;
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.Add or Key.OemPlus: ZoomBy(1.5); break;
            case Key.Subtract or Key.OemMinus: ZoomBy(1 / 1.5); break;
            case Key.Home: FitRoute(); break;
            default: return;
        }
        e.Handled = true;
    }
}
