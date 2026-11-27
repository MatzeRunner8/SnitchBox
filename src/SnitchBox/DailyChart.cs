using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Balken je Tag im Kopf des Netzwerkmonitors: empfangen (blau) und gesendet (orange) nebeneinander, der heutige Tag rechts.
/// Über einem Tag zeigt ein Tooltip Datum und Mengen.</summary>
public sealed class DailyChart : FrameworkElement
{
    private static readonly SolidColorBrush DownBrush = Frozen(Color.FromRgb(0x2E, 0x8B, 0xE6)), UpBrush = Frozen(Color.FromRgb(0xE0, 0x8A, 0x2E)),
        Baseline = Frozen(Color.FromArgb(0x50, 0x80, 0x80, 0x80));
    private IReadOnlyList<(DateOnly Day, long Down, long Up)> _series = [];
    private readonly ToolTip _tip = new() { Placement = PlacementMode.Relative };
    private int _tipIndex = -1;

    private static SolidColorBrush Frozen(Color c)
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }

    public DailyChart()
    {
        _tip.PlacementTarget = this;
        ClipToBounds = true;
    }

    public IReadOnlyList<(DateOnly Day, long Down, long Up)> Series
    {
        get => _series;
        set
        {
            _series = value;
            if (_tipIndex >= value.Count) CloseTip();
            else if (_tipIndex >= 0) _tip.Content = TipText(value[_tipIndex]);
            InvalidateVisual();
        }
    }

    private double Slot => _series.Count == 0 ? 0 : ActualWidth / _series.Count;

    protected override void OnRender(DrawingContext dc)
    {
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, ActualWidth, ActualHeight)); // auch leere Stellen zeigen den Tooltip
        if (_series.Count == 0 || ActualWidth < 10 || ActualHeight < 6) return;
        var max = Math.Max(1024, _series.Max(s => Math.Max(s.Down, s.Up)));
        var slot = Slot;
        var bar = Math.Max(1, Math.Min(12, slot * 0.36));
        var h = ActualHeight - 1;
        dc.DrawRectangle(Baseline, null, new Rect(0, h, ActualWidth, 1));
        for (var i = 0; i < _series.Count; i++)
        {
            var (_, down, up) = _series[i];
            var center = slot * i + slot / 2;
            var dh = down / (double)max * (h - 1);
            var uh = up / (double)max * (h - 1);
            if (down > 0) dc.DrawRectangle(DownBrush, null, new Rect(center - bar - 0.5, h - Math.Max(1, dh), bar, Math.Max(1, dh)));
            if (up > 0) dc.DrawRectangle(UpBrush, null, new Rect(center + 0.5, h - Math.Max(1, uh), bar, Math.Max(1, uh)));
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (_series.Count == 0) { CloseTip(); return; }
        var pos = e.GetPosition(this);
        var i = Math.Clamp((int)(pos.X / Slot), 0, _series.Count - 1);
        if (i != _tipIndex)
        {
            _tipIndex = i;
            _tip.Content = TipText(_series[i]);
            _tip.IsOpen = false;
        }
        _tip.HorizontalOffset = pos.X + 14;
        _tip.VerticalOffset = pos.Y + 16;
        _tip.IsOpen = true;
    }

    private static string TipText((DateOnly Day, long Down, long Up) d) =>
        d.Day.ToDateTime(TimeOnly.MinValue).ToString("D", CultureFor()) + "\n↓ " + Ui.Size(d.Down) + "   ↑ " + Ui.Size(d.Up);

    protected override void OnMouseLeave(MouseEventArgs e) => CloseTip();

    private void CloseTip()
    {
        _tipIndex = -1;
        _tip.IsOpen = false;
    }

    /// <summary>Datum in der Sprache von SnitchBox (nicht in der von Windows).</summary>
    internal static CultureInfo CultureFor()
    {
        try { return CultureInfo.GetCultureInfo(Loc.Language); }
        catch (CultureNotFoundException) { return CultureInfo.CurrentCulture; }
    }
}
