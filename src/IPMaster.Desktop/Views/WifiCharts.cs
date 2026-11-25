using System.Globalization;
using System.Net.NetworkInformation;
using Avalonia;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using IPMaster.Core.Wifi;
using K = IPMaster.Desktop.Styling.Theme.Keys;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Channel spectrum of one band (WIFI-03): every BSS as a trapezoid over the spectrum it occupies, height = signal.
/// Overlap is visible as overlapping shapes; the connected BSS is drawn with a thick outline and "●" in its label.
/// DFS channels (5 GHz 52–144) are shaded and labelled. Width unknown = drawn at 20 MHz with a dashed outline.
/// </summary>
internal sealed class SpectrumChart : Styling.ThemedControl
{
    private static readonly string[] Series = [K.Series1, K.Series2, K.Series3, K.Series4];

    public WifiBand Band { get; set; } = WifiBand.Band24;

    public IReadOnlyList<WifiBss> Networks { get; set; } = [];

    public PhysicalAddress? Connected { get; set; }

    public static (double Low, double High) Range(WifiBand band) => band switch
    {
        WifiBand.Band5 => (5150, 5895),
        WifiBand.Band6 => (5925, 7125),
        _ => (2399, 2496),
    };

    public override void Render(DrawingContext context)
    {
        var b = Bounds;
        if (b.Width < 120 || b.Height < 80) return;
        const double left = 52, bottom = 24, top = 22, right = 10;
        var plot = new Rect(left, top, b.Width - left - right, b.Height - top - bottom);
        var text = Brush(K.ChartText);
        context.FillRectangle(Brush(K.ChartSurface), plot);
        var (lo, hi) = Range(Band);
        double X(double mhz) => plot.Left + ((mhz - lo) / (hi - lo) * plot.Width);
        double Y(double dbm) => plot.Bottom - ((Math.Clamp(dbm, -100, -20) + 100) / 80 * plot.Height);
        FormattedText Label(string s, IBrush brush, double size = 11) => new(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, size, brush);

        if (Band == WifiBand.Band5)
        {
            var dfs = new Rect(new Point(X(5250), plot.Top), new Point(X(5730), plot.Bottom));
            context.FillRectangle(Tint(K.ChartGrid, 0.6), dfs);
            context.DrawText(Label("DFS (radar detection)", text, 10), new Point(dfs.Left + 4, plot.Top + 2));
        }

        var grid = Pen(K.ChartGrid);
        for (var dbm = -90; dbm <= -30; dbm += 10)
        {
            var y = Y(dbm);
            context.DrawLine(grid, new Point(plot.Left, y), new Point(plot.Right, y));
            context.DrawText(Label($"{dbm} dBm", text, 10), new Point(4, y - 7));
        }

        foreach (var (ch, mhz) in Ticks(Band))
        {
            var x = X(mhz);
            context.DrawLine(grid, new Point(x, plot.Bottom), new Point(x, plot.Bottom + 4));
            var t = Label(ch.ToString(CultureInfo.InvariantCulture), text, 10);
            context.DrawText(t, new Point(x - (t.Width / 2), plot.Bottom + 5));
        }

        var visible = Networks.Where(n => n.Band == Band).OrderBy(n => n.RssiDbm).ToList();
        var labels = new List<(Rect Box, FormattedText Text)>();
        foreach (var n in visible)
        {
            var (l, h) = n.Span;
            var key = Series[(int)((uint)StringComparer.Ordinal.GetHashCode(n.Ssid) % Series.Length)];
            var connected = Connected is not null && n.Bssid.Equals(Connected);
            var y = Y(n.RssiDbm);
            var edge = Math.Min(6, (X(h) - X(l)) / 4);
            var geometry = new StreamGeometry();
            using (var g = geometry.Open())
            {
                g.BeginFigure(new Point(X(l), plot.Bottom), true);
                g.LineTo(new Point(X(l) + edge, y));
                g.LineTo(new Point(X(h) - edge, y));
                g.LineTo(new Point(X(h), plot.Bottom));
                g.EndFigure(true);
            }

            context.DrawGeometry(Tint(key, connected ? 0.3 : 0.12), Pen(key, connected ? 2.5 : 1.2, n.WidthMhz is null ? DashStyle.Dash : null), geometry);
            var name = (connected ? "● " : "") + (n.Hidden ? "(hidden)" : n.Ssid);
            var label = Label(name, connected ? Brush(K.TextPrimary) : text, 10);
            var box = new Rect(((X(l) + X(h)) / 2) - (label.Width / 2), Math.Max(2, y - 14), label.Width, label.Height);
            if (connected) labels.RemoveAll(x => x.Box.Intersects(box)); // the connected network's name always shows
            if (connected || (label.Width < (X(h) - X(l)) * 1.6 && !labels.Any(x => x.Box.Intersects(box)))) labels.Add((box, label));
        }

        // labels after the shapes, so no outline crosses a name; a name that would overlap another is left out
        foreach (var (box, label) in labels) context.DrawText(label, box.TopLeft);

        if (visible.Count == 0) context.DrawText(Label("No networks seen in this band.", text, 12), new Point(plot.Left + 8, plot.Top + 8));
    }

    private static IEnumerable<(int Channel, double Mhz)> Ticks(WifiBand band)
    {
        switch (band)
        {
            case WifiBand.Band24:
                for (var c = 1; c <= 14; c++) yield return (c, WifiChannels.FrequencyOf(band, c)!.Value);
                break;
            case WifiBand.Band5:
                foreach (var c in new[] { 36, 52, 64, 100, 116, 132, 144, 149, 165, 177 }) yield return (c, WifiChannels.FrequencyOf(band, c)!.Value);
                break;
            default:
                for (var c = 5; c <= 233; c += 16) yield return (c, WifiChannels.FrequencyOf(band, c)!.Value); // preferred scanning channels
                break;
        }
    }
}

/// <summary>Signal (dBm) over time with the −67 dBm (calls/video) and −75 dBm (weak) reference lines; gaps when disconnected.</summary>
internal sealed class SignalChart : Styling.ThemedControl
{
    public IReadOnlyList<(DateTimeOffset At, int? Rssi)> Samples { get; set; } = [];

    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(10);

    public override void Render(DrawingContext context)
    {
        var b = Bounds;
        if (b.Width < 60 || b.Height < 40) return;
        const double left = 58, bottom = 20, top = 8, right = 8;
        var plot = new Rect(left, top, b.Width - left - right, b.Height - top - bottom);
        var text = Brush(K.ChartText);
        context.FillRectangle(Brush(K.ChartSurface), plot);
        var now = DateTimeOffset.UtcNow;
        var from = now - Window;
        double X(DateTimeOffset t) => plot.Left + ((t - from).TotalSeconds / Window.TotalSeconds * plot.Width);
        double Y(double dbm) => plot.Bottom - ((Math.Clamp(dbm, -100, -20) + 100) / 80 * plot.Height);
        FormattedText Label(string s, IBrush brush) => new(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, 11, brush);
        void Ref(int dbm, string key)
        {
            var y = Y(dbm);
            context.DrawLine(Pen(key, 1, DashStyle.Dash), new Point(plot.Left, y), new Point(plot.Right, y));
            context.DrawText(Label($"{dbm} dBm", Brush(key)), new Point(2, y - 8));
        }

        Ref(-67, K.ChartGood);
        Ref(-75, K.ChartCritical);
        context.DrawText(Label($"−{Window.TotalMinutes:0} min", text), new Point(plot.Left, plot.Bottom + 4));
        context.DrawText(Label("now", text), new Point(plot.Right - 24, plot.Bottom + 4));
        var pen = Pen(K.Series1, 1.5);
        Point? prev = null;
        foreach (var (at, rssi) in Samples.Where(s => s.At >= from))
        {
            if (rssi is not { } r)
            {
                prev = null;
                continue;
            }

            var p = new Point(X(at), Y(r));
            if (prev is { } q) context.DrawLine(pen, q, p);
            else context.DrawEllipse(Brush(K.Series1), null, p, 1.5, 1.5);
            prev = p;
        }
    }
}

/// <summary>
/// Floor plan with survey points and an interpolated heatmap (WIFI-06). Points are numbered; the heatmap is an estimate
/// between them (the caption says so). A click on the plan reports its position as fractions of the image.
/// </summary>
internal sealed class SurveyCanvas : Styling.ThemedControl
{
    public Bitmap? FloorPlan { get; set; }

    public IReadOnlyList<SurveyPoint> Points { get; set; } = [];

    public double?[,]? Heatmap { get; set; }

    public event Action<double, double>? PlanClicked;

    /// <summary>The image rectangle inside the control (uniform fit).</summary>
    public Rect ImageRect()
    {
        var b = Bounds;
        if (FloorPlan is null) return new Rect(0, 0, b.Width, b.Height);
        var s = FloorPlan.Size;
        var scale = Math.Min(b.Width / s.Width, b.Height / s.Height);
        var w = s.Width * scale;
        var h = s.Height * scale;
        return new Rect((b.Width - w) / 2, (b.Height - h) / 2, w, h);
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        var r = ImageRect();
        var p = e.GetPosition(this);
        if (r.Contains(p) && r.Width > 0 && r.Height > 0) PlanClicked?.Invoke((p.X - r.X) / r.Width, (p.Y - r.Y) / r.Height);
    }

    public override void Render(DrawingContext context)
    {
        var b = Bounds;
        context.FillRectangle(Brush(K.ChartSurface), new Rect(b.Size));
        var r = ImageRect();
        var text = Brush(K.TextPrimary);
        if (FloorPlan is not null) context.DrawImage(FloorPlan, r);
        else if (Points.Count == 0)
        {
            context.DrawText(new FormattedText("Load a floor plan (or measure on this blank plan): click a spot to capture a measurement there.",
                CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, 12, Brush(K.ChartText)), new Point(12, 12));
        }

        if (Heatmap is { } grid)
        {
            // one pixel per cell, drawn scaled with smoothing: no cell edges
            int rows = grid.GetLength(0), cols = grid.GetLength(1);
            var weak = ((ISolidColorBrush)Brush(K.ChartCritical)).Color;
            var mid = ((ISolidColorBrush)Brush(K.Warning)).Color;
            var good = ((ISolidColorBrush)Brush(K.ChartGood)).Color;
            using var heat = new WriteableBitmap(new PixelSize(cols, rows), new Vector(96, 96), Avalonia.Platform.PixelFormat.Bgra8888, Avalonia.Platform.AlphaFormat.Premul);
            using (var fb = heat.Lock())
            {
                var row = new byte[cols * 4];
                for (var y = 0; y < rows; y++)
                {
                    Array.Clear(row);
                    for (var x = 0; x < cols; x++)
                    {
                        if (grid[y, x] is not { } v) continue;
                        var t = Math.Clamp((v + 85) / 30, 0, 1); // −85 dBm weak … −55 dBm strong
                        var c = t < 0.5 ? Blend(weak, mid, t * 2) : Blend(mid, good, (t - 0.5) * 2);
                        const double alpha = 0.45;
                        row[(x * 4) + 0] = (byte)(c.B * alpha);
                        row[(x * 4) + 1] = (byte)(c.G * alpha);
                        row[(x * 4) + 2] = (byte)(c.R * alpha);
                        row[(x * 4) + 3] = (byte)(255 * alpha);
                    }

                    System.Runtime.InteropServices.Marshal.Copy(row, 0, fb.Address + (y * fb.RowBytes), row.Length);
                }
            }

            context.DrawImage(heat, new Rect(0, 0, cols, rows), r);
        }

        for (var i = 0; i < Points.Count; i++)
        {
            var p = new Point(r.X + (Points[i].X * r.Width), r.Y + (Points[i].Y * r.Height));
            context.DrawEllipse(Brush(K.ChartSurface), Pen(K.TextPrimary, 1.5), p, 9, 9);
            var label = new FormattedText((i + 1).ToString(CultureInfo.InvariantCulture), CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, 10, text);
            context.DrawText(label, new Point(p.X - (label.Width / 2), p.Y - (label.Height / 2)));
        }
    }

    private static Color Blend(Color a, Color b, double t) =>
        Color.FromArgb(255, (byte)(a.R + ((b.R - a.R) * t)), (byte)(a.G + ((b.G - a.G) * t)), (byte)(a.B + ((b.B - a.B) * t))); // theme-exception: blend of two token colours
}
