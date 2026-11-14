using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace VPNShare.Desktop;

// Original VPN Share mark: Wi-Fi, protected connection and device sharing.
// A deliberately simplified rendering keeps the icon legible at 16x16.
internal static class BrandIcon
{
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    internal static Icon Create()
    {
        using var bitmap = new Bitmap(64, 64, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var background = new LinearGradientBrush(
                new Rectangle(2, 2, 60, 60),
                Color.FromArgb(6, 43, 85), Color.FromArgb(57, 15, 100), 25f);
            using var tile = new GraphicsPath();
            const int inset = 2, size = 60, corner = 15;
            tile.AddArc(inset, inset, corner, corner, 180, 90);
            tile.AddArc(inset + size - corner, inset, corner, corner, 270, 90);
            tile.AddArc(inset + size - corner, inset + size - corner, corner, corner, 0, 90);
            tile.AddArc(inset, inset + size - corner, corner, corner, 90, 90);
            tile.CloseFigure();
            g.FillPath(background, tile);
            using var border = new Pen(Color.FromArgb(91, 221, 250), 2);
            g.DrawPath(border, tile);

            // Two high-contrast wireless arcs, rather than tiny lettering.
            using var wifi = new Pen(Color.FromArgb(112, 245, 255), 4.5f)
                { StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawArc(wifi, 15, 9, 34, 25, 211, 118);
            g.DrawArc(wifi, 22, 18, 20, 14, 211, 118);
            using var dot = new SolidBrush(Color.FromArgb(122, 245, 255));
            g.FillEllipse(dot, 30, 29, 4, 4);

            // Shield is intentionally central and remains distinct in the tray.
            using var shield = new GraphicsPath();
            shield.AddPolygon(new[] {
                new Point(32, 31), new Point(48, 36), new Point(46, 49),
                new Point(32, 58), new Point(18, 49), new Point(16, 36)
            });
            using var fill = new LinearGradientBrush(
                new Rectangle(16, 31, 32, 27),
                Color.FromArgb(7, 123, 200), Color.FromArgb(111, 37, 175), 30f);
            g.FillPath(fill, shield);
            using var shieldBorder = new Pen(Color.FromArgb(210, 251, 255), 2.5f);
            g.DrawPath(shieldBorder, shield);

            // Three nodes indicate sharing, with no proprietary device silhouette.
            using var line = new Pen(Color.White, 2.6f)
                { StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawLine(line, 28, 46, 36, 42);
            g.DrawLine(line, 28, 46, 36, 51);
            g.FillEllipse(Brushes.White, 24.5f, 42.5f, 7, 7);
            g.FillEllipse(Brushes.White, 33.5f, 38.5f, 7, 7);
            g.FillEllipse(Brushes.White, 33.5f, 47.5f, 7, 7);
        }

        var handle = bitmap.GetHicon();
        try
        {
            using var temporary = Icon.FromHandle(handle);
            return (Icon)temporary.Clone();
        }
        finally { DestroyIcon(handle); }
    }
}
