using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace VPNShare.Desktop;

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
                new Rectangle(1, 1, 62, 62),
                Color.FromArgb(15, 42, 83), Color.FromArgb(57, 22, 116), 45f);
            using var rounded = new GraphicsPath();
            rounded.AddArc(2, 2, 60, 60, 14, 180, 90);
            rounded.AddArc(2, 2, 60, 60, 14, 270, 90);
            rounded.AddArc(2, 2, 60, 60, 14, 0, 90);
            rounded.AddArc(2, 2, 60, 60, 14, 90, 90);
            rounded.CloseFigure();
            g.FillPath(background, rounded);
            using var rim = new Pen(Color.FromArgb(85, 211, 250), 2);
            g.DrawPath(rim, rounded);
            using var cyan = new Pen(Color.FromArgb(61, 235, 248), 4.5f)
                { StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawArc(cyan, 16, 9, 32, 24, 210, 120);
            g.DrawArc(cyan, 22, 17, 20, 15, 210, 120);
            g.FillEllipse(Brushes.Aqua, 30, 27, 4, 4);
            using var shield = new GraphicsPath();
            shield.AddPolygon(new[] {
                new Point(32, 30), new Point(47, 36), new Point(45, 49),
                new Point(32, 58), new Point(19, 49), new Point(17, 36)
            });
            using var shieldBrush = new LinearGradientBrush(
                new Rectangle(17, 30, 30, 28),
                Color.FromArgb(18, 125, 211), Color.FromArgb(79, 42, 174), 60f);
            g.FillPath(shieldBrush, shield);
            using var edge = new Pen(Color.FromArgb(195, 250, 255), 2.5f);
            g.DrawPath(edge, shield);
            using var font = new Font("Segoe UI", 10, FontStyle.Bold, GraphicsUnit.Pixel);
            using var white = new SolidBrush(Color.White);
            var text = "VPN";
            var size = g.MeasureString(text, font);
            g.DrawString(text, font, white, 32 - size.Width / 2, 37);
        }
        var handle = bitmap.GetHicon();
        try { using var temporary = Icon.FromHandle(handle); return (Icon)temporary.Clone(); }
        finally { DestroyIcon(handle); }
    }
}
