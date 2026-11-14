using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace VPNShare.Desktop;

// Windows 11 built-in capture fallback. No Npcap or software on clients.
// Uses short bounded ETL captures, converts locally, and discards packet files immediately.
internal sealed class PktMonSampler
{
    private readonly string _folder;
    private readonly Action<string> _log;
    private readonly string _exe;
    public PktMonSampler(string folder, Action<string> log)
    {
        _folder = Path.Combine(folder, "pktmon-capture");
        _log = log;
        _exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "pktmon.exe");
    }

    public bool Available => File.Exists(_exe);
    private static (int exit, string output) Run(string exe, IEnumerable<string> args, int timeoutMs)
    {
        using var p = new Process();
        p.StartInfo = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var arg in args) p.StartInfo.ArgumentList.Add(arg);
        p.Start();
        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(true); } catch { }
            throw new TimeoutException("PktMon command timed out.");
        }
        return (p.ExitCode, p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd());
    }
    private (int exit, string output) Run(int timeout, params string[] args) => Run(_exe, args, timeout);

    // Never stop another user's capture: require an idle global PktMon session.
    public Dictionary<string, (long rx, long tx)> Sample(string guid, int seconds, CancellationToken token)
    {
        if (!Available) throw new FileNotFoundException("Windows pktmon.exe отсутствует.");
        var status = Run(5000, "status");
        if (status.exit != 0) throw new InvalidOperationException("Не удалось проверить состояние PktMon: " + status.output);
        // "Not running" also contains "running"; never mistake an idle session for a busy one.
        var state = status.output.ToLowerInvariant();
        var explicitlyIdle = state.Contains("not running") || state.Contains("not active") ||
            state.Contains("stopped") || state.Contains("не запущен") ||
            state.Contains("не работает") || state.Contains("остановлен");
        if (!explicitlyIdle)
            throw new InvalidOperationException("Невозможно подтвердить, что PktMon свободен. Мониторинг не перехватывает чужую сессию: " + status.output.Trim());

        var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
            Guid.TryParse(n.Id, out var id) && id == Guid.Parse(guid));
        var address = nic?.GetIPProperties().UnicastAddresses.FirstOrDefault(a =>
            a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && a.IPv4Mask != null);
        if (address == null) throw new InvalidOperationException("Не найдена IPv4-подсеть Wi-Fi Direct.");
        var host = address.Address.GetAddressBytes();
        var mask = address.IPv4Mask.GetAddressBytes();
        Directory.CreateDirectory(_folder);
        var etl = Path.Combine(_folder, "capture.etl");
        var pcap = Path.Combine(_folder, "capture.pcapng");
        bool owned = false;
        try
        {
            var start = Run(8000, "start", "--capture", "--comp", "nics", "--pkt-size", "96",
                "--file-name", etl, "--file-size", "16", "--log-mode", "circular");
            if (start.exit != 0) throw new InvalidOperationException("PktMon start: " + start.output);
            owned = true;
            token.WaitHandle.WaitOne(TimeSpan.FromSeconds(seconds));
            var stop = Run(10000, "stop");
            owned = false;
            if (stop.exit != 0) throw new InvalidOperationException("PktMon stop: " + stop.output);
            var convert = Run(20000, "etl2pcap", etl, "--out", pcap);
            if (convert.exit != 0) throw new InvalidOperationException("PktMon convert: " + convert.output);
            return ParsePcapNg(pcap, host, mask);
        }
        finally
        {
            if (owned)
            {
                try { Run(10000, "stop"); } catch (Exception ex) { _log("[pktmon stop] " + ex.Message); }
            }
            try { File.Delete(etl); } catch { }
            try { File.Delete(pcap); } catch { }
        }
    }

    internal static Dictionary<string, (long rx, long tx)> ParsePcapNg(string path, byte[] host, byte[] mask)
    {
        var result = new Dictionary<string, (long rx, long tx)>();
        using var stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream);
        var links = new List<ushort>();
        var littleEndian = true;
        while (stream.Position + 12 <= stream.Length)
        {
            var blockStart = stream.Position;
            var typeBytes = reader.ReadBytes(4);
            var lengthBytes = reader.ReadBytes(4);
            var isSection = typeBytes.SequenceEqual(new byte[] {0x0a,0x0d,0x0d,0x0a});
            if (isSection)
            {
                if (stream.Position + 4 > stream.Length) break;
                var magic = reader.ReadBytes(4);
                littleEndian = magic.SequenceEqual(new byte[] {0x4d,0x3c,0x2b,0x1a});
                if (!littleEndian && !magic.SequenceEqual(new byte[] {0x1a,0x2b,0x3c,0x4d})) break;
                links.Clear();
            }
            uint U32(byte[] data) => littleEndian ? BitConverter.ToUInt32(data) : BitConverter.ToUInt32(data.Reverse().ToArray());
            var blockLen = U32(lengthBytes);
            if (blockLen < 12 || blockLen > 16 * 1024 * 1024 || blockStart + blockLen > stream.Length) break;
            var type = U32(typeBytes);
            if (type == 1 && blockLen >= 20)
            {
                stream.Position = blockStart + 8;
                var raw = reader.ReadBytes(2);
                links.Add(littleEndian ? BitConverter.ToUInt16(raw) : BitConverter.ToUInt16(raw.Reverse().ToArray()));
            }
            if (type == 6 && blockLen >= 32)
            {
                stream.Position = blockStart + 8;
                var iface = U32(reader.ReadBytes(4));
                stream.Position += 8; // timestamp
                var caplen = U32(reader.ReadBytes(4));
                var wirelen = U32(reader.ReadBytes(4));
                if (iface < links.Count && links[(int)iface] == 1 &&
                    caplen >= 34 && caplen <= 65535 && caplen <= blockLen - 32)
                {
                    var bytes = reader.ReadBytes((int)caplen);
                    CountEthernet(bytes, (int)wirelen, host, mask, result);
                }
            }
            stream.Position = blockStart + blockLen;
        }
        return result;
    }

    private static void CountEthernet(byte[] packet, int wirelen, byte[] host, byte[] mask,
        Dictionary<string, (long rx, long tx)> rates)
    {
        if (packet.Length < 34) return;
        int type = (packet[12] << 8) | packet[13], offset = 14;
        if (type is 0x8100 or 0x88a8)
        {
            if (packet.Length < 38) return;
            type = (packet[16] << 8) | packet[17];
            offset = 18;
        }
        if (type != 0x0800 || packet.Length < offset + 20 || packet[offset] >> 4 != 4) return;
        var source = packet.AsSpan(offset + 12, 4).ToArray();
        var dest = packet.AsSpan(offset + 16, 4).ToArray();
        bool Client(byte[] ip)
        {
            if (ip.SequenceEqual(host)) return false;
            for (var i = 0; i < 4; i++)
                if ((ip[i] & mask[i]) != (host[i] & mask[i])) return false;
            return true;
        }
        var from = Client(source);
        var to = Client(dest);
        if (from == to) return;
        var total = (packet[offset + 2] << 8) | packet[offset + 3];
        var count = Math.Min(total, Math.Max(0, wirelen - offset));
        if (count <= 0) return;
        var ip = new IPAddress(from ? source : dest).ToString();
        rates.TryGetValue(ip, out var old);
        rates[ip] = from ? (old.rx, old.tx + count) : (old.rx + count, old.tx);
    }
}
