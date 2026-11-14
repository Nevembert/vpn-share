using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace VPNShare.Desktop;

// Packet capture is optional. Npcap must be installed separately (with WinPcap-compatible API).
// Capture is restricted to the selected hotspot NIC; no payloads or destination history are stored.
internal sealed class ClientTrafficMonitor : IDisposable
{
    private readonly string _dataDir;
    private readonly Action<string> _log;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, Counters> _counters = new();
    private readonly string _output;
    private Task? _worker;
    private string _currentGuid = "";
    private byte[]? _subnetAddress;
    private byte[]? _subnetMask;
    private string _hostAddress = "";
    private string _state = "waiting";
    private string _detail = "Ожидание выбора Wi-Fi Direct.";
    private sealed class Counters
    {
        public long Rx;
        public long Tx;
        public long TotalRx;
        public long TotalTx;
    }
    private sealed record ClientRate(string ip, double rxMbps, double txMbps, long rxBytes, long txBytes);
    private sealed record Snapshot(string status, string detail, string adapterId, DateTime sampledAtUtc,
        ClientRate[] clients);

    public ClientTrafficMonitor(string dataDir, Action<string> log)
    {
        _dataDir = dataDir;
        _log = log;
        _output = Path.Combine(dataDir, "client-traffic.json");
        // Do not expose stale values from a previous session.
        try { File.Delete(_output); } catch { }
    }

    public void Start() => _worker = Task.Run(() => Run(_stop.Token));

    private void Run(CancellationToken token)
    {
        var last = DateTime.UtcNow;
        while (!token.IsCancellationRequested)
        {
            var guid = ReadSelectedGuid();
            if (guid != _currentGuid)
            {
                _currentGuid = guid;
                _counters.Clear();
                ResolveHotspotSubnet(guid);
                _state = "waiting";
                _detail = "Ожидание выбранного адаптера Wi-Fi Direct.";
            }

            if (string.IsNullOrEmpty(guid))
            {
                WriteSnapshot(1);
                if (token.WaitHandle.WaitOne(1000)) break;
                continue;
            }

            try
            {
                Capture(guid, token, ref last);
            }
            catch (DllNotFoundException)
            {
                _state = "missing-npcap";
                _detail = "Npcap не установлен. Установите Npcap с WinPcap API-compatible mode.";
                WriteSnapshot(1);
                if (token.WaitHandle.WaitOne(5000)) break;
            }
            catch (EntryPointNotFoundException)
            {
                _state = "missing-npcap";
                _detail = "Отсутствует совместимый wpcap.dll (Npcap).";
                WriteSnapshot(1);
                if (token.WaitHandle.WaitOne(5000)) break;
            }
            catch (Exception ex)
            {
                _state = "error";
                _detail = ex.Message;
                _log("[capture] " + ex);
                WriteSnapshot(1);
                if (token.WaitHandle.WaitOne(3000)) break;
            }
        }
        try { File.Delete(_output); } catch { }
    }

    private string ReadSelectedGuid()
    {
        try
        {
            var path = Path.Combine(_dataDir, "selection.json");
            if (!File.Exists(path)) return "";
            using var json = JsonDocument.Parse(File.ReadAllText(path));
            if (!json.RootElement.TryGetProperty("hotspot", out var value)) return "";
            var raw = value.GetString();
            return Guid.TryParse(raw, out var guid) ? guid.ToString("D") : "";
        }
        catch { return ""; }
    }

    private void ResolveHotspotSubnet(string guid)
    {
        _subnetAddress = null;
        _subnetMask = null;
        _hostAddress = "";
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => Guid.TryParse(n.Id, out var id) &&
                    id == Guid.Parse(guid));
            var address = nic?.GetIPProperties().UnicastAddresses.FirstOrDefault(a =>
                a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                a.IPv4Mask != null);
            if (address == null) return;
            _subnetAddress = address.Address.GetAddressBytes();
            _subnetMask = address.IPv4Mask.GetAddressBytes();
            _hostAddress = address.Address.ToString();
        }
        catch (Exception ex) { _log("[capture subnet] " + ex.Message); }
    }

    private bool IsHotspotClient(string ip)
    {
        if (_subnetAddress == null || _subnetMask == null || ip == _hostAddress ||
            !IPAddress.TryParse(ip, out var address)) return false;
        var bytes = address.GetAddressBytes();
        if (bytes.Length != 4) return false;
        for (var i = 0; i < 4; i++)
            if ((bytes[i] & _subnetMask[i]) != (_subnetAddress[i] & _subnetMask[i]))
                return false;
        return true;
    }

    private void Capture(string guid, CancellationToken token, ref DateTime last)
    {
        var device = @"\\Device\\NPF_{" + guid.ToUpperInvariant() + "}";
        var error = new byte[512];
        var handle = Native.pcap_open_live(device, 65535, 0, 250, error);
        if (handle == IntPtr.Zero)
        {
            _state = "error";
            _detail = "Не удалось открыть " + device + ": " +
                System.Text.Encoding.UTF8.GetString(error).TrimEnd('\0');
            WriteSnapshot(1);
            token.WaitHandle.WaitOne(3000);
            return;
        }

        try
        {
            var linkType = Native.pcap_datalink(handle);
            if (linkType != 1)
            {
                _state = "unsupported";
                _detail = "Неподдерживаемый формат канала Npcap (DLT=" + linkType + "). Нужен Ethernet DLT=1.";
                WriteSnapshot(1);
                token.WaitHandle.WaitOne(3000);
                return;
            }
            if (_subnetMask == null)\n            {\n                _state = "waiting";\n                _detail = "Не удалось определить IPv4-подсеть Wi-Fi Direct.";\n                WriteSnapshot(1);\n                token.WaitHandle.WaitOne(3000);\n                return;\n            }\n            _state = "capturing";
            _detail = "Npcap: учёт IPv4-пакетов на Wi-Fi Direct до NAT. Скорость приблизительная.";
            _log("[capture] Started on " + device);
            last = DateTime.UtcNow;
            while (!token.IsCancellationRequested && ReadSelectedGuid() == guid)
            {
                var result = Native.pcap_next_ex(handle, out var header, out var packet);
                if (result == 1 && header != IntPtr.Zero && packet != IntPtr.Zero)
                {
                    var caplen = Marshal.ReadInt32(header, 16);
                    var wirelen = Marshal.ReadInt32(header, 20);
                    if (caplen >= 34 && caplen <= 65535 && wirelen >= 34)
                        CountPacket(packet, caplen, wirelen);
                }
                else if (result == -1 || result == -2)
                {
                    throw new InvalidOperationException("Npcap capture stopped (code " + result + ").");
                }

                var now = DateTime.UtcNow;
                var seconds = (now - last).TotalSeconds;
                if (seconds >= 1)
                {
                    WriteSnapshot(seconds);
                    last = now;
                }
            }
        }
        finally { Native.pcap_close(handle); }
    }

    private void CountPacket(IntPtr packet, int length, int wireLength)
    {
        var etherType = (Marshal.ReadByte(packet, 12) << 8) | Marshal.ReadByte(packet, 13);
        var offset = 14;
        if (etherType == 0x8100 || etherType == 0x88a8)
        {
            if (length < 38) return;
            etherType = (Marshal.ReadByte(packet, 16) << 8) | Marshal.ReadByte(packet, 17);
            offset = 18;
        }
        if (etherType != 0x0800 || length < offset + 20) return;
        var version = Marshal.ReadByte(packet, offset);
        if ((version >> 4) != 4) return;
        var headerLength = (version & 0x0f) * 4;
        if (headerLength < 20 || length < offset + headerLength) return;
        var source = ReadIp(packet, offset + 12);
        var destination = ReadIp(packet, offset + 16);

        // Count each packet once on the hotspot NIC, keyed by the client endpoint.
        // Only IPs in the actual observed neighbor table will be displayed by the UI.
        var payloadLength = Math.Max(0, (Marshal.ReadByte(packet, offset + 2) << 8) |
            Marshal.ReadByte(packet, offset + 3));
        if (payloadLength == 0) return;
        var bytes = Math.Min(payloadLength, Math.Max(0, wireLength - offset));
        if (bytes <= 0) return;
        if (IsHotspotClient(source) && !IsHotspotClient(destination))
        {
            var counters = _counters.GetOrAdd(source, _ => new Counters());
            Interlocked.Add(ref counters.Tx, bytes);
            Interlocked.Add(ref counters.TotalTx, bytes);
        }
        else if (IsHotspotClient(destination) && !IsHotspotClient(source))
        {
            var counters = _counters.GetOrAdd(destination, _ => new Counters());
            Interlocked.Add(ref counters.Rx, bytes);
            Interlocked.Add(ref counters.TotalRx, bytes);
        }
        else if (IsHotspotClient(source) && IsHotspotClient(destination))
        {
            // Local traffic is ambiguous without the hotspot subnet. Do not guess.
        }
    }

    private static string ReadIp(IntPtr ptr, int offset) =>
        new IPAddress(new[]
        {
            Marshal.ReadByte(ptr, offset), Marshal.ReadByte(ptr, offset + 1),
            Marshal.ReadByte(ptr, offset + 2), Marshal.ReadByte(ptr, offset + 3)
        }).ToString();

    private void WriteSnapshot(double seconds)
    {
        var rates = _counters.Select(pair =>
        {
            var rx = Interlocked.Exchange(ref pair.Value.Rx, 0);
            var tx = Interlocked.Exchange(ref pair.Value.Tx, 0);
            return new ClientRate(pair.Key, Math.Round(rx * 8d / 1e6 / seconds, 3),
                Math.Round(tx * 8d / 1e6 / seconds, 3),
                Interlocked.Read(ref pair.Value.TotalRx), Interlocked.Read(ref pair.Value.TotalTx));
        }).ToArray();
        try
        {
            var json = JsonSerializer.Serialize(new Snapshot(_state, _detail, _currentGuid,
                DateTime.UtcNow, rates));
            var tmp = _output + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, _output, true);
        }
        catch (Exception ex) { _log("[capture snapshot] " + ex.Message); }
    }

    public void Dispose()
    {
        _stop.Cancel();
        try { _worker?.Wait(2000); } catch { }
        _stop.Dispose();
        try { File.Delete(_output); } catch { }
    }

    private static class Native
    {
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int timeoutMs,
            [Out] byte[] errbuf);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_datalink(IntPtr handle);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_next_ex(IntPtr handle, out IntPtr header, out IntPtr data);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pcap_close(IntPtr handle);
    }
}
