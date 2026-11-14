using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Text;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using System.Windows.Forms;
using System.Text.Json;
using System.Security.Principal;

namespace VPNShare.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

        using var mutex = new Mutex(true, @"Local\VPNShareDesktop", out bool isFirst);
        if (!isFirst)
        {
            MessageBox.Show("VPN Share уже запущен. Проверьте значок в системном трее.",
                "VPN Share", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        try
        {
            using var form = new DashboardForm();
            Application.ThreadException += (_, args) => form.ShowFatal(args.Exception);
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
                form.RecordFatal(args.ExceptionObject as Exception ?? new Exception("Unknown fatal exception"));
            Application.Run(form);
        }
        catch (Exception ex)
        {
            var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "VPNShare", "logs");
            try
            {
                Directory.CreateDirectory(logDir);
                File.AppendAllText(Path.Combine(logDir, "launcher-crash.log"),
                    DateTime.Now.ToString("u") + Environment.NewLine + ex + Environment.NewLine,
                    new UTF8Encoding(true));
            }
            catch { /* Never hide the original failure. */ }

            MessageBox.Show(ex.ToString(), "VPN Share — ошибка запуска",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}

internal sealed class DashboardForm : Form
{
    private readonly Label _status = new()
    {
        Text = "Подготовка к запуску…",
        AutoSize = false,
        TextAlign = ContentAlignment.MiddleLeft,
        Width = 390,
        Height = 37,
        ForeColor = Color.FromArgb(205, 220, 241)
    };
    private readonly WebView2 _browser = new() { Dock = DockStyle.Fill };
    private readonly RichTextBox _diagnostics = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        WordWrap = false,
        BackColor = Color.FromArgb(12, 20, 36),
        ForeColor = Color.FromArgb(220, 234, 250),
        Font = new Font("Consolas", 10f),
        BorderStyle = BorderStyle.None
    };
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    private readonly object _logGate = new();
    private readonly string _dataDirectory;
    private readonly string _logDirectory;
    private readonly string _logPath;
    private readonly NotifyIcon _tray;
    private readonly CancellationTokenSource _lifetime = new();

    private ClientTrafficMonitor? _trafficMonitor;
    private CheckBox? _startupBox;
    private CheckBox? _hotspotBox;
    private Label? _settingsMessage;
    private const string StartupTask = @"\VPNShare\StartAtLogon";
    private Process? _backend;
    private string? _portFile;
    private string? _dashboardUrl;
    private bool _closingForReal;
    private bool _starting;
    private bool _trayHintShown;

    public DashboardForm()
    {
        Text = "VPN Share — VPN-раздача";
        Width = 1190;
        Height = 840;
        MinimumSize = new Size(780, 520);
        StartPosition = FormStartPosition.CenterScreen;
        Icon = BrandIcon.Create();
        BackColor = Color.FromArgb(11, 20, 35);

        _dataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VPNShare");
        _logDirectory = Path.Combine(_dataDirectory, "logs");
        Directory.CreateDirectory(_logDirectory);
        _logPath = Path.Combine(_logDirectory, "desktop-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".log");

        var bar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 58,
            AutoScroll = true,
            Padding = new Padding(12, 9, 8, 4),
            WrapContents = false,
            BackColor = Color.FromArgb(21, 36, 58)
        };
        var restart = NewButton("Перезапустить");
        restart.Click += async (_, _) => await StartBackendAsync();
        var logButton = NewButton("Диагностика");
        logButton.Click += (_, _) => _tabs.SelectedIndex = 2;
        var settingsButton = NewButton("Настройки");
        settingsButton.Click += (_, _) => _tabs.SelectedIndex = 1;
        var copyButton = NewButton("Копировать отчёт");
        copyButton.Click += (_, _) => CopyReport();
        var folderButton = NewButton("Открыть логи");
        folderButton.Click += (_, _) => OpenFolder(_logDirectory);
        var exitButton = NewButton("Выход");
        exitButton.Click += (_, _) => ExitApplication();

        bar.Controls.AddRange(new Control[] { restart, settingsButton, logButton, copyButton, folderButton, exitButton, _status });

        var dashboardTab = new TabPage("Панель") { BackColor = Color.FromArgb(10, 18, 33) };
        dashboardTab.Controls.Add(_browser);
        var settingsTab = new TabPage("Настройки") { BackColor = Color.FromArgb(12, 20, 36) };
        settingsTab.Controls.Add(BuildSettingsPanel());
        var logTab = new TabPage("Диагностика") { BackColor = Color.FromArgb(12, 20, 36) };
        logTab.Controls.Add(_diagnostics);
        _tabs.TabPages.Add(dashboardTab);
        _tabs.TabPages.Add(settingsTab);
        _tabs.TabPages.Add(logTab);
        Controls.Add(_tabs);
        Controls.Add(bar);

        var menu = new ContextMenuStrip();
        menu.Items.Add("Открыть VPN Share", null, (_, _) => RestoreWindow());
        menu.Items.Add("Настройки", null, (_, _) => { RestoreWindow(); _tabs.SelectedIndex = 1; });
        menu.Items.Add("Диагностика", null, (_, _) => { RestoreWindow(); _tabs.SelectedIndex = 2; });
        menu.Items.Add("Перезапустить сервер", null, async (_, _) => await StartBackendAsync());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Завершить VPN Share", null, (_, _) => ExitApplication());

        _tray = new NotifyIcon
        {
            Icon = Icon,
            Text = "VPN Share — фоновая раздача",
            ContextMenuStrip = menu,
            Visible = true
        };
        _tray.DoubleClick += (_, _) => RestoreWindow();

        Shown += async (_, _) => await StartBackendAsync();
        WriteLog("VPN Share desktop started; log: " + _logPath);
        _trafficMonitor = new ClientTrafficMonitor(_dataDirectory, WriteLog);
        _trafficMonitor.Start();
    }

    private Control BuildSettingsPanel()
    {
        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown,
            WrapContents = false, AutoScroll = true, Padding = new Padding(22),
            BackColor = Color.FromArgb(12, 20, 36)
        };
        var heading = new Label { Text = "Настройки VPN Share", Font = new Font("Segoe UI", 17, FontStyle.Bold),
            ForeColor = Color.White, AutoSize = true, Margin = new Padding(4, 5, 4, 22) };
        _startupBox = new CheckBox { Text = "Запускать VPN Share при входе в Windows",
            ForeColor = Color.White, AutoSize = true, Margin = new Padding(4, 8, 4, 10) };
        _hotspotBox = new CheckBox { Text = "Автоматически настраивать ICS при включении точки доступа",
            ForeColor = Color.White, AutoSize = true, Margin = new Padding(4, 8, 4, 10) };
        var explanation = new Label
        {
            Text = "Автозапуск Windows создаёт задачу планировщика с повышенными правами. " +
                   "Не перемещайте VPNShare.exe после включения.\n\n" +
                   "Автоматическая настройка ICS срабатывает только при активном VPN и Wi-Fi Direct " +
                   "и сохранённом выборе адаптеров. Проверка раз в 30 секунд. " +
                   "Не включает сам мобильный хот-спот Windows и не запускает VPN. " +
                   "Функция экспериментальная, не является Kill Switch.",
            ForeColor = Color.FromArgb(176, 195, 219), AutoSize = false,
            Width = 650, Height = 145, Margin = new Padding(4, 10, 4, 14)
        };
        var save = NewButton("Сохранить настройки");
        save.Click += async (_, _) => await SaveSettingsAsync();
        _settingsMessage = new Label { Text = "", ForeColor = Color.FromArgb(136, 222, 184),
            AutoSize = true, Margin = new Padding(4, 12, 4, 0) };
        panel.Controls.AddRange(new Control[] { heading, _startupBox, _hotspotBox, explanation, save, _settingsMessage });
        panel.HandleCreated += (_, _) => LoadSettings();
        return panel;
    }

    private string PreferencesFile => Path.Combine(_dataDirectory, "preferences.json");

    private void LoadSettings()
    {
        if (_startupBox == null || _hotspotBox == null) return;
        try
        {
            var query = RunTaskCommand("/query", "/tn", StartupTask);
            _startupBox.Checked = query == 0;
        }
        catch (Exception ex) { WriteLog("[settings query] " + ex.Message); }
        try
        {
            if (File.Exists(PreferencesFile))
            {
                using var json = JsonDocument.Parse(File.ReadAllText(PreferencesFile));
                _hotspotBox.Checked = json.RootElement.TryGetProperty("autoHotspot", out var value) &&
                    value.ValueKind == JsonValueKind.True;
            }
        }
        catch (Exception ex) { WriteLog("[settings read] " + ex.Message); }
    }

    private static int RunTaskCommand(params string[] args)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true
        };
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);
        process.Start();
        if (!process.WaitForExit(12000))
        {
            try { process.Kill(true); } catch { }
            throw new TimeoutException("Windows Task Scheduler не ответил.");
        }
        return process.ExitCode;
    }

    private async Task SaveSettingsAsync()
    {
        if (_startupBox == null || _hotspotBox == null || _settingsMessage == null) return;
        try
        {
            var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Путь приложения неизвестен.");
            if (_startupBox.Checked)
            {
                var identity = WindowsIdentity.GetCurrent().Name;
                var code = RunTaskCommand("/create", "/f", "/tn", StartupTask,
                    "/sc", "onlogon", "/ru", identity, "/rl", "highest", "/it",
                    "/tr", "\"" + exe + "\"");
                if (code != 0) throw new InvalidOperationException("Не удалось создать задачу автозапуска (код " + code + ").");
            }
            else if (RunTaskCommand("/query", "/tn", StartupTask) == 0)
            {
                if (RunTaskCommand("/delete", "/f", "/tn", StartupTask) != 0)
                    throw new InvalidOperationException("Не удалось удалить задачу автозапуска.");
            }
            var json = JsonSerializer.Serialize(new { autoHotspot = _hotspotBox.Checked });
            var tmp = PreferencesFile + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, PreferencesFile, true);
            _settingsMessage.Text = "Настройки сохранены. Перезапуск локального сервера…";
            await StartBackendAsync();
            _settingsMessage.Text = "Настройки сохранены.";
        }
        catch (Exception ex)
        {
            WriteLog("[settings] " + ex);
            _settingsMessage.Text = "Ошибка: " + ex.Message;
        }
    }

    private static Button NewButton(string title) => new()
    {
        Text = title,
        AutoSize = true,
        Height = 36,
        BackColor = Color.FromArgb(46, 68, 101),
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Margin = new Padding(3, 0, 3, 0)
    };

    private void SetStatus(string value)
    {
        if (IsDisposed || Disposing) return;
        _status.Text = value;
        WriteLog("[status] " + value);
    }

    private void WriteLog(string message)
    {
        var line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " " + message;
        try
        {
            lock (_logGate)
                File.AppendAllText(_logPath, line + Environment.NewLine, new UTF8Encoding(false));
        }
        catch { /* Log pane still works if disk logging fails. */ }

        if (_diagnostics.IsDisposed || !_diagnostics.IsHandleCreated) return;
        try
        {
            _diagnostics.BeginInvoke((Action)(() =>
            {
                if (_diagnostics.IsDisposed) return;
                if (_diagnostics.TextLength > 180000)
                    _diagnostics.Text = _diagnostics.Text.Substring(_diagnostics.TextLength - 100000);
                _diagnostics.AppendText(line + Environment.NewLine);
            }));
        }
        catch (InvalidOperationException) { /* Window is closing. */ }
    }

    internal void RecordFatal(Exception ex) => WriteLog("[FATAL] " + ex);

    internal void ShowFatal(Exception ex)
    {
        RecordFatal(ex);
        _tabs.SelectedIndex = 1;
        SetStatus("Ошибка. Откройте диагностику.");
        MessageBox.Show(this, ex.Message + Environment.NewLine + "Подробности: " + _logPath,
            "VPN Share — ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    private string ExtractBundledBackend()
    {
        // Never execute a script extracted into the user-writable Desktop or Downloads folder.
        // The launcher runs elevated; ProgramData is used for its private runtime directory.
        var runtime = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "VPNShare", "DesktopRuntime", "2.0.9");
        Directory.CreateDirectory(runtime);
        var file = Path.Combine(runtime, "VPNShareWeb.ps1");

        using var stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("VPNShare.Desktop.VPNShareWeb.ps1")
            ?? throw new FileNotFoundException("В сборке отсутствует встроенный VPNShareWeb.ps1");
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), true);
        var script = reader.ReadToEnd();
        File.WriteAllText(file, script.TrimStart('\uFEFF'), new UTF8Encoding(true));
        return file;
    }

    private async Task StartBackendAsync()
    {
        if (_starting || _closingForReal) return;
        _starting = true;
        try
        {
            StopBackend();
            _dashboardUrl = null;
            SetStatus("Запуск VPN-сервера…");
            _tabs.SelectedIndex = 0;

            var script = ExtractBundledBackend();
            _portFile = Path.Combine(_dataDirectory, "port-" + Guid.NewGuid().ToString("N") + ".txt");
            var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(powershell))
                throw new FileNotFoundException("Windows PowerShell 5.1 не найден.", powershell);

            var info = new ProcessStartInfo
            {
                FileName = powershell,
                WorkingDirectory = Path.GetDirectoryName(script)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", script, "-NoBrowser", "-PortFile", _portFile })
                info.ArgumentList.Add(arg);

            var process = new Process { StartInfo = info, EnableRaisingEvents = true };
            process.OutputDataReceived += (_, args) =>
            {
                if (args.Data != null) WriteLog("[powershell] " + args.Data);
            };
            process.ErrorDataReceived += (_, args) =>
            {
                if (args.Data != null) WriteLog("[stderr] " + args.Data);
            };
            process.Exited += (_, _) =>
            {
                var exitCode = -1;
                try { exitCode = process.ExitCode; } catch { }
                WriteLog("[backend] Exited with code " + exitCode);
                if (IsDisposed || !IsHandleCreated) return;
                try
                {
                    BeginInvoke((Action)(() =>
                    {
                        if (!ReferenceEquals(_backend, process) || _closingForReal) return;
                        SetStatus("Сервер завершился (код " + exitCode + ")");
                        _tabs.SelectedIndex = 1;
                    }));
                }
                catch (InvalidOperationException) { }
            };

            _backend = process;
            if (!process.Start()) throw new InvalidOperationException("Не удалось запустить PowerShell.");
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            var deadline = DateTime.UtcNow.AddSeconds(25);
            while (DateTime.UtcNow < deadline && !_lifetime.IsCancellationRequested)
            {
                if (process.HasExited)
                    throw new InvalidOperationException(
                        "Сервер завершился до открытия веб-панели. Смотрите вкладку «Диагностика».");

                if (_portFile != null && File.Exists(_portFile))
                {
                    try
                    {
                        var value = File.ReadAllText(_portFile).Trim();
                        if (int.TryParse(value, out var port) && port is >= 18761 and <= 18780)
                        {
                            _dashboardUrl = "http://127.0.0.1:" + port + "/";
                            break;
                        }
                    }
                    catch (IOException) { /* Writer has not finished yet. */ }
                }
                await Task.Delay(200, _lifetime.Token);
            }
            if (_dashboardUrl == null)
                throw new TimeoutException("Сервер не сообщил локальный порт за 25 секунд.");

            await LoadDashboardAsync(_dashboardUrl);
            SetStatus("Работает: " + _dashboardUrl + " | Win+L доступен");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            WriteLog("[start error] " + ex);
            if (!_closingForReal && !IsDisposed)
            {
                _tabs.SelectedIndex = 1;
                SetStatus("Ошибка запуска. Откройте диагностику.");
                MessageBox.Show(this, ex.Message + Environment.NewLine + "Журнал: " + _logPath,
                    "VPN Share — ошибка запуска", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        finally
        {
            _starting = false;
        }
    }

    private async Task LoadDashboardAsync(string url)
    {
        if (_browser.CoreWebView2 == null)
        {
            var dataFolder = Path.Combine(_dataDirectory, "webview2");
            Directory.CreateDirectory(dataFolder);
            CoreWebView2Environment environment;
            try
            {
                environment = await CoreWebView2Environment.CreateAsync(userDataFolder: dataFolder);
                await _browser.EnsureCoreWebView2Async(environment);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "Не удалось запустить WebView2. Установите Microsoft Edge WebView2 Runtime. " +
                    "Подробности в журнале.", ex);
            }
            _browser.CoreWebView2.Settings.AreDevToolsEnabled = true;
            _browser.CoreWebView2.NavigationStarting += (_, e) =>
            {
                if (!IsOwnDashboardUrl(e.Uri))
                {
                    e.Cancel = true;
                    OpenExternalUrl(e.Uri);
                }
            };
            _browser.CoreWebView2.NewWindowRequested += (_, e) =>
            {
                e.Handled = true;
                OpenExternalUrl(e.Uri);
            };
            _browser.CoreWebView2.ProcessFailed += (_, e) =>
                WriteLog("[webview] Process failed: " + e.ProcessFailedKind);
        }
        _browser.CoreWebView2.Navigate(url);
    }

    private bool IsOwnDashboardUrl(string candidate)
    {
        if (_dashboardUrl == null ||
            !Uri.TryCreate(candidate, UriKind.Absolute, out var uri) ||
            !Uri.TryCreate(_dashboardUrl, UriKind.Absolute, out var allowed))
            return false;
        return uri.Scheme == Uri.UriSchemeHttp && uri.Host == "127.0.0.1" &&
               uri.Port == allowed.Port && uri.UserInfo.Length == 0;
    }

    private void OpenExternalUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return;
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return;
        try
        {
            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception ex) { WriteLog("[external link] " + ex.Message); }
    }

    private void StopBackend()
    {
        var process = _backend;
        _backend = null;
        try
        {
            if (process != null && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
        }
        catch (Exception ex) { WriteLog("[shutdown warning] " + ex.Message); }
        finally { process?.Dispose(); }

        if (_portFile != null)
        {
            try { File.Delete(_portFile); } catch { }
            _portFile = null;
        }
    }

    private void CopyReport()
    {
        try
        {
            var content = File.Exists(_logPath) ? File.ReadAllText(_logPath) : _diagnostics.Text;
            Clipboard.SetText(content);
            SetStatus("Диагностика скопирована.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Не удалось скопировать журнал");
        }
    }

    private void OpenFolder(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", "\"" + path + "\"")
                { UseShellExecute = true });
        }
        catch (Exception ex) { WriteLog("[explorer] " + ex.Message); }
    }

    private void RestoreWindow()
    {
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
    }

    private void ExitApplication()
    {
        _closingForReal = true;
        _lifetime.Cancel();
        _trafficMonitor?.Dispose();
        _trafficMonitor = null;
        StopBackend();
        _tray.Visible = false;
        Close();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_closingForReal && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            if (!_trayHintShown)
            {
                _trayHintShown = true;
                _tray.ShowBalloonTip(3000, "VPN Share работает в фоне",
                    "Чтобы завершить VPN Share, откройте меню значка в трее и выберите «Завершить».",
                    ToolTipIcon.Info);
            }
            return;
        }

        _closingForReal = true;
        _lifetime.Cancel();
        StopBackend();
        _tray.Visible = false;
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _tray.Dispose();
            _lifetime.Dispose();
        }
        base.Dispose(disposing);
    }
}
