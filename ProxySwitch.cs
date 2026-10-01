using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace ProxySwitch
{
    public class TimeoutWebClient : WebClient
    {
        public int TimeoutMs { get; set; }
        public TimeoutWebClient(int timeoutMs = 6000) { TimeoutMs = timeoutMs; }
        protected override WebRequest GetWebRequest(Uri address)
        {
            WebRequest req = base.GetWebRequest(address);
            if (req != null) req.Timeout = TimeoutMs;
            return req;
        }
    }

    public class ProxyItem
    {
        public string Tag;
        public string Endpoint;
        public string Username;
        public string Password;
        public long PingMs;

        public ProxyItem(string tag, string endpoint, string username = "", string password = "")
        {
            Tag = Sanitize(tag);
            Endpoint = Sanitize(endpoint);
            Username = Sanitize(username);
            Password = Sanitize(password);
            PingMs = -1;
        }

        private static string Sanitize(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            return input.Replace(";", "_").Replace("|", "_").Trim();
        }

        public bool HasAuth
        {
            get { return !string.IsNullOrEmpty(Username); }
        }

        public override string ToString()
        {
            string authLabel = HasAuth ? " [AUTH]" : "";
            if (string.IsNullOrEmpty(Tag)) return Endpoint + authLabel;
            return Tag + " [" + Endpoint + "]" + authLabel;
        }

        public string ToRawString()
        {
            return string.Format("{0};{1};{2};{3}", Tag, Endpoint, Username, Password);
        }

        public static ProxyItem FromRawString(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return null;
            if (raw.Contains(";"))
            {
                string[] parts = raw.Split(';');
                if (parts.Length >= 4)
                    return new ProxyItem(parts[0], parts[1], parts[2], parts[3]);
                if (parts.Length >= 2)
                    return new ProxyItem(parts[0], parts[1]);
            }
            return new ProxyItem("", raw);
        }
    }

    public class LocalAuthBridge
    {
        private TcpListener listener;
        private CancellationTokenSource cts;
        public int LocalPort { get; private set; }
        public string RemoteHost { get; private set; }
        public int RemotePort { get; private set; }
        public string Username { get; private set; }
        public string Password { get; private set; }
        public bool IsRunning { get; private set; }

        public void Start(string remoteEndpoint, string username, string password)
        {
            Stop();

            string[] parts = remoteEndpoint.Split(':');
            RemoteHost = parts[0];
            RemotePort = int.Parse(parts[1]);
            Username = username;
            Password = password;

            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            LocalPort = ((IPEndPoint)listener.LocalEndpoint).Port;
            cts = new CancellationTokenSource();
            IsRunning = true;

            Task.Run(async () =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        TcpClient client = await listener.AcceptTcpClientAsync();
                        Task bgTask = ProcessClientAsync(client, cts.Token);
                    }
                    catch
                    {
                        break;
                    }
                }
            });
        }

        public void Stop()
        {
            IsRunning = false;
            try { if (cts != null) cts.Cancel(); } catch { }
            try { if (listener != null) listener.Stop(); } catch { }
        }

        private async Task ProcessClientAsync(TcpClient client, CancellationToken token)
        {
            TcpClient server = new TcpClient();
            try
            {
                await server.ConnectAsync(RemoteHost, RemotePort);

                NetworkStream clientStream = client.GetStream();
                NetworkStream serverStream = server.GetStream();

                byte[] buffer = new byte[8192];
                int read = await clientStream.ReadAsync(buffer, 0, buffer.Length, token);
                if (read <= 0) { client.Close(); server.Close(); return; }

                string initialRequest = Encoding.ASCII.GetString(buffer, 0, read);
                string authHeader = "";
                if (!string.IsNullOrEmpty(Username))
                {
                    string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(Username + ":" + Password));
                    authHeader = "Proxy-Authorization: Basic " + credentials + "\r\n";
                }

                if (initialRequest.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                {
                    int firstLineEnd = initialRequest.IndexOf("\r\n");
                    if (firstLineEnd > 0)
                    {
                        string firstLine = initialRequest.Substring(0, firstLineEnd + 2);
                        string remainder = initialRequest.Substring(firstLineEnd + 2);
                        string modified = firstLine + authHeader + remainder;
                        byte[] modBytes = Encoding.ASCII.GetBytes(modified);
                        await serverStream.WriteAsync(modBytes, 0, modBytes.Length, token);

                        byte[] srvResp = new byte[4096];
                        int srvRead = await serverStream.ReadAsync(srvResp, 0, srvResp.Length, token);
                        string srvRespStr = Encoding.ASCII.GetString(srvResp, 0, srvRead);

                        if (srvRespStr.Contains("200 Connection established") || srvRespStr.Contains("200 OK"))
                        {
                            byte[] ok200 = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");
                            await clientStream.WriteAsync(ok200, 0, ok200.Length, token);
                        }
                        else
                        {
                            await clientStream.WriteAsync(srvResp, 0, srvRead, token);
                            client.Close();
                            server.Close();
                            return;
                        }
                    }
                }
                else
                {
                    int firstLineEnd = initialRequest.IndexOf("\r\n");
                    if (firstLineEnd > 0)
                    {
                        string firstLine = initialRequest.Substring(0, firstLineEnd + 2);
                        string remainder = initialRequest.Substring(firstLineEnd + 2);
                        string modified = firstLine + authHeader + remainder;
                        byte[] modBytes = Encoding.ASCII.GetBytes(modified);
                        await serverStream.WriteAsync(modBytes, 0, modBytes.Length, token);
                    }
                    else
                    {
                        await serverStream.WriteAsync(buffer, 0, read, token);
                    }
                }

                Task t1 = RelayStreamAsync(clientStream, serverStream, token);
                Task t2 = RelayStreamAsync(serverStream, clientStream, token);
                await Task.WhenAny(t1, t2);
            }
            catch { }
            finally
            {
                try { client.Close(); } catch { }
                try { server.Close(); } catch { }
            }
        }

        private async Task RelayStreamAsync(NetworkStream from, NetworkStream to, CancellationToken token)
        {
            byte[] buf = new byte[16384];
            try
            {
                while (!token.IsCancellationRequested)
                {
                    int r = await from.ReadAsync(buf, 0, buf.Length, token);
                    if (r <= 0) break;
                    await to.WriteAsync(buf, 0, r, token);
                }
            }
            catch { }
        }
    }

    public class SolidCard : Panel
    {
        public Color BorderColor { get; set; }
        public SolidCard()
        {
            this.SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true);
            this.BackColor = Color.FromArgb(16, 16, 18);
            BorderColor = Color.FromArgb(34, 34, 38);
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            Graphics g = e.Graphics;
            using (SolidBrush bgBrush = new SolidBrush(this.BackColor)) { g.FillRectangle(bgBrush, this.ClientRectangle); }
            using (Pen borderPen = new Pen(BorderColor, 1f)) { g.DrawRectangle(borderPen, 0, 0, this.Width - 1, this.Height - 1); }
        }
    }

    public class SolidButton : Button
    {
        public bool IsPrimary { get; set; }
        private bool isHovered = false;
        private bool isPressed = false;

        public SolidButton()
        {
            this.SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true);
            this.FlatStyle = FlatStyle.Flat;
            this.FlatAppearance.BorderSize = 0;
            this.Cursor = Cursors.Hand;
            this.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);
            this.MouseEnter += (s, e) => { isHovered = true; Invalidate(); };
            this.MouseLeave += (s, e) => { isHovered = false; isPressed = false; Invalidate(); };
            this.MouseDown += (s, e) => { isPressed = true; Invalidate(); };
            this.MouseUp += (s, e) => { isPressed = false; Invalidate(); };
        }

        protected override void OnPaint(PaintEventArgs pevent)
        {
            Graphics g = pevent.Graphics;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            Rectangle rect = new Rectangle(0, 0, this.Width, this.Height);

            if (IsPrimary)
            {
                Color fill = isPressed ? Color.FromArgb(200, 200, 205) : (isHovered ? Color.FromArgb(235, 235, 240) : Color.White);
                using (SolidBrush b = new SolidBrush(fill)) g.FillRectangle(b, rect);
                TextRenderer.DrawText(g, this.Text, this.Font, rect, Color.FromArgb(10, 10, 12), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            }
            else
            {
                Color bg = isPressed ? Color.FromArgb(28, 28, 32) : (isHovered ? Color.FromArgb(24, 24, 28) : Color.FromArgb(16, 16, 18));
                using (SolidBrush b = new SolidBrush(bg)) g.FillRectangle(b, rect);
                Color border = isHovered ? Color.FromArgb(80, 80, 88) : Color.FromArgb(36, 36, 42);
                using (Pen p = new Pen(border, 1f)) g.DrawRectangle(p, 0, 0, this.Width - 1, this.Height - 1);
                Color txt = isHovered ? Color.White : Color.FromArgb(190, 190, 196);
                TextRenderer.DrawText(g, this.Text, this.Font, rect, txt, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            }
        }
    }

    public class MainForm : Form
    {
        [DllImport("user32.dll")] public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [DllImport("user32.dll")] public static extern bool ReleaseCapture();
        [DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
        [DllImport("user32.dll")] public static extern bool RegisterHotKey(IntPtr hWnd, int id, int fsModifiers, int vk);
        [DllImport("user32.dll")] public static extern bool UnregisterHotKey(IntPtr hWnd, int id);

        private const int HOTKEY_ID = 9000;
        private const int MOD_CONTROL = 0x0002;
        private const int MOD_SHIFT = 0x0004;
        private const int VK_P = 0x50;

        private const string REG_PATH = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        private const string REG_AUTORUN = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string APP_NAME = "ProxySwitch";

        private static readonly Regex BypassValidationRegex = new Regex(@"^[a-zA-Z0-9\.\*\<\>\:\-_;\s]+$");
        private static readonly Regex EndpointValidationRegex = new Regex(@"^[a-zA-Z0-9\.\-_]+:[0-9]{1,5}$");

        private string cfgPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "proxy_dominator_cfg.txt");
        private List<ProxyItem> proxies = new List<ProxyItem>();
        private string currentCountry = "";
        private LocalAuthBridge authBridge = new LocalAuthBridge();

        Panel titleBar;
        Label titleLbl;
        Label closeBtn;

        SolidCard statusCard;
        Label statusLbl;
        Label ipLbl;

        ComboBox proxyCombo;
        TextBox tagTxt;
        TextBox endpointTxt;
        TextBox userTxt;
        TextBox passTxt;
        SolidButton addBtn;
        SolidButton delBtn;
        SolidButton toggleBtn;
        SolidButton refreshBtn;
        SolidButton pingBtn;
        SolidButton speedBtn;

        TextBox customPingTxt;
        SolidButton customPingBtn;
        Label customPingRes;

        TextBox bypassTxt;
        SolidButton saveBypassBtn;

        CheckBox autoRunChk;
        CheckBox failoverChk;

        RichTextBox resultsBox;
        NotifyIcon trayIcon;
        ContextMenu trayMenu;
        private System.Windows.Forms.Timer failoverTimer;

        class PingTarget
        {
            public string Name; public string Url; public bool Geo;
            public PingTarget(string n, string u, bool g) { Name = n; Url = u; Geo = g; }
        }

        public MainForm()
        {
            this.FormBorderStyle = FormBorderStyle.None;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Size = new Size(520, 870);
            this.BackColor = Color.FromArgb(10, 10, 11);
            this.ForeColor = Color.White;
            this.Text = "PROXY SWITCH";

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            try {
                if (File.Exists("app.ico")) this.Icon = new Icon("app.ico");
                else if (Icon.ExtractAssociatedIcon(Application.ExecutablePath) != null)
                    this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            } catch { }

            InitTray();
            InitUI();
            LoadConfig();
            LoadBypass();

            RegisterHotKey(this.Handle, HOTKEY_ID, MOD_CONTROL | MOD_SHIFT, VK_P);
            CheckState();
            Task dummy = FetchGeoAsync();

            failoverTimer = new System.Windows.Forms.Timer();
            failoverTimer.Interval = 60000;
            failoverTimer.Tick += async (s, e) => { if (failoverChk.Checked) await RunHealthCheckAsync(); };
            failoverTimer.Start();
        }

        protected override void WndProc(ref Message m)
        {
            const int WM_HOTKEY = 0x0312;
            if (m.Msg == WM_HOTKEY && m.WParam.ToInt32() == HOTKEY_ID)
            {
                this.BeginInvoke((MethodInvoker)delegate { ToggleProxy(this, EventArgs.Empty); });
            }
            base.WndProc(ref m);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                HideToTray();
                return;
            }

            authBridge.Stop();
            UnregisterHotKey(this.Handle, HOTKEY_ID);
            if (trayIcon != null) { trayIcon.Visible = false; trayIcon.Dispose(); }
            base.OnFormClosing(e);
        }

        private void HideToTray()
        {
            this.Hide();
            if (trayIcon != null)
            {
                trayIcon.ShowBalloonTip(1000, "Proxy Dominator", "Свернуто в трей. Выход через меню трея.", ToolTipIcon.Info);
            }
        }

        private void InitTray()
        {
            trayMenu = new ContextMenu();
            trayMenu.MenuItems.Add("Переключить прокси (Ctrl+Shift+P)", (s, e) => ToggleProxy(s, e));
            trayMenu.MenuItems.Add("Открыть окно", (s, e) => ShowFromTray());
            trayMenu.MenuItems.Add("-");
            trayMenu.MenuItems.Add("Выход (Exit)", (s, e) => {
                authBridge.Stop();
                UnregisterHotKey(this.Handle, HOTKEY_ID);
                if (trayIcon != null) { trayIcon.Visible = false; trayIcon.Dispose(); }
                Application.Exit();
            });

            trayIcon = new NotifyIcon();
            trayIcon.Text = "Proxy Dominator";
            try { if (this.Icon != null) trayIcon.Icon = this.Icon; } catch { }
            trayIcon.ContextMenu = trayMenu;
            trayIcon.Visible = true;
            trayIcon.DoubleClick += (s, e) => ShowFromTray();
        }

        private void ShowFromTray()
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
            this.BringToFront();
        }

        private void InitUI()
        {
            // TitleBar
            titleBar = new Panel { Bounds = new Rectangle(0, 0, 520, 42), BackColor = Color.FromArgb(14, 14, 16) };
            titleBar.MouseDown += (s, e) => { ReleaseCapture(); SendMessage(Handle, 0xA1, 0x2, 0); };

            titleLbl = new Label { Text = "PROXY SWITCH", Font = new Font("Segoe UI", 10.5f, FontStyle.Bold), ForeColor = Color.FromArgb(180, 180, 185), AutoSize = true, Location = new Point(16, 12) };
            titleLbl.MouseDown += (s, e) => { ReleaseCapture(); SendMessage(Handle, 0xA1, 0x2, 0); };

            closeBtn = new Label { Text = "✕", Font = new Font("Segoe UI", 12, FontStyle.Bold), ForeColor = Color.FromArgb(130, 130, 135), AutoSize = true, Location = new Point(488, 10), Cursor = Cursors.Hand };
            closeBtn.Click += (s, e) => HideToTray();
            closeBtn.MouseEnter += (s, e) => closeBtn.ForeColor = Color.FromArgb(255, 75, 75);
            closeBtn.MouseLeave += (s, e) => closeBtn.ForeColor = Color.FromArgb(130, 130, 135);

            titleBar.Controls.Add(titleLbl);
            titleBar.Controls.Add(closeBtn);
            this.Controls.Add(titleBar);

            // Status Card
            statusCard = new SolidCard { Bounds = new Rectangle(16, 54, 488, 80) };
            statusLbl = new Label { Bounds = new Rectangle(10, 10, 468, 32), Text = "STATUS: CHECKING...", Font = new Font("Segoe UI", 18, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter, BackColor = Color.Transparent, ForeColor = Color.White };
            ipLbl = new Label { Bounds = new Rectangle(10, 44, 468, 24), Text = "IP: -", Font = new Font("Segoe UI", 11.5f, FontStyle.Regular), ForeColor = Color.FromArgb(210, 210, 215), TextAlign = ContentAlignment.MiddleCenter, BackColor = Color.Transparent };
            statusCard.Controls.Add(statusLbl);
            statusCard.Controls.Add(ipLbl);
            this.Controls.Add(statusCard);

            // Proxy Manager Card with Auth fields
            SolidCard pmCard = new SolidCard { Bounds = new Rectangle(16, 144, 488, 154) };
            Label pmLbl = new Label { Bounds = new Rectangle(12, 6, 460, 16), Text = "СЕРВЕРЫ (МЕНЕДЖЕР ПРОКСИ)", Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), ForeColor = Color.FromArgb(130, 130, 138) };

            proxyCombo = new ComboBox { Bounds = new Rectangle(12, 26, 342, 25), Font = new Font("Segoe UI", 10f), BackColor = Color.FromArgb(22, 22, 26), ForeColor = Color.White, DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat };
            delBtn = new SolidButton { Text = "DEL", Size = new Size(54, 26), Location = new Point(362, 25) };
            delBtn.Click += (s, e) => {
                if (proxyCombo.SelectedIndex >= 0 && proxyCombo.SelectedIndex < proxies.Count) {
                    proxies.RemoveAt(proxyCombo.SelectedIndex);
                    SaveConfig();
                    UpdateCombo();
                }
            };

            SolidButton sortBtn = new SolidButton { Text = "SORT", Size = new Size(54, 26), Location = new Point(422, 25) };
            sortBtn.Click += async (s, e) => await SortProxiesByPingAsync();

            tagTxt = new TextBox { Bounds = new Rectangle(12, 58, 120, 24), Font = new Font("Segoe UI", 9.5f), BackColor = Color.FromArgb(22, 22, 26), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Text = "Tag" };
            tagTxt.GotFocus += (s, e) => { if (tagTxt.Text == "Tag") tagTxt.Text = ""; };
            tagTxt.LostFocus += (s, e) => { if (string.IsNullOrWhiteSpace(tagTxt.Text)) tagTxt.Text = "Tag"; };

            endpointTxt = new TextBox { Bounds = new Rectangle(140, 58, 232, 24), Font = new Font("Segoe UI", 9.5f), BackColor = Color.FromArgb(22, 22, 26), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Text = "IP:PORT" };
            endpointTxt.GotFocus += (s, e) => { if (endpointTxt.Text == "IP:PORT") endpointTxt.Text = ""; };
            endpointTxt.LostFocus += (s, e) => { if (string.IsNullOrWhiteSpace(endpointTxt.Text)) endpointTxt.Text = "IP:PORT"; };

            addBtn = new SolidButton { Text = "ADD PROXY", Size = new Size(100, 56), Location = new Point(376, 58) };
            addBtn.Click += (s, e) => {
                string ep = endpointTxt.Text.Trim();
                string tg = tagTxt.Text.Trim();
                string usr = userTxt.Text.Trim();
                string pwd = passTxt.Text.Trim();

                if (tg == "Tag") tg = "";
                if (ep == "IP:PORT") ep = "";
                if (usr == "Username") usr = "";
                if (pwd == "Password") pwd = "";

                if (string.IsNullOrEmpty(ep) || !EndpointValidationRegex.IsMatch(ep)) {
                    MessageBox.Show("Формат должен быть строго IP:PORT (например 127.0.0.1:8080)", "Валидация", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                proxies.Add(new ProxyItem(tg, ep, usr, pwd));
                SaveConfig();
                UpdateCombo();
                endpointTxt.Text = "";
                userTxt.Text = "Username";
                passTxt.Text = "Password";
            };

            userTxt = new TextBox { Bounds = new Rectangle(12, 90, 175, 24), Font = new Font("Segoe UI", 9.5f), BackColor = Color.FromArgb(22, 22, 26), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Text = "Username" };
            userTxt.GotFocus += (s, e) => { if (userTxt.Text == "Username") userTxt.Text = ""; };
            userTxt.LostFocus += (s, e) => { if (string.IsNullOrWhiteSpace(userTxt.Text)) userTxt.Text = "Username"; };

            passTxt = new TextBox { Bounds = new Rectangle(197, 90, 175, 24), Font = new Font("Segoe UI", 9.5f), BackColor = Color.FromArgb(22, 22, 26), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Text = "Password" };
            passTxt.GotFocus += (s, e) => { if (passTxt.Text == "Password") passTxt.Text = ""; };
            passTxt.LostFocus += (s, e) => { if (string.IsNullOrWhiteSpace(passTxt.Text)) passTxt.Text = "Password"; };

            Label hotkeyNotice = new Label { Bounds = new Rectangle(12, 126, 460, 18), Text = "Поддерживается логин/пароль через локальный TCP мост", Font = new Font("Segoe UI", 8.5f), ForeColor = Color.FromArgb(100, 100, 108) };

            pmCard.Controls.Add(pmLbl);
            pmCard.Controls.Add(proxyCombo);
            pmCard.Controls.Add(delBtn);
            pmCard.Controls.Add(sortBtn);
            pmCard.Controls.Add(tagTxt);
            pmCard.Controls.Add(endpointTxt);
            pmCard.Controls.Add(userTxt);
            pmCard.Controls.Add(passTxt);
            pmCard.Controls.Add(addBtn);
            pmCard.Controls.Add(hotkeyNotice);
            this.Controls.Add(pmCard);

            // Action Buttons
            toggleBtn = new SolidButton { Text = "SWITCH PROXY", Bounds = new Rectangle(16, 308, 488, 44), Font = new Font("Segoe UI", 12f, FontStyle.Bold), IsPrimary = true };
            toggleBtn.Click += ToggleProxy;

            refreshBtn = new SolidButton { Text = "REFRESH ROUTE", Bounds = new Rectangle(16, 360, 156, 34) };
            refreshBtn.Click += async (s, e) => await FetchGeoAsync();

            pingBtn = new SolidButton { Text = "PING SERVICES", Bounds = new Rectangle(182, 360, 156, 34) };
            pingBtn.Click += async (s, e) => await PingServicesAsync();

            speedBtn = new SolidButton { Text = "SPEED TEST", Bounds = new Rectangle(348, 360, 156, 34) };
            speedBtn.Click += async (s, e) => await RunSpeedTestAsync();

            this.Controls.Add(toggleBtn);
            this.Controls.Add(refreshBtn);
            this.Controls.Add(pingBtn);
            this.Controls.Add(speedBtn);

            // Bypass Card
            SolidCard bpCard = new SolidCard { Bounds = new Rectangle(16, 406, 488, 66) };
            Label bpLbl = new Label { Bounds = new Rectangle(12, 6, 460, 16), Text = "ИСКЛЮЧЕНИЯ (PROXY OVERRIDE)", Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), ForeColor = Color.FromArgb(130, 130, 138) };
            bypassTxt = new TextBox { Bounds = new Rectangle(12, 26, 380, 24), Font = new Font("Segoe UI", 9.5f), BackColor = Color.FromArgb(22, 22, 26), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
            saveBypassBtn = new SolidButton { Text = "SAVE", Size = new Size(78, 26), Location = new Point(398, 25) };
            saveBypassBtn.Click += (s, e) => SaveBypass();
            bpCard.Controls.Add(bpLbl);
            bpCard.Controls.Add(bypassTxt);
            bpCard.Controls.Add(saveBypassBtn);
            this.Controls.Add(bpCard);

            // Custom Ping Card
            SolidCard cpCard = new SolidCard { Bounds = new Rectangle(16, 482, 488, 68) };
            Label cpLbl = new Label { Bounds = new Rectangle(12, 6, 460, 16), Text = "ПРОВЕРКА URL", Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), ForeColor = Color.FromArgb(130, 130, 138) };
            customPingTxt = new TextBox { Bounds = new Rectangle(12, 26, 290, 24), Font = new Font("Segoe UI", 9.5f), BackColor = Color.FromArgb(22, 22, 26), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Text = "example.com" };
            customPingBtn = new SolidButton { Text = "TEST", Size = new Size(70, 26), Location = new Point(308, 25) };
            customPingRes = new Label { Bounds = new Rectangle(386, 28, 92, 20), Text = "", Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), ForeColor = Color.White };

            customPingBtn.Click += async (s, e) => {
                string url = customPingTxt.Text.Trim();
                if (string.IsNullOrEmpty(url)) return;
                if (!url.StartsWith("http://") && !url.StartsWith("https://")) url = "https://" + url;
                customPingRes.Text = "PING...";
                customPingRes.ForeColor = Color.FromArgb(200, 200, 205);
                long ms = await PingUrlAsync(url);
                if (ms == -1) { customPingRes.ForeColor = Color.FromArgb(255, 80, 80); customPingRes.Text = "DEAD"; }
                else { customPingRes.ForeColor = Color.White; customPingRes.Text = ms.ToString() + " ms"; }
            };

            cpCard.Controls.Add(cpLbl);
            cpCard.Controls.Add(customPingTxt);
            cpCard.Controls.Add(customPingBtn);
            cpCard.Controls.Add(customPingRes);
            this.Controls.Add(cpCard);

            // Settings Bar
            SolidCard setCard = new SolidCard { Bounds = new Rectangle(16, 560, 488, 44) };
            autoRunChk = new CheckBox { Text = "Автозапуск Windows", Bounds = new Rectangle(16, 10, 160, 24), ForeColor = Color.FromArgb(170, 170, 178), Font = new Font("Segoe UI", 8.5f) };
            autoRunChk.CheckedChanged += (s, e) => ToggleAutoRun(autoRunChk.Checked);

            failoverChk = new CheckBox { Text = "Автоотключение при сбое (Failover)", Bounds = new Rectangle(200, 10, 260, 24), ForeColor = Color.FromArgb(170, 170, 178), Font = new Font("Segoe UI", 8.5f), Checked = true };

            setCard.Controls.Add(autoRunChk);
            setCard.Controls.Add(failoverChk);
            this.Controls.Add(setCard);

            // Results Terminal Card
            resultsBox = new RichTextBox {
                Bounds = new Rectangle(16, 614, 488, 240),
                BackColor = Color.FromArgb(14, 14, 16),
                ForeColor = Color.FromArgb(200, 200, 205),
                Font = new Font("Segoe UI", 9.5f),
                ReadOnly = true,
                BorderStyle = BorderStyle.None
            };
            this.Controls.Add(resultsBox);
        }

        private void ToggleAutoRun(bool enable)
        {
            try {
                using (var key = Registry.CurrentUser.OpenSubKey(REG_AUTORUN, true)) {
                    if (key == null) throw new UnauthorizedAccessException("Ключ реестра недоступен.");
                    if (enable) key.SetValue(APP_NAME, Application.ExecutablePath);
                    else key.DeleteValue(APP_NAME, false);
                }
            } catch (Exception ex) {
                autoRunChk.CheckedChanged -= (s, e) => ToggleAutoRun(autoRunChk.Checked);
                autoRunChk.Checked = !enable;
                autoRunChk.CheckedChanged += (s, e) => ToggleAutoRun(autoRunChk.Checked);
                MessageBox.Show("Не удалось изменить автозапуск: " + ex.Message, "Ошибка реестра", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void LoadConfig()
        {
            try {
                if (File.Exists(cfgPath))
                {
                    string raw = File.ReadAllText(cfgPath);
                    if (!string.IsNullOrWhiteSpace(raw))
                    {
                        proxies.Clear();
                        string[] items = raw.Split('|');
                        foreach (var it in items)
                        {
                            ProxyItem pi = ProxyItem.FromRawString(it);
                            if (pi != null && !string.IsNullOrEmpty(pi.Endpoint)) proxies.Add(pi);
                        }
                    }
                }
            } catch { }

            if (proxies.Count == 0)
            {
                proxies.Add(new ProxyItem("Пример", "127.0.0.1:8080"));
            }
            UpdateCombo();
        }

        private void SaveConfig()
        {
            try {
                List<string> rawList = new List<string>();
                foreach (var p in proxies) rawList.Add(p.ToRawString());
                File.WriteAllText(cfgPath, string.Join("|", rawList.ToArray()));
            } catch (Exception ex) {
                MessageBox.Show("Не удалось сохранить конфигурацию: " + ex.Message, "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void LoadBypass()
        {
            try {
                using (var key = Registry.CurrentUser.OpenSubKey(REG_PATH, false)) {
                    if (key != null) {
                        object ov = key.GetValue("ProxyOverride");
                        if (ov != null) { bypassTxt.Text = ov.ToString(); return; }
                    }
                }
            } catch { }
            bypassTxt.Text = "localhost;127.0.0.1;*.ru;<local>";
        }

        private void SaveBypass()
        {
            string input = bypassTxt.Text.Trim();
            if (!string.IsNullOrEmpty(input) && !BypassValidationRegex.IsMatch(input))
            {
                MessageBox.Show("Список исключений содержит недопустимые символы!", "Валидация", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try {
                using (var key = Registry.CurrentUser.OpenSubKey(REG_PATH, true)) {
                    if (key == null) throw new UnauthorizedAccessException("Ветка настроек сети недоступна.");
                    key.SetValue("ProxyOverride", input);
                }
                InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
                InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
                MessageBox.Show("Список исключений сохранен в системе.", "Proxy Dominator");
            } catch (Exception ex) {
                MessageBox.Show("Ошибка реестра: " + ex.Message, "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void UpdateCombo()
        {
            proxyCombo.Items.Clear();
            foreach (var p in proxies) proxyCombo.Items.Add(p);
            if (proxyCombo.Items.Count > 0) proxyCombo.SelectedIndex = 0;
            else proxyCombo.Text = "";
        }

        private void CheckState()
        {
            try {
                using (var key = Registry.CurrentUser.OpenSubKey(REG_PATH, true)) {
                    if (key == null) return;
                    object val = key.GetValue("ProxyEnable");
                    if (val == null) { key.SetValue("ProxyEnable", 0); val = 0; }

                    int state = (int)val;
                    if (state == 1) {
                        statusLbl.Text = "STATUS: ACTIVE";
                        statusLbl.ForeColor = Color.White;
                        statusCard.BorderColor = Color.White;
                        toggleBtn.Text = "DISABLE PROXY";
                    } else {
                        statusLbl.Text = "STATUS: INACTIVE";
                        statusLbl.ForeColor = Color.FromArgb(140, 140, 146);
                        statusCard.BorderColor = Color.FromArgb(40, 40, 46);
                        toggleBtn.Text = "ENABLE PROXY";
                    }
                }
            } catch { }
        }

        private void ToggleProxy(object s, EventArgs e)
        {
            try {
                using (var key = Registry.CurrentUser.OpenSubKey(REG_PATH, true)) {
                    if (key == null) throw new UnauthorizedAccessException("Ветка настроек реестра недоступна.");

                    int state = (int)key.GetValue("ProxyEnable", 0);
                    if (state == 1) {
                        key.SetValue("ProxyEnable", 0);
                        authBridge.Stop();
                    } else {
                        if (proxyCombo.SelectedIndex == -1 || proxyCombo.SelectedItem == null) {
                            MessageBox.Show("Не выбран прокси-сервер!", "Proxy Dominator", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }
                        ProxyItem selected = (ProxyItem)proxyCombo.SelectedItem;

                        if (selected.HasAuth)
                        {
                            authBridge.Start(selected.Endpoint, selected.Username, selected.Password);
                            key.SetValue("ProxyServer", "127.0.0.1:" + authBridge.LocalPort);
                        }
                        else
                        {
                            authBridge.Stop();
                            key.SetValue("ProxyServer", selected.Endpoint);
                        }

                        key.SetValue("ProxyEnable", 1);
                    }
                }
                InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
                InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);

                CheckState();
                ipLbl.Text = "IP: Switching...";
                Task.Delay(500).ContinueWith(_dummy => FetchGeoAsync());
            } catch (Exception ex) {
                MessageBox.Show("Ошибка: " + ex.Message, "Сбой", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private WebProxy GetActiveProxy()
        {
            try {
                using (var key = Registry.CurrentUser.OpenSubKey(REG_PATH, false)) {
                    if (key != null) {
                        int state = (int)key.GetValue("ProxyEnable", 0);
                        if (state == 1) {
                            string srv = (string)key.GetValue("ProxyServer", "");
                            if (!string.IsNullOrEmpty(srv)) return new WebProxy("http://" + srv);
                        }
                    }
                }
            } catch { }
            return null;
        }

        private async Task FetchGeoAsync()
        {
            this.Invoke((MethodInvoker)delegate { ipLbl.Text = "IP: Fetching..."; });
            try {
                using (var wc = new TimeoutWebClient(5000)) {
                    wc.Proxy = GetActiveProxy();
                    string json = await wc.DownloadStringTaskAsync("https://get.geojs.io/v1/ip/geo.json?t=" + Guid.NewGuid().ToString());
                    string ip = Regex.Match(json, "\"ip\":\"([^\"]+)\"").Groups[1].Value;
                    string cc = Regex.Match(json, "\"country_code\":\"([^\"]+)\"").Groups[1].Value;
                    currentCountry = cc;

                    this.Invoke((MethodInvoker)delegate {
                        ipLbl.Text = "IP: " + ip + " [" + cc + "]";
                        resultsBox.SelectionColor = Color.FromArgb(140, 140, 146);
                        resultsBox.AppendText("\n[ROUTE] Выходной IP: " + ip + " | Регион: " + cc + "\n");
                    });
                }
            } catch {
                this.Invoke((MethodInvoker)delegate {
                    ipLbl.Text = "IP: Offline / Unreachable";
                    currentCountry = "";
                });
            }
        }

        private async Task<long> PingUrlAsync(string url)
        {
            return await Task.Run(() => {
                var sw = Stopwatch.StartNew();
                try {
                    var req = (HttpWebRequest)WebRequest.Create(url);
                    req.Timeout = 4000;
                    req.Method = "HEAD";
                    req.Proxy = GetActiveProxy();
                    using (var res = req.GetResponse()) { }
                    sw.Stop();
                    return sw.ElapsedMilliseconds;
                } catch (WebException we) {
                    sw.Stop();
                    if (we.Response != null) return sw.ElapsedMilliseconds;
                    return -1;
                } catch {
                    return -1;
                }
            });
        }

        private async Task SortProxiesByPingAsync()
        {
            resultsBox.Clear();
            resultsBox.SelectionColor = Color.White;
            resultsBox.AppendText(">> БЕНЧМАРК И СОРТИРОВКА СЕРВЕРОВ...\n\n");

            var throttler = new SemaphoreSlim(5);
            var tasks = new List<Task>();

            foreach (var p in proxies)
            {
                tasks.Add(Task.Run(async () => {
                    await throttler.WaitAsync();
                    try {
                        var sw = Stopwatch.StartNew();
                        long ms = 99999;
                        try {
                            var req = (HttpWebRequest)WebRequest.Create("https://www.google.com/generate_204");
                            req.Timeout = 3500;
                            var webProxy = new WebProxy("http://" + p.Endpoint);
                            if (p.HasAuth)
                            {
                                webProxy.Credentials = new NetworkCredential(p.Username, p.Password);
                            }
                            req.Proxy = webProxy;
                            using (var res = req.GetResponse()) { }
                            sw.Stop();
                            ms = sw.ElapsedMilliseconds;
                        } catch {
                            ms = 99999;
                        }
                        p.PingMs = ms;

                        this.Invoke((MethodInvoker)delegate {
                            resultsBox.SelectionColor = (ms < 2000) ? Color.White : Color.FromArgb(255, 80, 80);
                            resultsBox.AppendText(p.ToString().PadRight(30) + (ms < 99999 ? ms.ToString() + " ms\n" : "TIMEOUT\n"));
                        });
                    } finally {
                        throttler.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);
            proxies.Sort((a, b) => a.PingMs.CompareTo(b.PingMs));
            SaveConfig();
            UpdateCombo();
            resultsBox.AppendText("\n>> Сортировка завершена.\n");
        }

        private async Task RunSpeedTestAsync()
        {
            resultsBox.Clear();
            resultsBox.SelectionColor = Color.White;
            resultsBox.AppendText(">> ТЕСТ СКОРОСТИ СКАЧИВАНИЯ (CLOUDFLARE CDN 2MB)...\n");

            try {
                using (var wc = new TimeoutWebClient(10000)) {
                    wc.Proxy = GetActiveProxy();
                    Stopwatch sw = Stopwatch.StartNew();
                    byte[] data = await wc.DownloadDataTaskAsync("https://speed.cloudflare.com/__down?bytes=2000000");
                    sw.Stop();

                    double elapsedMs = Math.Max(1, sw.ElapsedMilliseconds);
                    double seconds = elapsedMs / 1000.0;
                    double megabits = (data.Length * 8.0) / (1024.0 * 1024.0);
                    double speedMbps = megabits / seconds;

                    resultsBox.SelectionColor = Color.White;
                    resultsBox.AppendText(">> РЕЗУЛЬТАТ: " + speedMbps.ToString("0.00") + " Mbps (время: " + elapsedMs.ToString("0") + " ms)\n");
                }
            } catch (Exception ex) {
                resultsBox.SelectionColor = Color.FromArgb(255, 80, 80);
                resultsBox.AppendText(">> ОШИБКА: " + ex.Message + "\n");
            }
        }

        private async Task RunHealthCheckAsync()
        {
            using (var key = Registry.CurrentUser.OpenSubKey(REG_PATH, false)) {
                if (key == null || (int)key.GetValue("ProxyEnable", 0) != 1) return;
            }

            long ms = await PingUrlAsync("https://www.google.com/generate_204");
            if (ms == -1)
            {
                using (var key = Registry.CurrentUser.OpenSubKey(REG_PATH, true)) {
                    if (key != null) key.SetValue("ProxyEnable", 0);
                }
                authBridge.Stop();
                InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
                InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);

                CheckState();
                trayIcon.ShowBalloonTip(3000, "Proxy Dominator", "Сервер перестал отвечать. Прокси отключен для сохранения доступа в сеть.", ToolTipIcon.Warning);
            }
        }

        private async Task PingServicesAsync()
        {
            resultsBox.Clear();
            resultsBox.SelectionColor = Color.FromArgb(140, 140, 146);
            resultsBox.AppendText(">> ПРОВЕРКА ДОСТУПНОСТИ СЕРВИСОВ...\n\n");

            var targets = new PingTarget[] {
                new PingTarget("Google/Gemini", "https://www.google.com/generate_204", true),
                new PingTarget("Anthropic/Claude", "https://api.anthropic.com/", true),
                new PingTarget("OpenAI/ChatGPT", "https://api.openai.com/", true),
                new PingTarget("YouTube", "https://www.youtube.com/generate_204", false),
                new PingTarget("Twitch", "https://www.twitch.tv/", false),
                new PingTarget("Discord", "https://discord.com/", false),
                new PingTarget("Telegram", "https://telegram.org/", false),
                new PingTarget("VKontakte", "https://vk.com/", false)
            };

            var blockedGeo = new List<string> { "RU", "BY", "CN", "IR", "KP", "SY", "CU" };
            bool isBlocked = !string.IsNullOrEmpty(currentCountry) && blockedGeo.Contains(currentCountry);

            foreach (var t in targets)
            {
                long ms = await PingUrlAsync(t.Url);
                resultsBox.SelectionColor = Color.FromArgb(190, 190, 196);
                resultsBox.AppendText(t.Name.PadRight(20));

                if (t.Geo && isBlocked) {
                    resultsBox.SelectionColor = Color.FromArgb(255, 80, 80);
                    resultsBox.AppendText("BLOCKED GEO\n");
                } else if (ms == -1) {
                    resultsBox.SelectionColor = Color.FromArgb(255, 80, 80);
                    resultsBox.AppendText("TIMEOUT\n");
                } else {
                    resultsBox.SelectionColor = Color.White;
                    resultsBox.AppendText(ms.ToString() + " ms\n");
                }
            }
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
