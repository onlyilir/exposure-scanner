// Exposure Scanner desktop app (WPF, C# 5, built with the .NET Framework csc.exe that ships with
// Windows; see app\Build-App.ps1). The same exe is the installer (--install) and uninstaller
// (--uninstall). The checks themselves run in scanner.exe next to it (the C engine, --json).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

[assembly: AssemblyTitle("Exposure Scanner")]
[assembly: AssemblyProduct("Exposure Scanner")]
[assembly: AssemblyDescription("Website and code safety check-ups with plain-language reports")]
[assembly: AssemblyVersion("0.7.0.0")]
[assembly: AssemblyFileVersion("0.7.0.0")]

namespace ExposureScanner
{
    static class Program
    {
        public const string Version = "0.7.0";
        public const string AppName = "Exposure Scanner";
        public const string ExeName = "ExposureScanner.exe";
        public const string RepoUrl = "https://github.com/onlyilir/exposure-scanner";
        public const string CoffeeUrl = "https://buymeacoffee.com/only.ilir";
        public const string FormUrl = RepoUrl + "/blob/main/docs/permission-form.md";

        [STAThread]
        static int Main(string[] args)
        {
            bool install = args.Contains("--install"), uninstall = args.Contains("--uninstall");
            string target = ArgValue(args, "--target") ?? Installer.DefaultTarget;

            if (args.Contains("--quiet") && (install || uninstall))
                return Installer.Quiet(install, target, args);
            string shots = ArgValue(args, "--ui-snapshots"); // developer check: every screen to PNG

            // one window only: opening the app again brings the running one to the front (the setup
            // window is the same exe, so only the normal app takes the lock)
            System.Threading.Mutex single = null;
            if (!install && !uninstall && shots == null)
            {
                bool first;
                single = new System.Threading.Mutex(true, "Local\\ExposureScanner.App", out first);
                if (!first)
                {
                    FocusRunningCopy();
                    return 0;
                }
            }

            var app = new Application();
            app.ShutdownMode = ShutdownMode.OnMainWindowClose;
            app.DispatcherUnhandledException += (s, e) =>
            {
                Crash(e.Exception);
                e.Handled = true;
                app.Shutdown(1);
            };
            try
            {
                app.Resources = (ResourceDictionary)Ui.Load("Styles.xaml");
                if (shots != null)
                    return Snapshots.Run(app, shots);
                Window w = install || uninstall
                    ? new SetupController(uninstall, target).Window
                    : new MainController().Window;
                int code = app.Run(w);
                GC.KeepAlive(single); // hold the one-window lock until the app closes
                return code;
            }
            catch (Exception ex)
            {
                Crash(ex);
                return 1;
            }
        }

        // a log for support plus a plain message instead of a silent exit
        static void Crash(Exception ex)
        {
            string log = Path.Combine(Path.GetTempPath(), "ExposureScanner-crash.log");
            try { File.WriteAllText(log, DateTime.Now.ToString("u") + "\r\n" + ex); }
            catch (Exception) { }
            MessageBox.Show("Exposure Scanner hit a problem and has to close.\n\n" + ex.Message +
                            "\n\nDetails were saved to " + log, AppName, MessageBoxButton.OK, MessageBoxImage.Error);
        }

        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);
        [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);

        static void FocusRunningCopy()
        {
            int me = Process.GetCurrentProcess().Id;
            foreach (Process p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(ExeName)))
            {
                if (p.Id == me || p.MainWindowHandle == IntPtr.Zero)
                    continue;
                if (IsIconic(p.MainWindowHandle))
                    ShowWindow(p.MainWindowHandle, 9); // SW_RESTORE
                SetForegroundWindow(p.MainWindowHandle);
                return;
            }
        }

        static string ArgValue(string[] args, string name)
        {
            int i = Array.IndexOf(args, name);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }
    }

    // ------------------------------------------------------------------ shared UI helpers

    static class Ui
    {
        public static object Load(string name)
        {
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
                return XamlReader.Load(s);
        }

        public static T Find<T>(Window w, string name) where T : class
        {
            T e = w.FindName(name) as T;
            if (e == null)
                throw new InvalidOperationException("UI element missing: " + name);
            return e;
        }

        public static Brush Res(string key)
        {
            return (Brush)Application.Current.Resources[key];
        }

        // custom title bar: caption buttons and the margin Windows needs when maximized
        public static void HookChrome(Window w, FrameworkElement root, Button min, Button max, Button close,
                                      System.Windows.Shapes.Path maxGlyph)
        {
            if (min != null)
                min.Click += delegate { w.WindowState = WindowState.Minimized; };
            if (max != null)
                max.Click += delegate
                {
                    w.WindowState = w.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
                };
            close.Click += delegate { w.Close(); };
            w.StateChanged += delegate
            {
                bool m = w.WindowState == WindowState.Maximized;
                root.Margin = m ? new Thickness(7) : new Thickness(0);
                if (maxGlyph != null)
                    maxGlyph.Data = Geometry.Parse(m ? "M2.5,0.5 L9.5,0.5 L9.5,7.5 M0.5,2.5 L7.5,2.5 L7.5,9.5 L0.5,9.5 Z"
                                                    : "M0.5,0.5 L9.5,0.5 L9.5,9.5 L0.5,9.5 Z");
            };
        }

        public static void Open(string path)
        {
            try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
            catch (Exception) { }
        }

        public static void ShowInFolder(string path)
        {
            try { Process.Start("explorer.exe", "/select,\"" + path + "\""); }
            catch (Exception) { }
        }
    }

    // ------------------------------------------------------------------ main window

    public class IssueVm
    {
        public string Level { get; set; }
        public string Site { get; set; }
        public string Title { get; set; }
        public string Fix { get; set; }
        public string Detail { get; set; }
        public Brush Fg { get; set; }
        public Brush Bg { get; set; }
    }

    public class ReportVm
    {
        public string Name { get; set; }
        public string Info { get; set; }
        public string Path { get; set; }
    }

    class MainController
    {
        public readonly Window Window;
        readonly Window w;
        readonly TextBox siteBox, folderBox, clientBox, byBox;
        readonly CheckBox permBox;
        readonly Button runButton;
        readonly TextBlock runHint, formError, runningTitle, runningStep, pdfStatus;
        readonly FrameworkElement formPanel, runningPanel, siteFields, folderFields, nortonTip;
        readonly RadioButton modeSite, navCheck, navReports, navHelp;
        readonly FrameworkElement[] pages;
        string lastReport;
        bool running;

        public static string ReportsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Exposure Scanner", "Reports");
        static readonly CultureInfo En = CultureInfo.GetCultureInfo("en-GB");

        public MainController()
        {
            w = Window = (Window)Ui.Load("MainWindow.xaml");
            Ui.HookChrome(w, Ui.Find<FrameworkElement>(w, "Root"), Ui.Find<Button>(w, "MinButton"),
                          Ui.Find<Button>(w, "MaxButton"), Ui.Find<Button>(w, "CloseButton"),
                          Ui.Find<System.Windows.Shapes.Path>(w, "MaxGlyph"));

            siteBox = Ui.Find<TextBox>(w, "SiteBox");
            folderBox = Ui.Find<TextBox>(w, "FolderBox");
            clientBox = Ui.Find<TextBox>(w, "ClientBox");
            byBox = Ui.Find<TextBox>(w, "ByBox");
            permBox = Ui.Find<CheckBox>(w, "PermBox");
            runButton = Ui.Find<Button>(w, "RunButton");
            runHint = Ui.Find<TextBlock>(w, "RunHint");
            formError = Ui.Find<TextBlock>(w, "FormError");
            runningTitle = Ui.Find<TextBlock>(w, "RunningTitle");
            runningStep = Ui.Find<TextBlock>(w, "RunningStep");
            pdfStatus = Ui.Find<TextBlock>(w, "PdfStatus");
            formPanel = Ui.Find<FrameworkElement>(w, "FormPanel");
            runningPanel = Ui.Find<FrameworkElement>(w, "RunningPanel");
            siteFields = Ui.Find<FrameworkElement>(w, "SiteFields");
            folderFields = Ui.Find<FrameworkElement>(w, "FolderFields");
            nortonTip = Ui.Find<FrameworkElement>(w, "NortonTip");
            modeSite = Ui.Find<RadioButton>(w, "ModeSite");
            navCheck = Ui.Find<RadioButton>(w, "NavCheck");
            navReports = Ui.Find<RadioButton>(w, "NavReports");
            navHelp = Ui.Find<RadioButton>(w, "NavHelp");
            pages = new FrameworkElement[] {
                Ui.Find<FrameworkElement>(w, "PageCheck"), Ui.Find<FrameworkElement>(w, "PageResult"),
                Ui.Find<FrameworkElement>(w, "PageReports"), Ui.Find<FrameworkElement>(w, "PageHelp") };

            Ui.Find<TextBlock>(w, "VersionText").Text = "Version " + Program.Version;
            byBox.Text = Settings.Load("by");

            // navigation
            navCheck.Checked += delegate { ShowPage(0); };
            navReports.Checked += delegate { RefreshReports(); ShowPage(2); };
            navHelp.Checked += delegate { ShowPage(3); };
            Ui.Find<Button>(w, "BackButton").Click += delegate { ShowPage(0); };

            // form
            modeSite.Checked += delegate { SetMode(true); };
            Ui.Find<RadioButton>(w, "ModeFolder").Checked += delegate { SetMode(false); };
            foreach (TextBox t in new[] { siteBox, folderBox, clientBox, byBox })
                t.TextChanged += delegate { Validate(); };
            permBox.Checked += delegate { Validate(); };
            permBox.Unchecked += delegate { Validate(); };
            runButton.Click += delegate { Run(); };
            Ui.Find<Button>(w, "BrowseButton").Click += delegate
            {
                string f = FolderPicker.Pick(w, folderBox.Text);
                if (f != null)
                    folderBox.Text = f;
            };
            w.PreviewKeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter && pages[0].Visibility == Visibility.Visible && runButton.IsEnabled && !running)
                {
                    e.Handled = true;
                    Run();
                }
            };

            // result
            Ui.Find<Button>(w, "OpenReportButton").Click += delegate { if (lastReport != null) Ui.Open(lastReport); };
            Ui.Find<Button>(w, "ShowFolderButton").Click += delegate { if (lastReport != null) Ui.ShowInFolder(lastReport); };
            var pdfButton = Ui.Find<Button>(w, "PdfButton");
            pdfButton.Click += async delegate
            {
                if (lastReport == null)
                    return;
                pdfButton.IsEnabled = false;
                pdfStatus.Visibility = Visibility.Visible;
                pdfStatus.Text = "Saving PDF...";
                pdfStatus.Text = await SavePdf(lastReport, true);
                pdfButton.IsEnabled = true;
            };

            // reports
            Ui.Find<Button>(w, "OpenReportsFolder").Click += delegate
            {
                Directory.CreateDirectory(ReportsDir);
                Ui.Open(ReportsDir);
            };
            Ui.Find<ItemsControl>(w, "ReportsList").AddHandler(Button.ClickEvent, new RoutedEventHandler(async (s, e) =>
            {
                Button b = e.OriginalSource as Button;
                if (b == null || !(b.Tag is string))
                    return;
                string path = (string)b.Tag, what = b.Content as string;
                if (what == "Open")
                    Ui.Open(path);
                else if (what == "Folder")
                    Ui.ShowInFolder(path);
                else if (what == "PDF")
                {
                    b.IsEnabled = false;
                    b.Content = "Saving...";
                    await SavePdf(path, true);
                    b.Content = "PDF";
                    b.IsEnabled = true;
                    RefreshReports();
                }
            }));

            BuildHelp();
            Validate();
            Ui.Find<Button>(w, "CoffeeButton").Click += delegate { Ui.Open(Program.CoffeeUrl); };
            Ui.Find<Button>(w, "UpdateButton").Click += delegate { Ui.Open(Program.RepoUrl + "/releases/latest"); };
            w.Loaded += delegate
            {
                siteBox.Focus();
                if (!Snapshots.Active)
                {
                    Task t = CheckForUpdate();
                }
            };
        }

        void ShowPage(int n)
        {
            for (int i = 0; i < pages.Length; i++)
                pages[i].Visibility = i == n ? Visibility.Visible : Visibility.Collapsed;
            if (n <= 1 && navCheck.IsChecked != true)
                navCheck.IsChecked = true;
        }

        void SetMode(bool site)
        {
            siteFields.Visibility = site ? Visibility.Visible : Visibility.Collapsed;
            folderFields.Visibility = site ? Visibility.Collapsed : Visibility.Visible;
            nortonTip.Visibility = site ? Visibility.Visible : Visibility.Collapsed;
            Ui.Find<TextBlock>(w, "PermText").Text = site
                ? "The owner of this website has signed the permission form."
                : "This is my folder, or its owner has given me permission to scan it.";
            Ui.Find<TextBlock>(w, "ClientLabel").Text = site ? "Client name" : "Client or project name";
            permBox.IsChecked = false;
            formError.Visibility = Visibility.Collapsed;
            Validate();
            (site ? siteBox : folderBox).Focus();
        }

        bool SiteMode { get { return modeSite.IsChecked == true; } }

        // "https://www.Shop.com/en/" -> "www.shop.com"; null when it does not look like a host
        public static string NormalizeHost(string s)
        {
            string h = Regex.Replace((s ?? "").Trim(), "^[A-Za-z]+://", "");
            h = h.Split('/', '?', '#')[0];
            return Regex.IsMatch(h, @"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+(:\d{1,5})?$")
                ? h.ToLowerInvariant() : null;
        }

        void Validate()
        {
            bool targetOk = SiteMode ? NormalizeHost(siteBox.Text) != null
                                     : folderBox.Text.Trim().Length > 0 && Directory.Exists(folderBox.Text.Trim());
            bool ok = targetOk && permBox.IsChecked == true && !running;
            runButton.IsEnabled = ok;
            if (ok)
                runHint.Text = "Takes a few seconds.";
            else if (!targetOk && SiteMode)
                runHint.Text = siteBox.Text.Trim().Length == 0 ? "Enter the website address." : "That address doesn't look right yet.";
            else if (!targetOk)
                runHint.Text = folderBox.Text.Trim().Length == 0 ? "Choose a folder." : "That folder doesn't exist.";
            else
                runHint.Text = "Tick the permission box to continue.";
        }

        static string Clean(string s)
        {
            return (s ?? "").Replace("\"", "").Replace("\r", " ").Replace("\n", " ").Trim();
        }

        // one command-line argument in quotes, safe for the C runtime's parser
        static string Q(string s)
        {
            s = Clean(s);
            if (s.EndsWith(":\\"))
                s += ".";
            return "\"" + s.TrimEnd('\\') + "\"";
        }

        static string NextReportPath(string stem)
        {
            Directory.CreateDirectory(ReportsDir);
            stem = Regex.Replace(stem.ToLowerInvariant(), "[^a-z0-9.-]+", "-").Trim('-');
            if (stem.Length == 0)
                stem = "report";
            stem += "-" + DateTime.Now.ToString("yyyy-MM-dd");
            string p = Path.Combine(ReportsDir, stem + ".html");
            for (int n = 2; File.Exists(p); n++)
                p = Path.Combine(ReportsDir, stem + "-" + n + ".html");
            return p;
        }

        void Run()
        {
            Task t = RunAsync();
        }

        async Task RunAsync()
        {
            if (running || !runButton.IsEnabled)
                return;
            bool site = SiteMode;
            string host = site ? NormalizeHost(siteBox.Text) : null;
            string folder = site ? null : folderBox.Text.Trim();
            string label = site ? host : new DirectoryInfo(folder).Name;
            string client = Clean(clientBox.Text), by = Clean(byBox.Text);
            if (client.Length == 0)
                client = label;
            if (!Snapshots.Active)
                Settings.Save("by", by); // an empty field forgets the saved name

            string scanner = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "scanner.exe");
            if (!File.Exists(scanner))
            {
                ShowError("scanner.exe is missing next to the app. Reinstall Exposure Scanner.");
                return;
            }
            string html = NextReportPath(label);
            string args = site
                ? "site " + Q(host) + " --i-own-this --json --html " + Q(html) + " --client " + Q(client)
                : "all " + Q(folder) + " --json --html " + Q(html) + " --client " + Q(client);
            if (by.Length > 0)
                args += " --by " + Q(by);

            running = true;
            formError.Visibility = Visibility.Collapsed;
            formPanel.Visibility = Visibility.Collapsed;
            runningPanel.Visibility = Visibility.Visible;
            runningTitle.Text = "Checking " + label;
            string[] steps = site
                ? new[] { "Connecting...", "Reading the security settings...", "Checking the certificate...", "Writing the report..." }
                : new[] { "Reading files...", "Looking for passwords and keys...", "Checking Python packages...", "Writing the report..." };
            int step = 0;
            runningStep.Text = steps[0];
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.4) };
            timer.Tick += delegate { if (step < steps.Length - 1) runningStep.Text = steps[++step]; };
            timer.Start();
            DateTime started = DateTime.Now;

            ExecResult r = await Task.Run(() => Exec(scanner, args, 180));

            // keep the progress view up briefly so a fast run doesn't flash
            TimeSpan shown = DateTime.Now - started;
            if (shown < TimeSpan.FromMilliseconds(1200))
                await Task.Delay(TimeSpan.FromMilliseconds(1200) - shown);
            timer.Stop();
            running = false;
            runningPanel.Visibility = Visibility.Collapsed;
            formPanel.Visibility = Visibility.Visible;
            Validate();

            if (!File.Exists(html))
            {
                string msg = r.Stderr.Trim();
                ShowError(msg.Length > 0 ? "The check did not finish: " + msg : "The check did not finish (scanner exit code " + r.Exit + ").");
                return;
            }
            ShowResult(r.Stdout, html, label, client);
        }

        void ShowError(string msg)
        {
            formError.Text = msg;
            formError.Visibility = Visibility.Visible;
        }

        static int ToInt(object o)
        {
            try { return Convert.ToInt32(o, CultureInfo.InvariantCulture); }
            catch (Exception) { return 0; }
        }

        void ShowResult(string json, string html, string label, string client)
        {
            lastReport = html;
            pdfStatus.Visibility = Visibility.Collapsed;
            Dictionary<string, object> summary = null;
            try
            {
                var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                var root = js.DeserializeObject(json) as Dictionary<string, object>;
                if (root != null && root.ContainsKey("summary"))
                    summary = root["summary"] as Dictionary<string, object>;
            }
            catch (Exception) { }
            if (summary == null)
                summary = new Dictionary<string, object>();

            int imp = summary.ContainsKey("important") ? ToInt(summary["important"]) : 0;
            int rec = summary.ContainsKey("recommended") ? ToInt(summary["recommended"]) : 0;
            int tip = summary.ContainsKey("tip") ? ToInt(summary["tip"]) : 0;
            int ok = summary.ContainsKey("passed") ? ToInt(summary["passed"]) : 0;
            bool ready = summary.ContainsKey("ready_to_send") && summary["ready_to_send"] is bool && (bool)summary["ready_to_send"];
            var warnings = summary.ContainsKey("warnings") ? summary["warnings"] as object[] : null;

            Ui.Find<TextBlock>(w, "ResultTitle").Text = label;
            Ui.Find<TextBlock>(w, "ResultSub").Text = client + "  \u00B7  " + DateTime.Now.ToString("d MMMM yyyy, HH:mm", En);
            Ui.Find<TextBlock>(w, "CountImp").Text = imp.ToString();
            Ui.Find<TextBlock>(w, "CountRec").Text = rec.ToString();
            Ui.Find<TextBlock>(w, "CountTip").Text = tip.ToString();
            Ui.Find<TextBlock>(w, "CountOk").Text = ok.ToString();

            var banner = Ui.Find<Border>(w, "ReadyBanner");
            var dot = Ui.Find<Border>(w, "ReadyDot");
            var glyph = Ui.Find<System.Windows.Shapes.Path>(w, "ReadyGlyph");
            var title = Ui.Find<TextBlock>(w, "ReadyTitle");
            var text = Ui.Find<TextBlock>(w, "ReadyText");
            if (ready)
            {
                banner.Background = Ui.Res("OkBg");
                banner.BorderBrush = Ui.Res("OkLine");
                dot.Background = Ui.Res("OkFg");
                glyph.Data = Geometry.Parse("M0,4 L3.5,7.5 L10,0");
                title.Text = "Ready to send";
                title.Foreground = text.Foreground = new SolidColorBrush(Color.FromRgb(0x06, 0x5F, 0x46));
                text.Text = "The report is complete. Open it to read it through, then save it as a PDF for your client.";
            }
            else
            {
                banner.Background = Ui.Res("ImpBg");
                banner.BorderBrush = Ui.Res("ImpLine");
                dot.Background = Ui.Res("ImpFg");
                glyph.Data = Geometry.Parse("M0,0 L0,6.5 M0,10 L0,10.2");
                title.Text = "Not ready to send";
                title.Foreground = text.Foreground = new SolidColorBrush(Color.FromRgb(0x99, 0x1B, 0x1B));
                text.Text = warnings != null && warnings.Length > 0
                    ? string.Join(" ", warnings.Select(o => o as string).Where(s => s != null))
                    : "Something went wrong during the check. Run it again.";
            }

            string verdict;
            if (imp > 0)
                verdict = imp + (imp == 1 ? " important issue should" : " important issues should") + " be fixed soon.";
            else if (rec > 0)
                verdict = "No urgent problems. " + rec + (rec == 1 ? " improvement is" : " improvements are") + " recommended.";
            else if (tip > 0)
                verdict = "No urgent problems. A few optional tips below.";
            else
                verdict = "No problems found in the checks that were run.";
            Ui.Find<TextBlock>(w, "VerdictText").Text = verdict;

            var items = new List<IssueVm>();
            object[] issues = summary.ContainsKey("issues") ? summary["issues"] as object[] : null;
            if (issues != null)
                foreach (object o in issues)
                {
                    var d = o as Dictionary<string, object>;
                    if (d == null)
                        continue;
                    string lvl = d.ContainsKey("level") ? d["level"] as string : "";
                    var vm = new IssueVm
                    {
                        Site = d.ContainsKey("site") ? d["site"] as string : "",
                        Title = d.ContainsKey("title") ? d["title"] as string : "",
                        Fix = d.ContainsKey("fix") ? d["fix"] as string : "",
                        Detail = d.ContainsKey("detail") ? (d["detail"] as string ?? "") : ""
                    };
                    if (lvl == "important") { vm.Level = "Important"; vm.Fg = Ui.Res("ImpFg"); vm.Bg = Ui.Res("ImpBg"); }
                    else if (lvl == "recommended") { vm.Level = "Recommended"; vm.Fg = Ui.Res("RecFg"); vm.Bg = Ui.Res("RecBg"); }
                    else { vm.Level = "Tip"; vm.Fg = Ui.Res("TipFg"); vm.Bg = Ui.Res("TipBg"); }
                    items.Add(vm);
                }
            Ui.Find<ItemsControl>(w, "IssuesList").ItemsSource = items;
            Ui.Find<FrameworkElement>(w, "NothingToFix").Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            ShowPage(1);
            ((ScrollViewer)pages[1]).ScrollToTop();
        }

        void RefreshReports()
        {
            Ui.Find<TextBlock>(w, "ReportsSub").Text = "Saved in " + ReportsDir;
            var list = new List<ReportVm>();
            if (Directory.Exists(ReportsDir))
                foreach (FileInfo f in new DirectoryInfo(ReportsDir).GetFiles("*.html").OrderByDescending(f => f.LastWriteTime))
                {
                    bool pdf = File.Exists(Path.ChangeExtension(f.FullName, ".pdf"));
                    list.Add(new ReportVm
                    {
                        Name = Path.GetFileNameWithoutExtension(f.Name),
                        Info = f.LastWriteTime.ToString("d MMM yyyy, HH:mm", En) + (pdf ? "   \u00B7   PDF saved" : ""),
                        Path = f.FullName
                    });
                }
            Ui.Find<ItemsControl>(w, "ReportsList").ItemsSource = list;
            Ui.Find<FrameworkElement>(w, "NoReports").Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        // Edge prints the report to PDF without any clicks; a private profile folder keeps it from
        // handing the job to an Edge window that is already open.
        static async Task<string> SavePdf(string html, bool open)
        {
            string pdf = Path.ChangeExtension(html, ".pdf");
            string edge = new[] {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) }
                .Select(p => Path.Combine(p, @"Microsoft\Edge\Application\msedge.exe"))
                .FirstOrDefault(File.Exists);
            if (edge == null)
                return "Microsoft Edge was not found. Open the report and press Ctrl+P, then choose Save as PDF.";
            // a fresh profile per PDF: an Edge still busy with an earlier job never swallows this one
            string profile = Path.Combine(Path.GetTempPath(), "ExposureScannerPdf-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            string args = "--headless --disable-gpu --no-first-run --no-pdf-header-footer --user-data-dir=" + Q(profile) +
                          " --print-to-pdf=" + Q(pdf) + " " + Q(new Uri(html).AbsoluteUri);
            try { File.Delete(pdf); }
            catch (Exception) { }
            DateTime t0 = DateTime.Now;
            ExecResult r = await Task.Run(() => Exec(edge, args, 90));
            Task cleanup = Task.Run(() =>
            {
                for (int i = 0; i < 10 && Directory.Exists(profile); i++)
                {
                    try { Directory.Delete(profile, true); }
                    catch (Exception) { System.Threading.Thread.Sleep(500); }
                }
            });
            if (!File.Exists(pdf))
            {
                try
                {
                    File.WriteAllText(Path.Combine(Path.GetTempPath(), "ExposureScanner-pdf.log"),
                        DateTime.Now.ToString("u") + "\r\nedge: " + edge + "\r\nargs: " + args + "\r\nexit: " + r.Exit +
                        "\r\nms: " + (int)(DateTime.Now - t0).TotalMilliseconds + "\r\nstderr: " + r.Stderr + "\r\nstdout: " + r.Stdout);
                }
                catch (Exception) { }
                return "The PDF could not be made. Open the report and press Ctrl+P, then choose Save as PDF.";
            }
            if (open)
                Ui.Open(pdf);
            return "PDF saved: " + pdf;
        }

        public class ExecResult
        {
            public int Exit;
            public string Stdout = "", Stderr = "";
        }

        public static ExecResult Exec(string exe, string args, int timeoutSeconds)
        {
            var r = new ExecResult();
            try
            {
                var psi = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                    WorkingDirectory = Path.GetDirectoryName(exe)
                };
                using (Process p = Process.Start(psi))
                {
                    Task<string> o = p.StandardOutput.ReadToEndAsync(), e = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(timeoutSeconds * 1000))
                    {
                        try { p.Kill(); }
                        catch (Exception) { }
                        r.Exit = -1;
                        r.Stderr = "it took longer than " + timeoutSeconds + " seconds.";
                        return r;
                    }
                    r.Exit = p.ExitCode;
                    r.Stdout = o.Result;
                    r.Stderr = e.Result;
                }
            }
            catch (Exception ex)
            {
                r.Exit = -1;
                r.Stderr = ex.Message;
            }
            return r;
        }

        // --ui-snapshots: every main-window state as a PNG (made-up data, except the folder check,
        // which really runs scanner.exe on the folder given in ES_SNAPSHOT_FOLDER)
        internal async Task SnapshotAll(string dir)
        {
            FrameworkElement root = Ui.Find<FrameworkElement>(w, "Root");
            Func<string, Task> snap = async name =>
            {
                await Task.Delay(350);
                Snapshots.Save(root, Path.Combine(dir, name));
            };
            await snap("01-new-checkup.png");

            siteBox.Text = "https://www.Rosas-Bakery.example/menu";
            clientBox.Text = "Rosa's Bakery";
            byBox.Text = "Your Name";
            permBox.IsChecked = true;
            await snap("02-form-filled.png");

            formPanel.Visibility = Visibility.Collapsed;
            runningPanel.Visibility = Visibility.Visible;
            runningTitle.Text = "Checking www.rosas-bakery.example";
            runningStep.Text = "Reading the security settings...";
            await snap("03-running.png");
            runningPanel.Visibility = Visibility.Collapsed;
            formPanel.Visibility = Visibility.Visible;

            string fake = Path.Combine(ReportsDir, "rosas-bakery.example-sample.html");
            ShowResult(Snapshots.SampleJson(true), fake, "www.rosas-bakery.example", "Rosa's Bakery");
            await snap("04-result-ready.png");
            Snapshots.Save((FrameworkElement)((ScrollViewer)pages[1]).Content, Path.Combine(dir, "04b-result-full.png"));
            ShowResult(Snapshots.SampleJson(false), fake, "www.rosas-bakery.example", "Rosa's Bakery");
            await snap("05-result-not-ready.png");

            navReports.IsChecked = true;
            await snap("06-reports.png");
            navHelp.IsChecked = true;
            await snap("07-help.png");
            Snapshots.Save((FrameworkElement)((ScrollViewer)pages[3]).Content, Path.Combine(dir, "07b-help-full.png"));

            navCheck.IsChecked = true;
            Ui.Find<RadioButton>(w, "ModeFolder").IsChecked = true;
            await snap("08-folder-mode.png");
            string folder = Environment.GetEnvironmentVariable("ES_SNAPSHOT_FOLDER");
            if (!string.IsNullOrEmpty(folder) && Directory.Exists(folder))
            {
                folderBox.Text = folder;
                clientBox.Text = "My project";
                permBox.IsChecked = true;
                await RunAsync(); // the real engine
                await snap("09-folder-result.png");
                string pdfMsg = lastReport != null ? await SavePdf(lastReport, false) : "(no report)"; // the real PDF step
                File.WriteAllText(Path.Combine(dir, "09-folder-result.txt"),
                    "report=" + (lastReport ?? "(none)") + "\r\nexists=" + (lastReport != null && File.Exists(lastReport)) +
                    "\r\nerror=" + (formError.Visibility == Visibility.Visible ? formError.Text : "") +
                    "\r\npdf=" + pdfMsg);
            }
        }

        void BuildHelp()
        {
            string[][] steps = {
                new[] { "Get permission", "Send the client the permission form and get it signed. Never check a site without it." },
                new[] { "Pause HTTPS scanning", "In Norton: Security \u203A Advanced Security \u203A Web \u203A Safe Web \u203A Settings \u203A HTTPS scanning. Turn it back on afterwards." },
                new[] { "Run the check-up", "Enter the website, the client's name and yours, tick the permission box and press Run check-up." },
                new[] { "Check the result", "If it says Not ready to send, fix what it says and run it again." },
                new[] { "Send the PDF", "Press Save as PDF and email the file to your client." }
            };
            var panel = Ui.Find<StackPanel>(w, "StepsPanel");
            for (int i = 0; i < steps.Length; i++)
            {
                var g = new Grid { Margin = new Thickness(0, i == 0 ? 0 : 18, 0, 0) };
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                g.ColumnDefinitions.Add(new ColumnDefinition());
                var circle = new Border
                {
                    Width = 30, Height = 30, CornerRadius = new CornerRadius(15),
                    Background = Ui.Res("AccentSoft"), VerticalAlignment = VerticalAlignment.Top,
                    Child = new TextBlock
                    {
                        Text = (i + 1).ToString(), Foreground = Ui.Res("Accent"), FontWeight = FontWeights.SemiBold,
                        FontSize = 14, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center
                    }
                };
                var text = new StackPanel { Margin = new Thickness(16, 3, 0, 0) };
                text.Children.Add(new TextBlock { Text = steps[i][0], FontSize = 14.5, FontWeight = FontWeights.SemiBold });
                text.Children.Add(new TextBlock
                {
                    Text = steps[i][1], FontSize = 13.5, Foreground = Ui.Res("Muted"), TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 3, 0, 0)
                });
                Grid.SetColumn(text, 1);
                g.Children.Add(circle);
                g.Children.Add(text);
                panel.Children.Add(g);
            }
            Ui.Find<TextBlock>(w, "CliExamples").Text =
                "scanner site shop.com --i-own-this --html report.html\n" +
                "scanner secrets C:\\code\\my-project\n" +
                "scanner          (shows every command)";
            string listDate = AdvisoryDate();
            Ui.Find<TextBlock>(w, "AboutText").Text = Program.AppName + " " + Program.Version +
                (listDate != null ? "  \u00B7  Known-problem list checked " + listDate : "") +
                "  \u00B7  Reports are saved in " + ReportsDir;
            Ui.Find<Button>(w, "FormButton").Click += delegate { Ui.Open(Program.FormUrl); };
            Ui.Find<Button>(w, "RepoButton").Click += delegate { Ui.Open(Program.RepoUrl); };
            Ui.Find<Button>(w, "CoffeeButton2").Click += delegate { Ui.Open(Program.CoffeeUrl); };
        }

        // "Verified 2026-10-23" in the header of data\advisories.txt -> "23 October 2026"
        static string AdvisoryDate()
        {
            try
            {
                string f = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data", "advisories.txt");
                Match m = Regex.Match(File.ReadAllText(f), @"Verified (\d{4}-\d{2}-\d{2})");
                if (m.Success)
                    return DateTime.ParseExact(m.Groups[1].Value, "yyyy-MM-dd", CultureInfo.InvariantCulture)
                                   .ToString("d MMMM yyyy", En);
            }
            catch (Exception) { }
            return null;
        }

        // One request to GitHub's public releases API on start-up; shows a sidebar button when a
        // newer version exists. Nothing about the user or their checks is sent.
        async Task CheckForUpdate()
        {
            string tag = await Task.Run(() =>
            {
                try
                {
                    System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12;
                    var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(
                        "https://api.github.com/repos/onlyilir/exposure-scanner/releases/latest");
                    req.UserAgent = "ExposureScanner/" + Program.Version;
                    req.Timeout = 8000;
                    using (var resp = req.GetResponse())
                    using (var sr = new StreamReader(resp.GetResponseStream()))
                    {
                        Match m = Regex.Match(sr.ReadToEnd(), "\"tag_name\"\\s*:\\s*\"v?([0-9]+(\\.[0-9]+){1,3})\"");
                        return m.Success ? m.Groups[1].Value : null;
                    }
                }
                catch (Exception) { return null; } // offline, rate-limited, no release yet: stay quiet
            });
            Version latest, mine;
            if (tag == null || !Version.TryParse(tag, out latest) || !Version.TryParse(Program.Version, out mine) ||
                latest <= mine)
                return;
            Ui.Find<TextBlock>(w, "UpdateText").Text = "Update available: " + tag;
            Ui.Find<FrameworkElement>(w, "UpdateButton").Visibility = Visibility.Visible;
        }
    }

    // ------------------------------------------------------------------ developer snapshots

    static class Snapshots
    {
        public static bool Active;

        public static int Run(Application app, string dir)
        {
            Active = true;
            Directory.CreateDirectory(dir);
            MainController.ReportsDir = Path.Combine(dir, "reports");
            Directory.CreateDirectory(MainController.ReportsDir);
            File.WriteAllText(Path.Combine(MainController.ReportsDir, "shop.example-2026-10-20.html"), "<html></html>");
            File.WriteAllText(Path.Combine(MainController.ReportsDir, "rosas-bakery.example-2026-10-24.html"), "<html></html>");
            File.WriteAllText(Path.Combine(MainController.ReportsDir, "rosas-bakery.example-2026-10-24.pdf"), "");

            var main = new MainController();
            Window w = main.Window;
            OffScreen(w);
            w.ContentRendered += async delegate
            {
                try
                {
                    await main.SnapshotAll(dir);
                    foreach (bool un in new[] { false, true })
                    {
                        // a neutral example path, shown only; nothing is installed
                        var s = new SetupController(un, @"C:\Users\you\AppData\Local\Programs\Exposure Scanner");
                        OffScreen(s.Window);
                        s.Window.Show();
                        await s.SnapshotAll(dir, un ? "11-uninstall" : "10-setup");
                        s.Window.Close();
                    }
                }
                catch (Exception ex)
                {
                    File.WriteAllText(Path.Combine(dir, "error.txt"), ex.ToString());
                }
                app.Shutdown(0);
            };
            return app.Run(w);
        }

        static void OffScreen(Window w)
        {
            w.WindowStartupLocation = WindowStartupLocation.Manual;
            w.Left = -12000;
            w.Top = 0;
            w.ShowActivated = false;
            w.ShowInTaskbar = false;
        }

        public static void Save(FrameworkElement e, string file)
        {
            e.UpdateLayout();
            int width = (int)Math.Ceiling(e.ActualWidth), height = (int)Math.Ceiling(e.ActualHeight);
            var dv = new DrawingVisual();
            using (DrawingContext dc = dv.RenderOpen())
            {
                dc.DrawRectangle(Ui.Res("Page"), null, new Rect(0, 0, width, height));
                dc.DrawRectangle(new VisualBrush(e) { Stretch = Stretch.None, AlignmentX = AlignmentX.Left, AlignmentY = AlignmentY.Top },
                                 null, new Rect(0, 0, width, height));
            }
            var bmp = new System.Windows.Media.Imaging.RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
            bmp.Render(dv);
            var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
            enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bmp));
            using (FileStream fs = File.Create(file))
                enc.Save(fs);
        }

        public static string SampleJson(bool ready)
        {
            return @"{""summary"":{""important"":2,""recommended"":3,""tip"":2,""passed"":5,""ready_to_send"":" +
                   (ready ? "true,\"warnings\":[]" :
                    "false,\"warnings\":[\"HTTPS inspection on this computer replaced the certificate. Pause HTTPS scanning (for example Norton Safe Web) and run the check again.\"]") +
                   @",""issues"":[
{""level"":""important"",""site"":""rosas-bakery.example"",""title"":""Possibly outdated software with a known security problem: PHP 8.2.20"",""fix"":""Ask your host to confirm the version and update to a fixed release (8.2.35, 8.3.36, 8.4.27, 8.5.12)."",""detail"":""Reported in the X-Powered-By header.""},
{""level"":""important"",""site"":""rosas-bakery.example"",""title"":""The certificate expires in 9 days"",""fix"":""Ask your host to renew it before that date and to turn on automatic renewal."",""detail"":""Valid until Nov  1 08:00:00 2026 GMT""},
{""level"":""recommended"",""site"":""rosas-bakery.example"",""title"":""Other sites can show your pages inside theirs"",""fix"":""Ask for the header X-Frame-Options: SAMEORIGIN, or frame-ancestors 'self' in the content security policy.""},
{""level"":""recommended"",""site"":""rosas-bakery.example"",""title"":""Some cookies are missing protection flags"",""fix"":""Ask your developer to set the Secure and HttpOnly flags on cookies, plus SameSite=Lax.""},
{""level"":""tip"",""site"":""rosas-bakery.example"",""title"":""No content security policy"",""fix"":""Ask your developer to add a Content-Security-Policy header. It needs care so the site keeps working, so start with the report-only version.""}
]}}";
        }
    }

    // ------------------------------------------------------------------ settings

    static class Settings
    {
        static readonly string FilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Exposure Scanner", "settings.txt");

        public static string Load(string key)
        {
            try
            {
                foreach (string line in File.ReadAllLines(FilePath, Encoding.UTF8))
                    if (line.StartsWith(key + "="))
                        return line.Substring(key.Length + 1);
            }
            catch (Exception) { }
            return "";
        }

        public static void Save(string key, string value)
        {
            try
            {
                var lines = File.Exists(FilePath)
                    ? File.ReadAllLines(FilePath, Encoding.UTF8).Where(l => !l.StartsWith(key + "=")).ToList()
                    : new List<string>();
                lines.Add(key + "=" + value);
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath));
                File.WriteAllLines(FilePath, lines, new UTF8Encoding(false));
            }
            catch (Exception) { }
        }
    }

    // ------------------------------------------------------------------ modern folder picker

    static class FolderPicker
    {
        [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
        class FileOpenDialogCom { }

        [ComImport, Guid("42f85136-db7e-439c-85f1-e4075d135fc8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IFileDialog
        {
            [PreserveSig] int Show(IntPtr parent);
            void SetFileTypes(uint count, IntPtr specs);
            void SetFileTypeIndex(uint index);
            void GetFileTypeIndex(out uint index);
            void Advise(IntPtr events, out uint cookie);
            void Unadvise(uint cookie);
            void SetOptions(uint fos);
            void GetOptions(out uint fos);
            void SetDefaultFolder(IShellItem item);
            void SetFolder(IShellItem item);
            void GetFolder(out IShellItem item);
            void GetCurrentSelection(out IShellItem item);
            void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string name);
            void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string name);
            void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
            void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
            void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
            void GetResult(out IShellItem item);
            void AddPlace(IShellItem item, int place);
            void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string ext);
            void Close(int hr);
            void SetClientGuid(ref Guid guid);
            void ClearClientData();
            void SetFilter(IntPtr filter);
        }

        [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IShellItem
        {
            void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
            void GetParent(out IShellItem parent);
            void GetDisplayName(uint sigdn, [MarshalAs(UnmanagedType.LPWStr)] out string name);
            void GetAttributes(uint mask, out uint attrs);
            void Compare(IShellItem other, uint hint, out int order);
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        static extern void SHCreateItemFromParsingName(string path, IntPtr pbc, ref Guid riid, out IShellItem item);

        public static string Pick(Window owner, string start)
        {
            try
            {
                var dlg = (IFileDialog)new FileOpenDialogCom();
                dlg.SetOptions(0x20 | 0x40); // FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM
                dlg.SetTitle("Choose the folder to scan");
                dlg.SetOkButtonLabel("Scan this folder");
                if (!string.IsNullOrEmpty(start) && Directory.Exists(start))
                {
                    Guid iid = typeof(IShellItem).GUID;
                    IShellItem si;
                    SHCreateItemFromParsingName(start, IntPtr.Zero, ref iid, out si);
                    dlg.SetFolder(si);
                }
                if (dlg.Show(new WindowInteropHelper(owner).Handle) != 0)
                    return null; // cancelled
                IShellItem result;
                dlg.GetResult(out result);
                string path;
                result.GetDisplayName(0x80058000, out path); // SIGDN_FILESYSPATH
                return path;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

    // ------------------------------------------------------------------ install / uninstall

    static class Installer
    {
        public static string DefaultTarget
        {
            get
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                    "Programs", "Exposure Scanner");
            }
        }

        const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\ExposureScanner";
        static readonly string[] AppFiles = { Program.ExeName, "scanner.exe", "README.txt", "LICENSE.txt", "THIRD-PARTY-NOTICES.txt" };
        static readonly string[] DataFiles = { "advisories.txt", "spki_blocklist.txt" };

        public class Options
        {
            public bool StartMenu = true, Desktop = true, AddPath = true, Registry = true;
        }

        // ES_TEST_LINK_DIR (tests only) puts both shortcuts in that folder instead of the real ones
        static string LinkDir(Environment.SpecialFolder real, string sub)
        {
            string test = Environment.GetEnvironmentVariable("ES_TEST_LINK_DIR");
            return string.IsNullOrEmpty(test) ? Environment.GetFolderPath(real) : Path.Combine(test, sub);
        }

        static string StartMenuLink
        {
            get { return Path.Combine(LinkDir(Environment.SpecialFolder.Programs, "start-menu"), "Exposure Scanner.lnk"); }
        }

        static string DesktopLink
        {
            get { return Path.Combine(LinkDir(Environment.SpecialFolder.DesktopDirectory, "desktop"), "Exposure Scanner.lnk"); }
        }

        // Antivirus programs often hold a freshly run exe open for a few seconds; retry before failing.
        static void Retry(Action a)
        {
            for (int i = 0; ; i++)
            {
                try
                {
                    a();
                    return;
                }
                catch (IOException)
                {
                    if (i >= 40)
                        throw;
                }
                catch (UnauthorizedAccessException)
                {
                    if (i >= 40)
                        throw;
                }
                System.Threading.Thread.Sleep(250);
            }
        }

        public static bool IsInstalled(string target)
        {
            return File.Exists(Path.Combine(target, Program.ExeName));
        }

        static bool SamePath(string a, string b)
        {
            return string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'),
                                 StringComparison.OrdinalIgnoreCase);
        }

        public static void Install(string source, string target, Options o)
        {
            Directory.CreateDirectory(Path.Combine(target, "data"));
            foreach (string f in AppFiles)
            {
                string src = Path.Combine(source, f), dst = Path.Combine(target, f);
                if (File.Exists(src) && !SamePath(src, dst))
                    Retry(() => File.Copy(src, dst, true));
            }
            foreach (string f in DataFiles)
            {
                // flat in the setup package, under data\ in a normal folder
                string src = File.Exists(Path.Combine(source, f)) ? Path.Combine(source, f) : Path.Combine(source, "data", f);
                string dst = Path.Combine(target, "data", f);
                if (!File.Exists(src))
                    throw new FileNotFoundException("The setup package is incomplete (" + f + " is missing).");
                if (!SamePath(src, dst))
                    Retry(() => File.Copy(src, dst, true));
            }
            if (!File.Exists(Path.Combine(target, "scanner.exe")) || !File.Exists(Path.Combine(target, Program.ExeName)))
                throw new FileNotFoundException("The setup package is incomplete.");

            string exe = Path.Combine(target, Program.ExeName);
            if (o.StartMenu)
                Shortcut(StartMenuLink, exe, target);
            if (o.Desktop)
                Shortcut(DesktopLink, exe, target);
            else if (File.Exists(DesktopLink))
                File.Delete(DesktopLink);
            if (o.AddPath)
                UserPath(target, true);
            if (o.Registry)
                WriteUninstallEntry(target);
        }

        // Returns true when the folder itself still has to go after this process exits.
        public static bool Uninstall(string target, Options o)
        {
            if (o.StartMenu && File.Exists(StartMenuLink))
                File.Delete(StartMenuLink);
            if (o.Desktop && File.Exists(DesktopLink))
                File.Delete(DesktopLink);
            if (o.AddPath)
                UserPath(target, false);
            if (o.Registry)
            {
                Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false);
                // saved settings (the remembered name) go too, so a reinstall starts clean; reports stay
                string settings = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                               "Exposure Scanner");
                try
                {
                    File.Delete(Path.Combine(settings, "settings.txt"));
                    if (Directory.Exists(settings) && Directory.GetFileSystemEntries(settings).Length == 0)
                        Directory.Delete(settings);
                }
                catch (Exception) { }
            }

            string self = Assembly.GetExecutingAssembly().Location;
            bool runningFromTarget = SamePath(Path.GetDirectoryName(self), target);
            if (!Directory.Exists(target))
                return false;
            foreach (string f in AppFiles)
            {
                string p = Path.Combine(target, f);
                if (File.Exists(p) && !(runningFromTarget && SamePath(p, self)))
                    Retry(() => File.Delete(p));
            }
            string data = Path.Combine(target, "data");
            if (Directory.Exists(data))
                Retry(() => Directory.Delete(data, true));
            if (runningFromTarget)
                return true;
            if (Directory.GetFileSystemEntries(target).Length == 0)
                Directory.Delete(target);
            return false;
        }

        // removes the install folder (and the running exe in it) a moment after we exit
        public static void DeleteFolderLater(string target)
        {
            try
            {
                Process.Start(new ProcessStartInfo("cmd.exe",
                    "/c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"" + target.TrimEnd('\\') + "\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WorkingDirectory = Path.GetTempPath()
                });
            }
            catch (Exception) { }
        }

        static void Shortcut(string link, string exe, string workDir)
        {
            Type t = Type.GetTypeFromProgID("WScript.Shell");
            dynamic shell = Activator.CreateInstance(t);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(link));
                dynamic lnk = shell.CreateShortcut(link);
                lnk.TargetPath = exe;
                lnk.WorkingDirectory = workDir;
                lnk.IconLocation = exe + ",0";
                lnk.Description = "Website and code safety check-ups";
                lnk.Save();
                Marshal.FinalReleaseComObject(lnk);
            }
            finally
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags,
                                                uint timeout, out UIntPtr result);

        // adds or removes target in the user's PATH (HKCU\Environment), keeping %VARS% unexpanded
        public static void UserPath(string target, bool add)
        {
            using (RegistryKey k = Registry.CurrentUser.CreateSubKey("Environment"))
            {
                string cur = k.GetValue("Path", "", RegistryValueOptions.DoNotExpandEnvironmentNames) as string ?? "";
                var parts = cur.Split(';').Where(p => p.Trim().Length > 0).ToList();
                Func<string, bool> mine = p => string.Equals(p.Trim().TrimEnd('\\'), target.TrimEnd('\\'),
                                                             StringComparison.OrdinalIgnoreCase);
                bool has = parts.Any(mine);
                if (add == has)
                    return;
                if (add)
                    parts.Add(target);
                else
                    parts.RemoveAll(p => mine(p));
                k.SetValue("Path", string.Join(";", parts), RegistryValueKind.ExpandString);
            }
            UIntPtr res;
            SendMessageTimeout((IntPtr)0xffff, 0x001A, UIntPtr.Zero, "Environment", 0x0002, 3000, out res);
        }

        static void WriteUninstallEntry(string target)
        {
            string exe = Path.Combine(target, Program.ExeName);
            long kb = new DirectoryInfo(target).GetFiles("*", SearchOption.AllDirectories).Sum(f => f.Length) / 1024;
            using (RegistryKey k = Registry.CurrentUser.CreateSubKey(UninstallKey))
            {
                k.SetValue("DisplayName", Program.AppName);
                k.SetValue("DisplayVersion", Program.Version);
                k.SetValue("Publisher", Program.AppName);
                k.SetValue("DisplayIcon", exe + ",0");
                k.SetValue("InstallLocation", target);
                k.SetValue("UninstallString", "\"" + exe + "\" --uninstall");
                k.SetValue("QuietUninstallString", "\"" + exe + "\" --uninstall --quiet");
                k.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
                k.SetValue("EstimatedSize", (int)kb, RegistryValueKind.DWord);
                k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }
        }

        // --install/--uninstall --quiet [--target dir] [--no-start-menu --no-desktop --no-path
        // --no-registry]: no window; exit code 0 = done, 1 = failed (message in %TEMP%).
        public static int Quiet(bool install, string target, string[] args)
        {
            var o = new Options
            {
                StartMenu = !args.Contains("--no-start-menu"),
                Desktop = !args.Contains("--no-desktop"),
                AddPath = !args.Contains("--no-path"),
                Registry = !args.Contains("--no-registry")
            };
            try
            {
                if (install)
                    Install(AppDomain.CurrentDomain.BaseDirectory, target, o);
                else if (Uninstall(target, o))
                    DeleteFolderLater(target);
                return 0;
            }
            catch (Exception ex)
            {
                try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "ExposureScanner-setup.log"), ex.ToString()); }
                catch (Exception) { }
                return 1;
            }
        }
    }

    class SetupController
    {
        public readonly Window Window;
        readonly Window w;
        readonly bool uninstall;
        readonly string target;
        bool deleteLater;

        public SetupController(bool uninstall, string target)
        {
            this.uninstall = uninstall;
            this.target = target;
            w = Window = (Window)Ui.Load("SetupWindow.xaml");
            var closeX = Ui.Find<Button>(w, "CloseX");
            closeX.Click += delegate { w.Close(); };
            Ui.Find<Button>(w, "CancelButton").Click += delegate { w.Close(); };
            Ui.Find<Button>(w, "DoneClose").Click += delegate { w.Close(); };
            Ui.Find<TextBlock>(w, "LocationText").Text = target;
            w.Closed += delegate { if (deleteLater) Installer.DeleteFolderLater(target); };

            bool update = !uninstall && Installer.IsInstalled(target);
            var go = Ui.Find<Button>(w, "GoButton");
            if (uninstall)
            {
                w.Title = "Uninstall Exposure Scanner";
                Ui.Find<TextBlock>(w, "HeadTitle").Text = "Uninstall Exposure Scanner";
                Ui.Find<TextBlock>(w, "HeadSub").Text = "Version " + Program.Version;
                Ui.Find<TextBlock>(w, "IntroText").Text =
                    "Removes the app, its shortcuts and the scanner command. Your saved reports stay in your Documents folder.";
                Ui.Find<TextBlock>(w, "LocationLabel").Text = "Installed in";
                Ui.Find<FrameworkElement>(w, "OptionsPanel").Visibility = Visibility.Collapsed;
                go.Content = "Uninstall";
                go.Style = (Style)Application.Current.Resources["DangerButton"];
            }
            else
            {
                Ui.Find<TextBlock>(w, "HeadTitle").Text = update ? "Update Exposure Scanner" : "Install Exposure Scanner";
                Ui.Find<TextBlock>(w, "HeadSub").Text = "Version " + Program.Version + "  \u00B7  for your Windows account";
                go.Content = update ? "Update" : "Install";
            }
            go.Click += delegate { Go(); };
            Ui.Find<Button>(w, "LaunchButton").Click += delegate
            {
                Ui.Open(Path.Combine(target, Program.ExeName));
                w.Close();
            };
        }

        // --ui-snapshots: the setup window's three steps, without installing anything
        internal async Task SnapshotAll(string dir, string prefix)
        {
            FrameworkElement root = (FrameworkElement)w.Content;
            await Task.Delay(350);
            Snapshots.Save(root, Path.Combine(dir, prefix + "-a-options.png"));
            Ui.Find<FrameworkElement>(w, "StepOptions").Visibility = Visibility.Collapsed;
            Ui.Find<FrameworkElement>(w, "StepWork").Visibility = Visibility.Visible;
            Ui.Find<TextBlock>(w, "WorkTitle").Text = uninstall ? "Removing..." : "Installing...";
            await Task.Delay(350);
            Snapshots.Save(root, Path.Combine(dir, prefix + "-b-working.png"));
            Ui.Find<FrameworkElement>(w, "StepWork").Visibility = Visibility.Collapsed;
            Ui.Find<FrameworkElement>(w, "StepDone").Visibility = Visibility.Visible;
            Ui.Find<TextBlock>(w, "DoneTitle").Text = uninstall ? "Uninstalled" : "Ready to go";
            Ui.Find<TextBlock>(w, "DoneText").Text = uninstall
                ? "Exposure Scanner has been removed. Your reports are still in Documents\\Exposure Scanner."
                : "Find Exposure Scanner in the Start menu and on your desktop. To use the scanner command, open a new Command Prompt or PowerShell window.";
            if (uninstall)
                Ui.Find<FrameworkElement>(w, "LaunchButton").Visibility = Visibility.Collapsed;
            await Task.Delay(350);
            Snapshots.Save(root, Path.Combine(dir, prefix + "-c-done.png"));
        }

        async void Go()
        {
            var opt = new Installer.Options
            {
                Desktop = !uninstall ? Ui.Find<CheckBox>(w, "OptDesktop").IsChecked == true : true,
                AddPath = !uninstall ? Ui.Find<CheckBox>(w, "OptPath").IsChecked == true : true
            };
            Ui.Find<FrameworkElement>(w, "StepOptions").Visibility = Visibility.Collapsed;
            Ui.Find<FrameworkElement>(w, "StepWork").Visibility = Visibility.Visible;
            Ui.Find<TextBlock>(w, "WorkTitle").Text = uninstall ? "Removing..." : "Installing...";
            Ui.Find<TextBlock>(w, "WorkStep").Text = uninstall ? "Removing files and shortcuts" : "Copying files and adding shortcuts";
            string source = AppDomain.CurrentDomain.BaseDirectory;
            Exception error = null;
            DateTime started = DateTime.Now;
            await Task.Run(() =>
            {
                try
                {
                    if (uninstall)
                        deleteLater = Installer.Uninstall(target, opt);
                    else
                        Installer.Install(source, target, opt);
                }
                catch (Exception ex) { error = ex; }
            });
            TimeSpan shown = DateTime.Now - started;
            if (shown < TimeSpan.FromMilliseconds(900))
                await Task.Delay(TimeSpan.FromMilliseconds(900) - shown);
            Ui.Find<FrameworkElement>(w, "StepWork").Visibility = Visibility.Collapsed;

            if (error != null)
            {
                var err = Ui.Find<TextBlock>(w, "ErrorText");
                err.Text = (error is IOException || error is UnauthorizedAccessException)
                    ? "A file is in use. Close Exposure Scanner (and any terminal running scanner) and try again.\n" + error.Message
                    : error.Message;
                err.Visibility = Visibility.Visible;
                Ui.Find<FrameworkElement>(w, "StepOptions").Visibility = Visibility.Visible;
                return;
            }
            Ui.Find<FrameworkElement>(w, "StepDone").Visibility = Visibility.Visible;
            Ui.Find<Button>(w, "CloseX").Visibility = Visibility.Visible;
            if (uninstall)
            {
                Ui.Find<TextBlock>(w, "DoneTitle").Text = "Uninstalled";
                Ui.Find<TextBlock>(w, "DoneText").Text = "Exposure Scanner has been removed. Your reports are still in Documents\\Exposure Scanner.";
                Ui.Find<FrameworkElement>(w, "LaunchButton").Visibility = Visibility.Collapsed;
            }
            else
            {
                Ui.Find<TextBlock>(w, "DoneTitle").Text = "Ready to go";
                Ui.Find<TextBlock>(w, "DoneText").Text =
                    "Find Exposure Scanner in the Start menu" + (opt.Desktop ? " and on your desktop" : "") + "." +
                    (opt.AddPath ? " To use the scanner command, open a new Command Prompt or PowerShell window." : "");
            }
        }
    }
}
