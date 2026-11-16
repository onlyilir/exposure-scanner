// Monthly monitoring: clients on a monthly plan, their websites and check-up history. Check-ups
// run only when the user presses Run (never in the background), at most once a month per client
// as the permission form allows, and each report compares itself with the month before
// (scanner.exe --monthly --since). Data: %APPDATA%\Exposure Scanner\clients.json and
// monitoring\<client id>\*.json (each check-up's JSON); reports go to the normal Reports folder.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace ExposureScanner
{
    public class MonClient
    {
        public string Id = "", Name = "", By = "";
        public string Signed = "", Start = ""; // yyyy-MM-dd
        public List<string> Sites = new List<string>();
        public bool Paused;
        public List<MonRun> Runs = new List<MonRun>();
    }

    public class MonRun
    {
        public string Date = "";           // yyyy-MM-dd HH:mm, local time
        public string Report = "", Json = "";
        public int Important, Recommended, Tips, Passed;
        public int Fixed, New, Urgent;     // Urgent: new important/recommended problems, expiring certificates
        public bool Ready, Compared;
    }

    static class MonStore
    {
        static readonly string Dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Exposure Scanner");
        public static readonly string FilePath = Path.Combine(Dir, "clients.json");
        public static readonly string RunsDir = Path.Combine(Dir, "monitoring");
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        public static List<MonClient> Load()
        {
            try
            {
                if (File.Exists(FilePath))
                    return new JavaScriptSerializer().Deserialize<List<MonClient>>(File.ReadAllText(FilePath, Encoding.UTF8))
                           ?? new List<MonClient>();
            }
            catch (Exception)
            {
                // keep an unreadable file for support instead of overwriting it
                try { File.Copy(FilePath, FilePath + ".unreadable", true); }
                catch (Exception) { }
            }
            return new List<MonClient>();
        }

        public static void Save(List<MonClient> clients)
        {
            if (Snapshots.Active)
                return;
            Directory.CreateDirectory(Dir);
            string tmp = FilePath + ".new";
            File.WriteAllText(tmp, new JavaScriptSerializer().Serialize(clients), new UTF8Encoding(false));
            if (File.Exists(FilePath))
                File.Replace(tmp, FilePath, null);
            else
                File.Move(tmp, FilePath);
        }

        public static DateTime? ParseDay(string s)
        {
            DateTime d;
            return DateTime.TryParseExact(s ?? "", "yyyy-MM-dd", Inv, DateTimeStyles.None, out d) ? (DateTime?)d : null;
        }

        static DateTime? RunDay(MonRun r)
        {
            DateTime d;
            return DateTime.TryParseExact(r.Date ?? "", "yyyy-MM-dd HH:mm", Inv, DateTimeStyles.None, out d)
                ? (DateTime?)d.Date : null;
        }

        // the permission covers one check-up a month: a month after the last one, or the first date
        public static DateTime NextDue(MonClient c)
        {
            MonRun last = c.Runs.LastOrDefault();
            DateTime? d = last != null ? RunDay(last) : null;
            if (d != null)
                return d.Value.AddMonths(1);
            return ParseDay(c.Start) ?? DateTime.Today;
        }

        public static bool IsDue(MonClient c)
        {
            return !c.Paused && DateTime.Today >= NextDue(c);
        }

        // a check-up this month that was not ready to send (for example HTTPS scanning was on) may
        // be run again; it replaces that one instead of counting as another month
        public static bool CanRedo(MonClient c)
        {
            MonRun last = c.Runs.LastOrDefault();
            return !c.Paused && last != null && !last.Ready;
        }
    }

    partial class MainController
    {
        List<MonClient> clients = new List<MonClient>();
        bool monRunning;
        MonClient editing; // null = adding

        void InitMonitoring()
        {
            clients = Snapshots.Active ? SnapshotClients() : MonStore.Load();
            Ui.Find<Button>(w, "MonAdd").Click += delegate { ShowMonForm(null, null, null); };
            Ui.Find<Button>(w, "MonCancel").Click += delegate { Ui.Find<FrameworkElement>(w, "MonForm").Visibility = Visibility.Collapsed; };
            Ui.Find<Button>(w, "MonSave").Click += delegate { SaveMonForm(); };
            Ui.Find<Button>(w, "MonRunDue").Click += async delegate
            {
                await RunMonitors(clients.Where(MonStore.IsDue).ToList());
            };
            Ui.Find<Button>(w, "MonitorButton").Click += delegate
            {
                navMonitor.IsChecked = true;
                ShowMonForm(null, lastResultClient, lastResultSite);
            };
            Ui.Find<TextBlock>(w, "MonTip").Text =
                "Before you run: pause your antivirus's HTTPS scanning (only that feature), or the reports will say Not ready to send.";
            RefreshMonitor();
        }

        void ShowMonForm(MonClient c, string name, string site)
        {
            editing = c;
            Ui.Find<TextBlock>(w, "MonFormTitle").Text = c == null ? "Add a client" : "Edit " + c.Name;
            Ui.Find<TextBox>(w, "MonName").Text = c != null ? c.Name : name ?? "";
            Ui.Find<TextBox>(w, "MonSites").Text = c != null ? string.Join("\r\n", c.Sites) : site ?? "";
            Ui.Find<TextBox>(w, "MonBy").Text = c != null ? c.By : byBox.Text;
            Ui.Find<DatePicker>(w, "MonSigned").SelectedDate = c != null ? MonStore.ParseDay(c.Signed) : null;
            Ui.Find<DatePicker>(w, "MonStart").SelectedDate = c != null ? MonStore.ParseDay(c.Start) : DateTime.Today;
            Ui.Find<CheckBox>(w, "MonAgreed").IsChecked = c != null;
            Ui.Find<FrameworkElement>(w, "MonFormError").Visibility = Visibility.Collapsed;
            var form = Ui.Find<FrameworkElement>(w, "MonForm");
            form.Visibility = Visibility.Visible;
            w.Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
            {
                form.BringIntoView();
                Ui.Find<TextBox>(w, "MonName").Focus();
            }));
        }

        void SaveMonForm()
        {
            var err = Ui.Find<TextBlock>(w, "MonFormError");
            string name = Clean(Ui.Find<TextBox>(w, "MonName").Text);
            var lines = Ui.Find<TextBox>(w, "MonSites").Text.Split(new[] { '\r', '\n', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            var sites = lines.Select(NormalizeHost).ToList();
            DateTime? signed = Ui.Find<DatePicker>(w, "MonSigned").SelectedDate;
            DateTime? start = Ui.Find<DatePicker>(w, "MonStart").SelectedDate;
            string problem =
                name.Length == 0 ? "Enter the business name." :
                lines.Length == 0 ? "Enter at least one website." :
                sites.Any(s => s == null) ? "\"" + lines[sites.FindIndex(s => s == null)] + "\" doesn't look like a website address." :
                sites.Count > 10 ? "Up to 10 websites per client." :
                signed == null ? "Enter the date the permission form was signed." :
                signed.Value.Date > DateTime.Today ? "The permission date can't be in the future." :
                start == null ? "Choose the date of the first check-up." :
                Ui.Find<CheckBox>(w, "MonAgreed").IsChecked != true ? "Tick the box to confirm the client chose monthly re-checks." :
                null;
            if (problem != null)
            {
                err.Text = problem;
                err.Visibility = Visibility.Visible;
                return;
            }
            MonClient c = editing ?? new MonClient { Id = Guid.NewGuid().ToString("N").Substring(0, 12) };
            c.Name = name;
            c.Sites = sites.Distinct().ToList();
            c.By = Clean(Ui.Find<TextBox>(w, "MonBy").Text);
            c.Signed = signed.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            c.Start = start.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            if (editing == null)
                clients.Add(c);
            if (!SaveClients())
                return;
            Ui.Find<FrameworkElement>(w, "MonForm").Visibility = Visibility.Collapsed;
            RefreshMonitor();
        }

        bool SaveClients()
        {
            try
            {
                MonStore.Save(clients);
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(w, "The client list could not be saved.\n" + ex.Message, Program.AppName,
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
        }

        // ------------------------------------------------------------------ the list

        void RefreshMonitor()
        {
            int due = clients.Count(MonStore.IsDue);
            Ui.Find<FrameworkElement>(w, "MonBadge").Visibility = due > 0 ? Visibility.Visible : Visibility.Collapsed;
            Ui.Find<TextBlock>(w, "MonBadgeText").Text = due.ToString();
            var status = Ui.Find<TextBlock>(w, "MonStatus");
            var sub = Ui.Find<TextBlock>(w, "MonStatusSub");
            var runDue = Ui.Find<Button>(w, "MonRunDue");
            if (!monRunning)
            {
                status.Text = clients.Count == 0 ? "No clients on monthly monitoring yet."
                            : due == 0 ? "All check-ups are up to date."
                            : due + (due == 1 ? " check-up is due." : " check-ups are due.");
                DateTime? next = clients.Where(c => !c.Paused && !MonStore.IsDue(c)).Select(c => (DateTime?)MonStore.NextDue(c)).Min();
                sub.Text = clients.Count == 0
                    ? "Add a client once they have signed the permission form and chosen monthly re-checks."
                    : next != null ? "Next one after that: " + next.Value.ToString("d MMMM yyyy", En) + "." : "";
            }
            runDue.Content = due > 0 ? "Run " + due + " due check-up" + (due == 1 ? "" : "s") : "Run due check-ups";
            runDue.IsEnabled = due > 0 && !monRunning;
            Ui.Find<Button>(w, "MonAdd").IsEnabled = !monRunning;

            var list = Ui.Find<StackPanel>(w, "MonList");
            list.Children.Clear();
            foreach (MonClient c in clients.OrderBy(c => c.Paused).ThenBy(c => MonStore.NextDue(c)))
                list.Children.Add(ClientCard(c));
        }

        static Border Pill(string text, string bg, string fg)
        {
            return new Border
            {
                Background = Ui.Res(bg), CornerRadius = new CornerRadius(999), Padding = new Thickness(10, 3, 10, 3),
                VerticalAlignment = VerticalAlignment.Top,
                Child = new TextBlock { Text = text, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Ui.Res(fg) }
            };
        }

        Button CardButton(string text, bool primary, Action click, bool enabled = true, string tip = null)
        {
            var b = new Button
            {
                Content = text, Margin = new Thickness(0, 0, 8, 8), IsEnabled = enabled && !monRunning,
                Style = (Style)Application.Current.Resources[primary ? "PrimaryButton" : "SecondaryButton"]
            };
            if (tip != null)
            {
                b.ToolTip = tip;
                ToolTipService.SetShowOnDisabled(b, true);
            }
            b.Click += delegate { click(); };
            return b;
        }

        UIElement ClientCard(MonClient c)
        {
            bool due = MonStore.IsDue(c), redo = !due && MonStore.CanRedo(c);
            MonRun last = c.Runs.LastOrDefault();
            DateTime next = MonStore.NextDue(c);
            var card = new Border { Style = (Style)Application.Current.Resources["CardBox"], Margin = new Thickness(0, 0, 0, 14) };
            var root = new StackPanel();
            var head = new Grid();
            head.ColumnDefinitions.Add(new ColumnDefinition());
            head.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var names = new StackPanel();
            names.Children.Add(new TextBlock { Text = c.Name, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            names.Children.Add(new TextBlock
            {
                Text = string.Join("  ·  ", c.Sites), FontSize = 13, Foreground = Ui.Res("Muted"),
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0)
            });
            head.Children.Add(names);
            Border pill = c.Paused ? Pill("Paused", "Hover", "Muted")
                        : due ? Pill("Due now", "RecBg", "RecFg")
                        : last != null && last.Urgent > 0 ? Pill("Needs attention", "ImpBg", "ImpFg")
                        : Pill("Next: " + next.ToString("d MMM yyyy", En), "OkBg", "OkFg");
            Grid.SetColumn(pill, 1);
            head.Children.Add(pill);
            root.Children.Add(head);

            string lastText;
            if (last == null)
                lastText = "No check-up yet. The first one is due " + (due ? "now" : "on " + next.ToString("d MMMM yyyy", En)) + ".";
            else
            {
                DateTime when;
                DateTime.TryParseExact(last.Date, "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out when);
                lastText = "Last check-up " + when.ToString("d MMMM yyyy", En) + ": " + last.Important + " important, " +
                           last.Recommended + " recommended, " + last.Tips + (last.Tips == 1 ? " tip" : " tips") +
                           (last.Compared ? ".  Since the month before: " + last.Fixed + " fixed, " + last.New + " new." : ".") +
                           (last.Ready ? "" : "  Not ready to send: run it again with HTTPS scanning paused.");
            }
            root.Children.Add(new TextBlock
            {
                Text = lastText, FontSize = 13.5, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 12, 0, 0),
                Foreground = last != null && !last.Ready ? Ui.Res("ImpFg") : Ui.Res("Ink2")
            });
            root.Children.Add(new TextBlock
            {
                Text = "Permission signed " + (MonStore.ParseDay(c.Signed) ?? DateTime.Today).ToString("d MMM yyyy", En) +
                       "  ·  " + c.Runs.Count + (c.Runs.Count == 1 ? " check-up" : " check-ups") + " so far",
                FontSize = 12, Foreground = Ui.Res("Muted"), Margin = new Thickness(0, 6, 0, 0)
            });

            var buttons = new WrapPanel { Margin = new Thickness(0, 14, 0, -8) };
            string wait = "The next check-up is due on " + next.ToString("d MMMM yyyy", En) +
                          ". The permission form covers one a month.";
            buttons.Children.Add(CardButton(redo ? "Run again" : "Run now", due || redo,
                async () => await RunMonitors(new List<MonClient> { c }), due || redo, due || redo ? null : wait));
            if (last != null && File.Exists(last.Report))
                buttons.Children.Add(CardButton("Open last report", false, () => Ui.Open(last.Report)));
            buttons.Children.Add(CardButton(c.Paused ? "Resume" : "Pause", false, () =>
            {
                c.Paused = !c.Paused;
                SaveClients();
                RefreshMonitor();
            }));
            buttons.Children.Add(CardButton("Edit", false, () => ShowMonForm(c, null, null)));
            buttons.Children.Add(CardButton("Remove", false, () =>
            {
                if (MessageBox.Show(w, "Remove " + c.Name + " from monthly monitoring?\nTheir reports stay in " + ReportsDir + ".",
                                    Program.AppName, MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                    return;
                clients.Remove(c);
                SaveClients();
                RefreshMonitor();
            }));
            root.Children.Add(buttons);
            card.Child = root;
            return card;
        }

        // ------------------------------------------------------------------ running

        async Task RunMonitors(List<MonClient> run)
        {
            if (monRunning || run.Count == 0)
                return;
            monRunning = true;
            RefreshMonitor();
            var status = Ui.Find<TextBlock>(w, "MonStatus");
            var sub = Ui.Find<TextBlock>(w, "MonStatusSub");
            var alerts = new List<string>();
            int done = 0, notReady = 0, failed = 0;
            for (int i = 0; i < run.Count; i++)
            {
                MonClient c = run[i];
                status.Text = "Checking " + c.Name + (run.Count > 1 ? " (" + (i + 1) + " of " + run.Count + ")" : "") + "...";
                sub.Text = string.Join(", ", c.Sites);
                string error = null;
                MonRun r = await RunOne(c, e => error = e);
                if (r == null)
                {
                    failed++;
                    alerts.Add(c.Name + ": the check-up did not finish" + (error != null ? " (" + error + ")" : "") + ".");
                    continue;
                }
                done++;
                if (!r.Ready)
                    notReady++;
                if (r.Urgent > 0)
                    alerts.Add(c.Name + ": " + r.Urgent + (r.Urgent == 1 ? " new problem needs" : " new problems need") + " attention.");
            }
            monRunning = false;
            RefreshMonitor();
            status.Text = done + (done == 1 ? " check-up" : " check-ups") + " done" +
                          (failed > 0 ? ", " + failed + " did not finish" : "") + ".";
            sub.Text = alerts.Count > 0 ? string.Join("  ", alerts)
                     : notReady > 0 ? notReady + " not ready to send: pause HTTPS scanning and press Run again."
                     : "No new problems. Open each report to read it through, then send it to the client.";
            if (!Snapshots.Active && (alerts.Count > 0 || notReady > 0))
                Notify("Exposure Scanner: monthly check-ups", alerts.Count > 0 ? string.Join("\n", alerts.Take(3))
                                                              : notReady + " report(s) not ready to send.");
        }

        async Task<MonRun> RunOne(MonClient c, Action<string> fail)
        {
            string scanner = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "scanner.exe");
            if (!File.Exists(scanner))
            {
                fail("scanner.exe is missing next to the app");
                return null;
            }
            MonRun last = c.Runs.LastOrDefault(x => File.Exists(x.Json));
            bool redo = !MonStore.IsDue(c) && MonStore.CanRedo(c);
            MonRun previous = redo ? c.Runs.Take(c.Runs.Count - 1).LastOrDefault(x => File.Exists(x.Json)) : last;
            string html = NextReportPath(c.Name + " monthly");
            string args = "site " + string.Join(" ", c.Sites.Select(Q)) + " --i-own-this --json --monthly --html " + Q(html) +
                          " --client " + Q(c.Name) + (c.By.Length > 0 ? " --by " + Q(c.By) : "");
            string since = null;
            if (previous != null)
            {
                since = Path.Combine(Path.GetTempPath(), "ExposureScanner-since-" + c.Id + ".txt");
                File.WriteAllLines(since, IssueLines(previous.Json), new UTF8Encoding(false));
                DateTime when;
                DateTime.TryParseExact(previous.Date, "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out when);
                args += " --since " + Q(since) + " --since-date " + Q(when.ToString("d MMMM yyyy", En));
            }
            ExecResult r = await Task.Run(() => Exec(scanner, args, 300));
            if (since != null)
                try { File.Delete(since); }
                catch (Exception) { }
            if (!File.Exists(html))
            {
                fail(r.Stderr.Trim().Length > 0 ? r.Stderr.Trim() : "scanner exit code " + r.Exit);
                return null;
            }

            var run = new MonRun { Date = DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture), Report = html };
            try
            {
                string dir = Path.Combine(MonStore.RunsDir, c.Id);
                Directory.CreateDirectory(dir);
                run.Json = Path.Combine(dir, DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".json");
                File.WriteAllText(run.Json, r.Stdout, new UTF8Encoding(false));
            }
            catch (Exception) { run.Json = ""; }
            ReadSummary(r.Stdout, run);
            if (redo)
                c.Runs.RemoveAt(c.Runs.Count - 1); // the not-ready one this replaces
            c.Runs.Add(run);
            SaveClients();
            return run;
        }

        static Dictionary<string, object> SummaryOf(string json)
        {
            try
            {
                var root = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(json) as Dictionary<string, object>;
                object s;
                return root != null && root.TryGetValue("summary", out s) ? s as Dictionary<string, object> : null;
            }
            catch (Exception) { return null; }
        }

        static object Get(Dictionary<string, object> d, string key)
        {
            object v;
            return d != null && d.TryGetValue(key, out v) ? v : null;
        }

        static void ReadSummary(string json, MonRun run)
        {
            var s = SummaryOf(json);
            run.Important = ToInt(Get(s, "important"));
            run.Recommended = ToInt(Get(s, "recommended"));
            run.Tips = ToInt(Get(s, "tip"));
            run.Passed = ToInt(Get(s, "passed"));
            run.Ready = Get(s, "ready_to_send") is bool && (bool)Get(s, "ready_to_send");
            var since = Get(s, "since") as Dictionary<string, object>;
            run.Compared = since != null;
            run.Fixed = ToInt(Get(since, "fixed"));
            run.New = ToInt(Get(since, "new"));
            foreach (var it in (Get(s, "issues") as object[] ?? new object[0]).OfType<Dictionary<string, object>>())
            {
                string level = Get(it, "level") as string ?? "", title = Get(it, "title") as string ?? "";
                bool isNew = Get(it, "new") is bool && (bool)Get(it, "new");
                bool serious = level == "important" || level == "recommended";
                // a first check-up has nothing to compare: its important problems count as new
                if ((serious && (isNew || (!run.Compared && level == "important"))) || title.Contains("certificate expires"))
                    run.Urgent++;
            }
        }

        // the last check-up's problems for scanner.exe --since: level TAB site TAB title
        static IEnumerable<string> IssueLines(string jsonPath)
        {
            var s = SummaryOf(File.Exists(jsonPath) ? File.ReadAllText(jsonPath, Encoding.UTF8) : "");
            foreach (var it in (Get(s, "issues") as object[] ?? new object[0]).OfType<Dictionary<string, object>>())
                yield return string.Join("\t", new[] { "level", "site", "title" }.Select(k =>
                    ((Get(it, k) as string) ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ')));
        }

        // a normal Windows notification (balloon / toast), gone after a few seconds
        void Notify(string title, string text)
        {
            try
            {
                var icon = new System.Windows.Forms.NotifyIcon
                {
                    Icon = System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location),
                    Text = Program.AppName,
                    Visible = true
                };
                icon.BalloonTipClicked += delegate
                {
                    w.Activate();
                    navMonitor.IsChecked = true;
                };
                icon.ShowBalloonTip(10000, title, text, System.Windows.Forms.ToolTipIcon.Warning);
                var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
                t.Tick += delegate
                {
                    t.Stop();
                    icon.Visible = false;
                    icon.Dispose();
                };
                t.Start();
            }
            catch (Exception) { } // notifications are a convenience; the page shows the same
        }

        // --ui-snapshots: three example clients, nothing saved
        static List<MonClient> SnapshotClients()
        {
            Func<int, string> Day = d => DateTime.Today.AddDays(d).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            Func<int, string> At = d => DateTime.Today.AddDays(d).ToString("yyyy-MM-dd 10:30", CultureInfo.InvariantCulture);
            return new List<MonClient>
            {
                new MonClient { Id = "a", Name = "Rosa's Bakery", By = "Your Name", Signed = Day(-70), Start = Day(-62),
                    Sites = new List<string> { "rosas-bakery.example", "order.rosas-bakery.example" },
                    Runs = new List<MonRun> {
                        new MonRun { Date = At(-62), Important = 2, Recommended = 3, Tips = 2, Passed = 9, Ready = true },
                        new MonRun { Date = At(-31), Important = 1, Recommended = 2, Tips = 2, Passed = 11, Ready = true,
                                     Compared = true, Fixed = 2, New = 1, Urgent = 1 } } },
                new MonClient { Id = "b", Name = "Sam's Garage", By = "Your Name", Signed = Day(-40), Start = Day(-18),
                    Sites = new List<string> { "samsgarage.example" },
                    Runs = new List<MonRun> {
                        new MonRun { Date = At(-18), Important = 0, Recommended = 1, Tips = 1, Passed = 12, Ready = true } } },
                new MonClient { Id = "c", Name = "Lee Dental", By = "Your Name", Signed = Day(-90), Start = Day(-90), Paused = true,
                    Sites = new List<string> { "leedental.example" } },
            };
        }
    }
}
