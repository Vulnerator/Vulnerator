// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Vulnerator.Metrics;

namespace Vulnerator.Dashboards
{
    /// <summary>The Dashboards page: a tab per view. Data loads off the UI thread; Refresh reloads.</summary>
    public sealed class DashboardView : UserControl
    {
        public static readonly string[] TabNames = { "Severity", "Top hosts", "Compliance", "POA&M", "Trend", "Coverage", "STIGs", "IAVMs" };

        private static readonly string[] LevelNames = { "Very High", "High", "Moderate", "Low", "Very Low", "Unknown" };
        private readonly IDashboardSource source;
        private readonly DockPanel root = new DockPanel();
        private readonly TextBlock status = Charts.Text(string.Empty, 12, false, new Thickness(12, 0, 0, 0));
        private readonly Button refresh = new Button { Content = "Refresh", MinWidth = 90 };
        private readonly TabControl tabs = new TabControl();
        private bool loading;
        private bool loaded;

        // View options kept across refreshes.
        private bool severityByCat;
        private HostSourceFilter hostFilter = HostSourceFilter.All;
        private int hostCount = 10;

        public DashboardView(IDashboardSource source)
        {
            this.source = source ?? throw new ArgumentNullException(nameof(source));
            var toolbar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(8, 8, 8, 4) };
            status.VerticalAlignment = VerticalAlignment.Center;
            refresh.Click += (sender, e) => Refresh();
            toolbar.Children.Add(refresh);
            toolbar.Children.Add(status);
            DockPanel.SetDock(toolbar, Dock.Top);
            root.Children.Add(toolbar);
            tabs.Margin = new Thickness(8, 0, 8, 8);
            root.Children.Add(tabs);
            Content = root;
            Loaded += (sender, e) => { if (!loaded) Refresh(); };
        }

        /// <summary>The model on screen (null until loaded).</summary>
        public DashboardModel Model { get; private set; }

        /// <summary>Loads in the background and redraws.</summary>
        public void Refresh()
        {
            if (loading) return;
            loading = true;
            loaded = true;
            refresh.IsEnabled = false;
            status.Text = "Loading...";
            Task.Run(() => source.Load()).ContinueWith(task =>
            {
                loading = false;
                refresh.IsEnabled = true;
                if (task.IsFaulted)
                {
                    Exception error = task.Exception?.GetBaseException();
                    status.Text = "The dashboards could not be loaded: " + (error?.Message ?? "unknown error");
                    return;
                }
                Render(task.Result);
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        /// <summary>Draws a model (UI thread). Public for tests.</summary>
        public void Render(DashboardModel model)
        {
            Model = model ?? throw new ArgumentNullException(nameof(model));
            loaded = true;
            int selected = Math.Max(0, tabs.SelectedIndex);
            foreach (UIElement banner in root.Children.OfType<Border>().ToList()) root.Children.Remove(banner);
            if (!string.IsNullOrEmpty(model.Marking))
            {
                Border top = Charts.Banner(model.Marking), bottom = Charts.Banner(model.Marking);
                DockPanel.SetDock(top, Dock.Top);
                DockPanel.SetDock(bottom, Dock.Bottom);
                root.Children.Insert(0, top);
                root.Children.Insert(1, bottom);
            }
            status.Text = Charts.Number(model.FindingCount) + " findings, as of " + model.BuiltAt.ToString("yyyy-MM-dd HH:mm") + ".";

            tabs.Items.Clear();
            AddTab(TabNames[0], SeverityTab());
            AddTab(TabNames[1], TopHostsTab());
            AddTab(TabNames[2], ComplianceTab());
            AddTab(TabNames[3], PoamTab());
            AddTab(TabNames[4], TrendTab());
            AddTab(TabNames[5], CoverageTab());
            AddTab(TabNames[6], StigsTab());
            AddTab(TabNames[7], IavmsTab());
            tabs.SelectedIndex = Math.Min(selected, tabs.Items.Count - 1);
        }

        private void AddTab(string header, UIElement content)
        {
            tabs.Items.Add(new TabItem
            {
                Header = header,
                Content = new ScrollViewer { Content = content, Padding = new Thickness(12), VerticalScrollBarVisibility = ScrollBarVisibility.Auto }
            });
        }

        // 1. Open findings by severity level or CAT, per source.
        private UIElement SeverityTab()
        {
            var panel = new StackPanel();
            panel.Children.Add(Charts.Heading("Open findings by " + (severityByCat ? "CAT" : "severity level")));
            var byLevel = new RadioButton { Content = "Severity level", IsChecked = !severityByCat, Margin = new Thickness(0, 0, 16, 0) };
            var byCat = new RadioButton { Content = "CAT", IsChecked = severityByCat };
            byLevel.Checked += (s, e) => { severityByCat = false; Redraw(0); };
            byCat.Checked += (s, e) => { severityByCat = true; Redraw(0); };
            var choice = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            choice.Children.Add(byLevel);
            choice.Children.Add(byCat);
            panel.Children.Add(choice);

            string[] names = severityByCat ? Charts.CatNames : LevelNames.Take(5).ToArray();
            Brush[] brushes = severityByCat ? Charts.CatBrushes : Charts.LevelBrushes.Take(5).ToArray();
            panel.Children.Add(Charts.Legend(names, brushes));
            int max = Math.Max(1, Model.Severity.Max(c => severityByCat ? c.OpenByCat.Sum() : c.Open));
            panel.Children.Add(Charts.BarRows(Model.Severity.Select(c =>
            {
                int[] values = severityByCat ? c.OpenByCat : c.OpenByLevel.Take(5).ToArray();
                string detail = string.Join("  ", values.Select((v, i) => names[i] + " " + Charts.Number(v)));
                return Tuple.Create(c.Label == "All" ? "All sources" : c.Label, Charts.StackedBar(values, brushes, names, max), detail);
            }), 140));

            int unverified = Model.Severity[0].Unverified;
            if (unverified > 0)
            {
                panel.Children.Add(Charts.Text(Charts.Number(unverified) + " ACAS finding(s) are Unverified: the host's newest scan no longer reports them. " +
                                               "They are not counted above and are not counted as closed.", 12, false, new Thickness(0, 10, 0, 0)));
            }
            return panel;
        }

        // 2. Top hosts, worst first.
        private UIElement TopHostsTab()
        {
            var panel = new StackPanel();
            panel.Children.Add(Charts.Heading("Top hosts with open findings"));
            var options = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            var filter = new ComboBox { Width = 160, Margin = new Thickness(0, 0, 12, 0), ItemsSource = new[] { "ACAS and STIG", "ACAS (Nessus)", "STIG and SCAP" }, SelectedIndex = (int)hostFilter };
            var count = new ComboBox { Width = 80, ItemsSource = new[] { "Top 10", "Top 25", "Top 50" }, SelectedIndex = hostCount == 50 ? 2 : hostCount == 25 ? 1 : 0 };
            filter.SelectionChanged += (s, e) => { hostFilter = (HostSourceFilter)filter.SelectedIndex; Redraw(1); };
            count.SelectionChanged += (s, e) => { hostCount = count.SelectedIndex == 2 ? 50 : count.SelectedIndex == 1 ? 25 : 10; Redraw(1); };
            options.Children.Add(filter);
            options.Children.Add(count);
            panel.Children.Add(options);
            panel.Children.Add(Charts.Text("Ranked by Very High, then High, Moderate and Low counts. Informational (Very Low) findings are not ranked.", 12));

            Brush[] brushes = Charts.LevelBrushes.Take(4).ToArray();
            string[] names = LevelNames.Take(4).ToArray();
            panel.Children.Add(Charts.Legend(names, brushes));
            IList<HostRisk> hosts = Model.TopHosts(hostFilter, hostCount);
            if (hosts.Count == 0)
            {
                panel.Children.Add(Charts.Text("No hosts with open findings."));
                return panel;
            }
            int max = Math.Max(1, hosts.Max(h => h.OpenRated));
            panel.Children.Add(Charts.BarRows(hosts.Select(h =>
            {
                int[] values = h.OpenByLevel.Take(4).ToArray();
                string detail = string.Join("  ", values.Select((v, i) => names[i] + " " + Charts.Number(v))) +
                                (h.Unverified > 0 ? "  (Unverified " + Charts.Number(h.Unverified) + ")" : string.Empty);
                return Tuple.Create(h.HostName, Charts.StackedBar(values, brushes, names, max), detail);
            })));
            return panel;
        }

        // 3. Compliance by control family.
        private UIElement ComplianceTab()
        {
            var panel = new StackPanel();
            panel.Children.Add(Charts.Heading("Compliance by NIST SP 800-53 Rev 5 control family"));
            panel.Children.Add(Charts.Text("Compliant = Not a Finding / (Not a Finding + Open), from STIG and SCAP results. Not Applicable is left out; " +
                                           "Not Reviewed is shown separately. ACAS results have no CCIs and are not included.", 12));
            panel.Children.Add(Charts.BarRows(Model.Compliance.Select(f =>
            {
                double? percent = f.CompliantPercent;
                FrameworkElement bar = Charts.StackedBar(
                    percent.HasValue ? new[] { (int)Math.Round(percent.Value * 10), 1000 - (int)Math.Round(percent.Value * 10) } : new[] { 0, 0 },
                    new[] { Charts.GoodBrush, Charts.LevelBrushes[1] }, new[] { "Compliant", "Open" }, 1000);
                string detail = percent.HasValue
                    ? Math.Round(percent.Value, 1).ToString("0.#") + "% (" + Charts.Number(f.NotAFinding) + " of " + Charts.Number(f.NotAFinding + f.Open) + ")"
                    : "Not assessed";
                if (f.NotReviewed > 0) detail += "  Not reviewed " + Charts.Number(f.NotReviewed);
                return Tuple.Create(f.Family + "  " + f.Name, bar, detail);
            }), 300));
            return panel;
        }

        // 4. POA&M aging.
        private UIElement PoamTab()
        {
            PoamAgingReport poam = Model.Poam;
            var panel = new StackPanel();
            panel.Children.Add(Charts.Heading("POA&M aging"));
            panel.Children.Add(Charts.Text("Items as the eMASS POA&M export builds them. Ongoing " + Charts.Number(poam.Ongoing) + ", Risk Accepted " +
                                           Charts.Number(poam.RiskAccepted) + ", Completed " + Charts.Number(poam.Completed) +
                                           ". Age counts from the date identified.", 12));
            panel.Children.Add(Charts.Matrix(PoamAgingReport.BucketNames, LevelNames.Take(5).ToList(), (r, c) => poam.Buckets[r, c], Charts.LevelBrushes));
            panel.Children.Add(Charts.Heading("Overdue (" + Charts.Number(poam.Overdue.Count) + ")"));
            panel.Children.Add(PoamTable(poam.Overdue));
            panel.Children.Add(Charts.Heading("Due within 30 days (" + Charts.Number(poam.DueWithin30Days.Count) + ")"));
            panel.Children.Add(PoamTable(poam.DueWithin30Days));
            return panel;
        }

        private static UIElement PoamTable(IList<MetricPoamItem> items)
        {
            if (items.Count == 0) return Charts.Text("None.");
            return Charts.Table(new[] { "Scheduled completion", "Severity", "Identified", "Security checks", "Devices", "Summary" },
                items.Select(i => new[]
                {
                    Charts.Date(i.ScheduledCompletion), Definitions.LevelName(i.Level), Charts.Date(i.DateIdentified),
                    string.Join(", ", i.SecurityChecks), Charts.Number(i.Devices.Count), i.Summary
                }));
        }

        // 5. Open vs. closed trend.
        private UIElement TrendTab()
        {
            var panel = new StackPanel();
            panel.Children.Add(Charts.Heading("Open findings over time"));
            panel.Children.Add(Charts.Text("One snapshot per day, taken after imports and when this page loads. History starts when the add-on is first used.", 12));
            IList<TrendSnapshot> trend = Model.Trend;
            if (trend.Count == 0)
            {
                panel.Children.Add(Charts.Text("No snapshots yet."));
                return panel;
            }
            panel.Children.Add(Charts.Legend(LevelNames.Take(5).Concat(new[] { "Unverified" }).ToList(), Charts.LevelBrushes.Take(5).Concat(new[] { Charts.UnverifiedBrush }).ToList()));
            panel.Children.Add(Charts.Columns(
                trend.Select(t => t.TakenOn.ToString("MM-dd")).ToList(),
                trend.Select(t => t.OpenByLevel.Take(5).Concat(new[] { t.Unverified }).ToArray()).ToList(),
                Charts.LevelBrushes.Take(5).Concat(new[] { Charts.UnverifiedBrush }).ToList(),
                LevelNames.Take(5).Concat(new[] { "Unverified" }).ToList()));
            panel.Children.Add(Charts.Heading("Snapshots"));
            panel.Children.Add(Charts.Table(new[] { "Date", "Open", "Very High", "High", "Unverified", "Not a Finding", "Newly open", "Newly closed" },
                trend.Reverse().Select(t => new[]
                {
                    t.TakenOn.ToString("yyyy-MM-dd HH:mm"), Charts.Number(t.Open), Charts.Number(t.OpenByLevel[0]), Charts.Number(t.OpenByLevel[1]),
                    Charts.Number(t.Unverified), Charts.Number(t.NotAFinding), Charts.Number(t.NewlyOpen), Charts.Number(t.NewlyClosed)
                })));
            return panel;
        }

        // 6. Assets with no scan or checklist, per device (hardware records matched by short name or linked by hand).
        private UIElement CoverageTab()
        {
            IList<AssetCoverage> rows = Model.Coverage;
            var panel = new StackPanel();
            panel.Children.Add(Charts.Heading("Assets with no scan or checklist"));
            if (rows.Count == 0)
            {
                panel.Children.Add(Charts.Text("The Hardware list is empty (Configuration Management > Hardware)."));
                return panel;
            }
            panel.Children.Add(Charts.Text(Charts.Number(rows.Count) + " devices: " +
                                           Charts.Number(rows.Count(r => !r.HasAcas && !r.HasStig)) + " with neither, " +
                                           Charts.Number(rows.Count(r => !r.HasAcas)) + " with no ACAS scan, " +
                                           Charts.Number(rows.Count(r => r.AcasStale)) + " with an ACAS scan older than " + Definitions.StaleScanDays + " days, " +
                                           Charts.Number(rows.Count(r => !r.HasStig)) + " with no STIG checklist.", 12));
            int matched = rows.Count(r => r.IsMatched);
            if (matched > 0)
                panel.Children.Add(Charts.Text(Charts.Number(matched) + " devices combine more than one hardware record (for example an ACAS host W01.Contoso.com and " +
                                               "a checklist host W01.Contoso). See Device matching below.", 12));
            panel.Children.Add(Charts.Table(new[] { "Device", "Operating system", "Gap", "Last ACAS scan", "STIGs", "Last checklist", "Hardware records (source)", "Matched by" },
                rows.Select(r => new[]
                {
                    r.HostName, r.OperatingSystem, r.Gap, Charts.Date(r.LastAcasScan), Charts.Number(r.StigCount), Charts.Date(r.LastChecklist), r.Seen, r.MatchedBy
                }), 600));
            panel.Children.Add(DeviceMatchingPanel(rows));
            return panel;
        }

        /// <summary>Settings for matching hardware records into devices: by short name, by hand, or kept separate.</summary>
        private UIElement DeviceMatchingPanel(IList<AssetCoverage> rows)
        {
            var editor = source as IDeviceMatchEditor;
            DeviceMatchSettings settings = Model.Matching ?? DeviceMatchSettings.None;
            var panel = new StackPanel { Margin = new Thickness(0, 4, 0, 0) };
            panel.Children.Add(Charts.Heading("Device matching"));
            panel.Children.Add(Charts.Text("The same device can be in the Hardware list more than once when ACAS and STIG checklists name it differently. " +
                                           "Matched records count as one device here; the Hardware list and reports are not changed.", 12));
            if (editor == null)
            {
                panel.Children.Add(Charts.Text("Matching cannot be changed here.", 12));
                return panel;
            }

            var shortNames = new CheckBox
            {
                Content = "Treat hosts with the same short name as one device (W01.Contoso.com, W01.Contoso and W01)",
                IsChecked = settings.MatchShortNames,
                Margin = new Thickness(0, 0, 0, 8)
            };
            shortNames.Click += (sender, e) => SaveMatching(editor, s => s.MatchShortNames = shortNames.IsChecked == true);
            panel.Children.Add(shortNames);

            var linkRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            var first = new ComboBox { ItemsSource = Model.HostNames, MinWidth = 220, Margin = new Thickness(0, 0, 6, 0), IsEditable = false };
            var second = new ComboBox { ItemsSource = Model.HostNames, MinWidth = 220, Margin = new Thickness(0, 0, 6, 0), IsEditable = false };
            var link = new Button { Content = "Link as one device", MinWidth = 140 };
            link.Click += (sender, e) =>
            {
                string a = first.SelectedItem as string, b = second.SelectedItem as string;
                if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b) || string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
                {
                    status.Text = "Pick two different hosts to link.";
                    return;
                }
                SaveMatching(editor, s => s.Link(new[] { a, b }));
            };
            linkRow.Children.Add(Charts.Text("Link", 12, false, new Thickness(0, 4, 6, 0)));
            linkRow.Children.Add(first);
            linkRow.Children.Add(Charts.Text("with", 12, false, new Thickness(0, 4, 6, 0)));
            linkRow.Children.Add(second);
            linkRow.Children.Add(link);
            panel.Children.Add(linkRow);

            List<AssetCoverage> devices = rows.Where(r => r.IsMatched).OrderBy(r => r.HostName, StringComparer.OrdinalIgnoreCase).ToList();
            if (devices.Count == 0)
                panel.Children.Add(Charts.Text("No hardware records are matched.", 12));
            foreach (AssetCoverage device in devices)
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 4), LastChildFill = true };
                var separate = new Button { Content = "Keep separate", MinWidth = 110, Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Top };
                List<string> names = device.Members.Select(m => m.HostName).ToList();
                separate.Click += (sender, e) => SaveMatching(editor, s => s.Separate(names));
                DockPanel.SetDock(separate, Dock.Left);
                row.Children.Add(separate);
                row.Children.Add(Charts.Text(device.Seen + "  [" + device.MatchedBy + "]", 12, false, new Thickness(0, 4, 0, 0)));
                panel.Children.Add(row);
            }
            if (settings.KeepSeparate.Count > 0)
            {
                var resetRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0) };
                var reset = new Button { Content = "Match these by short name again", Margin = new Thickness(0, 0, 8, 0) };
                reset.Click += (sender, e) => SaveMatching(editor, s => s.KeepSeparate.Clear());
                resetRow.Children.Add(reset);
                resetRow.Children.Add(Charts.Text("Kept separate: " + string.Join(", ", settings.KeepSeparate.OrderBy(h => h, StringComparer.OrdinalIgnoreCase)), 12, false, new Thickness(0, 4, 0, 0)));
                panel.Children.Add(resetRow);
            }
            return panel;
        }

        /// <summary>Changes and saves the matching settings, then reloads the dashboards.</summary>
        private void SaveMatching(IDeviceMatchEditor editor, Action<DeviceMatchSettings> change)
        {
            try
            {
                DeviceMatchSettings settings = Model.Matching ?? new DeviceMatchSettings();
                change(settings);
                editor.SaveMatching(settings);
                Refresh();
            }
            catch (Exception ex)
            {
                status.Text = "The device matching could not be saved: " + ex.Message;
            }
        }

        // 7. STIG benchmarks submitted, current or outdated.
        private UIElement StigsTab()
        {
            StigCurrencyReport report = Model.Stigs;
            var panel = new StackPanel();
            panel.Children.Add(Charts.Heading("STIG checklists submitted"));
            panel.Children.Add(Charts.Text(report.LibraryNote, 12, report.LibraryStale));
            if (report.Rows.Count == 0)
            {
                panel.Children.Add(Charts.Text("No checklists or SCAP results recorded yet. Releases are recorded for files imported with Vulnerator 7.4.0 or later; import older files again to list them."));
                return panel;
            }
            panel.Children.Add(Charts.Text(Charts.Number(report.Rows.Count) + " host/STIG pairs: " + Charts.Number(report.Outdated) + " outdated, " +
                                           Charts.Number(report.Rows.Count(r => r.State == StigCurrencyState.Unknown)) + " not in the loaded library.", 12));
            panel.Children.Add(Charts.Table(new[] { "Host", "STIG", "Submitted", "Latest loaded", "Status", "Benchmark date", "Type", "Imported", "File" },
                report.Rows.OrderBy(r => r.State == StigCurrencyState.Outdated ? 0 : r.State == StigCurrencyState.Unknown ? 1 : 2)
                    .Select(r => new[]
                    {
                        r.Submission.HostName, r.Submission.StigName, r.Submission.SubmittedVersion, r.Submission.LatestVersion, r.State.ToString(),
                        Charts.Date(r.Submission.BenchmarkDate), r.Submission.FindingType, Charts.Date(r.Submission.ImportedOn), r.Submission.SourceFile
                    }), 600));
            return panel;
        }

        // 8. Active IAVMs.
        private UIElement IavmsTab()
        {
            var panel = new StackPanel();
            panel.Children.Add(Charts.Heading("Active IAVMs"));
            panel.Children.Add(Charts.Text("IAVMs referenced by at least one open ACAS finding. Severity is the worse of DISA's severity for the plugin and the finding's " +
                                           "severity. Release and due dates are not in scan data, so deadlines are not shown.", 12));
            panel.Children.Add(Charts.Matrix(Definitions.IavmTypes, LevelNames.Take(5).ToList(), (r, c) => Model.IavmCounts[Definitions.IavmTypes[r]][c], Charts.LevelBrushes));
            if (Model.Iavms.Count == 0)
            {
                panel.Children.Add(Charts.Text("No active IAVMs."));
                return panel;
            }
            panel.Children.Add(Charts.Table(new[] { "IAVM", "Type", "Severity", "Findings", "Hosts", "Plugins", "Open findings", "Unverified", "First seen" },
                Model.Iavms.Select(i => new[]
                {
                    i.Iavm, i.Type, Definitions.LevelName(i.Level), string.Join("; ", i.Titles), Charts.Number(i.Hosts.Count), string.Join(", ", i.Plugins.OrderBy(p => p)),
                    Charts.Number(i.OpenFindings), Charts.Number(i.UnverifiedFindings), Charts.Date(i.FirstSeen)
                }), 600));
            return panel;
        }

        private void Redraw(int tab)
        {
            if (Model == null || tab >= tabs.Items.Count) return;
            UIElement content = tab == 0 ? SeverityTab() : TopHostsTab();
            ((ScrollViewer)((TabItem)tabs.Items[tab]).Content).Content = content;
        }
    }
}
