// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
// Dashboards add-on tests: packaging, the model, every tab rendered, and the add-on entry with a fake host.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using Vulnerator.AddOns;
using Vulnerator.Dashboards;
using Vulnerator.Metrics;

internal static class Program
{
    private static int passed;
    private static int failed;
    private static readonly DateTime Now = new DateTime(2026, 11, 6, 9, 0, 0);

    [STAThread]
    private static int Main()
    {
        try
        {
            Packaging();
            ModelAndView();
            EmptyModel();
            DeviceMatchingView();
            Entry();
        }
        catch (Exception ex)
        {
            Check(false, "unexpected exception", ex.ToString());
        }
        Console.WriteLine(passed + " checks passed, " + failed + " failed.");
        return failed == 0 ? 0 : 1;
    }

    private static void Packaging()
    {
        Assembly addOn = typeof(DashboardsAddOn).Assembly;
        Check(Path.GetFileName(addOn.Location) == "Vulnerator.Dashboards.AddOn.dll", "file name ends in .AddOn.dll", Path.GetFileName(addOn.Location));
        var attribute = addOn.GetCustomAttribute<VulneratorAddOnAttribute>();
        Check(attribute != null && attribute.AddOnType == typeof(DashboardsAddOn) && attribute.ApiVersion == 3 && attribute.MinimumCoreVersion == "7.4.0",
            "add-on attribute: entry type, interface version 3", attribute == null ? "missing" : attribute.ApiVersion.ToString());
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "mscorlib", "System", "System.Core", "System.Xml", "System.Xaml", "System.Runtime.Serialization",
            "PresentationCore", "PresentationFramework", "WindowsBase", "Vulnerator.AddOns"
        };
        string[] references = addOn.GetReferencedAssemblies().Select(a => a.Name).ToArray();
        string[] extra = references.Where(r => !allowed.Contains(r)).ToArray();
        Check(extra.Length == 0, "only .NET Framework, WPF and the add-on contract are referenced", string.Join(", ", extra));
        Check(!typeof(IAddOnLicensing).IsAssignableFrom(typeof(DashboardsAddOn)), "no license handling", null);
        string informational = addOn.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? string.Empty;
        Check(informational.StartsWith("1.2.0", StringComparison.Ordinal), "version 1.2.0", informational);
    }

    private static DashboardInput SampleInput()
    {
        var findings = new List<MetricFinding>
        {
            Acas(1, "web01", "500101", "Very High", "I", Now.AddDays(-1), "IAVA:2026-A-0001", "CVE:CVE-2026-0001"),
            Acas(1, "web01", "500102", "High", "I", Now.AddDays(-1)),
            Acas(1, "web01", "500103", "Moderate", "II", Now.AddDays(-20), "IAVB:2026-B-0002"),
            Acas(2, "db01", "500101", "Very High", "I", Now.AddDays(-2), "IAVA:2026-A-0001"),
            Acas(2, "db01", "19506", "Very Low", "IV", Now.AddDays(-2)),
            Stig(1, "web01", "V-1001", "I", "Open", "AC-2"),
            Stig(1, "web01", "V-1002", "II", "Not a Finding", "AC-3"),
            Stig(1, "web01", "V-1003", "II", "Not a Finding", "AC-6"),
            Stig(1, "web01", "V-1004", "III", "Not Reviewed", "AU-2"),
            Stig(1, "web01", "V-1005", "II", "Not Applicable", "CM-6")
        };
        var hardware = new List<MetricHardware>
        {
            new MetricHardware { Id = 1, HostName = "web01", OperatingSystem = "Microsoft Windows Server 2022" }, new MetricHardware { Id = 2, HostName = "db01" }, new MetricHardware { Id = 3, HostName = "spare01" }
        };
        var submissions = new List<MetricSubmission>
        {
            new MetricSubmission { FindingType = "CKL", HardwareId = 1, HostName = "web01", StigName = "Test Server STIG", SubmittedVersion = "V2R4", LatestVersion = "V2R5", IsOutdated = true, ImportedOn = Now.AddDays(-3), SourceFile = "web01.ckl", BenchmarkDate = new DateTime(2025, 10, 15) }
        };
        var poam = new List<MetricPoamItem>
        {
            new MetricPoamItem { Status = "Ongoing", SeverityName = "High", DateIdentified = Now.AddDays(-100), ScheduledCompletion = Now.AddDays(-10), Summary = "Overdue item", SecurityChecks = new List<string> { "V-1001" }, Devices = new List<string> { "web01" } },
            new MetricPoamItem { Status = "Ongoing", SeverityName = "Moderate", DateIdentified = Now.AddDays(-5), ScheduledCompletion = Now.AddDays(15), Summary = "Due soon item" },
            new MetricPoamItem { Status = "Completed", SeverityName = "Low", DateIdentified = Now.AddDays(-50) }
        };
        var trend = new List<TrendSnapshot>
        {
            new TrendSnapshot { TakenOn = Now.AddDays(-2), OpenByLevel = new[] { 2, 3, 1, 0, 1, 0 }, NewlyOpen = 7 },
            new TrendSnapshot { TakenOn = Now.AddDays(-1), OpenByLevel = new[] { 2, 2, 0, 0, 1, 0 }, Unverified = 1, NewlyClosed = 2 }
        };
        return new DashboardInput { Findings = findings, Hardware = hardware, Submissions = submissions, PoamItems = poam, Trend = trend, LibraryImported = Now.AddDays(-20), Now = Now };
    }

    private static void ModelAndView()
    {
        DashboardModel model = DashboardModel.Build(SampleInput(), "CUI");
        Check(model.FindingCount == 10 && model.Severity[0].OpenByLevel[0] == 2, "model: severity", string.Join(",", model.Severity[0].OpenByLevel));
        Check(model.Severity[0].Unverified == 1, "model: the Moderate plugin missing from web01's newest scan is Unverified", model.Severity[0].Unverified.ToString());
        Check(model.Iavms.Count == 1 && model.Iavms[0].Iavm == "2026-A-0001" && model.Iavms[0].Hosts.Count == 2, "model: active IAVMs (the unverified IAVB is not active)", model.Iavms.Count.ToString());
        Check(model.Coverage.Single(c => c.HostName == "spare01").Gap == "No ACAS scan or STIG checklist" && model.Coverage.Last().HostName == "web01",
            "model: coverage gaps listed first", string.Join(", ", model.Coverage.Select(c => c.HostName + "=" + c.Gap)));
        Check(model.Stigs.Outdated == 1 && !model.Stigs.LibraryStale, "model: STIG currency", model.Stigs.LibraryNote);
        Check(Math.Abs(model.Compliance.First(f => f.Family == "AC").CompliantPercent.Value - 66.666) < 0.01, "model: AC 2 of 3 compliant", null);
        Check(model.Poam.Overdue.Count == 1 && model.Poam.DueWithin30Days.Count == 1 && model.Poam.Ongoing == 2, "model: POA&M", null);

        var view = new DashboardView(new StaticSource(model));
        view.Render(model);
        TabControl tabs = Find<TabControl>(view).Single();
        string[] headers = tabs.Items.Cast<TabItem>().Select(t => (string)t.Header).ToArray();
        Check(headers.SequenceEqual(DashboardView.TabNames), "eight tabs", string.Join(", ", headers));

        var window = new Window { Content = view, Width = 1280, Height = 900, ShowInTaskbar = false, WindowStyle = WindowStyle.None, Left = -20000, Top = -20000 };
        window.Show();
        try
        {
            var texts = new List<string>();
            for (int i = 0; i < tabs.Items.Count; i++)
            {
                tabs.SelectedIndex = i;
                window.UpdateLayout();
                texts.AddRange(AllText(((TabItem)tabs.Items[i]).Content));
            }
            string all = string.Join(" | ", texts);
            Check(all.Contains("web01") && all.Contains("db01"), "top hosts listed", null);
            Check(all.Contains("2026-A-0001") && !all.Contains("2026-B-0002 |"), "active IAVM listed", null);
            Check(all.Contains("Outdated") && all.Contains("V2R4") && all.Contains("V2R5"), "outdated STIG listed", null);
            Check(all.Contains("Overdue item") && all.Contains("Due soon item"), "POA&M tables", null);
            Check(all.Contains("66.7% (2 of 3)") && all.Contains("Not assessed"), "compliance text", null);
            Check(all.Contains("spare01") && all.Contains("No ACAS scan or STIG checklist"), "coverage table", null);
            Check(all.Contains("web01 | Microsoft Windows Server 2022 |"), "coverage shows the device operating system", null);
            Check(all.Contains("2026-A-0001 | IAVA | Very High | Plugin 500101 |"), "IAVM rows show the finding titles", null);
            Check(all.Contains("Device matching") && all.Contains("Matching cannot be changed here."), "device matching section (read-only source)", null);
            Check(all.Contains("Unverified"), "unverified note", null);
            Check(Find<Border>(view).Count(b => b.Child is TextBlock tb && tb.Text == "CUI") == 2, "marking banner top and bottom", null);
            Check(Charts_BannerIsPurple(), "CUI banner colour", null);

            tabs.SelectedIndex = 0;
            window.UpdateLayout();
            RadioButton cat = Find<RadioButton>((DependencyObject)((ScrollViewer)((TabItem)tabs.Items[0]).Content).Content).First(r => (string)r.Content == "CAT");
            cat.IsChecked = true;
            window.UpdateLayout();
            Check(AllText(((TabItem)tabs.Items[0]).Content).Any(t => t == "Open findings by CAT"), "severity tab switches to CAT", null);

            tabs.SelectedIndex = 1;
            window.UpdateLayout();
            ComboBox filter = Find<ComboBox>((DependencyObject)((ScrollViewer)((TabItem)tabs.Items[1]).Content).Content).First();
            filter.SelectedIndex = 2;
            window.UpdateLayout();
            string hostsText = string.Join(" | ", AllText(((TabItem)tabs.Items[1]).Content));
            Check(hostsText.Contains("web01") && !hostsText.Contains("db01"), "top hosts: STIG and SCAP filter", hostsText);

            view.Render(model);
            Check(tabs.SelectedIndex == 1, "refresh keeps the selected tab", tabs.SelectedIndex.ToString());
        }
        finally
        {
            window.Close();
        }
    }

    private static void DeviceMatchingView()
    {
        var input = new DashboardInput
        {
            Now = Now,
            Hardware = new List<MetricHardware>
            {
                new MetricHardware { Id = 1, HostName = "W01.Contoso.com", OperatingSystem = "Microsoft Windows 11" },
                new MetricHardware { Id = 2, HostName = "W01.Contoso" },
                new MetricHardware { Id = 3, HostName = "printer7" }
            },
            Findings = new List<MetricFinding> { Acas(1, "W01.Contoso.com", "500102", "High", "I", Now.AddDays(-1)), Stig(2, "W01.Contoso", "V-1001", "I", "Open", "AC-2") }
        };
        var source = new EditableSource(input);
        DashboardModel model = source.Load();
        AssetCoverage w01 = model.Coverage.Single(c => c.IsMatched);
        Check(model.Coverage.Count == 2 && w01.HostName == "W01.Contoso.com" && !w01.HasGap, "view model: W01.Contoso.com (ACAS) and W01.Contoso (STIG) are one covered device",
            string.Join(", ", model.Coverage.Select(c => c.HostName + "=" + c.Gap)));
        var view = new DashboardView(source);
        view.Render(model);
        var window = new Window { Content = view, Width = 1280, Height = 900, ShowInTaskbar = false, WindowStyle = WindowStyle.None, Left = -20000, Top = -20000 };
        window.Show();
        try
        {
            TabControl tabs = Find<TabControl>(view).Single();
            tabs.SelectedIndex = 5;
            window.UpdateLayout();
            var content = (DependencyObject)((ScrollViewer)((TabItem)tabs.Items[5]).Content).Content;
            string text = string.Join(" | ", AllText(content));
            Check(text.Contains("W01.Contoso (STIG); W01.Contoso.com (ACAS)") && text.Contains("short name"), "coverage lists the matched records and why", text);
            Check(Find<CheckBox>(content).Any(c => (c.Content as string ?? string.Empty).StartsWith("Treat hosts with the same short name")), "short-name matching switch", null);
            Button keep = Find<Button>(content).FirstOrDefault(b => b.Content as string == "Keep separate");
            Check(keep != null, "Keep separate button for a matched device", null);
            List<ComboBox> boxes = Find<ComboBox>(content).ToList();
            Button link = Find<Button>(content).FirstOrDefault(b => b.Content as string == "Link as one device");
            Check(boxes.Count == 2 && link != null, "link controls", boxes.Count.ToString());
            if (boxes.Count == 2 && link != null)
            {
                boxes[0].SelectedItem = "printer7";
                boxes[1].SelectedItem = "W01.Contoso";
                link.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
                Check(source.Saved != null && source.Saved.Links.Any(l => l.Hosts.Contains("printer7") && l.Hosts.Contains("W01.Contoso")), "Link as one device saves the link",
                    source.Saved == null ? "not saved" : string.Join(" | ", source.Saved.Links.Select(l => string.Join(",", l.Hosts))));
            }
        }
        finally
        {
            window.Close();
        }
    }

    private sealed class EditableSource : IDashboardSource, IDeviceMatchEditor
    {
        private readonly DashboardInput input;
        public EditableSource(DashboardInput input) { this.input = input; }
        public DeviceMatchSettings Saved { get; private set; }
        public DashboardModel Load() => DashboardModel.Build(input, string.Empty);
        public void SaveMatching(DeviceMatchSettings settings)
        {
            Saved = settings;
            input.Matching = settings;
        }
    }

    private static bool Charts_BannerIsPurple()
    {
        Type charts = typeof(DashboardView).Assembly.GetType("Vulnerator.Dashboards.Charts");
        MethodInfo method = charts.GetMethod("BannerColor", BindingFlags.Public | BindingFlags.Static);
        object[] args = { "CUI", false };
        string cui = (string)method.Invoke(null, args);
        args = new object[] { "SECRET//NOFORN", false };
        string secret = (string)method.Invoke(null, args);
        args = new object[] { "UNCLASSIFIED", false };
        string unclassified = (string)method.Invoke(null, args);
        return cui == "#502B85" && secret == "#C8102E" && unclassified == "#007A33";
    }

    private static void EmptyModel()
    {
        DashboardModel model = DashboardModel.Build(new DashboardInput { Now = Now }, string.Empty);
        var view = new DashboardView(new StaticSource(model));
        view.Render(model);
        var window = new Window { Content = view, Width = 1000, Height = 700, ShowInTaskbar = false, WindowStyle = WindowStyle.None, Left = -20000, Top = -20000 };
        window.Show();
        try
        {
            TabControl tabs = Find<TabControl>(view).Single();
            var texts = new List<string>();
            for (int i = 0; i < tabs.Items.Count; i++)
            {
                tabs.SelectedIndex = i;
                window.UpdateLayout();
                texts.AddRange(AllText(((TabItem)tabs.Items[i]).Content));
            }
            string all = string.Join(" | ", texts);
            Check(all.Contains("No hosts with open findings") && all.Contains("No snapshots yet") && all.Contains("No active IAVMs"), "empty database: every tab says so", null);
            Check(all.Contains("No DISA STIG library has been imported"), "empty database: library note", null);
            Check(!Find<Border>(view).Any(b => b.Child is TextBlock tb && tb.Text == string.Empty), "no banner without a marking", null);
        }
        finally
        {
            window.Close();
        }
    }

    private static void Entry()
    {
        string folder = Path.Combine(Path.GetTempPath(), "vdash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var host = new FakeHost(folder);
            var addOn = new DashboardsAddOn();
            addOn.Initialize(host);
            Check(addOn.Id == "dashboards" && host.Pages.Count == 1 && host.Pages[0].Item1 == "Dashboards" && host.Pages[0].Item2 == "ChartBar", "one menu page, Dashboards", host.Pages.Count.ToString());
            Check(addOn.Version == "1.2.0", "version shown without the commit suffix", addOn.Version);
            object page = host.Pages[0].Item3();
            Check(page is DashboardView, "the page opens", page == null ? "null" : page.GetType().FullName);
            host.RaiseDataChanged();
            string trendFile = Path.Combine(folder, TrendStore.FileName);
            for (int i = 0; i < 50 && !File.Exists(trendFile); i++) Thread.Sleep(100);
            Check(File.Exists(trendFile), "an import records a trend snapshot", null);
        }
        finally
        {
            try { Directory.Delete(folder, true); } catch (IOException) { }
        }
    }

    private static MetricFinding Acas(long hw, string host, string plugin, string level, string cat, DateTime seen, params string[] refs)
    {
        return new MetricFinding
        {
            FindingType = "ACAS", SourceName = "ACAS", HardwareId = hw, HostName = host, Asset = host, VulnerabilityId = plugin, RuleId = plugin,
            Title = "Plugin " + plugin, SeverityLevelName = level, Cat = cat, Status = "Open", LastObserved = seen, FirstDiscovered = seen.AddDays(-30),
            References = refs.ToList(), SecondarySeverity = cat
        };
    }

    private static MetricFinding Stig(long hw, string host, string rule, string cat, string status, params string[] controls)
    {
        return new MetricFinding
        {
            FindingType = "CKL", SourceName = "Test Server STIG", HardwareId = hw, HostName = host, Asset = host, VulnerabilityId = rule, RuleId = rule,
            Title = "Rule " + rule, Cat = cat, Status = status, LastObserved = Now.AddDays(-3), NistControls = controls.ToList()
        };
    }

    private static IEnumerable<T> Find<T>(DependencyObject root) where T : DependencyObject
    {
        if (root == null) yield break;
        if (root is T match) yield return match;
        foreach (object child in LogicalTreeHelper.GetChildren(root))
        {
            if (child is DependencyObject d)
            {
                foreach (T found in Find<T>(d)) yield return found;
            }
        }
    }

    private static IEnumerable<string> AllText(object root)
    {
        var d = root as DependencyObject;
        if (d == null) yield break;
        foreach (TextBlock t in Find<TextBlock>(d)) yield return t.Text;
        foreach (DataGrid g in Find<DataGrid>(d))
        {
            foreach (object item in g.ItemsSource)
            {
                if (item is string[] row) yield return string.Join(" | ", row) + " |";
            }
        }
    }

    private static void Check(bool condition, string name, string detail)
    {
        if (condition) passed++;
        else
        {
            failed++;
            Console.WriteLine("::error::" + name + ": " + (detail ?? string.Empty).Replace("\r", string.Empty).Replace("\n", " | "));
        }
    }

    private sealed class StaticSource : IDashboardSource
    {
        private readonly DashboardModel model;
        public StaticSource(DashboardModel model) { this.model = model; }
        public DashboardModel Load() => model;
    }

    private sealed class FakeHost : IAddOnHost, IAddOnLog, IFindingsData
    {
        public FakeHost(string folder) { DataFolder = folder; }
        public List<Tuple<string, string, Func<object>>> Pages { get; } = new List<Tuple<string, string, Func<object>>>();
        public List<string> Logged { get; } = new List<string>();
        public int ApiVersion => 3;
        public string CoreVersion => "7.4.0-beta.3";
        public string DataFolder { get; }
        public string ClassificationMarking => "UNCLASSIFIED";
        public IAddOnLog Log => this;
        public IFindingsData Data => this;
        public IReadOnlyList<string> Licenses => new string[0];
        public event EventHandler DataChanged;
        public event EventHandler LicensesChanged;
        public void AddPage(string title, string iconName, Func<object> createView) => Pages.Add(Tuple.Create(title, iconName, createView));
        public void AddSettingsSection(string title, Func<object> createView) { }
        public void RaiseDataChanged() => DataChanged?.Invoke(this, EventArgs.Empty);
        public void RaiseLicensesChanged() => LicensesChanged?.Invoke(this, EventArgs.Empty);
        public void Info(string message) => Logged.Add(message);
        public void Warning(string message) => Logged.Add(message);
        public void Error(string message, Exception exception = null) => Logged.Add(message);
        public IReadOnlyList<FindingRecord> GetFindings() => new FindingRecord[0];
        public IReadOnlyList<HardwareRecord> GetHardware() => new HardwareRecord[0];
        public IReadOnlyList<StigSubmissionRecord> GetStigSubmissions() => new StigSubmissionRecord[0];
        public IReadOnlyList<PoamItemRecord> GetPoamItems() => new PoamItemRecord[0];
        public DateTime? GetLastStigLibraryImport() => null;
    }
}
