using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Vulnerator.View.UI.ConfigurationManagement
{
    /// <summary>
    /// Merge Hardware: the whole hardware inventory with a Find box. Tick the records that are the same device; they are
    /// combined into one device, which keeps the oldest registry number (shown live). Records ticked or selected in the
    /// Hardware list start ticked. Offers a database backup first.
    /// </summary>
    public sealed class MergeHardwareWindow : Window
    {
        private readonly List<Candidate> candidates;
        private readonly ICollectionView view;
        private readonly TextBox find = new TextBox { Margin = new Thickness(0, 0, 8, 0), MinWidth = 320 };
        private readonly CheckBox tickedOnly = new CheckBox { Content = "Show ticked only", VerticalAlignment = VerticalAlignment.Center };
        private readonly TextBlock summary = new TextBlock { TextWrapping = TextWrapping.Wrap, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 4) };
        private readonly CheckBox backUp = new CheckBox { Content = "Back up the database first (recommended)", IsChecked = true, Margin = new Thickness(0, 4, 0, 8) };
        private readonly Button merge = new Button { Content = "Merge", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 0, 8, 0), IsEnabled = false };

        public MergeHardwareWindow(IEnumerable<Vulnerator.Model.Entity.Hardware> inventory, IEnumerable<long> preTicked)
        {
            Title = "Merge Hardware";
            Width = 980;
            Height = 640;
            MinWidth = 700;
            MinHeight = 420;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            HashSet<long> ticked = new HashSet<long>(preTicked ?? new long[0]);
            candidates = (inventory ?? new Vulnerator.Model.Entity.Hardware[0])
                .Select(h => new Candidate(h, ticked.Contains(h.Hardware_ID)))
                .OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
            foreach (Candidate candidate in candidates)
            { candidate.PropertyChanged += (sender, e) => { if (tickedOnly.IsChecked == true) view.Refresh(); UpdateSummary(); }; }
            view = CollectionViewSource.GetDefaultView(candidates);
            view.Filter = Matches;

            DockPanel root = new DockPanel { Margin = new Thickness(12) };

            TextBlock intro = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8),
                Text = "Tick the records that are the same device (for example W01.Contoso.com from ACAS and W01.Contoso from a checklist). " +
                       "Use Find to look them up by name, other name, registry number, IP address or operating system."
            };
            DockPanel.SetDock(intro, Dock.Top);
            root.Children.Add(intro);

            DockPanel findRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            findRow.Children.Add(new TextBlock { Text = "Find:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
            findRow.Children.Add(find);
            Button clear = new Button { Content = "Untick All", MinWidth = 90, Margin = new Thickness(8, 0, 0, 0) };
            clear.Click += (sender, e) => { foreach (Candidate c in candidates) c.Include = false; };
            DockPanel.SetDock(clear, Dock.Right);
            findRow.Children.Insert(0, clear);
            findRow.Children.Add(tickedOnly);
            DockPanel.SetDock(findRow, Dock.Top);
            root.Children.Add(findRow);
            find.TextChanged += (sender, e) => view.Refresh();
            tickedOnly.Click += (sender, e) => view.Refresh();

            StackPanel bottom = new StackPanel();
            bottom.Children.Add(summary);
            bottom.Children.Add(new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Text = "Findings, checklists, IP and MAC addresses, groups, software and ports from all ticked records move to that device; when " +
                       "records have the same finding, the newest result is kept. The other records' names become its other names, so later " +
                       "checklists or scans with those names update it, and their registry numbers point to it. This cannot be undone."
            });
            bottom.Children.Add(backUp);
            StackPanel buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            Button cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90 };
            merge.Click += (sender, e) =>
            {
                BackUpFirst = backUp.IsChecked == true;
                if (!BackUpFirst && MessageBox.Show(this, "Merge without a backup? This cannot be undone.", "Merge Hardware",
                        MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                { return; }
                SelectedIds = candidates.Where(c => c.Include).Select(c => c.Hardware.Hardware_ID).ToList();
                KeepId = Keep(candidates.Where(c => c.Include)).Hardware.Hardware_ID;
                DialogResult = true;
            };
            buttons.Children.Add(merge);
            buttons.Children.Add(cancel);
            bottom.Children.Add(buttons);
            DockPanel.SetDock(bottom, Dock.Bottom);
            root.Children.Add(bottom);

            DataGrid grid = new DataGrid
            {
                ItemsSource = view,
                AutoGenerateColumns = false,
                CanUserAddRows = false,
                CanUserDeleteRows = false,
                SelectionMode = DataGridSelectionMode.Single,
                HeadersVisibility = DataGridHeadersVisibility.Column
            };
            FrameworkElementFactory box = new FrameworkElementFactory(typeof(CheckBox));
            box.SetValue(HorizontalAlignmentProperty, HorizontalAlignment.Center);
            box.SetBinding(System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty,
                new Binding("Include") { Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });
            grid.Columns.Add(new DataGridTemplateColumn { Header = "Merge", CellTemplate = new DataTemplate { VisualTree = box }, Width = DataGridLength.Auto });
            grid.Columns.Add(Text("Registry No.", "Registry"));
            grid.Columns.Add(Text("Host Name", "Name"));
            grid.Columns.Add(Text("Other Names", "OtherNames", 200));
            grid.Columns.Add(Text("Sources", "Sources"));
            grid.Columns.Add(Text("Scan IP", "ScanIP"));
            grid.Columns.Add(Text("Operating System", "OperatingSystem", 200));
            grid.Columns.Add(Text("Last Seen", "LastSeen"));
            // Clicking anywhere on a row ticks or unticks it.
            grid.MouseLeftButtonUp += (sender, e) =>
            {
                DependencyObject source = e.OriginalSource as DependencyObject;
                while (source != null && !(source is DataGridRow) && !(source is CheckBox))
                {
                    source = source is System.Windows.Media.Visual || source is System.Windows.Media.Media3D.Visual3D
                        ? System.Windows.Media.VisualTreeHelper.GetParent(source)
                        : LogicalTreeHelper.GetParent(source);
                }
                if (source is DataGridRow row && row.Item is Candidate candidate)
                { candidate.Include = !candidate.Include; }
            };
            root.Children.Add(grid);
            Content = root;

            // One record picked in the Hardware list: look for its other records by its short name.
            List<Candidate> start = candidates.Where(c => c.Include).ToList();
            if (start.Count == 1)
            { find.Text = ShortName(start[0].Name); }
            UpdateSummary();
            Loaded += (sender, e) => find.Focus();
        }

        /// <summary>The hardware records to combine.</summary>
        public List<long> SelectedIds { get; private set; } = new List<long>();

        /// <summary>The record that remains: the one with the oldest registry number.</summary>
        public long KeepId { get; private set; }

        public bool BackUpFirst { get; private set; } = true;

        private static DataGridTextColumn Text(string header, string path, double width = double.NaN)
        {
            return new DataGridTextColumn
            {
                Header = header,
                Binding = new Binding(path) { Mode = BindingMode.OneWay },
                IsReadOnly = true,
                Width = double.IsNaN(width) ? DataGridLength.Auto : new DataGridLength(width),
                ElementStyle = new Style(typeof(TextBlock)) { Setters = { new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis) } }
            };
        }

        private bool Matches(object item)
        {
            Candidate candidate = (Candidate)item;
            if (tickedOnly.IsChecked == true) return candidate.Include;
            string text = (find.Text ?? string.Empty).Trim();
            if (text.Length == 0 || candidate.Include) return true;
            return candidate.SearchText.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void UpdateSummary()
        {
            List<Candidate> chosen = candidates.Where(c => c.Include).ToList();
            merge.IsEnabled = chosen.Count >= 2;
            if (chosen.Count == 0)
            { summary.Text = "Tick two or more records to combine."; return; }
            Candidate keep = Keep(chosen);
            string device = (string.IsNullOrWhiteSpace(keep.Registry) ? string.Empty : keep.Registry + " ") + keep.Name;
            summary.Text = chosen.Count == 1
                ? $"1 record ticked ({device}). Tick at least one more."
                : $"{chosen.Count} records ticked. They will be combined into {device}, which keeps the oldest registry number.";
        }

        /// <summary>The oldest registry number, else the oldest record (the same rule as HardwareMerger.ChooseKeep).</summary>
        private static Candidate Keep(IEnumerable<Candidate> chosen)
        {
            return chosen.OrderBy(c => c.RegistryValue).ThenBy(c => c.Hardware.Hardware_ID).First();
        }

        private static string ShortName(string name)
        {
            string value = (name ?? string.Empty).Trim();
            int dot = value.IndexOf('.');
            return dot > 0 && !Regex.IsMatch(value, @"^\d+\.\d+\.\d+\.\d+$") ? value.Substring(0, dot) : value;
        }

        private sealed class Candidate : INotifyPropertyChanged
        {
            private bool include;

            public Candidate(Vulnerator.Model.Entity.Hardware hardware, bool include)
            {
                Hardware = hardware;
                this.include = include;
                Registry = hardware.RegistryNumber ?? string.Empty;
                Match digits = Regex.Match(Registry, @"\d+");
                RegistryValue = digits.Success && long.TryParse(digits.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long number) ? number : long.MaxValue;
                Name = string.IsNullOrWhiteSpace(hardware.DisplayedHostName) ? hardware.DiscoveredHostName : hardware.DisplayedHostName;
                if (!string.IsNullOrWhiteSpace(hardware.DiscoveredHostName) && !string.Equals(hardware.DiscoveredHostName, Name, StringComparison.Ordinal))
                { Name += " (" + hardware.DiscoveredHostName + ")"; }
                OtherNames = string.Join(", ", new[] { hardware.AlsoKnownAs, hardware.FQDN, hardware.NetBIOS }
                    .Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase));
                Sources = hardware.ScanSources ?? string.Empty;
                ScanIP = hardware.ScanIP ?? string.Empty;
                OperatingSystem = (hardware.OperatingSystem ?? string.Empty).Replace("\r", " ").Replace("\n", " / ");
                LastSeen = hardware.LastScan.HasValue ? hardware.LastScan.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : string.Empty;
                SearchText = string.Join(" ", Registry, Name, OtherNames, ScanIP, OperatingSystem, Sources,
                    RegistryValue == long.MaxValue ? string.Empty : RegistryValue.ToString(CultureInfo.InvariantCulture));
            }

            public event PropertyChangedEventHandler PropertyChanged;

            public Vulnerator.Model.Entity.Hardware Hardware { get; }
            public string Registry { get; }
            public long RegistryValue { get; }
            public string Name { get; }
            public string OtherNames { get; }
            public string Sources { get; }
            public string ScanIP { get; }
            public string OperatingSystem { get; }
            public string LastSeen { get; }
            public string SearchText { get; }

            public bool Include
            {
                get => include;
                set
                {
                    if (include == value) return;
                    include = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Include)));
                }
            }
        }
    }
}
