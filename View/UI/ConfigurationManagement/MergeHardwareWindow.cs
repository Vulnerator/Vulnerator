using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace Vulnerator.View.UI.ConfigurationManagement
{
    /// <summary>
    /// Confirms a merge of the ticked hardware records. Nothing to pick: all of them are combined into one device, which
    /// keeps the oldest registry number (VUL-...). The other records' names become its other names and their numbers
    /// point to it. When records have the same finding, the newest result is kept. Offers a database backup first.
    /// </summary>
    public sealed class MergeHardwareWindow : Window
    {
        private readonly CheckBox backUp = new CheckBox { Content = "Back up the database first (recommended)", IsChecked = true, Margin = new Thickness(0, 8, 0, 8) };

        public MergeHardwareWindow(IList<Vulnerator.Model.Entity.Hardware> records, long keepId)
        {
            Title = "Merge Hardware";
            Width = 600;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            Vulnerator.Model.Entity.Hardware keep = records.FirstOrDefault(r => r.Hardware_ID == keepId) ?? records.First();
            StackPanel panel = new StackPanel { Margin = new Thickness(12) };
            panel.Children.Add(new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8),
                Text = $"These {records.Count} records will be combined into one device:"
            });
            panel.Children.Add(new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(12, 0, 0, 8),
                Text = Describe(keep, true)
            });
            panel.Children.Add(new TextBlock { Text = "Combined into it:", Margin = new Thickness(0, 0, 0, 4) });
            foreach (Vulnerator.Model.Entity.Hardware record in records.Where(r => !ReferenceEquals(r, keep)))
            {
                panel.Children.Add(new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(12, 0, 0, 2), Text = Describe(record, false) });
            }
            panel.Children.Add(new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 8, 0, 0),
                Text = "The device keeps the oldest registry number. Findings, checklists, IP and MAC addresses, groups, software and ports " +
                       "from all records move to it; when records have the same finding, the newest result is kept. The other records' names " +
                       "become its other names, so later checklists or scans with those names update this device, and their registry numbers " +
                       "point to it. You can rename the device and edit its details in its Device Profile afterwards. This cannot be undone."
            });
            panel.Children.Add(backUp);
            panel.Children.Add(new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 12),
                Text = "The backup is a copy of the database file next to it, named \"<database>.before-merge-<date>\"."
            });
            StackPanel buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            Button merge = new Button { Content = "Merge", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 0, 8, 0) };
            Button cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90 };
            merge.Click += (sender, e) =>
            {
                BackUpFirst = backUp.IsChecked == true;
                if (!BackUpFirst && MessageBox.Show(this, "Merge without a backup? This cannot be undone.", "Merge Hardware",
                        MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                { return; }
                DialogResult = true;
            };
            buttons.Children.Add(merge);
            buttons.Children.Add(cancel);
            panel.Children.Add(buttons);
            Content = panel;
        }

        private static string Describe(Vulnerator.Model.Entity.Hardware record, bool kept)
        {
            List<string> details = new List<string>();
            if (!string.IsNullOrWhiteSpace(record.ScanSources)) details.Add(record.ScanSources);
            if (!string.IsNullOrWhiteSpace(record.ScanIP)) details.Add(record.ScanIP);
            if (!string.IsNullOrWhiteSpace(record.OperatingSystem)) details.Add(record.OperatingSystem.Split('\n')[0].Trim());
            if (record.LastScan.HasValue) details.Add("last seen " + record.LastScan.Value.ToString("yyyy-MM-dd"));
            string name = record.DisplayedHostName ?? record.DiscoveredHostName;
            if (!string.Equals(record.DisplayedHostName, record.DiscoveredHostName, StringComparison.Ordinal))
            { name += " (" + record.DiscoveredHostName + ")"; }
            string number = string.IsNullOrWhiteSpace(record.RegistryNumber) ? string.Empty : record.RegistryNumber + "  ";
            return number + name + (details.Count > 0 ? "  -  " + string.Join(", ", details) : string.Empty) + (kept ? "  (keeps this number)" : string.Empty);
        }

        public bool BackUpFirst { get; private set; } = true;
    }
}
