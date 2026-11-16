using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace Vulnerator.View.UI.ConfigurationManagement
{
    /// <summary>
    /// Asks which of the ticked hardware records to keep when merging, and whether to back up the database first.
    /// The record with ACAS results (or an ACAS host ID) is picked by default, since ACAS knows the device by its ID.
    /// </summary>
    public sealed class MergeHardwareWindow : Window
    {
        private readonly List<RadioButton> choices = new List<RadioButton>();
        private readonly CheckBox backUp = new CheckBox { Content = "Back up the database first (recommended)", IsChecked = true, Margin = new Thickness(0, 8, 0, 8) };

        public MergeHardwareWindow(IList<Vulnerator.Model.Entity.Hardware> records)
        {
            Title = "Merge Hardware";
            Width = 560;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            StackPanel panel = new StackPanel { Margin = new Thickness(12) };
            panel.Children.Add(new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8),
                Text = "These records will become one device. Pick the record to keep. Findings, IP and MAC addresses, groups, " +
                       "software and ports move to it; when both have the same finding, the newest result is kept. The other " +
                       "names are remembered, so later checklists or scans with those names land on the kept record. " +
                       "This cannot be undone."
            });
            Vulnerator.Model.Entity.Hardware suggested = records
                .OrderByDescending(h => !string.IsNullOrEmpty(h.AcasHostId))
                .ThenByDescending(h => h.LastAcasScan.HasValue)
                .ThenByDescending(h => (h.DiscoveredHostName ?? string.Empty).Length)
                .First();
            foreach (Vulnerator.Model.Entity.Hardware record in records)
            {
                List<string> details = new List<string>();
                if (!string.IsNullOrWhiteSpace(record.ScanSources)) details.Add(record.ScanSources);
                if (!string.IsNullOrWhiteSpace(record.ScanIP)) details.Add(record.ScanIP);
                if (!string.IsNullOrWhiteSpace(record.OperatingSystem)) details.Add(record.OperatingSystem);
                if (record.LastScan.HasValue) details.Add("last seen " + record.LastScan.Value.ToString("yyyy-MM-dd"));
                RadioButton choice = new RadioButton
                {
                    GroupName = "keep",
                    Tag = record,
                    IsChecked = ReferenceEquals(record, suggested),
                    Margin = new Thickness(0, 2, 0, 2),
                    Content = new TextBlock
                    {
                        TextWrapping = TextWrapping.Wrap,
                        Text = "Keep " + (record.DisplayedHostName ?? record.DiscoveredHostName) +
                               (string.Equals(record.DisplayedHostName, record.DiscoveredHostName, StringComparison.Ordinal) ? string.Empty : " (" + record.DiscoveredHostName + ")") +
                               (details.Count > 0 ? "  -  " + string.Join(", ", details) : string.Empty)
                    }
                };
                choices.Add(choice);
                panel.Children.Add(choice);
            }
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
                Keep = choices.Where(c => c.IsChecked == true).Select(c => (Vulnerator.Model.Entity.Hardware)c.Tag).FirstOrDefault();
                BackUpFirst = backUp.IsChecked == true;
                if (Keep == null) return;
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

        /// <summary>The record to keep (set when the window closes with Merge).</summary>
        public Vulnerator.Model.Entity.Hardware Keep { get; private set; }

        public bool BackUpFirst { get; private set; } = true;
    }
}
