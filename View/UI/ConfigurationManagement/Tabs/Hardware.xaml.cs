using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Vulnerator.View.UI.ConfigurationManagement.Tabs
{
    /// <summary>
    /// Interaction logic for Hardware.xaml
    /// </summary>
    public partial class Hardware : UserControl
    {
        /// <summary>Always shown: the check box column and the host name.</summary>
        private const string FixedColumn = "Preferred Host Name";

        /// <summary>Shown until the user picks columns (Settings key HardwareGridColumns).</summary>
        public const string DefaultColumns = "Registry No.|FQDN|NetBIOS|Last Scan IP|Operating System|Last ACAS Scan|Last Checklist / SCAP";

        public Hardware()
        {
            InitializeComponent();
            ApplyColumnChoice(Vulnerator.Properties.Settings.Default.HardwareGridColumns);
            // The list is replaced after every edit or import; keep the search applied to the new list.
            System.ComponentModel.DependencyPropertyDescriptor.FromProperty(ItemsControl.ItemsSourceProperty, typeof(DataGrid))
                .AddValueChanged(hardwareGrid, (sender, e) => ApplySearch());
        }

        private void HardwareSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        { ApplySearch(); }

        /// <summary>Double-clicking a device opens its Device Profile (the side panel).</summary>
        private void HardwareGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            DependencyObject source = e.OriginalSource as DependencyObject;
            while (source != null && !(source is DataGridRow))
            {
                source = source is System.Windows.Media.Visual || source is System.Windows.Media.Media3D.Visual3D
                    ? System.Windows.Media.VisualTreeHelper.GetParent(source)
                    : LogicalTreeHelper.GetParent(source);
            }
            if (source != null)
            { profileExpander.IsExpanded = true; }
        }

        /// <summary>Shows only the hardware matching the search box (all of it when the box is empty).</summary>
        private void ApplySearch()
        {
            if (hardwareGrid.ItemsSource == null) return;
            System.ComponentModel.ICollectionView view = CollectionViewSource.GetDefaultView(hardwareGrid.ItemsSource);
            if (view == null) return;
            string text = (hardwareSearchBox.Text ?? string.Empty).Trim();
            view.Filter = text.Length == 0 ? null : (Predicate<object>)(item => Matches(item as Vulnerator.Model.Entity.Hardware, text));
        }

        /// <summary>
        /// True when the device has the registry number (its own, or one of a device merged into it), or when the text is
        /// part of its names, other names, FQDN, NetBIOS name, operating system or IP addresses.
        /// </summary>
        public static bool Matches(Vulnerator.Model.Entity.Hardware hardware, string text)
        {
            if (hardware == null) return false;
            long? number = Vulnerator.Model.DataAccess.DeviceRegistry.Parse(text);
            if (number.HasValue)
            {
                string formatted = Vulnerator.Model.DataAccess.DeviceRegistry.Format(number.Value);
                if (string.Equals(hardware.RegistryNumber, formatted, StringComparison.OrdinalIgnoreCase) ||
                    (hardware.AlsoKnownAs ?? string.Empty).IndexOf(formatted, StringComparison.OrdinalIgnoreCase) >= 0)
                { return true; }
                if (text.StartsWith(Vulnerator.Model.DataAccess.DeviceRegistry.Prefix, StringComparison.OrdinalIgnoreCase))
                { return false; }
            }
            IEnumerable<string> values = new[]
            {
                hardware.DisplayedHostName, hardware.DiscoveredHostName, hardware.FQDN, hardware.NetBIOS, hardware.ScanIP,
                hardware.RegistryNumber, hardware.AlsoKnownAs, hardware.OperatingSystem
            };
            if (hardware.IP_Addresses != null)
            { values = values.Concat(hardware.IP_Addresses.Where(i => i != null).Select(i => i.IpAddress)); }
            return values.Any(v => !string.IsNullOrEmpty(v) && v.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        /// <summary>The optional columns (header text), in the order they are defined.</summary>
        private IEnumerable<DataGridColumn> OptionalColumns()
        {
            return hardwareGrid.Columns.Where(c => c.Header is string && (string)c.Header != FixedColumn);
        }

        /// <summary>Shows the columns named in <paramref name="choice"/> ("|"-separated headers) and hides the others.</summary>
        public void ApplyColumnChoice(string choice)
        {
            HashSet<string> visible = new HashSet<string>((string.IsNullOrWhiteSpace(choice) ? DefaultColumns : choice)
                .Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries).Select(c => c.Trim()), StringComparer.OrdinalIgnoreCase);
            foreach (DataGridColumn column in OptionalColumns())
            { column.Visibility = visible.Contains((string)column.Header) ? Visibility.Visible : Visibility.Collapsed; }
        }

        private void SaveColumnChoice()
        {
            Vulnerator.Properties.Settings.Default.HardwareGridColumns =
                string.Join("|", OptionalColumns().Where(c => c.Visibility == Visibility.Visible).Select(c => (string)c.Header));
            // Nothing picked is kept as "|" so the default columns do not come back on the next start.
            if (string.IsNullOrEmpty(Vulnerator.Properties.Settings.Default.HardwareGridColumns))
            { Vulnerator.Properties.Settings.Default.HardwareGridColumns = "|"; }
            Vulnerator.Properties.Settings.Default.Save();
        }

        /// <summary>A menu of the optional columns with check marks; picking one shows or hides it and remembers the choice.</summary>
        private void HardwareColumnsButton_Click(object sender, RoutedEventArgs e)
        {
            ContextMenu menu = new ContextMenu { PlacementTarget = hardwareColumnsButton, Placement = System.Windows.Controls.Primitives.PlacementMode.Top };
            foreach (DataGridColumn column in OptionalColumns())
            {
                DataGridColumn target = column;
                MenuItem item = new MenuItem { Header = (string)column.Header, IsCheckable = true, IsChecked = column.Visibility == Visibility.Visible, StaysOpenOnClick = true };
                item.Click += (s, args) =>
                {
                    target.Visibility = item.IsChecked ? Visibility.Visible : Visibility.Collapsed;
                    SaveColumnChoice();
                };
                menu.Items.Add(item);
            }
            menu.Items.Add(new Separator());
            MenuItem reset = new MenuItem { Header = "Default columns" };
            reset.Click += (s, args) =>
            {
                ApplyColumnChoice(DefaultColumns);
                SaveColumnChoice();
            };
            menu.Items.Add(reset);
            menu.IsOpen = true;
        }
    }
}
