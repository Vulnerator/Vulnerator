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
