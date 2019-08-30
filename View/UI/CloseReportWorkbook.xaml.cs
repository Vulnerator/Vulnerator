using System.Windows;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Interaction logic for CloseReportWorkbook.xaml
    /// </summary>
    public partial class CloseReportWorkbook
    {
        public CloseReportWorkbook()
        {
            InitializeComponent();
        }

        private void CloseClick(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
