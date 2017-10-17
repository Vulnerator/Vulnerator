using System.Windows.Controls;
using System.Diagnostics;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Interaction logic for NewsView.xaml
    /// </summary>
    public partial class NewsView : UserControl
    {
        public NewsView()
        {
            InitializeComponent();
        }

        private void OpenHyperlink(object sender, System.Windows.Input.ExecutedRoutedEventArgs e)
        {
            Process.Start(e.Parameter.ToString());
        }
    }
}
