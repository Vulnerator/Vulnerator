using System.Windows.Controls;
using System.Diagnostics;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Interaction logic for UserGuideView.xaml
    /// </summary>
    public partial class UserGuideView : UserControl
    {
        public UserGuideView()
        {
            InitializeComponent();
        }

        private void OpenHyperlink(object sender, System.Windows.Input.ExecutedRoutedEventArgs e)
        {
            Process.Start(e.Parameter.ToString());
        }
    }
}
