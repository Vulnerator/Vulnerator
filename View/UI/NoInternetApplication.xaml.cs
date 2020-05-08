using System.Windows;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Interaction logic for NoInternetApplication.xaml
    /// </summary>
    public partial class NoInternetApplication
    {
        public NoInternetApplication()
        {
            InitializeComponent();
        }

        private void CloseClick(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
