using System.Windows;

namespace Vulnerator.View
{
    /// <summary>
    /// Interaction logic for NoEmailApplication.xaml
    /// </summary>
    public partial class NoEmailApplication
    {
        public NoEmailApplication()
        {
            InitializeComponent();
        }

        private void CloseClick(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
