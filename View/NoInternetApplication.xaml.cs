using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Vulnerator.View
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
            this.Close();
        }
    }
}
