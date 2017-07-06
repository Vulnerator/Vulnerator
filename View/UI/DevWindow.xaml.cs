using System;
using System.ComponentModel;
using System.Threading;
using System.Windows;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Interaction logic for DevWindow.xaml
    /// </summary>
    public partial class DevWindow
    {
        public DevWindow()
        {
            InitializeComponent();
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);

            Application.Current.Shutdown();
        }
    }
}
