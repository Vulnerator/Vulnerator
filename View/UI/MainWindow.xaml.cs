using System;
using System.ComponentModel;
using System.Threading;
using System.Windows;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        //LoadingWindow loadingWindow;

        public MainWindow()
        {
            // TODO: Implement LoadingWindow after updating MA.M library
            //Thread loadingThread = new Thread(ThreadStartingPoint);
            //loadingThread.SetApartmentState(ApartmentState.STA);
            //loadingThread.IsBackground = true;
            //loadingThread.Start();
            //InitializeComponent();
            //loadingThread.Abort();
        }

        private void ThreadStartingPoint()
        {
            //loadingWindow = new LoadingWindow();
            //loadingWindow.Show();       
            //System.Windows.Threading.Dispatcher.Run();
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);

            Application.Current.Shutdown();
        }
    }
}
