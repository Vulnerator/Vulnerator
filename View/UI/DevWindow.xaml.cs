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
        BackgroundWorker backgroundWorker;
        LoadingWindow loadingWindow;
        public DevWindow()
        {
            InitializeComponent();
            //backgroundWorker = new BackgroundWorker();
            //loadingWindow = new LoadingWindow();
            //loadingWindow.Show();
            //backgroundWorker.RunWorkerAsync();
            //backgroundWorker.DoWork += new DoWorkEventHandler(backgroundWorker_DoWork);
            //backgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(backgroundWorker_RunWorkerCompleted);
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);

            Application.Current.Shutdown();
        }

        void backgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        { System.Threading.Thread.Sleep(5000); }

        void backgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        { loadingWindow.Close(); }
    }
}
