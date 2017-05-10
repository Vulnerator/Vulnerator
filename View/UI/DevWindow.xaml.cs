using System;
using System.ComponentModel;
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
            backgroundWorker = new BackgroundWorker();
            backgroundWorker.DoWork += new DoWorkEventHandler(backgroundWorker_DoWork);
            backgroundWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(backgroundWorker_RunWorkerCompleted);
            InitializeComponent();
            //Uri xmlPath = new Uri(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Vulnerator\Vulnerator_Config.xml");

            //MyXmlDataProvider myXmlDataProvider = Resources["XmlConfig"] as MyXmlDataProvider;
            //if (myXmlDataProvider != null)
            //{
            //    myXmlDataProvider.Source = xmlPath;
            //    myXmlDataProvider.XPath = "preferencesRoot";
            //}
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);

            Application.Current.Shutdown();
        }

        void backgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        { System.Threading.Thread.Sleep(10000); }

        void backgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        { loadingWindow.Hide(); }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            loadingWindow = new LoadingWindow();
            loadingWindow.Show();
            backgroundWorker.RunWorkerAsync();
        }
    }
}
