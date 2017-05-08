using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace Vulnerator
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        public App()
        {
            DispatcherUnhandledException += new System.Windows.Threading.DispatcherUnhandledExceptionEventHandler(App_DispatcherUnhandledException);
            Startup += new StartupEventHandler(App_Startup);
            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            // hook on error before app really starts
            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
            Vulnerator.Properties.Settings.Default.Upgrade();
            Vulnerator.Properties.Settings.Default.Save();
            base.OnStartup(e);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            Vulnerator.Properties.Settings.Default.Save();
            base.OnExit(e);
        }

        void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            // put your tracing or logging code here (I put a message box as an example)
            ProcessError(e.ExceptionObject as Exception);
            MessageBox.Show(e.ExceptionObject.ToString(), "Goodbye, World!");
        }


        void App_DispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            ProcessError(e.Exception);
            e.Handled = true;
        }

        void App_Startup(object sender, StartupEventArgs e)
        { AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException; }

        void TaskScheduler_UnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            ProcessError(e.Exception);
            ProcessError();
            e.SetObserved();
        }

        [Conditional("DEBUG")]
        private void ProcessError(Exception exception)
        {
            var error = "Exception = " + exception.Message;

            while (exception.InnerException != null)
            {
                exception = exception.InnerException;
                error += " : Inner Exception = " + exception.Message;
            }

            string logPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string logFile = logPath + @"\Vulnerator_v6_StartupErrorLog.txt";
            string _exception = exception.ToString();

            if (!Directory.Exists(logPath))
            { Directory.CreateDirectory(logPath); }

            try
            {
                using (FileStream fs = new FileStream(logFile, FileMode.Append, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.WriteLine(DateTime.Now);
                    sw.WriteLine(exception);
                    sw.WriteLine(Environment.NewLine);
                    sw.Close();
                }
            }
            catch
            { return; }

            MessageBox.Show(error);
        }

        [Conditional("RELEASE")]
        private void ProcessError()
        {
            MessageBox.Show(@"The application has encountered an error; please notify the developer via the GitHub site at https://github.com/Vulnerator/Vulnerator", 
                "Application Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
