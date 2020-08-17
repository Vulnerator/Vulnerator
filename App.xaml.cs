using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Vulnerator.View.UI;

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
            //AddListeners();
            base.OnStartup(e);
        }

        void Application_Startup(object sender, StartupEventArgs e)
        {
            if (Vulnerator.Properties.Settings.Default["Environment"].ToString().Equals("Undefined"))
            {
                SplashWindow splashWindow = new SplashWindow();
                splashWindow.Show();
            }
            else
            {
                MainWindow mainWindow = new MainWindow();
                mainWindow.Show();
            }
        }

        [Conditional("DEBUG")]
        private void AddListeners()
        {
            PresentationTraceSources.Refresh();
            PresentationTraceSources.DataBindingSource.Listeners.Add(new ConsoleTraceListener());
            PresentationTraceSources.DataBindingSource.Listeners.Add(new DebugTraceListener());
            PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Warning | SourceLevels.Error | SourceLevels.Critical;
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

            if (!Directory.Exists(logPath))
            { Directory.CreateDirectory(logPath); }

            try
            {
                using (FileStream fs = new FileStream(logFile, FileMode.Append, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.WriteLine(DateTime.Now);
                    sw.WriteLine(error);
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

    public class DebugTraceListener : TraceListener
    {
        public override void Write(string message)
        {
        }

        public override void WriteLine(string message)
        {
            Debugger.Break();
        }
    }
}
