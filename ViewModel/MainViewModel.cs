using Enterwell.Clients.Wpf.Notifications;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using log4net;
using MahApps.Metro;
using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Vulnerator.Helper;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using Vulnerator.View.UI;
using Vulnerator.ViewModel.ViewModelHelper;
using Logger = Vulnerator.Helper.Logger;

namespace Vulnerator.ViewModel
{
    /// <summary>
    /// This class contains properties that the main View can data bind to.
    /// <para>
    /// Use the <strong>mvvminpc</strong> snippet to add bindable properties to this ViewModel.
    /// </para>
    /// <para>
    /// You can also use Blend to data bind with the tool's support.
    /// </para>
    /// <para>
    /// See http://www.galasoft.ch/mvvm
    /// </para>
    /// </summary>
    public class MainViewModel : ViewModelBase
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private AsyncObservableCollection<Release> ReleaseList;
        private BackgroundWorker backgroundWorker;
        private DatabaseBuilder databaseBuilder;
        private GitHubActions githubActions;
        public INotificationMessageManager NotificationMessageManager { get; set; } = new NotificationMessageManager();
        public Logger logger = new Logger();

        public string ApplicationVersion
        {
            get
            {
                Assembly assembly = Assembly.GetExecutingAssembly();
                return FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion.ToString();
            }
        }

        private string _newVersionText = "Update Info Unavailable";

        /// <summary>
        /// String to notify users of new application version(s) available for download
        /// </summary>
        public string NewVersionText
        {
            get => _newVersionText;
            set
            {
                if (_newVersionText != value)
                {
                    _newVersionText = value;
                    RaisePropertyChanged("NewVersionText");
                }
            }
        }

        private string _newVersionVisibility = "Collapsed";
        public string NewVersionVisibility
        {
            get => _newVersionVisibility;
            set
            {
                if (_newVersionVisibility != value)
                {
                    _newVersionVisibility = value;
                    RaisePropertyChanged("NewVersionVisibility");
                }
            }
        }

        private string _progressLabelText = "Awaiting Execution";
        public string ProgressLabelText
        {
            get => _progressLabelText;
            set
            {
                if (_progressLabelText != value)
                {
                    _progressLabelText = value;
                    RaisePropertyChanged("ProgressLabelText");
                }
            }
        }

        private string _progressRingVisibility = "Collapsed";
        public string ProgressRingVisibility
        {
            get => _progressRingVisibility;
            set
            {
                if (_progressRingVisibility != value)
                {
                    _progressRingVisibility = value;
                    RaisePropertyChanged("ProgressRingVisibility");
                }
            }
        }

        private bool _isEnabled = true;
        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                if (_isEnabled != value)
                {
                    _isEnabled = value;
                    RaisePropertyChanged("IsEnabled");
                }
            }
        }

        private Release _release = new Release();
        public Release Release
        {
            get => _release;
            set
            {
                if (_release != value)
                {
                    _release = value;
                    RaisePropertyChanged("Release");
                }
            }
        }

        /// <summary>
        /// Initializes a new instance of the MainViewModel class.
        /// </summary>
        public MainViewModel()
        {
            try
            {
                logger.Setup();
                LogWriter.LogStatusUpdate("'Logger' successfully initialized.");
                LogWriter.LogStatusUpdate("Initializing 'MainViewModel'.");
                githubActions = new GitHubActions();
                databaseBuilder = new DatabaseBuilder();
                VersionTest();
                Properties.Settings.Default.ActiveUser = Environment.UserName;
                Messenger.Default.Register<GuiFeedback>(this, (guiFeedback) => UpdateGui(guiFeedback));
                LogWriter.LogStatusUpdate("'UpdateGui' Messenger registered.");
                Messenger.Default.Register<string>(this, (databaseLocation) => InstantiateNewDatabase(databaseLocation));
                LogWriter.LogStatusUpdate("'InstantiateNewDatabase' Messenger registered.");
                Messenger.Default.Register<Notification>(this, (notification) => GenerateNotification(notification));
                LogWriter.LogStatusUpdate("'GenerateNotification' Messenger registered.");
                LogWriter.LogStatusUpdate("'MainViewModel' successfully initialized.");
            }
            catch (Exception exception)
            {
                string error = "Unable to initialize 'MainViewModel'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void UpdateGui(GuiFeedback guiFeedback)
        {
            try
            {
                ProgressLabelText = guiFeedback.ProgressLabelText;
                ProgressRingVisibility = guiFeedback.ProgressRingVisibility;
                IsEnabled = guiFeedback.IsEnabled;
            }
            catch (Exception exception)
            {
                string error = "Unable to update the GUI.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void InstantiateNewDatabase(string databaseLocation)
        { 
            try
            {
                LogWriter.LogStatusUpdate($"Instantiating new database at '{databaseLocation}'.");
                Properties.Settings.Default.Database = databaseLocation;
                DatabaseBuilder.databaseConnection = string.Format(@"Data Source = {0}; Version=3;", Properties.Settings.Default.Database);
                DatabaseBuilder.sqliteConnection = new System.Data.SQLite.SQLiteConnection(DatabaseBuilder.databaseConnection);
                databaseBuilder = new DatabaseBuilder();
                LogWriter.LogStatusUpdate($"Database instantiated at '{databaseLocation}'.");
            }
            catch (Exception exception)
            {
                string error = $"Unable to instantiate database at '{databaseLocation}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void VersionTest()
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += versionTestBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerAsync();
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to generate 'VersionTest' BackgroundWorker.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private async void versionTestBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                LogWriter.LogStatusUpdate("Obtaining latest available release information.");
                Release = await githubActions.GetLatestGitHubRelease();
                if (Release.TagName == "Unavailable")
                { return; }
                else
                {
                    int releaseVersion = int.Parse(Release.TagName.Replace("v", "").Replace(".", ""));
                    int currentVersion = int.Parse(ApplicationVersion.Replace(".", ""));
                    if (releaseVersion > currentVersion)
                    {
                        NewVersionText = "New Version Available: " + Release.TagName;
                        NewVersionVisibility = "Visible";
                    }
                    else
                    { NewVersionText = "Running Latest Version"; }
                }
                LogWriter.LogStatusUpdate("Latest available release information obtained, parsed, and presented successfully.");
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain application version update information.");
                throw exception;
            }
        }

        public RelayCommand<object> GetLatestVersionCommand => new RelayCommand<object>(GetLatestVersion);

        private void GetLatestVersion(object param)
        { WebNavigate(param.ToString()); }

        public RelayCommand<object> AboutLinksCommand => new RelayCommand<object>(AboutLinks);

        private void AboutLinks(object param)
        {
            string p = param.ToString();

            switch (p)
            {
                case "projectButton":
                    {
                        WebNavigate("https://vulnerator.github.io/Vulnerator");
                        break;
                    }
                case "wikiButton":
                    {
                        WebNavigate("https://github.com/Vulnerator/Vulnerator/wiki");
                        break;
                    }
                case "githubButton":
                    {
                        WebNavigate("https://github.com/Vulnerator/Vulnerator");
                        break;
                    }
                case "issueButton":
                    {
                        WebNavigate("https://github.com/Vulnerator/Vulnerator/issues");
                        break;
                    }
                case "gitterButton":
                    {
                        WebNavigate("https://gitter.im/Vulnerator/Vulnerator");
                        break;
                    }
                case "slackButton":
                    {
                        WebNavigate("https://join.slack.com/t/vulnerator-chat/shared_invite/enQtODcwMTkxMzI2NjQ3LTg0YzFjMjg0NjJkODkzMTIyNTgyN2I0ZDczYmQwMmFhODQyOWI4MDEyODU2MjJmM2ZkNDZiYzNmZjM0NzQ1ODQ");
                        break;
                    }
                default:
                    { break; }
            }
        }

        private void WebNavigate(string webPage)
        {
            try
            { Process.Start(GetDefaultBrowserPath(), webPage); }
            catch (Exception exception)
            {
                string error = $"Unable to navigate to {webPage}; no internet application exists.";
                LogWriter.LogErrorWithDebug(error, exception);
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
            }
        }

        public RelayCommand LaunchStigNotificationCommand => new RelayCommand(LaunchStigNotification);

        private void LaunchStigNotification()
        {
            try
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                Notification notification = new Notification
                {
                    Accent = appStyle.Item2.Resources["AccentColorBrush"].ToString(),
                    Background = appStyle.Item1.Resources["WindowBackgroundBrush"].ToString(),
                    Badge = "Info",
                    Foreground = appStyle.Item1.Resources["TextBrush"].ToString(),
                    Header = "STIG Library",
                    Message = "Please ingest the latest STIG Compilation Library on the settings page.",
                    AdditionalContentBottom = new Border
                    {
                        BorderThickness = new Thickness(0, 1, 0, 0),
                        BorderBrush = appStyle.Item1.Resources["GrayBrush7"] as SolidColorBrush,
                        Child = new CheckBox
                        {
                            Margin = new Thickness(12, 8, 12, 8),
                            HorizontalAlignment = HorizontalAlignment.Left,
                            Foreground = appStyle.Item1.Resources["TextBrush"] as SolidColorBrush,
                            Content = "Do not display this in the future."
                        }
                    }
                };
                GenerateNotification(notification);
            }
            catch (Exception exception)
            {
                string error = "Unable to display STIG Library ingestion notification.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void GenerateNotification(Notification notification)
        { 
            try
            {
                NotificationMessageManager.CreateMessage()
                    .Accent(notification.Accent)
                    .Background(notification.Background)
                    .Foreground(notification.Foreground)
                    .Animates(true)
                    .AnimationInDuration(0.25)
                    .AnimationOutDuration(0.25)
                    .HasBadge(notification.Badge)
                    .HasHeader(notification.Header)
                    .HasMessage(notification.Message)
                    .Dismiss().WithButton("Dismiss", button => { })
                    //.WithAdditionalContent(ContentLocation.Bottom,
                    //    new Border
                    //    {
                    //        BorderThickness = new Thickness(0,1,0,0),
                    //        BorderBrush = ThemeManager.DetectAppStyle(Application.Current).Item1.Resources["GrayBrush7"] as SolidColorBrush,
                    //        Child = new CheckBox
                    //        {
                    //            Margin = new Thickness(12,8,12,8),
                    //            HorizontalAlignment = HorizontalAlignment.Left,
                    //            Foreground = ThemeManager.DetectAppStyle(Application.Current).Item1.Resources["TextBrush"] as SolidColorBrush,
                    //            Content = "Do not display this in the future."
                    //        }
                    //    }
                    //)
                    .Queue();
            }
            catch (Exception exception)
            {
                string error = $"Unable to generate '{notification.Header}' notification";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public static string GetDefaultBrowserPath()
        {
            string urlAssociation = @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http";
            string browserPathKey = @"$BROWSER$\shell\open\command";

            try
            {
                RegistryKey userChoiceKey = Registry.CurrentUser.OpenSubKey(urlAssociation + @"\UserChoice", false);

                if (userChoiceKey == null)
                {
                    var browserKey = Registry.ClassesRoot.OpenSubKey(@"HTTP\shell\open\command", false);
                    if (browserKey == null)
                    {
                        browserKey =
                            Registry.CurrentUser.OpenSubKey(
                                urlAssociation, false);
                    }

                    var path = SanitizeBrowserPath(browserKey.GetValue(null) as string);
                    browserKey.Close();
                    return path;
                }
                else
                {
                    string progId = (userChoiceKey.GetValue("ProgId").ToString());
                    userChoiceKey.Close();
                    string concreteBrowserKey = browserPathKey.Replace("$BROWSER$", progId);
                    var kp = Registry.ClassesRoot.OpenSubKey(concreteBrowserKey, false);
                    string browserPath = SanitizeBrowserPath(kp.GetValue(null) as string);
                    kp.Close();
                    return browserPath;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain default browser information.");
                throw exception;
            }
        }

        private static string SanitizeBrowserPath(string path)
        {
            try
            {
                string[] url = path.Split('"');
                string clean = url[1];
                return clean;
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to sanitize browser path '{path}'");
                throw exception;
            }
        }
    }
}