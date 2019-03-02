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
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using Vulnerator.View.UI;
using Vulnerator.ViewModel.ViewModelHelper;

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
        private ConfigAlter configAlter;
        private DatabaseBuilder databaseBuilder;
        private GitHubActions githubActions;
        public INotificationMessageManager NotificationMessageManager { get; set; } = new NotificationMessageManager();
        public Logger logger = new Logger();
        public static readonly ILog log = LogManager.GetLogger(typeof(Logger));

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
            get { return _newVersionText; }
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
            get { return _newVersionVisibility; }
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
            get { return _progressLabelText; }
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
            get { return _progressRingVisibility; }
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
            get { return _isEnabled; }
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
            get { return _release; }
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
                log.Info("Initializing application.");
                githubActions = new GitHubActions();
                databaseBuilder = new DatabaseBuilder();
                VersionTest();
                Properties.Settings.Default.ActiveUser = Environment.UserName;
                Messenger.Default.Register<GuiFeedback>(this, (guiFeedback) => UpdateGui(guiFeedback));
                Messenger.Default.Register<string>(this, (databaseLocation) => InstantiateNewDatabase(databaseLocation));
                Messenger.Default.Register<Notification>(this, (notification) => GenerateNotification(notification));
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate MainViewModel."));
                log.Debug("Exception details:", exception);
            }
        }

        private void UpdateGui(GuiFeedback guiFeedback)
        {
            ProgressLabelText = guiFeedback.ProgressLabelText;
            ProgressRingVisibility = guiFeedback.ProgressRingVisibility;
            IsEnabled = guiFeedback.IsEnabled;
        }

        private void InstantiateNewDatabase(string databaseLocation)
        { 
            try
            {
                Properties.Settings.Default.Database = databaseLocation;
                DatabaseBuilder.databaseConnection = string.Format(@"Data Source = {0}; Version=3;", Properties.Settings.Default.Database);
                DatabaseBuilder.sqliteConnection = new System.Data.SQLite.SQLiteConnection(DatabaseBuilder.databaseConnection);
                databaseBuilder = new DatabaseBuilder();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate database"));
                log.Debug("Exception details:", exception);
            }
        }

        private void VersionTest()
        {
            backgroundWorker = new BackgroundWorker();
            backgroundWorker.DoWork += versionTestBackgroundWorker_DoWork;
            backgroundWorker.RunWorkerAsync();
            backgroundWorker.Dispose();
        }

        private async void versionTestBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
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
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain version update information.");
                throw exception;
            }
        }

        public RelayCommand<object> GetLatestVersionCommand
        { get { return new RelayCommand<object>(GetLatestVersion); } }

        private void GetLatestVersion(object param)
        {
            try
            { Process.Start(GetDefaultBrowserPath(), param.ToString()); }
            catch (Exception exception)
            {
                log.Error("Unable to obtain launch GitHub link; no internet application exists.");
                log.Debug("Exception details: " + exception);
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        public RelayCommand<object> AboutLinksCommand
        { get { return new RelayCommand<object>(AboutLinks); } }

        private void AboutLinks(object param)
        {
            string p = param.ToString();

            switch (p)
            {
                case "projectButton":
                    {
                        VisitProjectPage();
                        break;
                    }
                case "wikiButton":
                    {
                        VisitWikiPage();
                        break;
                    }
                case "githubButton":
                    {
                        VisitRepo();
                        break;
                    }
                case "issueButton":
                    {
                        VisitIssues();
                        break;
                    }
                case "gitterButton":
                    {
                        VisitGitter();
                        break;
                    }
                case "slackButton":
                    {
                        VisitSlack();
                        break;
                    }
                default:
                    { break; }
            }
        }

        private void VisitProjectPage()
        {
            string goTo = "https://vulnerator.github.io/Vulnerator";
            try
            { Process.Start(GetDefaultBrowserPath(), goTo); }
            catch (Exception exception)
            {
                log.Error("Unable to launch link; no internet application exists.");
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        private void VisitWikiPage()
        {
            string goTo = "https://github.com/Vulnerator/Vulnerator/wiki";
            try
            { Process.Start(GetDefaultBrowserPath(), goTo); }
            catch (Exception exception)
            {
                log.Error("Unable to launch link; no internet application exists.");
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        private void VisitRepo()
        {
            string goTo = "https://github.com/Vulnerator/Vulnerator";
            try
            { Process.Start(GetDefaultBrowserPath(), goTo); }
            catch (Exception exception)
            {
                log.Error("Unable to launch link; no internet application exists.");
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        private void VisitIssues()
        {
            string goTo = "https://github.com/Vulnerator/Vulnerator/issues";
            try
            { Process.Start(GetDefaultBrowserPath(), goTo); }
            catch (Exception exception)
            {
                log.Error("Unable to launch link; no internet application exists.");
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        private void VisitGitter()
        {
            string goTo = "https://gitter.im/Vulnerator/Vulnerator";
            try
            { Process.Start(GetDefaultBrowserPath(), goTo); }
            catch (Exception exception)
            {
                log.Error("Unable to launch link; no internet application exists.");
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        private void VisitSlack()
        {
            // Slack Invite Link, which allows new users to sign up - does not expire
            string goTo = "https://join.slack.com/t/vulnerator-chat/shared_invite/enQtMzQxMzc2MTE0NTI4LWQ1MTVmOGRmZjU4M2UzODU4ZDBhZDk1NGNlY2ZmMjgxNGEzNjUxMmE4OTkwNjQ3NTBhYzU3NmQ2OGI4YjViYzM";
            try
            { Process.Start(GetDefaultBrowserPath(), goTo); }
            catch (Exception exception)
            {
                log.Error("Unable to launch link; no internet application exists.");
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        public RelayCommand LaunchStigNotificationCommand
        { get { return new RelayCommand(LaunchStigNotification); } }

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
                log.Error(string.Format("Unable to launch STIG library ingestion notification."));
                log.Debug("Exception details:", exception);
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
                log.Error(string.Format("Unable to generate notification"));
                throw exception;
            }
        }

        public static string GetDefaultBrowserPath()
        {
            string urlAssociation = @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http";
            string browserPathKey = @"$BROWSER$\shell\open\command";

            RegistryKey userChoiceKey = null;
            string browserPath = "";

            try
            {
                userChoiceKey = Registry.CurrentUser.OpenSubKey(urlAssociation + @"\UserChoice", false);

                if (userChoiceKey == null)
                {
                    var browserKey = Registry.ClassesRoot.OpenSubKey(@"HTTP\shell\open\command", false);
                    if (browserKey == null)
                    {
                        browserKey =
                        Registry.CurrentUser.OpenSubKey(
                        urlAssociation, false);
                    }
                    var path = CleanifyBrowserPath(browserKey.GetValue(null) as string);
                    browserKey.Close();
                    return path;
                }
                else
                {
                    string progId = (userChoiceKey.GetValue("ProgId").ToString());
                    userChoiceKey.Close();
                    string concreteBrowserKey = browserPathKey.Replace("$BROWSER$", progId);
                    var kp = Registry.ClassesRoot.OpenSubKey(concreteBrowserKey, false);
                    browserPath = CleanifyBrowserPath(kp.GetValue(null) as string);
                    kp.Close();
                    return browserPath;
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain default browser data.");
                throw exception;
            }
        }

        private static string CleanifyBrowserPath(string p)
        {
            string[] url = p.Split('"');
            string clean = url[1];
            return clean;
        }
    }
}