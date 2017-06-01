using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using log4net;
using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
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
        private GitHubActions githubActions;
        private ConfigAlter configAlter;
        private BackgroundWorker backgroundWorker;
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private AsyncObservableCollection<Release> ReleaseList;
        private DatabaseBuilder databaseBuilder;
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
            logger.Setup();
            log.Info("Initializing application.");
            configAlter = new ConfigAlter();
            configAlter.CreateConfigurationXml();
            configAlter.CreateSettingsDictionary();
            githubActions = new GitHubActions();
            databaseBuilder = new DatabaseBuilder();
            VersionTest();
            Messenger.Default.Register<GuiFeedback>(this, (guiFeedback) => UpdateGui(guiFeedback));
        }

        ~MainViewModel()
        { configAlter.WriteSettingsToConfigurationXml(); }

        private void UpdateGui(GuiFeedback guiFeedback)
        {
            ProgressLabelText = guiFeedback.ProgressLabelText;
            ProgressRingVisibility = guiFeedback.ProgressRingVisibility;
            IsEnabled = guiFeedback.IsEnabled;
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