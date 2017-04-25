using GalaSoft.MvvmLight;
using log4net;
using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Input;
using System.Xml;
using System.Xml.Linq;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;
using Microsoft.EntityFrameworkCore;

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
            configAlter = new ConfigAlter();
            configAlter.CreateConfigurationXml();
            configAlter.CreateSettingsDictionary();
            githubActions = new GitHubActions();
            VersionTest();
        }

        ~MainViewModel()
        { configAlter.WriteSettingsToConfigurationXml(); }

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
    }
}