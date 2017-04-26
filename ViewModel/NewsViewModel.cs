using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using Vulnerator.Model.Object;
using System;
using log4net;
using Microsoft.Win32;
using Vulnerator.View.UI;

namespace Vulnerator.ViewModel
{
    public class NewsViewModel : ViewModelBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private GitHubActions githubActions = new GitHubActions();
        private AsyncObservableCollection<Issue> _issueList;
        public AsyncObservableCollection<Issue> IssueList
        {
            get { return _issueList; }
            set
            {
                if (_issueList != value)
                {
                    _issueList = value;
                    RaisePropertyChanged("IssueList");
                }
            }
        }

        private AsyncObservableCollection<Release> _releaseList;
        public AsyncObservableCollection<Release> ReleaseList
        {
            get { return _releaseList; }
            set
            {
                if (_releaseList != value)
                {
                    _releaseList = value;
                    RaisePropertyChanged("ReleaseList");
                }
            }
        }
        public NewsViewModel()
        {
            IssueList = new AsyncObservableCollection<Issue>();
            ReleaseList = new AsyncObservableCollection<Release>();
            githubActions.GetGitHubIssues(IssueList);
            githubActions.GetGitHubReleases(ReleaseList);
        }

        public RelayCommand<object> GitHubLinksCommand
        { get { return new RelayCommand<object>((p) => GitHubLinks(p)); } }

        private void GitHubLinks(object param)
        {
            try
            { System.Diagnostics.Process.Start(GetDefaultBrowserPath(), param.ToString()); }
            catch (Exception exception)
            {
                log.Error("Unable to obtain launch GitHub link; no internet application exists.");
                log.Debug("Exception details: " + exception);
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        private static string GetDefaultBrowserPath()
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
