using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using Markdig;
using Vulnerator.Model.Object;
using System;
using log4net;
using Microsoft.Win32;
using Vulnerator.Helper;
using Vulnerator.View.UI;

namespace Vulnerator.ViewModel
{
    public class NewsViewModel : ViewModelBase
    {
        private GitHubActions githubActions = new GitHubActions();
        public MarkdownPipeline MarkdownPipeline = new MarkdownPipelineBuilder()
            .UseAdvancedExtensions()
            .UseEmphasisExtras()
            .UseAutoLinks()
            .UseEmojiAndSmiley()
            .UseTaskLists()
            .Build();

        private AsyncObservableCollection<Issue> _issueList;
        public AsyncObservableCollection<Issue> IssueList
        {
            get => _issueList;
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
            get => _releaseList;
            set
            {
                if (_releaseList != value)
                {
                    _releaseList = value;
                    RaisePropertyChanged("ReleaseList");
                }
            }
        }

        private AsyncObservableCollection<IssueLabelCategory> _issueLabelCategoryList;
        public AsyncObservableCollection<IssueLabelCategory> IssueLabelCategoryList
        {
            get => _issueLabelCategoryList;
            set
            {
                if (_issueLabelCategoryList != value)
                {
                    _issueLabelCategoryList = value;
                    RaisePropertyChanged("IssueLabelCategoryList");
                }
            }
        }

        public NewsViewModel()
        {
            IssueList = new AsyncObservableCollection<Issue>();
            ReleaseList = new AsyncObservableCollection<Release>();
            IssueLabelCategoryList = new AsyncObservableCollection<IssueLabelCategory>();
            PopulateLabelCategoryList();
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
                string error = "Unable to obtain launch GitHub link; no internet application exists.";
                LogWriter.LogErrorWithDebug(error, exception);
                NoInternetApplication internetWarning = new NoInternetApplication();
                internetWarning.ShowDialog();
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
                LogWriter.LogError("Unable to obtain default browser data.");
                throw exception;
            }
        }

        private static string CleanifyBrowserPath(string p)
        {
            string[] url = p.Split('"');
            string clean = url[1];
            return clean;
        }

        private void PopulateLabelCategoryList()
        {
            string[] categoryNames = new string[] { "Issue Type", "Status", "Close Description", "Developer Related", "Level of Effort" };
            string[] categoryColors = new string[] { "#1d76db", "#d4c5f9", "#0e8a16", "#b3f442", "#ff8a05" };

            for (int i = 0; i < categoryNames.Length; i++)
            { IssueLabelCategoryList.Add(new IssueLabelCategory() { Category = categoryNames[i], Color = categoryColors[i] }); }
        }
    }
}
