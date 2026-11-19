using log4net;
using Markdig;
using Octokit;
using System;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using Vulnerator.Helper;
using Vulnerator.ViewModel;

namespace Vulnerator.Model.Object
{
    public class GitHubActions
    {
        // Vulnerator 2.0 is published from this repository; online checks contact it only when allowed in Settings.
        public const string Owner = "hbonesctr";
        public const string Repository = "Vulnerator";
        public const string RepositoryUrl = "https://github.com/" + Owner + "/" + Repository;

        /// <summary>
        /// Online checks are off unless turned on in Settings: on closed or air-gapped networks a connection
        /// "exists" but GitHub is unreachable, and the tool should not contact the internet unasked.
        /// </summary>
        public static bool OnlineChecksAllowed
        { get { return Properties.Settings.Default.AllowOnlineChecks && NetworkInterface.GetIsNetworkAvailable(); } }

        public async void GetGitHubIssues(AsyncObservableCollection<Issue> issueList)
        {
            try
            {
                if (OnlineChecksAllowed)
                {
                    GitHubClient githubClient = new GitHubClient(new ProductHeaderValue("Vulnerator"));
                    var issues = await githubClient.Issue.GetAllForRepository(Owner, Repository);
                    for (int i = 0; i < issues.Count; i++)
                    {
                        if (issues[i].HtmlUrl.Contains(@"/pull/"))
                        { continue; }
                        Issue issue = new Issue();
                        issue.Title = issues[i].Title;
                        issue.Body = issues[i].Body;
                        issue.Number = issues[i].Number;
                        issue.HtmlUrl = issues[i].HtmlUrl;
                        if (issues[i].Milestone != null)
                        { issue.Milestone = issues[i].Milestone.Title; }
                        else
                        { issue.Milestone = @"N/A"; }
                        issue.Comments = issues[i].Comments;
                        foreach (Octokit.Label label in issues[i].Labels)
                        {
                            Label issueLabel = new Label();
                            issueLabel.Color = "#" + label.Color;
                            issueLabel.Name = label.Name;
                            issue.Labels.Add(issueLabel);
                        }
                        issueList.Add(issue);
                    }
                }
                else
                {
                    LogWriter.LogStatusUpdate("GitHub issues not retrieved: online checks are off (Settings) or no network.");
                    Issue issue = new Issue();
                    issue.Title = "Online checks are off; turn them on in Settings to list GitHub issues";
                    issueList.Add(issue);
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to retrieve GitHub Vulnerator issue listing.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public async void GetGitHubReleases(AsyncObservableCollection<Release> releaseList)
        {
            try
            {
                if (OnlineChecksAllowed)
                {
                    GitHubClient githubClient = new GitHubClient(new ProductHeaderValue("Vulnerator"));
                    var releases = await githubClient.Repository.Release.GetAll(Owner, Repository);
                    for (int i = 0; i < releases.Count; i++)
                    {
                        Release release = new Release();
                        release.Name = releases[i].Name;
                        if (releases[i].TagName != null)
                        { release.TagName = releases[i].TagName; }
                        else
                        { release.TagName = "No Tag Name Assigned"; }
                        release.HtmlUrl = releases[i].HtmlUrl;
                        release.Body = releases[i].Body;
                        release.CreatedAt = releases[i].CreatedAt.Date.ToLongDateString();
                        release.Downloads = releases[i].Assets.Count > 0 ? releases[i].Assets[0].DownloadCount : 0;
                        releaseList.Add(release);
                    }
                }
                else
                { LogWriter.LogStatusUpdate("GitHub releases not retrieved: online checks are off (Settings) or no network."); }
            }
            catch (Exception exception)
            {
                string error = "Unable to retrieve GitHub Vulnerator release listing.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public async Task<Release> GetLatestGitHubRelease()
        {
            Release _release = new Release();

            try
            {
                if (OnlineChecksAllowed)
                {
                    GitHubClient githubClient = new GitHubClient(new ProductHeaderValue("Vulnerator"));
                    Octokit.Release release = await githubClient.Repository.Release.GetLatest(Owner, Repository).ConfigureAwait(false);
                    _release.TagName = release.TagName;
                    _release.HtmlUrl = release.HtmlUrl;
                }
                else
                { _release.TagName = "Unavailable"; }
                return _release;
            }
            catch (Exception exception)
            {
                string error = "Unable to retrieve GitHub Vulnerator release listing.";
                LogWriter.LogErrorWithDebug(error, exception);
                _release.TagName = "Unavailable";
                return _release;
            }
        }
    }
}
