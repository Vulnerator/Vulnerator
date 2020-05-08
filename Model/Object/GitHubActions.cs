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
        public async void GetGitHubIssues(AsyncObservableCollection<Issue> issueList)
        {
            try
            {
                if (NetworkInterface.GetIsNetworkAvailable())
                {
                    GitHubClient githubClient = new GitHubClient(new ProductHeaderValue("Vulnerator"));
                    var issues = await githubClient.Issue.GetAllForRepository("Vulnerator", "Vulnerator");
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
                    LogWriter.LogWarning("Github issues are only available if an internet connection is present.");
                    Issue issue = new Issue();
                    issue.Title = "Network connection unavailable";
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
                if (NetworkInterface.GetIsNetworkAvailable())
                {
                    GitHubClient githubClient = new GitHubClient(new ProductHeaderValue("Vulnerator"));
                    var releases = await githubClient.Repository.Release.GetAll("Vulnerator", "Vulnerator");
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
                        release.Downloads = releases[i].Assets[0].DownloadCount;
                        releaseList.Add(release);
                    }
                }
                else
                { LogWriter.LogWarning("GitHub releases are only available if an internet connection is available."); }
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
                if (NetworkInterface.GetIsNetworkAvailable())
                {
                    GitHubClient githubClient = new GitHubClient(new ProductHeaderValue("Vulnerator"));
                    Octokit.Release release = await githubClient.Repository.Release.GetLatest("Vulnerator", "Vulnerator");
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
