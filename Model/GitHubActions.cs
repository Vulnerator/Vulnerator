using Octokit;
using System;
using System.Net.NetworkInformation;

namespace Vulnerator.Model
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
                        Issue issue = new Issue();
                        issue.Title = issues[i].Title;
                        issue.Body = issues[i].Body;
                        issue.Number = issues[i].Number;
                        issue.HtmlUrl = issues[i].HtmlUrl.AbsoluteUri;
                        if (issues[i].Milestone != null)
                        { issue.Milestone = issues[i].Milestone.Title; }
                        else
                        { issue.Milestone = @"No Milestone Assigned"; }
                        issue.Comments = issues[i].Comments;
                        foreach (Octokit.Label label in issues[i].Labels)
                        {
                            Label issueLabel = new Label();
                            issueLabel.Color = label.Color;
                            issueLabel.Name = label.Name;
                            issue.Labels.Add(issueLabel);
                        }
                        issueList.Add(issue);
                    }
                }
                else
                {
                    Issue issue = new Issue();
                    issue.Title = "Network connection unavailable";
                    issueList.Add(issue);
                }
            }
            catch (Exception exception)
            {  WriteLog.LogWriter(exception, string.Empty); }
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
                        release.CreatedAt = releases[i].CreatedAt.Date.ToLongDateString();
                        releaseList.Add(release);
                    }
                }
            }
            catch (Exception exception)
            { WriteLog.LogWriter(exception, string.Empty); }
        }
    }
}
