using log4net;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Windows.Input;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class Issue
    {
        public string Title { get; set; }
        public int Number { get; set; }
        public string Body { get; set; }
        public string HtmlUrl { get; set; }
        public string Milestone { get; set; }
        public int Comments { get; set; }
        public List<Label> Labels = new List<Label>();
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public ICommand GitHubLinksCommand
        { get { return new DelegateCommand(GitHubLinks); } }

        private void GitHubLinks(object param)
        {
            try
            { System.Diagnostics.Process.Start(GetDefaultBrowserPath(), param.ToString()); }
            catch (Exception exception)
            {
                log.Error("Unable to obtain launch GitHub link; no internet application exists.");
                log.Debug("Exception details: " + exception);
                View.NoInternetApplication internetWarning = new View.NoInternetApplication();
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

    public class Label
    {
        public string Color { get; set; }
        public string Name { get; set; }
    }
}
