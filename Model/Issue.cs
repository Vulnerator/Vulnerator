using log4net;
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
            { System.Diagnostics.Process.Start(param.ToString()); }
            catch (Exception exception)
            {
                log.Error("Unable to obtain launch GitHub link due to a lack of internet connection.");
                log.Debug("Exception details: " + exception);
                View.NoInternetApplication internetWarning = new View.NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }
    }

    public class Label
    {
        public string Color { get; set; }
        public string Name { get; set; }
    }
}
