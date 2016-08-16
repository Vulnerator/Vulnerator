using log4net;
using System;
using System.Windows.Input;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class Release
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public string Name { get; set; }
        public string TagName { get; set; }
        public string HtmlUrl { get; set; }
        public string CreatedAt { get; set; }
        public int Downloads { get; set; }

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
}
