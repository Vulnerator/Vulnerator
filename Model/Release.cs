using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class Release
    {
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
            {
                System.Diagnostics.Process.Start(param.ToString());
            }
            catch (Exception exception)
            {
                WriteLog.LogWriter(exception, string.Empty);
                View.NoInternetApplication internetWarning = new View.NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }
    }
}
