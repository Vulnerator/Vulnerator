using System.Windows.Controls;
using System.Diagnostics;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Interaction logic for UserGuideView.xaml
    /// </summary>
    public partial class UserGuideView : UserControl
    {
        public UserGuideView()
        {
            InitializeComponent();
        }

        private void OpenHyperlink(object sender, System.Windows.Input.ExecutedRoutedEventArgs e)
        {
            // Only open web links; in-page anchors and relative paths have nothing to open.
            string target = e.Parameter?.ToString() ?? string.Empty;
            if (!target.StartsWith("https://", System.StringComparison.OrdinalIgnoreCase) &&
                !target.StartsWith("http://", System.StringComparison.OrdinalIgnoreCase))
            { return; }
            try
            { Process.Start(target); }
            catch (System.Exception exception)
            { Vulnerator.Helper.LogWriter.LogErrorWithDebug($"Unable to open link '{target}'.", exception); }
        }
    }
}
