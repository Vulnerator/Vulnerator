using GalaSoft.MvvmLight;
using System.Diagnostics;
using System.Reflection;

namespace Vulnerator.ViewModel
{
    public class AboutViewModel : ViewModelBase
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        public string ApplicationVersion
        {
            get
            {
                Assembly assembly = Assembly.GetExecutingAssembly();
                return FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion.ToString();
            }
        }

        public AboutViewModel()
        { }
    }
}
