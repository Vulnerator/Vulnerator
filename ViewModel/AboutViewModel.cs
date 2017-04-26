using GalaSoft.MvvmLight;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;

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

        public string License
        {
            get
            { return GetLicenseText(); }
        }

        public AboutViewModel()
        { }

        private string GetLicenseText()
        {
            string licenseText = string.Empty;
            using (Stream stream = assembly.GetManifestResourceStream("Vulnerator.LICENSE"))
            {
                using (StreamReader streamReader = new StreamReader(stream))
                {
                    licenseText = streamReader.ReadToEnd();
                    licenseText = licenseText.Replace("(c)", "©");
                    licenseText = Regex.Replace(licenseText, "\r\n", " ");
                    licenseText = Regex.Replace(licenseText, "  ", "\r\n\r\n");
                }
            }
            return licenseText;
        }
    }
}
