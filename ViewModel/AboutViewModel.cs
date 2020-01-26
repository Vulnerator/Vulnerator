using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using log4net;
using System.Diagnostics;
using System;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using Vulnerator.Helper;
using Vulnerator.Model.Object;
using Vulnerator.View.UI;

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
                return
                    $"{FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion.ToString()}{Properties.Settings.Default.VersionMetaData}";
            }
        }

        public string License => GetLicenseText();

        public AboutViewModel()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of AboutViewModel.");
                LogWriter.LogStatusUpdate("AboutViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate AboutViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private string GetLicenseText()
        {
            try
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
            catch (Exception exception)
            {
                string error = "Unable to retrieve Vulnerator license text.";
                LogWriter.LogErrorWithDebug(error, exception);
                return string.Empty;
            }
        }

        public RelayCommand<object> AboutLinksCommand => new RelayCommand<object>(AboutLinks);

        private void AboutLinks(object param)
        {
            string p = param.ToString();

            switch (p)
            {
                case "emailAlexTextBox":
                    {
                        EmailDeveloper("alex.kuchta@navy.mil");
                        break;
                    }
                case "emailJeffvTextBox":
                    {
                        EmailDeveloper("Jeff.Vanerwegen@Vencore.com");
                        break;
                    }
                case "emailRickTextBox":
                    {
                        EmailDeveloper("rick.murphy@navy.mil");
                        break;
                    }
                case "emailJeffpTextBox":
                    {
                        EmailDeveloper("jeffrey.a.purcell@navy.mil");
                        break;
                    }
                default:
                    { break; }
            }
        }

        private void EmailDeveloper(string email)
        {
            string mailTo = $"mailto:{email}";
            try
            { Process.Start(mailTo); }
            catch (Exception exception)
            {
                string error = "Unable to send email; no email application exists.";
                LogWriter.LogErrorWithDebug(error, exception);
                NoEmailApplication emailWarning = new NoEmailApplication();
                emailWarning.ShowDialog();
            }
        }
    }
}
