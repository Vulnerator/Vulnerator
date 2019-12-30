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
        { }

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
                LogWriter.LogError("Unable to retrieve Vulnerator license text.");
                throw exception;
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
                        EmailAlex();
                        break;
                    }
                case "emailJeffvTextBox":
                    {
                        EmailJeffV();
                        break;
                    }
                case "emailRickTextBox":
                    {
                        EmailRick();
                        break;
                    }
                case "emailJeffpTextBox":
                    {
                        EmailJeffP();
                        break;
                    }
                default:
                    { break; }
            }
        }

        private void EmailAlex()
        {
            string mailTo = "mailto:alex.kuchta@navy.mil";
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

        private void EmailJeffV()
        {
            string mailTo = "mailto:Jeff.Vanerwegen@Vencore.com";
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

        private void EmailRick()
        {
            string mailTo = "mailto:rick.murphy@navy.mil";
            try
            { Process.Start(mailTo); }
            catch (Exception exception)
            {
                string error = "Unable to send email; no email application exists.";
                LogWriter.LogErrorWithDebug(error, exception);
                NoEmailApplication emailWarning = new NoEmailApplication();
                emailWarning.ShowDialog();
                return;
            }
        }

        private void EmailJeffP()
        {
            string mailTo = "mailto:jeffrey.a.purcell@navy.mil";
            try
            { Process.Start(mailTo); }
            catch (Exception exception)
            {
                string error = "Unable to send email; no email application exists.";
                LogWriter.LogErrorWithDebug(error, exception);
                NoEmailApplication emailWarning = new NoEmailApplication();
                emailWarning.ShowDialog();
                return;
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
                return;
            }
        }
    }
}
