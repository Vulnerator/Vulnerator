using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using log4net;
using System.Diagnostics;
using System;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using Vulnerator.Model.Object;
using Vulnerator.View.UI;

namespace Vulnerator.ViewModel
{
    public class AboutViewModel : ViewModelBase
    {
        public static readonly ILog log = LogManager.GetLogger(typeof(Logger));
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
                log.Error("Unable to send email; no email application exists.");
                NoEmailApplication emailWarning = new NoEmailApplication();
                emailWarning.ShowDialog();
                return;
            }
        }

        private void EmailJeffV()
        {
            string mailTo = "mailto:Jeff.Vanerwegen@Vencore.com";
            try
            { Process.Start(mailTo); }
            catch (Exception exception)
            {
                log.Error("Unable to send email; no email application exists.");
                NoEmailApplication emailWarning = new NoEmailApplication();
                emailWarning.ShowDialog();
                return;
            }
        }

        private void EmailRick()
        {
            string mailTo = "mailto:rick.murphy@navy.mil";
            try
            { Process.Start(mailTo); }
            catch (Exception exception)
            {
                log.Error("Unable to send email; no email application exists.");
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
                log.Error("Unable to send email; no email application exists.");
                NoEmailApplication emailWarning = new NoEmailApplication();
                emailWarning.ShowDialog();
                return;
            }
        }
    }
}
