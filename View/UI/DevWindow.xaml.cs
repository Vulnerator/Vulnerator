using System;
using System.ComponentModel;
using Vulnerator.View.ViewHelper;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Interaction logic for DevWindow.xaml
    /// </summary>
    public partial class DevWindow
    {
        public DevWindow()
        {
            InitializeComponent();
            Uri xmlPath = new Uri(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Vulnerator\Vulnerator_Config.xml");

            MyXmlDataProvider myXmlDataProvider = Resources["XmlConfig"] as MyXmlDataProvider;
            if (myXmlDataProvider != null)
            {
                myXmlDataProvider.Source = xmlPath;
                myXmlDataProvider.XPath = "preferencesRoot";
            }
        }
    }
}
