using MahApps.Metro;
using MahApps.Metro.Controls.Dialogs;
using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Windows;
using System.Windows.Input;
using Vulnerator.Model;
using Vulnerator.ViewModel;

namespace Vulnerator
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        public MainWindow()
        {
            InitializeComponent();

            Uri xmlPath = new Uri (Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Vulnerator\Vulnerator_Config.xml");

            MyXmlDataProvider myXmlDataProvider = Resources["XmlConfig"] as MyXmlDataProvider;
            if (myXmlDataProvider != null)
            {
                myXmlDataProvider.Source = xmlPath;
                myXmlDataProvider.XPath = "preferencesRoot";
            }
            

            // Set theme at startup
            // TODO: Make more "MVVM-friendly"
            string themeName = ConfigAlter.ReadSettingsFromDictionary("currentTheme");
            string accentName = ConfigAlter.ReadSettingsFromDictionary("currentAccent");
            if (themeName == "Light")
            {
                ThemeManager.ChangeAppStyle(
                    Application.Current, 
                    ThemeManager.GetAccent(accentName), 
                    ThemeManager.GetAppTheme("BaseLight"));
                comboboxTheme.SelectedItem = comboboxitemLightTheme;
            }
            else if (themeName == "Dark")
            {
                ThemeManager.ChangeAppStyle(
                    Application.Current,
                    ThemeManager.GetAccent(accentName),
                    ThemeManager.GetAppTheme("BaseDark"));
                comboboxTheme.SelectedItem = comboboxitemDarkTheme;
            }
            
            // Set accent at startup
            // TODO: Make more "MVVM-friendly"
        }

        #region AccentManager

        // TODO: Make more "MVVM-friendly"
        private void ChangeAccent(string accentName)
        {
            Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
            ThemeManager.ChangeAppStyle(Application.Current, ThemeManager.GetAccent(accentName), appStyle.Item1);
            MainWindowViewModel.configAlter.WriteSettingsToDictionary("currentAccent", accentName);
        }
        
        private void SetAccentColor(object sender, MouseButtonEventArgs e)
        {
            if (sender == rectPink)
            { ChangeAccent("Pink"); }
            else if (sender == rectMagenta)
            { ChangeAccent("Magenta"); }
            else if (sender == rectCrimson)
            { ChangeAccent("Crimson"); }
            else if (sender == rectRed)
            { ChangeAccent("Red"); }
            else if (sender == rectOrange)
            { ChangeAccent("Orange"); }
            else if (sender == rectAmber)
            { ChangeAccent("Amber"); }
            else if (sender == rectYellow)
            { ChangeAccent("Yellow"); }
            else if (sender == rectSienna)
            { ChangeAccent("Sienna"); }
            else if (sender == rectBrown)
            { ChangeAccent("Brown"); }
            else if (sender == rectOlive)
            { ChangeAccent("Olive"); }
            else if (sender == rectLime)
            { ChangeAccent("Lime"); }
            else if (sender == rectGreen)
            { ChangeAccent("Green"); }
            else if (sender == rectEmerald)
            { ChangeAccent("Emerald"); }
            else if (sender == rectTeal)
            { ChangeAccent("Teal"); }
            else if (sender == rectCyan)
            { ChangeAccent("Cyan"); }
            else if (sender == rectSteel)
            { ChangeAccent("Steel"); }
            else if (sender == rectCobalt)
            { ChangeAccent("Cobalt"); }
            else if (sender == rectIndigo)
            { ChangeAccent("Indigo"); }
            else if (sender == rectViolet)
            { ChangeAccent("Violet"); }
            else if (sender == rectMauve)
            { ChangeAccent("Mauve"); }
        }

        #endregion

        #region ThemeManager
        
        // TODO: Make more "MVVM-friendly"
        private void ChangeTheme(object sender, RoutedEventArgs e)
        {
            if (sender == comboboxitemLightTheme)
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                ThemeManager.ChangeAppStyle(Application.Current, appStyle.Item2, ThemeManager.GetAppTheme("BaseLight"));
                MainWindowViewModel.configAlter.WriteSettingsToDictionary("currentTheme", "Light");
                comboboxTheme.SelectedItem = comboboxitemLightTheme;
            }
            else if (sender == comboboxitemDarkTheme)
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                ThemeManager.ChangeAppStyle(Application.Current, appStyle.Item2, ThemeManager.GetAppTheme("BaseDark"));
                MainWindowViewModel.configAlter.WriteSettingsToDictionary("currentTheme", "Dark");
                comboboxTheme.SelectedItem = comboboxitemDarkTheme;
            }
        }

        #endregion
    }
}
