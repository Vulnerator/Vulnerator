using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using MahApps.Metro;
using System;
using System.Windows;
using Vulnerator.Model.BusinessLogic;

namespace Vulnerator.ViewModel
{
    public class ThemeViewModel : ViewModelBase
    {
        public ThemeViewModel()
        {
            SetTheme(ConfigAlter.ReadSettingsFromDictionary("currentTheme"));
            SetAccent(ConfigAlter.ReadSettingsFromDictionary("currentAccent"));
        }

        private void SetTheme(string theme)
        {
            Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
            var oldTheme = ThemeManager.DetectAppStyle(Application.Current);
            ThemeManager.ChangeAppStyle(Application.Current, appStyle.Item2, ThemeManager.GetAppTheme(theme));
        }

        private void SetAccent(string accent)
        {
            Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
            ThemeManager.ChangeAppStyle(Application.Current, ThemeManager.GetAccent(accent), appStyle.Item1);
        }

        public RelayCommand<object> ChangeThemeCommand
        { get { return new RelayCommand<object>((p) => ChangeTheme(p)); } }
        private void ChangeTheme(object parameter)
        {
            string theme = (bool)parameter == true ? "BaseLight" : "BaseDark";
            Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
            ThemeManager.ChangeAppStyle(Application.Current, appStyle.Item2, ThemeManager.GetAppTheme(theme));
            ConfigAlter.WriteSettingsToDictionary("currentTheme", theme);
        }

        public RelayCommand<object> ChangeAccentCommand
        { get { return new RelayCommand<object>((p) => ChangeAccent(p)); } }
        private void ChangeAccent(object parameter)
        {
            Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
            ThemeManager.ChangeAppStyle(Application.Current, ThemeManager.GetAccent(parameter.ToString()), appStyle.Item1);
            ConfigAlter.WriteSettingsToDictionary("currentAccent", parameter.ToString());
        }
    }
}
