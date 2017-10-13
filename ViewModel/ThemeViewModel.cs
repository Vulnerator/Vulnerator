using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using MahApps.Metro;
using System;
using System.Windows;
using System.Windows.Media;

namespace Vulnerator.ViewModel
{
    public class ThemeViewModel : ViewModelBase
    {
        private bool _themeChecked;
        public bool ThemeChecked
        {
            get { return _themeChecked; }
            set
            {
                if (_themeChecked != value)
                {
                    _themeChecked = value;
                    RaisePropertyChanged("ThemeChecked");
                }
            }
        }

        public ThemeViewModel()
        {
            ThemeManager.AddAppTheme("PowerShellDark", new Uri("pack://application:,,,/Vulnerator;component/View/Theme/PowerShellDark.xaml"));
            SetTheme(Properties.Settings.Default["Theme"].ToString());
            SetAccent(Properties.Settings.Default["Accent"].ToString());
        }

        private void SetTheme(string theme)
        {
            Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
            ThemeManager.ChangeAppStyle(Application.Current, appStyle.Item2, ThemeManager.GetAppTheme(theme));
            ThemeChecked = theme.Equals("BaseLight") ? false : true;
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
            Properties.Settings.Default["Theme"] = theme;
        }

        public RelayCommand<object> ChangeAccentCommand
        { get { return new RelayCommand<object>((p) => ChangeAccent(p)); } }
        private void ChangeAccent(object parameter)
        {
            Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
            ThemeManager.ChangeAppStyle(Application.Current, ThemeManager.GetAccent(parameter.ToString()), appStyle.Item1);
            Properties.Settings.Default["Accent"] = parameter.ToString();
        }
    }
}
