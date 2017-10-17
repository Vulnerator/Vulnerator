using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using log4net;
using MahApps.Metro;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using Vulnerator.Model.Object;

namespace Vulnerator.ViewModel
{
    public class ThemeViewModel : ViewModelBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

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

        private List<ThemeDefinition> _themes { get; set; }
        public List<ThemeDefinition> Themes
        {
            get { return _themes; }
            set
            {
                if (_themes != value)
                {
                    _themes = value;
                    RaisePropertyChanged("Themes");
                }
            }
        }

        private ThemeDefinition _selectedTheme { get; set; }
        public ThemeDefinition SelectedTheme
        {
            get { return _selectedTheme; }
            set
            {
                if (_selectedTheme != value)
                {
                    _selectedTheme = value;
                    RaisePropertyChanged("SelectedTheme");
                }
            }
        }

        public ThemeViewModel()
        { 
            try
            {
                ThemeManager.AddAppTheme("PowerShellDark", new Uri("pack://application:,,,/Vulnerator;component/View/Theme/PowerShellDark.xaml"));
                ThemeManager.AddAppTheme("Matrix", new Uri("pack://application:,,,/Vulnerator;component/View/Theme/Matrix.xaml"));
                Themes = PopulateAvailableThemes();
                SetTheme(Properties.Settings.Default["Theme"].ToString());
                SetAccent(Properties.Settings.Default["Accent"].ToString());
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate new ThemeViewModel."));
                log.Debug("Exception details:", exception);
            }
        }

        private List<ThemeDefinition> PopulateAvailableThemes()
        { 
            try
            {
                List<ThemeDefinition> themes = new List<ThemeDefinition>();
                foreach (AppTheme theme in ThemeManager.AppThemes)
                {
                    string displayName = string.Empty;
                    switch (theme.Name)
                    {
                        case "BaseDark":
                            {
                                displayName = "Dark";
                                break;
                            }
                        case "BaseLight":
                            {
                                displayName = "Light";
                                break;
                            }
                        case "PowerShellDark":
                            {
                                displayName = "PowerShell Dark";
                                break;
                            }
                        case "Matrix":
                            {
                                displayName = "Matrix";
                                break;
                            }
                        default:
                            { break; }
                    }
                    themes.Add(new ThemeDefinition() { ActualName = theme.Name, DisplayName = displayName });
                }
                return themes;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to populate list of available themes."));
                throw exception;
            }
        }

        private void SetTheme(string theme)
        {
            Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
            ThemeManager.ChangeAppStyle(Application.Current, appStyle.Item2, ThemeManager.GetAppTheme(theme));
            //ThemeChecked = theme.Equals("BaseLight") ? false : true;
            SelectedTheme = Themes.FirstOrDefault(t => t.ActualName == theme);
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
            //string theme = (bool)parameter == true ? "BaseLight" : "BaseDark";
            string theme = SelectedTheme.ActualName;
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

        public class ThemeDefinition
        {
            public string DisplayName { get; set; }
            public string ActualName { get; set; }

            public ThemeDefinition()
            { }
        }
    }
}
