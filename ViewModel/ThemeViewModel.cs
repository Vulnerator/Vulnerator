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
using Vulnerator.Helper;
using Vulnerator.Model.Object;
using Vulnerator.Properties;

namespace Vulnerator.ViewModel
{
    public class ThemeViewModel : ViewModelBase
    {
        private bool _themeChecked;
        public bool ThemeChecked
        {
            get => _themeChecked;
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
            get => _themes;
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
            get => _selectedTheme;
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
                LogWriter.LogStatusUpdate("Begin instantiation of ThemeViewModel.");
                ThemeManager.AddAppTheme("PowerShellDark", new Uri("pack://application:,,,/Vulnerator;component/View/Theme/PowerShellDark.xaml"));
                ThemeManager.AddAppTheme("BlackAndWhite", new Uri("pack://application:,,,/Vulnerator;component/View/Theme/BlackAndWhite.xaml"));
                Themes = PopulateAvailableThemes();
                SetTheme(Properties.Settings.Default["Theme"].ToString());
                SetAccent(Properties.Settings.Default["Accent"].ToString());
                LogWriter.LogStatusUpdate("ThemeManagementViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate new ThemeViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
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
                        case "BlackAndWhite":
                            {
                                displayName = "Black & White";
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
                LogWriter.LogError("Unable to populate list of available themes.");
                throw exception;
            }
        }

        private void SetTheme(string theme)
        {
            try
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                ThemeManager.ChangeAppStyle(Application.Current, appStyle.Item2, ThemeManager.GetAppTheme(theme));
                SelectedTheme = Themes.FirstOrDefault(t => t.ActualName == theme);
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to set the application theme to '{theme}'.");
                throw exception;
            }
        }

        private void SetAccent(string accent)
        {
            try
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                ThemeManager.ChangeAppStyle(Application.Current, ThemeManager.GetAccent(accent), appStyle.Item1);
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to set the application accent to '{accent}'");
            }
        }

        public RelayCommand ChangeThemeCommand => new RelayCommand(ChangeTheme);
        private void ChangeTheme()
        {
            try
            {
                string theme = SelectedTheme.ActualName;
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                ThemeManager.ChangeAppStyle(Application.Current, appStyle.Item2, ThemeManager.GetAppTheme(theme));
                Settings.Default["Theme"] = theme;
            }
            catch (Exception exception)
            {
                string error = $"Unable to change the application theme to '{SelectedTheme.ActualName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand<object> ChangeAccentCommand
        { get { return new RelayCommand<object>((p) => ChangeAccent(p)); } }
        private void ChangeAccent(object parameter)
        {
            try
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                ThemeManager.ChangeAppStyle(Application.Current, ThemeManager.GetAccent(parameter.ToString()), appStyle.Item1);
                Settings.Default["Accent"] = parameter.ToString();
            }
            catch (Exception exception)
            {
                string error = $"Unable to change the application accent to '{parameter}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
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
