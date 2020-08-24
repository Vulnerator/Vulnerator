using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using log4net;
using MahApps.Metro;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.UI;
using System.Windows;
using System.Windows.Media;
using ControlzEx.Theming;
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

        private List<string> _themes { get; set; }
        public List<string> Themes
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

        private string _selectedTheme { get; set; }
        public string SelectedTheme
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

        private string _accent { get; set; }

        public string Accent
        {
            get => _accent;
            set
            {
                if (_accent != value)
                {
                    _accent = value;
                    RaisePropertyChanged("Accent");
                }
            }
        }

        public ThemeViewModel()
        { 
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of ThemeViewModel.");
                Themes = PopulateAvailableThemes();
                SetThemeAndAccent();
                LogWriter.LogStatusUpdate("ThemeManagementViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate new ThemeViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private List<string> PopulateAvailableThemes()
        { 
            try
            {
                List<string> themes = new List<string>();
                themes.Add("Dark");
                themes.Add("Light");
                return themes;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate list of available themes.");
                throw exception;
            }
        }

        private void SetThemeAndAccent()
        {
            try
            {
                ThemeManager.Current.ChangeTheme(Application.Current, $"{Settings.Default.Theme}.{Settings.Default.Accent}");
                SelectedTheme = Settings.Default.Theme;
                Accent = Settings.Default.Accent;
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to set the application theme to '{Settings.Default.Theme}'.");
                throw exception;
            }
        }

        public RelayCommand ChangeThemeCommand => new RelayCommand(ChangeTheme);
        private void ChangeTheme()
        {
            try
            {
                Settings.Default["Theme"] = SelectedTheme;
                SetThemeAndAccent();
            }
            catch (Exception exception)
            {
                string error = $"Unable to change the application theme to '{SelectedTheme}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand<object> ChangeAccentCommand
        { get { return new RelayCommand<object>((p) => ChangeAccent(p)); } }
        private void ChangeAccent(object parameter)
        {
            try
            {
                Settings.Default["Accent"] = parameter.ToString();
                SetThemeAndAccent();
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
