using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using MahApps.Metro.Controls;
using Microsoft.Win32;
using System;
using System.IO;

namespace Vulnerator.ViewModel
{
    public class SplashViewModel : ViewModelBase
    {
        private string fileName = string.Empty;
        private bool isPersistent = false;
        public bool IsPersistent
        {
            get { return isPersistent; }
            set
            {
                if (isPersistent != value)
                {
                    isPersistent = value;
                    RaisePropertyChanged("IsPersistent");
                }
            }
        }

        private string databasePath;
        public string DatabasePath
        {
            get { return databasePath; }
            set
            {
                if (databasePath != value)
                {
                    databasePath = value;
                    RaisePropertyChanged("DatabasePath");
                }
            }
        }

        private string errorVisibility = "Collapsed";
        public string ErrorVisibility
        {
            get { return errorVisibility; }
            set
            {
                if (errorVisibility != value)
                {
                    errorVisibility = value;
                    RaisePropertyChanged("ErrorVisibility");
                }
            }
        }

        public RelayCommand BrowseForDatabaseCommand
        { get { return new RelayCommand(BrowseForDatabase); } }

        private void BrowseForDatabase()
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.OverwritePrompt = true;
            saveFileDialog.DefaultExt = "sqlite";
            saveFileDialog.Filter = "SQLite File (*sqlite)|*.sqlite";
            saveFileDialog.Title = "Please select or create a SQLite file";
            saveFileDialog.CheckPathExists = true;
            if ((bool)saveFileDialog.ShowDialog())
            { fileName = saveFileDialog.FileName; }
            DatabasePath = fileName;
        }

        public RelayCommand<MetroWindow> LaunchCommand
        { get { return new RelayCommand<MetroWindow>(Launch); } }

        private void Launch(MetroWindow metroWindow)
        {
            if (IsPersistent && string.IsNullOrWhiteSpace(DatabasePath))
            {
                ErrorVisibility = "Visible";
                return;
            }
            else
            {
                if (IsPersistent)
                {
                    Properties.Settings.Default["Environment"] = "Persistent";
                    Properties.Settings.Default["Database"] = DatabasePath;
                    Properties.Settings.Default["LogPath"] = Path.Combine(Environment.SpecialFolder.LocalApplicationData.ToString(), "Vulnerator");
                }
                else
                {
                    Properties.Settings.Default["Environment"] = "Portable";
                    Properties.Settings.Default["Database"] = Path.Combine(Environment.CurrentDirectory, "Vulnerator.sqlite");
                    Properties.Settings.Default["LogPath"] = Path.Combine(Environment.CurrentDirectory, "Logs");
                }
            }
            if (metroWindow != null)
            {
                metroWindow.Close();
                View.UI.DevWindow devWindow = new View.UI.DevWindow();
                devWindow.Show();
            }
        }
    }
}
