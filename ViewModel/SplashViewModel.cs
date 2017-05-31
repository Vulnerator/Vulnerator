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

        private bool isPortable = false;
        public bool IsPortable
        {
            get { return isPortable; }
            set
            {
                if (isPortable != value)
                {
                    isPortable = value;
                    RaisePropertyChanged("IsPortable");
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

        private string errorText;
        public string ErrorText
        {
            get { return errorText; }
            set
            {
                if (errorText != value)
                {
                    errorText = value;
                    RaisePropertyChanged("ErrorText");
                }
            }
        }

        public RelayCommand BrowseForDatabaseCommand
        { get { return new RelayCommand(BrowseForDatabase); } }

        private void BrowseForDatabase()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.CheckFileExists = true;
            openFileDialog.DefaultExt = "sqlite";
            openFileDialog.Filter = "SQLite File (*sqlite)|*.sqlite";
            openFileDialog.Title = "Please select a SQLite file";
            if ((bool)openFileDialog.ShowDialog())
            { fileName = openFileDialog.FileName; }
            DatabasePath = fileName;
        }

        public RelayCommand CreateDatabaseCommand
        { get { return new RelayCommand(CreateDatabase); } }

        private void CreateDatabase()
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.OverwritePrompt = true;
            saveFileDialog.DefaultExt = "sqlite";
            saveFileDialog.Filter = "SQLite File (*sqlite)|*.sqlite";
            saveFileDialog.Title = "Please provide a name for the SQLite file";
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
                ErrorText = "A database location is required for persistent usage; please select or create a database above.";
                ErrorVisibility = "Visible";
                return;
            }
            else
            {
                if (IsPersistent)
                {
                    Properties.Settings.Default["Environment"] = "Persistent";
                    Properties.Settings.Default["Database"] = DatabasePath;
                    Properties.Settings.Default["LogPath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Vulnerator", "Logs", "V6Log.txt");
                }
                else if (IsPortable)
                {
                    Properties.Settings.Default["Environment"] = "Portable";
                    Properties.Settings.Default["Database"] = Path.Combine(Environment.CurrentDirectory, "Vulnerator.sqlite");
                    Properties.Settings.Default["LogPath"] = Path.Combine(Environment.CurrentDirectory, "Logs", "V6Log.txt");
                }
                else
                {
                    ErrorText = "The application must be designated as \"Portable\" or \"Persistant\" prior to launch.";
                    ErrorVisibility = "Visible";
                    return;
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
