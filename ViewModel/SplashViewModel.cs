using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Vulnerator.ViewModel
{
    public class SplashViewModel : ViewModelBase
    {
        private string fileName = string.Empty;
        private bool isPersistent;
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

        private string database;
        public string Database
        {
            get { return database; }
            set
            {
                if (database != value)
                {
                    database = value;
                    RaisePropertyChanged("Database");
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
            {
                fileName = saveFileDialog.FileName;
                Database = fileName;
            }
        }

        public RelayCommand LaunchCommand
        { get { return new RelayCommand(Launch); } }

        private void Launch()
        {
            if (IsPersistent && string.IsNullOrWhiteSpace(Database))
            {
                ErrorVisibility = "Visible";
                return;
            }
            else
            {
                if (IsPersistent)
                {
                    Properties.Settings.Default["Database"] = Database;
                    Properties.Settings.Default["LogPath"] = Path.Combine(Environment.SpecialFolder.LocalApplicationData.ToString(), "Vulnerator");
                }
                else
                {
                    Properties.Settings.Default["Database"] = Path.Combine(Environment.CurrentDirectory, "Vulnerator.sqlite");
                    Properties.Settings.Default["LogPath"] = Path.Combine(Environment.CurrentDirectory, "Logs");
                }
            }
        }
    }
}
