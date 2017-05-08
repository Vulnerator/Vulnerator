using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Vulnerator.ViewModel
{
    public class SplashViewModel : ViewModelBase
    {
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
            { Database = saveFileDialog.FileName; }
        }
    }
}
