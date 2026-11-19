using log4net;
using MahApps.Metro;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Windows;
using ControlzEx.Theming;
using Vulnerator.Helper;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using Vulnerator.Properties;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel
{
    public class SettingsViewModel : ViewModelBase
    {
        OpenFileDialog openFileDialog;
        private BackgroundWorker backgroundWorker;
        private GuiFeedback guiFeedback = new GuiFeedback();
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        int? stigFilesAttempted;
        int? stigFilesParsed;

        private string stigLibraryLocation;
        public string StigLibraryLocation
        {
            get => stigLibraryLocation;
            set
            {
                if (stigLibraryLocation != value)
                {
                    stigLibraryLocation = value;
                    RaisePropertyChanged("StigLibraryLocation");
                }
            }
        }

        private int progressBarMax;
        public int ProgressBarMax
        {
            get => progressBarMax;
            set
            {
                if (progressBarMax != value)
                {
                    progressBarMax = value;
                    RaisePropertyChanged("ProgressBarMax");
                }
            }
        }

        private int progressBarValue;
        public int ProgressBarValue
        {
            get => progressBarValue;
            set
            {
                if (progressBarValue != value)
                {
                    progressBarValue = value;
                    RaisePropertyChanged("ProgressBarValue");
                }
            }
        }

        private string progressVisibility = "Collapsed";
        public string ProgressVisibility
        {
            get => progressVisibility;
            set
            {
                if (progressVisibility != value)
                {
                    progressVisibility = value;
                    RaisePropertyChanged("ProgressVisibility");
                }
            }
        }

        private string noLibraryVisibility = "Collapsed";
        public string NoLibraryVisibility
        {
            get => noLibraryVisibility;
            set
            {
                if (noLibraryVisibility != value)
                {
                    noLibraryVisibility = value;
                    RaisePropertyChanged("NoLibraryVisibility");
                }
            }
        }

        private string ingestionErrorVisibility = "Collapsed";
        public string IngestionErrorVisibility
        {
            get => ingestionErrorVisibility;
            set
            {
                if (ingestionErrorVisibility != value)
                {
                    ingestionErrorVisibility = value;
                    RaisePropertyChanged("IngestionErrorVisibility");
                }
            }
        }

        private string ingestionSuccessVisibility = "Collapsed";
        public string IngestionSuccessVisibility
        {
            get => ingestionSuccessVisibility;
            set
            {
                if (ingestionSuccessVisibility != value)
                {
                    ingestionSuccessVisibility = value;
                    RaisePropertyChanged("IngestionSuccessVisibility");
                }
            }
        }

        public RelayCommand BrowseForDatabaseCommand => new RelayCommand(BrowseForDatabase);

        private void BrowseForDatabase()
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.CheckFileExists = true;
                openFileDialog.DefaultExt = "sqlite";
                openFileDialog.Filter = "SQLite File (*sqlite)|*.sqlite";
                openFileDialog.Title = "Please select a SQLite file";
                if ((bool)openFileDialog.ShowDialog())
                {
                    Settings.Default.Database = openFileDialog.FileName;
                    DatabaseBuilder.databaseConnection = DatabaseBuilder.ConnectionStringFor(Settings.Default.Database);
                    DatabaseBuilder.sqliteConnection = new SQLiteConnection(DatabaseBuilder.databaseConnection);
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to browse for the Vulnerator Database.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand ImportEmassAssessmentProceduresCommand => new RelayCommand(ImportEmassAssessmentProcedures);

        private void ImportEmassAssessmentProcedures()
        {
            try
            {
                OpenFileDialog dialog = new OpenFileDialog
                {
                    CheckFileExists = true,
                    Filter = "Assessment procedures (*.xlsx;*.xlsm;*.csv;*.tsv;*.txt)|*.xlsx;*.xlsm;*.csv;*.tsv;*.txt|All files (*.*)|*.*",
                    Title = "Select an assessment procedure list (eMASS IG/AP export, or a workbook / CSV with CCI and AP columns)"
                };
                if (dialog.ShowDialog() != true)
                { return; }
                string result = EmassAssessmentProcedureImporter.Import(dialog.FileName, label => MessageBox.Show(
                    $"This file carries the sensitivity label \"{label}\"." + Environment.NewLine + Environment.NewLine +
                    "Its content will be stored in the Vulnerator database, which does not keep the label: handle the database " +
                    "and the exports at that level (exports carry the marking you set in Settings)." + Environment.NewLine + Environment.NewLine +
                    "Import it?", "Labeled file", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes);
                MessageBox.Show(result, "Assessment procedures", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Unable to import the assessment procedure list.", exception);
                MessageBox.Show("The import failed; see the Vulnerator log for details.", "Assessment procedures",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        public RelayCommand CreateDatabaseCommand => new RelayCommand(CreateDatabase);

        private void CreateDatabase()
        {
            try
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog();
                saveFileDialog.OverwritePrompt = true;
                saveFileDialog.DefaultExt = "sqlite";
                saveFileDialog.Filter = "SQLite File (*sqlite)|*.sqlite";
                saveFileDialog.Title = "Please provide a name for the SQLite file";
                saveFileDialog.CheckPathExists = true;
                if (!(bool) saveFileDialog.ShowDialog()) return;
                Messenger.Default.Send(saveFileDialog.FileName);
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
            }
            catch (Exception exception)
            {
                string error = "Unable to create the new Vulnerator Database.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand SelectStigLibraryCommand => new RelayCommand(SelectStigLibrary);

        private void SelectStigLibrary()
        {
            try
            {
                if (openFileDialog != null)
                { openFileDialog = null; }
                openFileDialog = new OpenFileDialog();
                openFileDialog.Multiselect = true;
                openFileDialog.CheckFileExists = true;
                openFileDialog.Filter = "STIG library, STIG zips or benchmarks (*.zip;*.xml)|*.zip;*.xml";
                openFileDialog.Title = "Select the DISA STIG library zip, STIG zips, or STIG benchmark (.xml) files";
                if (openFileDialog.ShowDialog() == true && openFileDialog.FileNames.Length > 0)
                { StigLibraryLocation = string.Join(";", openFileDialog.FileNames); }
            }
            catch (Exception exception)
            {
                string error = "Unable to retrieve STIG Library.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private string _lastLibraryLoad;

        /// <summary>When a STIG library was last loaded into the open database, for the Settings page.</summary>
        public string LastLibraryLoad
        {
            get => _lastLibraryLoad ?? (_lastLibraryLoad = DescribeLastLibraryLoad());
            set
            {
                if (_lastLibraryLoad != value)
                {
                    _lastLibraryLoad = value;
                    RaisePropertyChanged("LastLibraryLoad");
                }
            }
        }

        private static string DescribeLastLibraryLoad()
        {
            DateTime? last = StigLibraryImporter.LastLibraryImport();
            return last.HasValue ? "Last loaded into this database: " + last.Value.ToString("d MMM yyyy HH:mm") : "No STIG library loaded into this database yet";
        }

        public RelayCommand ExtractStigBenchmarksCommand => new RelayCommand(ExtractStigBenchmarks);

        /// <summary>
        /// Unpacks a DISA library zip into individual STIG benchmark .xml files, for moving to a machine where the zip
        /// itself is not allowed; those files are then loaded with the STIG library button.
        /// </summary>
        private void ExtractStigBenchmarks()
        {
            try
            {
                OpenFileDialog zipDialog = new OpenFileDialog
                {
                    CheckFileExists = true,
                    Filter = "STIG library or STIG zip (*.zip)|*.zip",
                    Title = "Select the DISA STIG library zip to extract"
                };
                if (zipDialog.ShowDialog() != true)
                { return; }
                CommonOpenFileDialog folderDialog = new CommonOpenFileDialog
                {
                    IsFolderPicker = true,
                    Title = "Select an empty folder for the STIG benchmark files"
                };
                if (folderDialog.ShowDialog() != CommonFileDialogResult.Ok)
                { return; }
                int written = StigLibraryImporter.ExtractBenchmarks(zipDialog.FileName, folderDialog.FileName);
                MessageBox.Show($"{written} STIG benchmark file(s) written to:{Environment.NewLine}{folderDialog.FileName}{Environment.NewLine}{Environment.NewLine}" +
                                "Move the .xml files to the Vulnerator machine and load them with the STIG library button (you can select them all at once).",
                    "STIG library", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Unable to extract STIG benchmarks.", exception);
                MessageBox.Show("The STIG benchmarks could not be extracted; see the Vulnerator log for details.", "STIG library",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        public RelayCommand IngestStigLibraryCommand => new RelayCommand(IngestStigLibrary);

        private void IngestStigLibrary()
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += ingestStigLibraryBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += ingestStigLibraryBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync();
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to ingest the STIG library.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void ingestStigLibraryBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                stigFilesParsed = stigFilesAttempted = 0;
                if (string.IsNullOrWhiteSpace(StigLibraryLocation))
                {
                    e.Result = "No Library";
                    return;
                }
                else
                {
                    ProgressBarValue = 0;
                    ProgressVisibility = "Visible";
                    databaseInterface.DropIndices();
                    StigLibraryImporter importer = new StigLibraryImporter
                    {
                        TotalItems = count => ProgressBarMax = count,
                        Progress = name =>
                        {
                            if (name == null)
                            {
                                ProgressBarValue++;
                                return;
                            }
                            guiFeedback.SetFields($"Ingesting {name}", "Visible", true);
                            Messenger.Default.Send(guiFeedback);
                        }
                    };
                    importer.Import(StigLibraryLocation.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).Select(p => p.Trim()).ToArray());
                    LastLibraryLoad = DescribeLastLibraryLoad();
                    stigFilesAttempted = importer.Attempted;
                    stigFilesParsed = importer.Parsed + importer.Older;
                    databaseInterface.CreateVulnerabilityRelatedIndices();
                    Properties.Settings.Default.StigLibraryIngestDate = DateTime.Now.ToLongDateString();
                    Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
                    StigLibraryLocation = string.Empty;
                    databaseInterface.Reindex();
                    if (stigFilesParsed == 0)
                    { e.Result = "None"; }
                    else if (stigFilesParsed < stigFilesAttempted)
                    { e.Result = "Partial"; }
                    else
                    { e.Result = "Success"; }
                }
            }
            catch (Exception exception)
            { e.Result = exception; }
        }

        private void ingestStigLibraryBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        { 
            try
            {
                Theme appStyle = ThemeManager.Current.DetectTheme(Application.Current);
                Notification notification = new Notification();
                if (e.Result != null)
                {
                    if (e.Result is Exception)
                    {
                        notification = new Notification
                        { 
                            Accent = "Red",
                            Background = appStyle.Resources["MahApps.Brushes.Window.Background"].ToString(),
                            Badge = "Failure",
                            Foreground = appStyle.Resources["MahApps.Brushes.Text"].ToString(),
                            Header = "STIG Library",
                            Message = "STIG Library failed to ingest."
                        };
                        Exception exception = e.Result as Exception;
                        string error = "Unable to ingest STIG Library.";
                        LogWriter.LogErrorWithDebug(error, exception);
                    }
                    else
                    {
                        switch (e.Result.ToString())
                        {
                            case "Success":
                                {
                                    notification = new Notification
                                    {
                                        Accent = "Green",
                                        Background = appStyle.Resources["MahApps.Brushes.Window.Background"].ToString(),
                                        Badge = "Success",
                                        Foreground = appStyle.Resources["MahApps.Brushes.Text"].ToString(),
                                        Header = "STIG Library",
                                        Message = "STIG Library successfully ingested."
                                    };
                                    break;
                                }
                            case "Partial":
                                {
                                    notification = new Notification
                                    {
                                        Accent = "Orange",
                                        Background = appStyle.Resources["MahApps.Brushes.Window.Background"].ToString(),
                                        Badge = "Warning",
                                        Foreground = appStyle.Resources["MahApps.Brushes.Text"].ToString(),
                                        Header = "STIG Library",
                                        Message = "STIG Library partially ingested; see log for errors."
                                    };
                                    break;
                                }
                            case "None":
                            {
                                notification = new Notification
                                {
                                    Accent = "Red",
                                    Background = appStyle.Resources["MahApps.Brushes.Window.Background"].ToString(),
                                    Badge = "Error",
                                    Foreground = appStyle.Resources["MahApps.Brushes.Text"].ToString(),
                                    Header = "STIG Library",
                                    Message = "No STIGs ingested; see log for errors."
                                };
                                break;
                            }
                            case "No Library":
                                {
                                    notification = new Notification
                                    {
                                        Accent = "Orange",
                                        Background = appStyle.Resources["MahApps.Brushes.Window.Background"].ToString(),
                                        Badge = "Warning",
                                        Foreground = appStyle.Resources["MahApps.Brushes.Text"].ToString(),
                                        Header = "STIG Library",
                                        Message = "No STIG library file selected."
                                    };
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                }
                Messenger.Default.Send(notification);
                guiFeedback.SetFields("Awaiting user input", "Collapsed", true);
                Messenger.Default.Send(guiFeedback);
                ProgressVisibility = "Collapsed";
                stigFilesParsed = stigFilesAttempted = null;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to handle STIG ingestion background worker completion events.");
                throw exception;
            }
        }
    }
}
