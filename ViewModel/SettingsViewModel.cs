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
                    DatabaseBuilder.databaseConnection =
                        $@"Data Source = {Settings.Default.Database}; Version=3;";
                    DatabaseBuilder.sqliteConnection = new SQLiteConnection(DatabaseBuilder.databaseConnection);
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to browse for the Vulnerator Database.";
                LogWriter.LogErrorWithDebug(error, exception);
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
                openFileDialog.Multiselect = false;
                openFileDialog.CheckFileExists = true;
                openFileDialog.Filter = "STIG Library (*.zip)|*.zip";
                openFileDialog.Title = "Please select a STIG Library to ingest";
                openFileDialog.ShowDialog();
                if (openFileDialog.FileName != null)
                { StigLibraryLocation = openFileDialog.FileName; }
            }
            catch (Exception exception)
            {
                string error = "Unable to retrieve STIG Library.";
                LogWriter.LogErrorWithDebug(error, exception);
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
                    ParseZip(StigLibraryLocation);
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
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                Notification notification = new Notification();
                if (e.Result != null)
                {
                    if (e.Result is Exception)
                    {
                        notification = new Notification
                        { 
                            Accent = "Red",
                            Background = appStyle.Item1.Resources["MahApps.Brushes.Window.Background"].ToString(),
                            Badge = "Failure",
                            Foreground = appStyle.Item1.Resources["MahApps.Brushes.Text"].ToString(),
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
                                        Background = appStyle.Item1.Resources["MahApps.Brushes.Window.Background"].ToString(),
                                        Badge = "Success",
                                        Foreground = appStyle.Item1.Resources["MahApps.Brushes.Text"].ToString(),
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
                                        Background = appStyle.Item1.Resources["MahApps.Brushes.Window.Background"].ToString(),
                                        Badge = "Warning",
                                        Foreground = appStyle.Item1.Resources["MahApps.Brushes.Text"].ToString(),
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
                                    Background = appStyle.Item1.Resources["MahApps.Brushes.Window.Background"].ToString(),
                                    Badge = "Error",
                                    Foreground = appStyle.Item1.Resources["MahApps.Brushes.Text"].ToString(),
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
                                        Background = appStyle.Item1.Resources["MahApps.Brushes.Window.Background"].ToString(),
                                        Badge = "Warning",
                                        Foreground = appStyle.Item1.Resources["MahApps.Brushes.Text"].ToString(),
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

        private void ParseZip(string fileName)
        {
            try
            {
                using (ZipArchive zipArchive = ZipFile.Open(fileName, ZipArchiveMode.Read))
                {
                    ProgressBarMax = zipArchive.Entries.Count();
                    foreach (ZipArchiveEntry entry in zipArchive.Entries)
                    {
                        HandleZipArchiveEntry(entry);
                        ProgressBarValue++;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to parse ZipArchive '{fileName}'");
                throw exception;
            }
        }

        private void ParseZip(ZipArchiveEntry zipArchiveEntry)
        {
            try
            {
                using (Stream stream = zipArchiveEntry.Open())
                {
                    using (ZipArchive zipArchive = new ZipArchive(stream, ZipArchiveMode.Read))
                    {
                        foreach (ZipArchiveEntry entry in zipArchive.Entries)
                        { HandleZipArchiveEntry(entry); }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to parse ZipArchiveEntry '{zipArchiveEntry}'.");
            }
        }

        private void HandleZipArchiveEntry(ZipArchiveEntry zipArchiveEntry)
        {
            try
            {
                if (zipArchiveEntry.Name.EndsWith("zip"))
                {
                    if (!zipArchiveEntry.Name.Contains("SCAP_1-1"))
                    { ParseZip(zipArchiveEntry); }
                }
                if (zipArchiveEntry.Name.EndsWith("xml"))
                {
                    stigFilesAttempted++;
                    guiFeedback.SetFields($"Ingesting {zipArchiveEntry.Name}", "Visible", true);
                    Messenger.Default.Send(guiFeedback);
                    RawStigReader rawStigReader = new RawStigReader();
                    if (rawStigReader.ReadRawStig(zipArchiveEntry) == "Parsed")
                    { stigFilesParsed++; }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to correctly handle ZipArchiveEntry '{zipArchiveEntry}'.");
            }
        }
    }
}
