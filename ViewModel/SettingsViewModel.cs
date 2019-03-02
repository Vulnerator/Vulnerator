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
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Windows;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel
{
    public class SettingsViewModel : ViewModelBase
    {
        OpenFileDialog openFileDialog;
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private BackgroundWorker backgroundWorker;
        private GuiFeedback guiFeedback = new GuiFeedback();
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        string ansibleReportFolder = string.Empty;
        int? stigFilesAttempted;
        int? stigFilesParsed;

        private string stigLibraryLocation;
        public string StigLibraryLocation
        {
            get { return stigLibraryLocation; }
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
            get { return progressBarMax; }
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
            get { return progressBarValue; }
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
            get { return progressVisibility; }
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
            get { return noLibraryVisibility; }
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
            get { return ingestionErrorVisibility; }
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
            get { return ingestionSuccessVisibility; }
            set
            {
                if (ingestionSuccessVisibility != value)
                {
                    ingestionSuccessVisibility = value;
                    RaisePropertyChanged("IngestionSuccessVisibility");
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
            {
                Properties.Settings.Default.Database = openFileDialog.FileName;
                DatabaseBuilder.databaseConnection =
                    $@"Data Source = {Properties.Settings.Default.Database}; Version=3;";
                DatabaseBuilder.sqliteConnection = new System.Data.SQLite.SQLiteConnection(DatabaseBuilder.databaseConnection);
            }
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
            {
                Messenger.Default.Send(saveFileDialog.FileName);
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
            }
        }

        public RelayCommand SelectStigLibraryCommand
        { get { return new RelayCommand(SelectStigLibrary); } }

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
                log.Error("Unable to retrieve STIG Library.");
                log.Debug("Exception details: " + exception);
            }
        }

        public RelayCommand IngestStigLibraryCommand
        { get { return new RelayCommand(IngestStigLibrary); } }

        private void IngestStigLibrary()
        {
            backgroundWorker = new BackgroundWorker();
            backgroundWorker.DoWork += ingestStigLibraryBackgroundWorker_DoWork;
            backgroundWorker.RunWorkerCompleted += ingestStigLibraryBackgroundWorker_RunWorkerCompleted;
            backgroundWorker.RunWorkerAsync();
            backgroundWorker.Dispose();
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
                    databaseInterface.DropVulnerabilityRelatedIndices();
                    ParseZip(StigLibraryLocation);
                    databaseInterface.CreateVulnerabilityRelatedIndices();
                    Properties.Settings.Default.StigLibraryIngestDate = DateTime.Now.ToLongDateString();
                    Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
                    StigLibraryLocation = string.Empty;
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
                            Background = appStyle.Item1.Resources["WindowBackgroundBrush"].ToString(),
                            Badge = "Failure",
                            Foreground = appStyle.Item1.Resources["TextBrush"].ToString(),
                            Header = "STIG Library",
                            Message = "STIG Library failed to ingest."
                        };
                        Exception exception = e.Result as Exception;
                        log.Error("Unable to ingest STIG Library.");
                        log.Debug("Exception details: " + exception);
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
                                        Background = appStyle.Item1.Resources["WindowBackgroundBrush"].ToString(),
                                        Badge = "Success",
                                        Foreground = appStyle.Item1.Resources["TextBrush"].ToString(),
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
                                        Background = appStyle.Item1.Resources["WindowBackgroundBrush"].ToString(),
                                        Badge = "Warning",
                                        Foreground = appStyle.Item1.Resources["TextBrush"].ToString(),
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
                                    Background = appStyle.Item1.Resources["WindowBackgroundBrush"].ToString(),
                                    Badge = "Error",
                                    Foreground = appStyle.Item1.Resources["TextBrush"].ToString(),
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
                                        Background = appStyle.Item1.Resources["WindowBackgroundBrush"].ToString(),
                                        Badge = "Warning",
                                        Foreground = appStyle.Item1.Resources["TextBrush"].ToString(),
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
                log.Error("Unable to handle STIG ingestion background worker completion events.");
                log.Debug($"Exception details: {exception}");
            }
        }

        private void ParseZip(string fileName)
        {
            using (ZipArchive zipArchive = ZipFile.Open(StigLibraryLocation, ZipArchiveMode.Read))
            {
                ProgressBarMax = zipArchive.Entries.Count();
                foreach (ZipArchiveEntry entry in zipArchive.Entries)
                {
                    HandleZipArchiveEntry(entry);
                    ProgressBarValue++;
                }
            }
        }

        private void ParseZip(ZipArchiveEntry zipArchiveEntry)
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

        private void HandleZipArchiveEntry(ZipArchiveEntry zipArchiveEntry)
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

        public RelayCommand BuildAnsibleTowerReportsCommand
        { get { return new RelayCommand(BuildAnsibleTowerReports); } }

        private void BuildAnsibleTowerReports()
        {
            try
            {
                CommonOpenFileDialog commonOpenFileDialog = new CommonOpenFileDialog();
                commonOpenFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                commonOpenFileDialog.IsFolderPicker = true;
                if (commonOpenFileDialog.ShowDialog() == CommonFileDialogResult.Ok)
                {
                    ansibleReportFolder = commonOpenFileDialog.FileName;
                    backgroundWorker = new BackgroundWorker();
                    backgroundWorker.DoWork += buildAnsibleTowerReportsBackgroundWorker_DoWork;
                    backgroundWorker.RunWorkerAsync();
                    backgroundWorker.Dispose();
                }
            }
            catch (Exception exception)
            { log.Debug("Exception details:", exception); }
        }

        private void buildAnsibleTowerReportsBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                string[] operatingSystems = new string[] { "Red Hat Enterprise Linux 6", "Red Hat Enterprise Linux 7", "Solaris 10", "Solaris 11", "SUSE" };
                foreach (string os in operatingSystems)
                {
                    string progressLabel = $"Processing {os}";
                    guiFeedback.SetFields(progressLabel, "Visible", true);
                    Messenger.Default.Send(guiFeedback);
                    string tempOs = os;
                    if (os.Contains("Red Hat"))
                    { tempOs = "Red Hat"; }
                    string saveFolder = $"{ansibleReportFolder}\\{tempOs.Replace(" ", "")}";
                    if (!Directory.Exists(saveFolder))
                    { Directory.CreateDirectory(saveFolder); }
                    AnsibleTowerBuilder ansibleTowerBuilder = new AnsibleTowerBuilder();
                    ansibleTowerBuilder.BuildRoles(os, saveFolder);
                }
                ansibleReportFolder = string.Empty;
                guiFeedback.SetFields("Ansible Tower report creation complete", "Collapsed", true);
                Messenger.Default.Send(guiFeedback);
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to generate Ansible Tower report templates."));
                throw exception;
            }
        }
    }
}
