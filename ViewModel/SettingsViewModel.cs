using log4net;
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
            backgroundWorker.RunWorkerAsync();
            backgroundWorker.Dispose();
        }

        private void ingestStigLibraryBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(StigLibraryLocation))
                {
                    ProgressVisibility = "Collapsed";
                    IngestionErrorVisibility = "Collapsed";
                    IngestionSuccessVisibility = "Collapsed";
                    NoLibraryVisibility = "Visible";
                    return;
                }
                else
                {
                    ProgressBarValue = 0;
                    ProgressVisibility = "Visible";
                    NoLibraryVisibility = "Collapsed";
                    IngestionErrorVisibility = "Collapsed";
                    IngestionSuccessVisibility = "Collapsed";
                    databaseInterface.DropVulnerabilityRelatedIndices();
                    ParseZip(StigLibraryLocation);
                    databaseInterface.CreateVulnerabilityRelatedIndices();
                    guiFeedback.SetFields("Awaiting user input", "Collapsed", true);
                    Properties.Settings.Default.StigLibraryIngestDate = DateTime.Now.ToLongDateString();
                    Messenger.Default.Send(guiFeedback);
                    StigLibraryLocation = string.Empty;
                    ProgressVisibility = "Collapsed";
                    IngestionSuccessVisibility = "Visible";
                    IngestionErrorVisibility = "Collapsed";
                    NoLibraryVisibility = "Collapsed";
                }
            }
            catch (Exception exception)
            {
                guiFeedback.SetFields("Awaiting user input", "Collapsed", true);
                Messenger.Default.Send(guiFeedback);
                ProgressVisibility = "Collapsed";
                IngestionErrorVisibility = "Visible";
                IngestionSuccessVisibility = "Collapsed";
                NoLibraryVisibility = "Collapsed";
                log.Error("Unable to ingest STIG Library.");
                log.Debug("Exception details: " + exception);
            }
        }

        private void ParseZip(string fileName)
        {
            using (ZipArchive zipArchive = ZipFile.Open(StigLibraryLocation, ZipArchiveMode.Read))
            {
                ProgressBarMax = zipArchive.Entries.Count();
                foreach (ZipArchiveEntry entry in zipArchive.Entries)
                {
                    if (entry.Name.EndsWith("zip"))
                    {
                        if (!entry.Name.Contains("SCAP_1-1"))
                        { ParseZip(entry); }
                    }
                    if (entry.Name.EndsWith("xml"))
                    {
                        guiFeedback.SetFields(string.Format("Ingesting {0}", entry.Name), "Visible", true);
                        Messenger.Default.Send(guiFeedback);
                        RawStigReader rawStigReader = new RawStigReader();
                        rawStigReader.ReadRawStig(entry);
                    }
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
                    {
                        if (entry.Name.EndsWith("zip"))
                        {
                            if (!entry.Name.Contains("SCAP_1-1"))
                            { ParseZip(entry); }
                        }
                        if (entry.Name.EndsWith("xml"))
                        {
                            guiFeedback.SetFields(string.Format("Ingesting {0}", entry.Name), "Visible", true);
                            Messenger.Default.Send(guiFeedback);
                            RawStigReader rawStigReader = new RawStigReader();
                            rawStigReader.ReadRawStig(entry);
                        }
                    }
                }
            }
        }

        public RelayCommand BuildAnsibleTowerReportsCommand
        { get { return new RelayCommand(BuildAnsibleTowerReports); } }

        private void BuildAnsibleTowerReports()
        {
            try
            {
                //backgroundWorker = new BackgroundWorker();
                //backgroundWorker.DoWork += buildAnsibleTowerReportsBackgroundWorker_DoWork;
                //backgroundWorker.RunWorkerAsync();
                //backgroundWorker.Dispose();

                CommonOpenFileDialog commonOpenFileDialog = new CommonOpenFileDialog();
                commonOpenFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                commonOpenFileDialog.IsFolderPicker = true;
                if (commonOpenFileDialog.ShowDialog() == CommonFileDialogResult.Ok)
                {
                    string[] operatingSystems = new string[] { "Red Hat Enterprise Linux 6", "Red Hat Enterprise Linux 7", "Solaris 10", "Solaris 11" };
                    foreach (string os in operatingSystems)
                    {
                        string progressLabel = string.Format("Processing {0}", os);
                        guiFeedback.SetFields(progressLabel, "Visible", true);
                        Messenger.Default.Send(guiFeedback);
                        string tempOs = os;
                        if (os.Contains("Red Hat"))
                        { tempOs = "Red Hat"; }
                        string saveFolder = string.Format("{0}\\{1}", commonOpenFileDialog.FileName, tempOs.Replace(" ", ""));
                        if (!Directory.Exists(saveFolder))
                        { Directory.CreateDirectory(saveFolder); }
                        AnsibleTowerBuilder ansibleTowerBuilder = new AnsibleTowerBuilder();
                        ansibleTowerBuilder.BuildRoles(os, saveFolder);
                    }
                }
                guiFeedback.SetFields("Ansible Tower report creation complete", "Collapsed", true);
                Messenger.Default.Send(guiFeedback);
            }
            catch (Exception exception)
            { log.Debug("Exception details:", exception); }
        }

        private void buildAnsibleTowerReportsBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                CommonOpenFileDialog commonOpenFileDialog = new CommonOpenFileDialog();
                commonOpenFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                commonOpenFileDialog.IsFolderPicker = true;
                if (commonOpenFileDialog.ShowDialog() == CommonFileDialogResult.Ok)
                {
                    string[] operatingSystems = new string[] { "Red Hat", "Solaris 10", "Solaris 11" };
                    foreach (string os in operatingSystems)
                    {
                        string progressLabel = string.Format("Processing {0}", os);
                        guiFeedback.SetFields(progressLabel, "Visible", true);
                        Messenger.Default.Send(guiFeedback);
                        string saveFolder = string.Format("{0}\\{1}", commonOpenFileDialog.FileName, os.Replace(" ", string.Empty));
                        if (!Directory.Exists(saveFolder))
                        { Directory.CreateDirectory(saveFolder); }
                        AnsibleTowerBuilder ansibleTowerBuilder = new AnsibleTowerBuilder();
                        ansibleTowerBuilder.BuildRoles(os, saveFolder);
                    }
                }
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
