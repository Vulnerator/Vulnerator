﻿using log4net;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel
{
    public class SettingsViewModel : ViewModelBase
    {
        OpenFileDialog openFileDialog;
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private BackgroundWorker backgroundWorker;

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
            GuiFeedback guiFeedback = new GuiFeedback();
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
                    using (ZipArchive zipArchive = ZipFile.Open(StigLibraryLocation, ZipArchiveMode.Read))
                    {
                        ProgressBarMax = zipArchive.Entries.Count(x => x.Name.EndsWith("zip") && !x.Name.Contains("SCAP_1-1"));
                        foreach (ZipArchiveEntry entry in zipArchive.Entries.Where(x => x.Name.EndsWith("zip") && !x.Name.Contains("SCAP_1-1")))
                        {
                            using (Stream stream = entry.Open())
                            {
                                using (ZipArchive innerZipArchive = new ZipArchive(stream, ZipArchiveMode.Read))
                                {
                                    if (innerZipArchive.Entries.FirstOrDefault(x => x.Name.EndsWith("zip")) != null)
                                    {
                                        ZipArchiveEntry innerEntry = innerZipArchive.Entries.FirstOrDefault(x => x.Name.EndsWith("zip"));
                                        using (Stream secondStream = innerEntry.Open())
                                        {
                                            using (ZipArchive tertiaryZipArchive = new ZipArchive(secondStream, ZipArchiveMode.Read))
                                            {
                                                ZipArchiveEntry rawStig = tertiaryZipArchive.Entries.FirstOrDefault(x => x.Name.EndsWith("xml"));
                                                if (rawStig == null)
                                                { continue; }
                                                guiFeedback.SetFields(string.Format("Ingesting {0}", rawStig.Name), "Visible", true);
                                                Messenger.Default.Send(guiFeedback);
                                                RawStigReader rawStigReader = new RawStigReader();
                                                rawStigReader.ReadRawStig(rawStig);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        ZipArchiveEntry rawStig = innerZipArchive.Entries.FirstOrDefault(x => x.Name.EndsWith("xml"));
                                        if (rawStig == null)
                                        { continue; }
                                        guiFeedback.SetFields(string.Format("Ingesting {0}", rawStig.Name), "Visible", true);
                                        Messenger.Default.Send(guiFeedback);
                                        RawStigReader rawStigReader = new RawStigReader();
                                        rawStigReader.ReadRawStig(rawStig);
                                    }
                                }
                            }
                            ProgressBarValue++;   
                        }
                    }
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
    }
}