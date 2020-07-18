using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Core.Objects;
using System.Data.SQLite;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using Vulnerator.Model.Entity;
using log4net;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using GalaSoft.MvvmLight.Messaging;
using MahApps.Metro;
using Microsoft.Win32;
using Vulnerator.Helper;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.BusinessLogic.Reports;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel
{
    public class ReportingViewModel : ViewModelBase
    {
        private BackgroundWorker backgroundWorker;
        private SaveFileDialog saveExcelFile;
        private SaveFileDialog savePdfFile;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        public static Stopwatch stopWatch = new Stopwatch();
        public static Stopwatch fileStopWatch = new Stopwatch();

        private List<Group> _groups { get; set; }
        public List<Group> Groups
        {
            get => _groups;
            set
            {
                if (_groups != value)
                {
                    _groups = value;
                    RaisePropertyChanged("Groups");
                }
            }
        }

        private ObservableCollection<RequiredReportUserSelection> _vulnerabilityReports;
        public ObservableCollection<RequiredReportUserSelection> VulnerabilityReports
        {
            get => _vulnerabilityReports;
            set
            {
                if (_vulnerabilityReports != value)
                {
                    _vulnerabilityReports = value;
                    RaisePropertyChanged("Reports");
                }
            }
        }

        private RequiredReportUserSelection _selectedReport;

        public RequiredReportUserSelection SelectedReport
        {
            get => _selectedReport;
            set
            {
                if (_selectedReport != value)
                {
                    _selectedReport = value;
                    RaisePropertyChanged("SelectedReport");
                }
            }
        }

        private ObservableCollection<ReportFindingTypeUserSettings> _selectedReportFindingTypeSettings;

        public ObservableCollection<ReportFindingTypeUserSettings> SelectedReportFindingTypeSettings
        {
            get => _selectedReportFindingTypeSettings;
            set
            {
                if (_selectedReportFindingTypeSettings != value)
                {
                    _selectedReportFindingTypeSettings = value;
                    RaisePropertyChanged("SelectedReportFindingTypeSettings");
                }
            }
        }

        private ObservableCollection<ReportSeverityUserSettings> _selectedReportSeveritySettings;

        public ObservableCollection<ReportSeverityUserSettings> SelectedReportSeveritySettings
        {
            get => _selectedReportSeveritySettings;
            set
            {
                if (_selectedReportSeveritySettings != value)
                {
                    _selectedReportSeveritySettings = value;
                    RaisePropertyChanged("SelectedReportSeveritySettings");
                }
            }
        }

        private ObservableCollection<ReportStatusUserSettings> _selectedReportStatusSettings;

        public ObservableCollection<ReportStatusUserSettings> SelectedReportStatusSettings
        {
            get => _selectedReportStatusSettings;
            set
            {
                if (_selectedReportStatusSettings != value)
                {
                    _selectedReportStatusSettings = value;
                    RaisePropertyChanged("SelectedReportStatusSettings");
                }
            }
        }

        public ReportingViewModel()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of ReportingViewModel.");
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated, (msg) => HandleModelUpdate(msg.Notification));
                LogWriter.LogStatusUpdate("ReportingViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate ReportingViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void HandleModelUpdate(string modelUpdated)
        { 
            try
            {
                if (modelUpdated.Equals("AllModels") || modelUpdated.Equals("ReportingModel"))
                { PopulateGui(); }
            }
            catch (Exception exception)
            {
                string error = "Unable to update ReportingViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void PopulateGui()
        {
            try
            {
                using (DatabaseContext databaseContext = new DatabaseContext())
                {
                    PopulateReports(databaseContext);
                    Groups = databaseContext.Groups.AsNoTracking().ToList();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate ReportingViewModel GUI.");
                throw exception;
            }
        }

        private void PopulateReports(DatabaseContext databaseContext)
        {
            try
            {
                VulnerabilityReports = databaseContext.RequiredReportUserSelections
                    .Include(r => r.RequiredReport)
                    .Where(r => r.RequiredReport.ReportCategory.Equals("Vulnerability Management") && r.UserName.Equals(Properties.Settings.Default.ActiveUser))
                    .OrderBy(r => r.RequiredReport.DisplayedReportName)
                    .AsNoTracking()
                    .ToObservableCollection();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate ReportingViewModel required reports list.");
                throw exception;
            }
        }

        public RelayCommand<object> ReportSelectionChangedCommand => new RelayCommand<object>(ReportSelectionChanged);

        private void ReportSelectionChanged(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += ReportSelectionChangedBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to handle report SelectionChanged event.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void ReportSelectionChangedBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                RequiredReportUserSelection selection = e.Argument as RequiredReportUserSelection;
                
                using (DatabaseContext databaseContext = new DatabaseContext())
                {
                    SelectedReportFindingTypeSettings = databaseContext.ReportFindingTypeUserSettings
                        .Include(r => r.FindingType)
                        .Where(r => r.RequiredReport_ID.Equals(selection.RequiredReport_ID) &&
                                    r.UserName.Equals(Properties.Settings.Default.ActiveUser))
                        .AsNoTracking()
                        .ToObservableCollection();
                    SelectedReportSeveritySettings = databaseContext.ReportSeverityUserSettings
                        .Where(r => r.RequiredReport_ID.Equals(selection.RequiredReport_ID) &&
                                    r.UserName.Equals(Properties.Settings.Default.ActiveUser))
                        .AsNoTracking()
                        .ToObservableCollection();
                    SelectedReportStatusSettings = databaseContext.ReportStatusUserSettings
                        .Where(r => r.RequiredReport_ID.Equals(selection.RequiredReport_ID) &&
                                    r.UserName.Equals(Properties.Settings.Default.ActiveUser))
                        .AsNoTracking()
                        .ToObservableCollection();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to update the view with the selected report information.");
                throw exception;
            }
        }

        public RelayCommand<object> SetReportIsSelectedCommand => new RelayCommand<object>(SetReportIsSelected);

        private void SetReportIsSelected(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += SetReportIsSelectedBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += ReportUpdateBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = $"Unable to set `IsReportSelected` value for the report with ID '{parameter}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetReportIsSelectedBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (e.Argument is null)
                {
                    e.Result = "No parameter";
                    return;
                }

                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                object[] args = e.Argument as object[];

                using (SQLiteCommand sqLiteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("RequiredReportUserSelection_ID", args[0]));
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("IsReportSelected", args[1].ToString()));
                    databaseInterface.UpdateReportIsSelected(sqLiteCommand);
                }

                e.Result = "Success";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("The 'SetReportIsSelected' background worker has failed.");
                e.Result = exception;
            }
        }

        public RelayCommand<object> SetReportFindingTypeIsSelectedCommand => new RelayCommand<object>(SetReportFindingTypeIsSelected);

        private void SetReportFindingTypeIsSelected(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += SetReportFindingTypeIsSelectedBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += ReportUpdateBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = $"Unable to set `IsSelected` value for the report finding type with ID '{parameter}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetReportFindingTypeIsSelectedBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (e.Argument is null)
                {
                    e.Result = "No parameter";
                    return;
                }
                
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                object[] args = e.Argument as object[];

                using (SQLiteCommand sqLiteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("ReportFindingTypeUserSettings_ID", args[0]));
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("IsSelected", args[1].ToString()));
                    databaseInterface.UpdateReportFindingTypeIsSelected(sqLiteCommand);
                }
                e.Result = "Success";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("The 'SetReportFindingTypeIsSelected' background worker has failed.");
                e.Result = exception;
                throw exception;
            }
        }

        public RelayCommand<object> SetReportSeverityIsSelectedCommand => new RelayCommand<object>(SetReportSeverityIsSelected);

        private void SetReportSeverityIsSelected(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += SetReportSeverityIsSelectedBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += ReportUpdateBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = $"Unable to set `IsSelected` value for the report severity with ID '{parameter}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetReportSeverityIsSelectedBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (e.Argument is null)
                {
                    e.Result = "No parameter";
                    return;
                }
                
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                object[] args = e.Argument as object[];

                using (SQLiteCommand sqLiteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("ReportSeverityUserSettings_ID", args[0]));
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("IsSelected", args[1].ToString()));
                    databaseInterface.UpdateReportSeverityIsSelected(sqLiteCommand);
                }
                e.Result = "Success";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("The 'SetReportSeverityIsSelected' background worker has failed.");
                e.Result = exception;
                throw exception;
            }
        }

        public RelayCommand<object> SetReportStatusIsSelectedCommand => new RelayCommand<object>(SetReportStatusIsSelected);

        private void SetReportStatusIsSelected(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += SetReportStatusIsSelectedBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += ReportUpdateBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = $"Unable to set `IsSelected` value for the report severity with ID '{parameter}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetReportStatusIsSelectedBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (e.Argument is null)
                {
                    e.Result = "No parameter";
                    return;
                }
                
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                object[] args = e.Argument as object[];

                using (SQLiteCommand sqLiteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("ReportStatusUserSettings_ID", args[0]));
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("IsSelected", args[1].ToString()));
                    databaseInterface.UpdateReportStatusIsSelected(sqLiteCommand);
                }
                e.Result = "Success";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("The 'SetReportStatusIsSelected' background worker has failed.");
                e.Result = exception;
                throw exception;
            }
        }
        
        private void ReportUpdateBackgroundWorker_RunWorkerCompleted(object sender,
            RunWorkerCompletedEventArgs e)
        {
            try
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                Notification notification = new Notification();
                notification.Background = appStyle.Item1.Resources["GrayBrush10"].ToString();
                notification.Foreground = appStyle.Item1.Resources["TextBrush"].ToString();
                if (e.Result != null)
                {
                    if (e.Result is Exception)
                    {
                        notification.Accent = "Red";
                        notification.Badge = "Failure";
                        notification.Header = "Report Update";
                        notification.Message = "Unable to update the report as requested; see log for details.";
                        Exception exception = e.Result as Exception;
                        string error = "Unable to update the report as requested.";
                        LogWriter.LogErrorWithDebug(error, exception);
                        PopulateGui();
                    }
                    else
                    {
                        switch (e.Result.ToString())
                        {
                            case "Success":
                            {
                                notification.Accent = "Green";
                                notification.Badge = "Success";
                                notification.Header = "Report Update";
                                notification.Message = "Requested report updates performed successfully.";
                                break;
                            }
                            case "No parameter":
                            {
                                notification.Accent = "Orange";
                                notification.Badge = "Warning";
                                notification.Header = "Report Update";
                                notification.Message = "No report selected to update.";
                                break;
                            }
                        }
                    }
                }
                Messenger.Default.Send(notification);
            }
            catch (Exception exception)
            {
                string error = "The 'ReportUpdated' background worker completion tasks have failed.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand ExecuteExportCommand => new RelayCommand(ExecuteExport);

        private void ExecuteExport()
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += ExecuteExportBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerAsync();
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to execute report export.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void ExecuteExportBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                GuiFeedback guiFeedback = new GuiFeedback();
                guiFeedback.SetFields("Generating requested reports", "Visible", false);
                Messenger.Default.Send(guiFeedback);
                if (Properties.Settings.Default.ReportPoamRar)
                {
                    if ((bool)GetExcelReportName())
                    {
                        OpenXmlReportCreator openXmlReportCreator = new OpenXmlReportCreator();
                        openXmlReportCreator.CreateExcelReport(saveExcelFile.FileName);
                    }
                }
                guiFeedback.SetFields("Report creation complete", "Collapsed", true);
                Messenger.Default.Send(guiFeedback);
            }
            catch (Exception exception)
            {
                LogWriter.LogError("An error occurred on the ExecuteExport BackgroundWorker.");
                throw exception;
            }
        }

        public RelayCommand SetReportRequirementCommand => new RelayCommand(SetReportRequirement);

        private void SetReportRequirement()
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += ExecuteSetReportRequirementBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerAsync();
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to set required reports.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void ExecuteSetReportRequirementBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Required_Report_ID", SelectedReport.RequiredReport_ID));
                    //sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Report_Selected", SelectedReport.IsReportSelected));
                    databaseInterface.UpdateRequiredReportSelected(sqliteCommand);
                }
                DatabaseBuilder.sqliteConnection.Close();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update report selection criteria for {SelectedReport.RequiredReport.DisplayedReportName}");
                throw exception;
            }
        }

        public RelayCommand<object> GenerateSingleReportCommand => new RelayCommand<object>(GenerateSingleReport);

        private void GenerateSingleReport(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += GenerateSingleReportBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += GenerateSingleReportBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = $"Unable to generate single report with ID {parameter}.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            
        }

        private void GenerateSingleReportBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                GuiFeedback guiFeedback = new GuiFeedback();
                switch (e.Argument.ToString())
                {
                    case "1":
                    {
                        if ((bool) GetExcelReportName())
                        {
                            
                            guiFeedback.SetFields("Creating report...", "Visible", false);
                            Messenger.Default.Send(guiFeedback);
                            OpenXmlEmassPoamReportCreator openXmlEmassPoamReportCreator = new OpenXmlEmassPoamReportCreator();
                            openXmlEmassPoamReportCreator.CreateEmassPoam(saveExcelFile.FileName);
                            e.Result = "Success";
                            Messenger.Default.Send(guiFeedback);
                        }
                        else
                        {
                            e.Result = "Cancelled";
                        }
                        return;
                    }
                    case "2":
                    {
                        if ((bool) GetExcelReportName())
                        {
                            guiFeedback.SetFields("Creating report...", "Visible", false);
                            Messenger.Default.Send(guiFeedback);
                            OpenXmlNavyRarReportCreator openXmlNavyRarReportCreator = new OpenXmlNavyRarReportCreator();
                            openXmlNavyRarReportCreator.CreateNavyRar(saveExcelFile.FileName);
                            e.Result = "Success";
                            Messenger.Default.Send(guiFeedback);
                        }
                        else
                        {
                            e.Result = "Cancelled";
                        }
                        return;
                    }
                    case "3":
                    {
                        if ((bool) GetExcelReportName())
                        {
                            guiFeedback.SetFields("Creating report...", "Visible", false);
                            Messenger.Default.Send(guiFeedback);
                            OpenXmlStigDiscrepanciesReportCreator openXmlStigDiscrepanciesReportCreator = new OpenXmlStigDiscrepanciesReportCreator();
                            openXmlStigDiscrepanciesReportCreator.CreateDiscrepanciesReport(saveExcelFile.FileName);
                            e.Result = "Success";
                            Messenger.Default.Send(guiFeedback);
                        }
                        else
                        {
                            e.Result = "Cancelled";
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                e.Result = exception;
            }
        }

        private void GenerateSingleReportBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(Application.Current);
                Notification notification = new Notification();
                notification.Background = appStyle.Item1.Resources["GrayBrush10"].ToString();
                notification.Foreground = appStyle.Item1.Resources["TextBrush"].ToString();
                if (e.Result != null)
                {
                    if (e.Result is Exception)
                    {
                        notification.Accent = "Red";
                        notification.Badge = "Failure";
                        notification.Header = "Report Creation";
                        notification.Message = "Requested report(s) failed to create; see log for details.";
                        Exception exception = e.Result as Exception;
                        string error = "Unable to create requested report(s).";
                        LogWriter.LogErrorWithDebug(error, exception);
                    }
                    else
                    {
                        switch (e.Result.ToString())
                        {
                            case "Success":
                            {
                                notification.Accent = "Green";
                                notification.Badge = "Success";
                                notification.Header = "Report Creation";
                                notification.Message = "Requested reports created successfully.";
                                break;
                            }
                            case "Cancelled":
                            {
                                notification.Accent = "Orange";
                                notification.Badge = "Warning";
                                notification.Header = "Report Creation";
                                notification.Message = "Report creation cancelled by user.";
                                break;
                            }
                        }
                    }
                }

                Messenger.Default.Send(notification);
                GuiFeedback guiFeedback = new GuiFeedback();
                guiFeedback.SetFields("Report creation complete", "Collapsed", true);
                Messenger.Default.Send(guiFeedback);
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to handle the single report creation background worker completion events.");
                throw exception;
            }
        }

        // TODO: Rework this for the actual reports
        // private bool ExcelReportsAreRequired()
        // {
        //     bool PoamAndRarAreNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbPoamRar"));
        //     bool SummaryTabIsNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbAssetOverview"));
        //     bool DiscrepanciesTabIsNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbDiscrepancies"));
        //     bool AcasOutputTabIsNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbAcasOutput"));
        //     bool StigDetailsTabIsNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbStigDetails"));
        //     if (PoamAndRarAreNeeded || SummaryTabIsNeeded || DiscrepanciesTabIsNeeded || AcasOutputTabIsNeeded || StigDetailsTabIsNeeded)
        //     { return true; }
        //     else
        //     { return false; }
        // }

        private bool? GetExcelReportName()
        {
            try
            {
                saveExcelFile = new SaveFileDialog();
                saveExcelFile.AddExtension = true;
                saveExcelFile.Filter = "Excel Files (*.xlsx)|*.xlsx";
                saveExcelFile.DefaultExt = "xlsx";
                saveExcelFile.Title = "Save Excel Report";
                saveExcelFile.OverwritePrompt = true;
                saveExcelFile.CheckPathExists = true;
                return saveExcelFile.ShowDialog();
            }
            catch (Exception exception)
            {
                string error = "Unable to get the Excel report name.";
                LogWriter.LogErrorWithDebug(error, exception);
                return null;
            }
        }

        private string CreateExcelReports()
        {
            LogWriter.LogStatusUpdate($"Begin creation of '{saveExcelFile.FileName}'.");
            fileStopWatch.Start();
            OpenXmlReportCreator openXmlReportCreator = new OpenXmlReportCreator();
            if (!openXmlReportCreator.CreateExcelReport(saveExcelFile.FileName).Contains("successful"))
            {
                LogWriter.LogError($"Creation of '{saveExcelFile.FileName}' failed; Elapsed time: '{fileStopWatch.Elapsed.ToString()}'");
                fileStopWatch.Stop();
                fileStopWatch.Reset();
                return "Excel report creation error; see log for details";
            }
            else
            {
                LogWriter.LogStatusUpdate($"'{saveExcelFile.FileName}' created successfully; Elapsed time: {fileStopWatch.Elapsed.ToString()}");
                fileStopWatch.Stop();
                fileStopWatch.Reset();
                return "Excel report created successfully";
            }
        }

        // TODO: Implement this in the correct method for the reworked reporting structure
        // private bool PdfReportIsRequired()
        // {
        //     if (bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbPdfSum")))
        //     { return true; }
        //     else
        //     { return false; }
        // }

        private bool? GetPdfReportName()
        {
            try
            {
                savePdfFile = new SaveFileDialog();
                savePdfFile.AddExtension = true;
                savePdfFile.Filter = "PDF Files (*.pdf)|*.pdf";
                savePdfFile.DefaultExt = "xls";
                savePdfFile.Title = "Save PDF Report";
                savePdfFile.OverwritePrompt = true;
                savePdfFile.CheckPathExists = true;
                return savePdfFile.ShowDialog();
            }
            catch (Exception exception)
            {
                string error = "Unable to get the PDF report name.";
                LogWriter.LogErrorWithDebug(error, exception);
                return null;
            }
        }

        private string CreatePdfReport()
        {
            LogWriter.LogStatusUpdate("Begin creation of " + savePdfFile.FileName);
            fileStopWatch.Start();
            PdfReportCreator pdfReportCreator = new PdfReportCreator();
            if (!pdfReportCreator.PdfWriter(savePdfFile.FileName.ToString(), string.Empty).Equals("Success"))
            {
                LogWriter.LogError($"Creation of '{savePdfFile.FileName}' failed; Elapsed time: {fileStopWatch.Elapsed.ToString()}");
                fileStopWatch.Stop();
                fileStopWatch.Reset();
                return "PDF report creation error; see log for details";
            }
            else
            {
                LogWriter.LogStatusUpdate($"'{savePdfFile.FileName}' created successfully; Elapsed time: {fileStopWatch.Elapsed.ToString()}");
                fileStopWatch.Stop();
                fileStopWatch.Reset();
                return "PDF summary created successfully";
            }
        }
    }
}
