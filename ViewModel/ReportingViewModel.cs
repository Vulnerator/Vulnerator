using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.Entity;
using System.Data.SQLite;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using Vulnerator.Model.Entity;
using log4net;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using GalaSoft.MvvmLight.Messaging;
using Microsoft.Win32;
using Vulnerator.Helper;
using Vulnerator.Model.BusinessLogic;
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

        private List<RequiredReport> _vulnerabilityReports;
        public List<RequiredReport> VulnerabilityReports
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

        private RequiredReport _selectedReport;

        public RequiredReport SelectedReport
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
                VulnerabilityReports = databaseContext.RequiredReports
                    .Where(r => r.ReportCategory.Equals("Vulnerability Management") && !r.IsReportEnabled.Equals("False"))
                    .OrderBy(r => r.DisplayedReportName)
                    .AsNoTracking()
                    .ToList();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate ReportingViewModel required reports list.");
                throw exception;
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
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Report_Selected", SelectedReport.IsReportSelected));
                    databaseInterface.UpdateRequiredReportSelected(sqliteCommand);
                }
                DatabaseBuilder.sqliteConnection.Close();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update report selection criteria for {SelectedReport.DisplayedReportName}");
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
