using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Core.Objects;
using System.Data.SQLite;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;
using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using Vulnerator.Model.Entity;
using log4net;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using GalaSoft.MvvmLight.Messaging;
using MahApps.Metro;
using Vulnerator.Helper;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.BusinessLogic.Reports;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel
{
    public class ReportingViewModel : ViewModelBase
    {
        private BackgroundWorker backgroundWorker;
        private FolderBrowserDialog folderBrowserDialog;
        private DialogResult? dialogResult;
        private Microsoft.Win32.SaveFileDialog saveExcelFile;
        private Microsoft.Win32.SaveFileDialog savePdfFile;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        public static Stopwatch stopWatch = new Stopwatch();
        public static Stopwatch fileStopWatch = new Stopwatch();

        private string _overrideLabel;

        public string OverrideLabel
        {
            get => _overrideLabel;
            set
            {
                if (_overrideLabel != value)
                {
                    _overrideLabel = value;
                    RaisePropertyChanged("OverrideLabel");
                }
            }
        }

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

        private ObservableCollection<ReportGroupUserSettings> _selectedReportGroupSettings;

        public ObservableCollection<ReportGroupUserSettings> SelectedReportGroupSettings
        {
            get => _selectedReportGroupSettings;
            set
            {
                if (_selectedReportGroupSettings != value)
                {
                    _selectedReportGroupSettings = value;
                    RaisePropertyChanged("SelectedReportGroupSettings");
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

        private ReportRmfOverrideUserSettings _selectedReportRmfOverrideUserSettings;

        public ReportRmfOverrideUserSettings SelectedReportRmfOverrideUserSettings
        {
            get => _selectedReportRmfOverrideUserSettings;
            set
            {
                if (_selectedReportRmfOverrideUserSettings != value)
                {
                    _selectedReportRmfOverrideUserSettings = value;
                    RaisePropertyChanged("SelectedReportRmfOverrideUserSettings");
                }
            }
        }

        private Group _selectedReportRmfOverrideUserSettingsGroup;

        public Group SelectedReportRmfOverrideUserSettingsGroup
        {
            get => _selectedReportRmfOverrideUserSettingsGroup;
            set
            {
                if (_selectedReportRmfOverrideUserSettingsGroup != value)
                {
                    _selectedReportRmfOverrideUserSettingsGroup = value;
                    RaisePropertyChanged("SelectedReportRmfOverrideUserSettingsGroup");
                }
            }
        }

        private ObservableCollection<ReportUseGlobalValueUserSettings> _selectedReportUseGlobalValueUserSettings;

        public ObservableCollection<ReportUseGlobalValueUserSettings> SelectedReportUseGlobalValueUserSettings
        {
            get => _selectedReportUseGlobalValueUserSettings;
            set
            {
                if (_selectedReportUseGlobalValueUserSettings != value)
                {
                    _selectedReportUseGlobalValueUserSettings = value;
                    RaisePropertyChanged("SelectedReportUseGlobalValueUserSettings");
                }
            }
        }

        private ObservableCollection<ReportFindingTypeUserSettings> _globalReportFindingTypeSettings;

        public ObservableCollection<ReportFindingTypeUserSettings> GlobalReportFindingTypeSettings
        {
            get => _globalReportFindingTypeSettings;
            set
            {
                if (_globalReportFindingTypeSettings != value)
                {
                    _globalReportFindingTypeSettings = value;
                    RaisePropertyChanged("GlobalReportFindingTypeSettings");
                }
            }
        }

        private ObservableCollection<ReportGroupUserSettings> _globalReportGroupSettings;

        public ObservableCollection<ReportGroupUserSettings> GlobalReportGroupSettings
        {
            get => _globalReportGroupSettings;
            set
            {
                if (_globalReportGroupSettings != value)
                {
                    _globalReportGroupSettings = value;
                    RaisePropertyChanged("GlobalReportGroupSettings");
                }
            }
        }

        private ObservableCollection<ReportSeverityUserSettings> _globalReportSeveritySettings;

        public ObservableCollection<ReportSeverityUserSettings> GlobalReportSeveritySettings
        {
            get => _globalReportSeveritySettings;
            set
            {
                if (_globalReportSeveritySettings != value)
                {
                    _globalReportSeveritySettings = value;
                    RaisePropertyChanged("GlobalReportSeveritySettings");
                }
            }
        }

        private ObservableCollection<ReportStatusUserSettings> _globalReportStatusSettings;

        public ObservableCollection<ReportStatusUserSettings> GlobalReportStatusSettings
        {
            get => _globalReportStatusSettings;
            set
            {
                if (_globalReportStatusSettings != value)
                {
                    _globalReportStatusSettings = value;
                    RaisePropertyChanged("GlobalReportStatusSettings");
                }
            }
        }

        private ReportRmfOverrideUserSettings _globalReportRmfOverrideUserSettings;

        public ReportRmfOverrideUserSettings GlobalReportRmfOverrideUserSettings
        {
            get => _globalReportRmfOverrideUserSettings;
            set
            {
                if (_globalReportRmfOverrideUserSettings != value)
                {
                    _globalReportRmfOverrideUserSettings = value;
                    RaisePropertyChanged("GlobalReportRmfOverrideUserSettings");
                }
            }
        }

        private Group _globalReportRmfOverrideUserSettingsGroup;

        public Group GlobalReportRmfOverrideUserSettingsGroup
        {
            get => _globalReportRmfOverrideUserSettingsGroup;
            set
            {
                if (_globalReportRmfOverrideUserSettingsGroup != value)
                {
                    _globalReportRmfOverrideUserSettingsGroup = value;
                    RaisePropertyChanged("GlobalReportRmfOverrideUserSettingsGroup");
                }
            }
        }

        private ReportUseGlobalValueUserSettings _reportUseGlobalValueUserSettings;

        public ReportUseGlobalValueUserSettings ReportUseGlobalValueUserSettings
        {
            get => _reportUseGlobalValueUserSettings;
            set
            {
                if (_reportUseGlobalValueUserSettings != value)
                {
                    _reportUseGlobalValueUserSettings = value;
                    RaisePropertyChanged("ReportUseGlobalValueUserSettings");
                }
            }
        }

        public ReportingViewModel()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of ReportingViewModel.");
                OverrideLabel = 
                    "An optional selection that overrides the individually set status, impact, risk, etc. for each asset " +
                    "using the values provided for the selected group.";
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
                    Groups = databaseContext.Groups.AsNoTracking().ToList();
                    PopulateReports(databaseContext);
                    PopulateGlobalLists(databaseContext);
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

        private void PopulateGlobalLists(DatabaseContext databaseContext)
        {
            try
            {
                GlobalReportFindingTypeSettings = databaseContext.ReportFindingTypeUserSettings
                    .Include(r => r.FindingType)
                    .Where(r => r.RequiredReport.DisplayedReportName.Equals("Global") &&
                                r.UserName.Equals(Properties.Settings.Default.ActiveUser))
                    .AsNoTracking()
                    .ToObservableCollection();
                GlobalReportGroupSettings = databaseContext.ReportGroupUserSettings
                    .Include(r => r.Group)
                    .Where(r => r.RequiredReport.DisplayedReportName.Equals("Global") &&
                                r.UserName.Equals(Properties.Settings.Default.ActiveUser))
                    .AsNoTracking()
                    .ToObservableCollection();
                GlobalReportSeveritySettings = databaseContext.ReportSeverityUserSettings
                    .Where(r => r.RequiredReport.DisplayedReportName.Equals("Global") &&
                                r.UserName.Equals(Properties.Settings.Default.ActiveUser))
                    .AsNoTracking()
                    .ToObservableCollection();
                GlobalReportStatusSettings = databaseContext.ReportStatusUserSettings
                    .Where(r => r.RequiredReport.DisplayedReportName.Equals("Global") &&
                                r.UserName.Equals(Properties.Settings.Default.ActiveUser))
                    .AsNoTracking()
                    .ToObservableCollection();
                GlobalReportRmfOverrideUserSettings = databaseContext.ReportRmfOverrideUserSettings
                    .Include(r => r.Group)
                    .FirstOrDefault(r => r.RequiredReport.DisplayedReportName.Equals("Global") &&
                                         r.UserName.Equals(Properties.Settings.Default.ActiveUser));
                if (GlobalReportRmfOverrideUserSettings != null && GlobalReportRmfOverrideUserSettings.Group != null)
                { GlobalReportRmfOverrideUserSettingsGroup = Groups.FirstOrDefault(x => x.Group_ID.Equals(GlobalReportRmfOverrideUserSettings.Group_ID)); }
                else
                { GlobalReportRmfOverrideUserSettingsGroup = null; }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate ReportingViewModel global user setting lists.");
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
                    SelectedReportGroupSettings = databaseContext.ReportGroupUserSettings
                        .Include(r => r.Group)
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
                    SelectedReportRmfOverrideUserSettings = databaseContext.ReportRmfOverrideUserSettings
                        .Include(r => r.Group)
                        .FirstOrDefault(r => r.RequiredReport_ID.Equals(selection.RequiredReport_ID) &&
                                             r.UserName.Equals(Properties.Settings.Default.ActiveUser));
                    if (SelectedReportRmfOverrideUserSettings != null && SelectedReportRmfOverrideUserSettings.Group != null)
                    { SelectedReportRmfOverrideUserSettingsGroup = Groups.FirstOrDefault(x => x.Group_ID.Equals(SelectedReportRmfOverrideUserSettings.Group_ID)); }
                    else
                    { SelectedReportRmfOverrideUserSettingsGroup = null; }

                    ReportUseGlobalValueUserSettings = databaseContext.ReportUseGlobalValueUserSettings
                        .FirstOrDefault(r => r.RequiredReport_ID.Equals(selection.RequiredReport_ID) && 
                                             r.UserName.Equals(Properties.Settings.Default.ActiveUser));
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

        public RelayCommand<object> SetReportGroupIsSelectedCommand => new RelayCommand<object>(SetReportGroupIsSelected);

        private void SetReportGroupIsSelected(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += SetReportGroupIsSelectedBackgroundWorker_DoWork;
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

        private void SetReportGroupIsSelectedBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
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
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("ReportGroupUserSettings_ID", args[0]));
                    sqLiteCommand.Parameters.Add(new SQLiteParameter("IsSelected", args[1].ToString()));
                    databaseInterface.UpdateReportGroupIsSelected(sqLiteCommand);
                }
                e.Result = "Success";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("The 'SetReportGroupIsSelected' background worker has failed.");
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

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("ReportStatusUserSettings_ID", args[0]));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IsSelected", args[1].ToString()));
                    databaseInterface.UpdateReportStatusIsSelected(sqliteCommand);
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
                if (e.Result.ToString().Equals("Success"))
                {
                    return;
                }
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(System.Windows.Application.Current);
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

        public RelayCommand<object> SetRmfOverrideGroupCommand => new RelayCommand<object>(SetRmfOverrideGroup);

        private void SetRmfOverrideGroup(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += SetRmfOverrideGroupBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to set RMF override group.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetRmfOverrideGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (e.Argument is null)
                {
                    e.Result = "No parameter";
                    return;
                }
                
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                { DatabaseBuilder.sqliteConnection.Open(); }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("UserName", Properties.Settings.Default.ActiveUser));
                    switch (e.Argument)
                    {
                        case "GlobalRmfOverride":
                        {
                            if (GlobalReportRmfOverrideUserSettingsGroup is null)
                            {
                                e.Result = "No global group";
                                return;
                            }
                            sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", GlobalReportRmfOverrideUserSettingsGroup.GroupName));
                            databaseInterface.UpdateReportRmfOverrideGlobal(sqliteCommand);
                            break;
                        }
                        case "SelectedReportRmfOverride":
                        {
                            if (SelectedReportRmfOverrideUserSettingsGroup is null)
                            {
                                e.Result = "No selected group";
                                return;
                            }
                            sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", SelectedReportRmfOverrideUserSettingsGroup.GroupName));
                            sqliteCommand.Parameters.Add(new SQLiteParameter("RequiredReport_ID", SelectedReport.RequiredReport_ID));
                            databaseInterface.UpdateReportRmfOverrideSelectedReport(sqliteCommand);
                            break;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                string error = "The 'SetRmfOverrideGroup' background worker has failed.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand<object> ClearRmfOverrideGroupCommand => new RelayCommand<object>(ClearRmfOverrideGroup);

        private void ClearRmfOverrideGroup(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += ClearRmfOverrideGroupBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to clear RMF override group.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void ClearRmfOverrideGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (e.Argument is null)
                {
                    e.Result = "No parameter";
                    return;
                }
                
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                { DatabaseBuilder.sqliteConnection.Open(); }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("UserName", Properties.Settings.Default.ActiveUser));
                    switch (e.Argument)
                    {
                        case "GlobalRmfOverride":
                        {
                            sqliteCommand.Parameters.Add(new SQLiteParameter("Group_ID", DBNull.Value));
                            databaseInterface.ClearReportRmfOverrideGlobal(sqliteCommand);
                            GlobalReportRmfOverrideUserSettingsGroup = null;
                            break;
                        }
                        case "SelectedReportRmfOverride":
                        {
                            if (SelectedReportRmfOverrideUserSettingsGroup is null)
                            {
                                e.Result = "No selected group";
                                return;
                            }
                            sqliteCommand.Parameters.Add(new SQLiteParameter("Group_ID", DBNull.Value));
                            sqliteCommand.Parameters.Add(new SQLiteParameter("RequiredReport_ID", SelectedReport.RequiredReport_ID));
                            databaseInterface.ClearReportRmfOverrideSelectedReport(sqliteCommand);
                            SelectedReportRmfOverrideUserSettingsGroup = null;
                            break;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                string error = "The 'ClearRmfOverrideGroup' background worker has failed.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand<object> SetUseGlobalValueCommand => new RelayCommand<object>(SetUseGlobalValue);

        private void SetUseGlobalValue(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += SetUseGlobalValueBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to set use global value.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetUseGlobalValueBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (e.Argument is null)
                {
                    e.Result = "No parameter";
                    return;
                }

                if (SelectedReport is null)
                {
                    e.Result = "No report selected";
                    return;
                }
                
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                object[] args = e.Argument as object[];

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {

                    sqliteCommand.Parameters.Add(new SQLiteParameter("ColumnValue", args[1].ToString()));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("RequiredReport_ID", SelectedReport.RequiredReport_ID));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("UserName", Properties.Settings.Default.ActiveUser));
                    databaseInterface.UpdateReportUseGlobalValueUserSettings(sqliteCommand, args[0].ToString());
                }
            }
            catch (Exception exception)
            {
                string error = "The 'SetUseGlobalValue' background worker has failed.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand<object> GenerateSingleVulnerabilityReportCommand => new RelayCommand<object>(GenerateSingleVulnerabilityReport);

        private void GenerateSingleVulnerabilityReport(object parameter)
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += GenerateSingleVulnerabilityReportBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += GenerateReportBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync(parameter);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = $"Unable to generate single report with ID {parameter}.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            
        }

        private void GenerateSingleVulnerabilityReportBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
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
                            
                            guiFeedback.SetFields("Creating eMASS POA&M...", "Visible", false);
                            Messenger.Default.Send(guiFeedback);
                            OpenXmlEmassPoamReportCreator openXmlEmassPoamReportCreator = new OpenXmlEmassPoamReportCreator();
                            openXmlEmassPoamReportCreator.CreateEmassPoam(saveExcelFile.FileName);
                            e.Result = "Success";
                            guiFeedback.SetFields("eMASS POA&M creation completed...", "Collapsed", false);
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
                            guiFeedback.SetFields("Creating Navy RAR...", "Visible", false);
                            Messenger.Default.Send(guiFeedback);
                            OpenXmlNavyRarReportCreator openXmlNavyRarReportCreator = new OpenXmlNavyRarReportCreator();
                            openXmlNavyRarReportCreator.CreateNavyRar(saveExcelFile.FileName);
                            e.Result = "Success";
                            guiFeedback.SetFields("Navy RAR creation completed...", "Collapsed", false);
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
                            guiFeedback.SetFields("Creating STIG Discrepancies Report...", "Visible", false);
                            Messenger.Default.Send(guiFeedback);
                            OpenXmlStigDiscrepanciesReportCreator openXmlStigDiscrepanciesReportCreator = new OpenXmlStigDiscrepanciesReportCreator();
                            openXmlStigDiscrepanciesReportCreator.CreateDiscrepanciesReport(saveExcelFile.FileName);
                            e.Result = "Success";
                            guiFeedback.SetFields("STIG Discrepancies report creation completed...", "Collapsed", false);
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

        public RelayCommand GenerateAllVulnerabilityReportsCommand => new RelayCommand(GenerateAllVulnerabilityReports);

        private void GenerateAllVulnerabilityReports()
        {
            try
            {
                backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += GenerateAllVulnerabilityReportsBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += GenerateReportBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync();
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to generate all reports.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void GenerateAllVulnerabilityReportsBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                GuiFeedback guiFeedback = new GuiFeedback();
                guiFeedback.SetFields("Creating vulnerability reports...", "Visible", false);
                Messenger.Default.Send(guiFeedback);

                string location = GetAllReportsSaveLocation();
                if (string.IsNullOrWhiteSpace(location))
                {
                    e.Result = "Cancelled";
                    return;
                }

                foreach (RequiredReportUserSelection report in VulnerabilityReports)
                {
                    if (report.IsReportSelected.Equals("False"))
                    {
                        continue;
                    }

                    switch (report.RequiredReportUserSelection_ID)
                    {
                        case 1:
                        {
                            OpenXmlNavyRarReportCreator openXmlNavyRarReportCreator = new OpenXmlNavyRarReportCreator();
                            openXmlNavyRarReportCreator.CreateNavyRar($"{location}\\eMASS-POA&M_{DateTime.Now.ToString("yyyyMMdd-HHmmss", new CultureInfo("en-US"))}.xlsx");
                            break;
                        }
                        case 2:
                        {
                            OpenXmlNavyRarReportCreator openXmlNavyRarReportCreator = new OpenXmlNavyRarReportCreator();
                            openXmlNavyRarReportCreator.CreateNavyRar($"{location}\\Navy-RAR_{DateTime.Now.ToString("yyyyMMdd-HHmmss", new CultureInfo("en-US"))}.xlsx");
                            break;
                        }
                        case 3:
                        {
                            OpenXmlStigDiscrepanciesReportCreator openXmlStigDiscrepanciesReportCreator = new OpenXmlStigDiscrepanciesReportCreator();
                            openXmlStigDiscrepanciesReportCreator.CreateDiscrepanciesReport($"{location}\\STIG-Discrepancies_{DateTime.Now.ToString("yyyyMMdd-HHmmss", new CultureInfo("en-US"))}.xlsx");
                            break;
                        }
                    }
                }

                dialogResult = null;
                e.Result = "Success";
                guiFeedback.SetFields("Reports created.", "Collapsed", false);
                Messenger.Default.Send(guiFeedback);
            }
            catch (Exception exception)
            {
                e.Result = exception;
            }
        }

        private void GenerateReportBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {
                Tuple<AppTheme, Accent> appStyle = ThemeManager.DetectAppStyle(System.Windows.Application.Current);
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

        private bool? GetExcelReportName()
        {
            try
            {
                saveExcelFile = new Microsoft.Win32.SaveFileDialog();
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

        private string GetAllReportsSaveLocation()
        {
            try
            {
                var invoking = System.Windows.Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                {
                    folderBrowserDialog = new FolderBrowserDialog();
                    dialogResult = folderBrowserDialog.ShowDialog();
                    
                }));
                invoking.Wait();
                
                if (dialogResult == DialogResult.OK)
                {
                    return folderBrowserDialog.SelectedPath;
                }

                return string.Empty;
            }
            catch (Exception exception)
            {
                string error = "Unable to get the Excel report name.";
                LogWriter.LogErrorWithDebug(error, exception);
                return string.Empty;
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
                savePdfFile = new Microsoft.Win32.SaveFileDialog();
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
