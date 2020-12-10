using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.Entity;
using System.Data.SQLite;
using System.Linq;
using System.Reflection;
using Vulnerator.Helper;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel.ConfigurationManagement.Tabs
{
    public class Software : ViewModelBase
    {
        private VulnerabilitySource vulnerabilitySource;
        private string saveDirectory = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private DdlReader _ddlReader = new DdlReader();
        private BackgroundWorkerFactory _backgroundWorkerFactory = new BackgroundWorkerFactory();
        private Assembly assembly = Assembly.GetExecutingAssembly();

        private List<Model.Entity.Hardware> _hardwares;

        public List<Model.Entity.Hardware> Hardwares
        {
            get => _hardwares;
            set
            {
                if (_hardwares != value)
                {
                    _hardwares = value;
                    RaisePropertyChanged("Hardwares");
                }
            }
        }

        private List<Model.Entity.Software> _softwares;

        public List<Model.Entity.Software> Softwares
        {
            get => _softwares;
            set
            {
                if (_softwares != value)
                {
                    _softwares = value;
                    RaisePropertyChanged("Softwares");
                }
            }
        }

        private List<HardwareSoftwarePortProtocolService> _hardwareSoftwarePortsProtocolsServices;

        public List<HardwareSoftwarePortProtocolService> HardwareSoftwarePortsProtocolsServices
        {
            get => _hardwareSoftwarePortsProtocolsServices;
            set
            {
                if (_hardwareSoftwarePortsProtocolsServices != value)
                {
                    _hardwareSoftwarePortsProtocolsServices = value;
                    RaisePropertyChanged("HardwareSoftwarePortsProtocolsServices");
                }
            }
        }

        private List<Contact> _contacts;

        public List<Contact> Contacts
        {
            get => _contacts;
            set
            {
                if (_contacts != value)
                {
                    _contacts = value;
                    RaisePropertyChanged("Contacts");
                }
            }
        }

        private List<Group> _groups;

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

        private Model.Entity.Software _newSoftware;

        public Model.Entity.Software NewSoftware
        {
            get => _newSoftware;
            set
            {
                if (_newSoftware != value)
                {
                    _newSoftware = value;
                    RaisePropertyChanged("NewSoftware");
                }
            }
        }

        private Model.Entity.Software _selectedSoftware;

        public Model.Entity.Software SelectedSoftware
        {
            get => _selectedSoftware;
            set
            {
                if (_selectedSoftware != value)
                {
                    _selectedSoftware = value;
                    RaisePropertyChanged("SelectedSoftware");
                    SetEditableSoftware();
                }
            }
        }

        private Model.Entity.Software _editableSoftware;

        public Model.Entity.Software EditableSoftware
        {
            get => _editableSoftware;
            set
            {
                if (_editableSoftware != value)
                {
                    _editableSoftware = value;
                    RaisePropertyChanged("EditableSoftware");
                }
            }
        }

        private Model.Entity.Hardware _selectedHardware;

        public Model.Entity.Hardware SelectedHardware
        {
            get => _selectedHardware;
            set
            {
                if (_selectedHardware != value)
                {
                    _selectedHardware = value;
                    RaisePropertyChanged("SelectedHardware");
                }
            }
        }

        private HardwareSoftwarePortProtocolService _selectedHardwareSoftwarePortProtocolService;

        public HardwareSoftwarePortProtocolService SelectedHardwareSoftwarePortProtocolService
        {
            get => _selectedHardwareSoftwarePortProtocolService;
            set
            {
                if (_selectedHardwareSoftwarePortProtocolService != value)
                {
                    _selectedHardwareSoftwarePortProtocolService = value;
                    RaisePropertyChanged("SelectedHardwareSoftwarePortProtocolService");
                    SetEditableHardwareSoftwarePortProtocolService();
                }
            }
        }

        private HardwareSoftwarePortProtocolService _editableHardwareSoftwarePortProtocolService;

        public HardwareSoftwarePortProtocolService EditableHardwareSoftwarePortProtocolService
        {
            get => _editableHardwareSoftwarePortProtocolService;
            set
            {
                if (_editableHardwareSoftwarePortProtocolService != value)
                {
                    _selectedHardwareSoftwarePortProtocolService = value;
                    RaisePropertyChanged("EditableHardwareSoftwarePortProtocolService");
                }
            }
        }

        public Software()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of Configuration Management view 'Software' tab ViewModel.");
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated,
                    (msg) => HandleModelUpdate(msg.Notification));
                LogWriter.LogStatusUpdate("Configuration Management view 'Software' tab ViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate Configuration Management view 'Software' tab ViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void HandleModelUpdate(string modelUpdated)
        {
            try
            {
                if (modelUpdated.Equals("SoftwareModel") || modelUpdated.Equals("AllModels"))
                {
                    PopulateGui();
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to update the 'Software' tab ViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void PopulateGui()
        {
            try
            {
                using (DatabaseContext databaseContext = new DatabaseContext())
                {
                    Softwares = databaseContext.Softwares
                        .Include(s => s.SoftwareHardwares
                            .Select(h => h.Hardware))
                        .Include("HardwareSoftwarePortsProtocolsServices.HardwareSoftwarePortsProtocolsServicesBoundaries.Boundary")
                        .Include("HardwareSoftwarePortsProtocolsServices.HardwarePortProtocolService")
                        .OrderBy(s => s.DisplayedSoftwareName)
                        .AsNoTracking().ToList();
                    //Contacts = databaseContext.Contacts
                    //    .Include(c => c.Groups)
                    //    .Include(c => c.Certifications)
                    //    .Include(c => c.Groups)
                    //    .Include(c => c.Organization)
                    //    .Include(c => c.Softwares)
                    //    .AsNoTracking().ToList();
                    Groups = databaseContext.Groups
                        .Include(g => g.Hardwares)
                        .AsNoTracking().ToList();
                    NewSoftware = new Model.Entity.Software();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate ConfigurationManagementView lists.");
                throw exception;
            }
        }

        private void SetEditableSoftware()
        {
            try
            {
                if (SelectedSoftware == null)
                {
                    EditableSoftware = null;
                    return;
                }

                EditableSoftware = SelectedSoftware;
            }
            catch (Exception exception)
            {
                string error = "Unable to set or clear EditableSoftware";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetEditableHardwareSoftwarePortProtocolService()
        {
            try
            {
                if (SelectedHardwareSoftwarePortProtocolService == null)
                {
                    EditableHardwareSoftwarePortProtocolService = null;
                    return;
                }

                EditableHardwareSoftwarePortProtocolService = SelectedHardwareSoftwarePortProtocolService;
            }
            catch (Exception exception)
            {
                string error = "Unable to set or clear EditableHardwareSoftwarePortProtocolService.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand ModifySoftwareCommand => new RelayCommand(ModifySoftware);

        private void ModifySoftware()
        {

            try
            {
                if (SelectedSoftware != null)
                {
                    _backgroundWorkerFactory.Build(UpdateSoftwareBackgroundWorker_DoWork, ModifySoftwareBackgroundWorker_RunWorkerCompleted);
                }
                else
                {
                    _backgroundWorkerFactory.Build(AddSoftwareBackgroundWorker_DoWork, ModifySoftwareBackgroundWorker_RunWorkerCompleted);
                }
            }
            catch (Exception exception)
            {
                string error = "";
                LogWriter.LogErrorWithDebug(error, exception);
                throw exception;
            }
        }

        private void AddSoftwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (NewSoftware == null)
                {
                    return;
                }

                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                    sqliteCommand.Parameters["DiscoveredSoftwareName"].Value = NewSoftware.DisplayedSoftwareName;
                    sqliteCommand.Parameters["DisplayedSoftwareName"].Value = NewSoftware.DisplayedSoftwareName;
                    sqliteCommand.Parameters["SoftwareAcronym"].Value = NewSoftware.SoftwareAcronym;
                    sqliteCommand.Parameters["SoftwareVersion"].Value = NewSoftware.SoftwareVersion;
                    sqliteCommand.Parameters["SoftwareFunction"].Value = NewSoftware.SoftwareFunction;
                    sqliteCommand.Parameters["SoftwareDescription"].Value = NewSoftware.SoftwareDescription;
                    sqliteCommand.Parameters["DADMS_ID"].Value = NewSoftware.DADMS_ID;
                    sqliteCommand.Parameters["DADMS_Disposition"].Value = NewSoftware.DADMS_Disposition;
                    sqliteCommand.Parameters["DADMS_LastDateAuthorized"].Value = NewSoftware.DADMS_LastDateAuthorized;
                    sqliteCommand.Parameters["HasCustomCode"].Value = NewSoftware.HasCustomCode;
                    sqliteCommand.Parameters["IA_OrIA_Enabled"].Value = NewSoftware.IA_OrIA_Enabled;
                    sqliteCommand.Parameters["IsOS_OrFirmware"].Value = NewSoftware.IsOS_OrFirmware;
                    sqliteCommand.Parameters["FAM_Accepted"].Value = NewSoftware.FAM_Accepted;
                    sqliteCommand.Parameters["ExternallyAuthorized"].Value = NewSoftware.ExternallyAuthorized;
                    sqliteCommand.Parameters["ReportInAccreditationGlobal"].Value = NewSoftware.ReportInAccreditationGlobal;
                    sqliteCommand.Parameters["ApprovedForBaselineGlobal"].Value = NewSoftware.ApprovedForBaselineGlobal;
                    sqliteCommand.Parameters["BaselineApproverGlobal"].Value = NewSoftware.BaselineApproverGlobal;
                    databaseInterface.InsertSoftware(sqliteCommand);
                    sqliteCommand.Parameters["Software_ID"].Value =
                        databaseInterface.SelectLastInsertRowId(sqliteCommand);

                    foreach (SoftwareHardware sh in NewSoftware.SoftwareHardwares)
                    {
                        sqliteCommand.Parameters["Hardware_ID"].Value = sh.Hardware_ID;
                        databaseInterface.MapHardwareToSoftwareById(sqliteCommand);
                    }

                    foreach (HardwareSoftwarePortProtocolService hspps in NewSoftware
                        .HardwareSoftwarePortsProtocolsServices)
                    {
                        sqliteCommand.Parameters["HardwarePortProtocolService_ID"].Value = hspps.HardwarePortProtocolService_ID;
                        sqliteCommand.Parameters["ReportInAccreditation"].Value = hspps.ReportInAccreditation;
                        databaseInterface.MapSoftwareToHardwarePortProtocolService(sqliteCommand);
                        sqliteCommand.Parameters["HardwareSoftwarePortProtocolService_ID"].Value =
                            databaseInterface.SelectLastInsertRowId(sqliteCommand);

                        foreach (HardwareSoftwarePortProtocolServiceBoundary hsppsb in hspps
                            .HardwareSoftwarePortsProtocolsServicesBoundaries)
                        {
                            sqliteCommand.Parameters["Boundary_ID"].Value = hsppsb.Boundary_ID;
                            sqliteCommand.Parameters["CAL_Compliant"].Value = hsppsb.CAL_Compliant;
                            sqliteCommand.Parameters["PPSM_Approved"].Value = hsppsb.PPSM_Approved;
                            sqliteCommand.Parameters["Direction"].Value = hsppsb.Direction;
                            sqliteCommand.Parameters["Classification"].Value = hsppsb.Classification;
                            databaseInterface.MapBoundaryToHardwareSoftwarePortProtocolService(sqliteCommand);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to add the new Software to the database.";
                LogWriter.LogErrorWithDebug(error, exception);
                throw exception;
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        private void UpdateSoftwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {

            try
            {
                if (EditableSoftware == null)
                {
                    return;
                }

                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                    sqliteCommand.Parameters["Software_ID"].Value = EditableSoftware.Software_ID;
                    sqliteCommand.Parameters["DisplayedSoftwareName"].Value = EditableSoftware.DisplayedSoftwareName;
                    sqliteCommand.Parameters["SoftwareAcronym"].Value = EditableSoftware.SoftwareAcronym;
                    sqliteCommand.Parameters["SoftwareVersion"].Value = EditableSoftware.SoftwareVersion;
                    sqliteCommand.Parameters["SoftwareFunction"].Value = EditableSoftware.SoftwareFunction;
                    sqliteCommand.Parameters["SoftwareDescription"].Value = EditableSoftware.SoftwareDescription;
                    sqliteCommand.Parameters["DADMS_ID"].Value = EditableSoftware.DADMS_ID;
                    sqliteCommand.Parameters["DADMS_Disposition"].Value = EditableSoftware.DADMS_Disposition;
                    sqliteCommand.Parameters["DADMS_LastDateAuthorized"].Value = EditableSoftware.DADMS_LastDateAuthorized;
                    sqliteCommand.Parameters["HasCustomCode"].Value = EditableSoftware.HasCustomCode;
                    sqliteCommand.Parameters["IA_OrIA_Enabled"].Value = EditableSoftware.IA_OrIA_Enabled;
                    sqliteCommand.Parameters["IsOS_OrFirmware"].Value = EditableSoftware.IsOS_OrFirmware;
                    sqliteCommand.Parameters["FAM_Accepted"].Value = EditableSoftware.FAM_Accepted;
                    sqliteCommand.Parameters["ExternallyAuthorized"].Value = EditableSoftware.ExternallyAuthorized;
                    sqliteCommand.Parameters["ReportInAccreditationGlobal"].Value = EditableSoftware.ReportInAccreditationGlobal;
                    sqliteCommand.Parameters["ApprovedForBaselineGlobal"].Value = EditableSoftware.ApprovedForBaselineGlobal;
                    sqliteCommand.Parameters["BaselineApproverGlobal"].Value = EditableSoftware.BaselineApproverGlobal;
                    databaseInterface.UpdateSoftware(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to update Software with ID '{EditableSoftware.Software_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
                throw exception;
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        private void ModifySoftwareBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {

            try
            {

            }
            catch (Exception exception)
            {
                LogWriter.LogError("");
                throw exception;
            }
        }
    }
}
