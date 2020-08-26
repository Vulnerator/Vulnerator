using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using log4net;
using Microsoft.Win32;
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
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel
{
    public class ConfigurationManagementViewModel : ViewModelBase
    {
        private VulnerabilitySource vulnerabilitySource;
        private string saveDirectory = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private DdlReader _ddlReader = new DdlReader();
        private Assembly assembly = Assembly.GetExecutingAssembly();

        private List<Hardware> _hardwares;

        public List<Hardware> Hardwares
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

        private List<Software> _softwares;

        public List<Software> Softwares
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

        private List<VulnerabilitySource> _vulnerabilitySources;

        public List<VulnerabilitySource> VulnerabilitySources
        {
            get => _vulnerabilitySources;
            set
            {
                if (_vulnerabilitySources != value)
                {
                    _vulnerabilitySources = value;
                    RaisePropertyChanged("VulnerabilitySources");
                }
            }
        }

        private List<PortProtocolService> _portsProtocolsServices;

        public List<PortProtocolService> PortsProtocolsServices
        {
            get => _portsProtocolsServices;
            set
            {
                if (_portsProtocolsServices != value)
                {
                    _portsProtocolsServices = value;
                    RaisePropertyChanged("PortsProtocolsServices");
                }
            }
        }

        private List<IP_Address> _ipAddresses;

        public List<IP_Address> IpAddresses
        {
            get => _ipAddresses;
            set
            {
                if (_ipAddresses != value)
                {
                    _ipAddresses = value;
                    RaisePropertyChanged("IpAddresses");
                }
            }
        }

        private List<MAC_Address> _macAddresses;

        public List<MAC_Address> MacAddresses
        {
            get => _macAddresses;
            set
            {
                if (_macAddresses != value)
                {
                    _macAddresses = value;
                    RaisePropertyChanged("MacAddresses");
                }
            }
        }

        private Hardware _selectedHardware;

        public Hardware SelectedHardware
        {
            get => _selectedHardware;
            set
            {
                if (_selectedHardware != value)
                {
                    _selectedHardware = value;
                    RaisePropertyChanged("SelectedHardware");
                    SetEditableHardware();
                }
            }
        }

        private Hardware _editableHardware;

        public Hardware EditableHardware
        {
            get => _editableHardware;
            set
            {
                if (_editableHardware != value)
                {
                    _editableHardware = value;
                    RaisePropertyChanged("EditableHardware");
                }
            }
        }

        private Hardware _newHardware;

        public Hardware NewHardware
        {
            get => _newHardware;
            set
            {
                if (_newHardware != value)
                {
                    _newHardware = value;
                    RaisePropertyChanged("NewHardware");
                }
            }
        }

        private Hardware _selectedHardwareForGroupMapping;

        public Hardware SelectedHardwareForGroupMapping
        {
            get => _selectedHardwareForGroupMapping;
            set
            {
                if (_selectedHardwareForGroupMapping != value)
                {
                    _selectedHardwareForGroupMapping = value;
                    RaisePropertyChanged("SelectedHardwareForGroupMapping");
                }
            }
        }

        private Software _newSoftware;

        public Software NewSoftware
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

        private Software _selectedSoftware;

        public Software SelectedSoftware
        {
            get => _selectedSoftware;
            set
            {
                if (_selectedSoftware != value)
                {
                    _selectedSoftware = value;
                    RaisePropertyChanged("SelectedSoftware");
                }
            }
        }

        private Software _editableSoftware;

        public Software EditableSoftware
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

        private PortProtocolService _newPortProtocolService;

        public PortProtocolService NewPortProtocolService
        {
            get => _newPortProtocolService;
            set
            {
                if (_newPortProtocolService != value)
                {
                    _newPortProtocolService = value;
                    RaisePropertyChanged("NewPortProtocolService");
                }
            }
        }

        private PortProtocolService _selectedPPS;

        public PortProtocolService SelectedPPS
        {
            get => _selectedPPS;
            set
            {
                if (_selectedPPS != value)
                {
                    _selectedPPS = value;
                    RaisePropertyChanged("SelectedPPS");
                }
            }
        }

        private PortProtocolService _editablePortProtocolService;

        public PortProtocolService EditablePortProtocolService
        {
            get => _editablePortProtocolService;
            set
            {
                if (_editablePortProtocolService != value)
                {
                    _editablePortProtocolService = value;
                    RaisePropertyChanged("EditablePortProtocolService");
                }
            }
        }

        private Group _selectedGroup;

        public Group SelectedGroup
        {
            get => _selectedGroup;
            set
            {
                if (_selectedGroup == value) return;
                _selectedGroup = value;
                RaisePropertyChanged("SelectedGroup");
            }
        }

        private Group _editableGroup;

        public Group EditableGroup
        {
            get => _editableGroup;
            set
            {
                if (_editableGroup != value)
                {
                    _editableGroup = value;
                    RaisePropertyChanged("EditableGroup");
                }
            }
        }

        private Group _selectedGroupForHardwareMapping;

        public Group SelectedGroupForHardwareMapping
        {
            get => _selectedGroupForHardwareMapping;
            set
            {
                if (_selectedGroupForHardwareMapping == value) return;
                _selectedGroupForHardwareMapping = value;
                RaisePropertyChanged("SelectedGroupForHardwareMapping");
            }
        }

        private Group _newGroup;

        public Group NewGroup
        {
            get { return _newGroup; }
            set
            {
                if (_newGroup == value) return;
                _newGroup = value;
                RaisePropertyChanged("NewGroup");
            }
        }

        private VulnerabilitySource _selectedVulnerabilitySource;

        public VulnerabilitySource SelectedVulnerabilitySource
        {
            get => _selectedVulnerabilitySource;
            set
            {
                if (_selectedVulnerabilitySource != value)
                {
                    _selectedVulnerabilitySource = value;
                    RaisePropertyChanged("SelectedVulnerabilitySource");
                }
            }
        }

        private List<LifecycleStatus> _lifecycleStatuses;

        public List<LifecycleStatus> LifecycleStatuses
        {
            get => _lifecycleStatuses;
            set
            {
                if (_lifecycleStatuses != value)
                {
                    _lifecycleStatuses = value;
                    RaisePropertyChanged("LifecycleStatuses");
                }
            }
        }

        private LifecycleStatus _lifecycleStatus;

        public LifecycleStatus LifecycleStatus
        {
            get => _lifecycleStatus;
            set
            {
                if (_lifecycleStatus != value)
                {
                    _lifecycleStatus = value;
                    RaisePropertyChanged("LifecycleStatus");
                }
            }
        }

        public ConfigurationManagementViewModel()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of ConfigurationManagementViewModel.");
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated,
                    (msg) => HandleModelUpdate(msg.Notification));
                LogWriter.LogStatusUpdate("ConfigurationManagementViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate ConfigurationManagementViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void HandleModelUpdate(string modelUpdated)
        {
            try
            {
                if (modelUpdated.Equals("ConfigurationManagementModel") || modelUpdated.Equals("AllModels"))
                {
                    PopulateGui();
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to update MitigationsNistViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void PopulateGui()
        {
            try
            {
                using (DatabaseContext databaseContext = new DatabaseContext())
                {
                    Hardwares = databaseContext.Hardwares
                        .Include(h => h.SoftwareHardwares.Select(s => s.Software))
                        .Include(h => h.IP_Addresses)
                        .Include(h => h.MAC_Addresses)
                        .Include(h => h.Groups)
                        .Include(h => h.Contacts)
                        .Include(h => h.HardwarePortsProtocolsServices.Select(p => p.PortProtocolService))
                        .OrderBy(h => h.DisplayedHostName)
                        .AsNoTracking().ToList();
                    Softwares = databaseContext.Softwares
                        .Include(s => s.SoftwareHardwares.Select(h => h.Hardware))
                        .OrderBy(s => s.DisplayedSoftwareName)
                        .AsNoTracking().ToList();
                    //Contacts = databaseContext.Contacts
                    //    .Include(c => c.Groups)
                    //    .Include(c => c.Certifications)
                    //    .Include(c => c.Groups)
                    //    .Include(c => c.Organization)
                    //    .Include(c => c.Softwares)
                    //    .AsNoTracking().ToList();
                    PortsProtocolsServices = databaseContext.PortsProtocolsServices
                        .Include(p => p.HardwarePortsProtocolsServices.Select(h => h.Hardware))
                        .AsNoTracking()
                        .ToList();
                    Groups = databaseContext.Groups
                        .Include(g => g.Hardwares)
                        .AsNoTracking().ToList();
                    //VulnerabilitySources = databaseContext.VulnerabilitySources
                    //    .Where(vs => !vs.SourceName.Contains("Nessus"))
                    //    .OrderBy(vs => vs.SourceName)
                    //    .AsNoTracking().ToList();
                    IpAddresses = databaseContext.IP_Addresses
                        .OrderBy(i => i.IpAddress)
                        .AsNoTracking()
                        .ToList();
                    MacAddresses = databaseContext.MAC_Addresses
                        .OrderBy(m => m.MacAddress)
                        .AsNoTracking()
                        .ToList();
                    NewGroup = new Group();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate ConfigurationManagementView lists.");
                throw exception;
            }
        }

        public RelayCommand<object> GenerateCklCommand
        {
            get { return new RelayCommand<object>(p => GenerateCkl(p)); }
        }

        private void GenerateCkl(object param)
        {
            try
            {
                CommonOpenFileDialog commonOpenFileDialog = new CommonOpenFileDialog();
                commonOpenFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                commonOpenFileDialog.IsFolderPicker = true;
                if (commonOpenFileDialog.ShowDialog() == CommonFileDialogResult.Ok)
                {
                    vulnerabilitySource = param as VulnerabilitySource;
                    saveDirectory = commonOpenFileDialog.FileName;
                    BackgroundWorker backgroundWorker = new BackgroundWorker();
                    backgroundWorker.DoWork += generateCklBackgroundWorker_DoWork;
                    backgroundWorker.RunWorkerAsync();
                    backgroundWorker.Dispose();
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to create CKL file.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                GuiFeedback guiFeedback = new GuiFeedback();
                guiFeedback.SetFields(
                    "Unable to generate the selected CKL for the select asset",
                    "Collapsed",
                    true);
                Messenger.Default.Send(guiFeedback);
            }
        }

        private void generateCklBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                GuiFeedback guiFeedback = new GuiFeedback();
                Hardware hardware = SelectedHardware as Hardware;
                CklCreator cklCreator = new CklCreator();
                cklCreator.CreateCklFromHardware(hardware, vulnerabilitySource, saveDirectory);
                guiFeedback.SetFields(
                    $"{vulnerabilitySource.SourceName} CKL created for {hardware.DisplayedHostName}",
                    "Collapsed",
                    true);
                Messenger.Default.Send(guiFeedback);
                vulnerabilitySource = null;
                saveDirectory = string.Empty;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate CKL file background worker.");
                throw exception;
            }
        }

        public RelayCommand AssociateStigToHardwareCommand => new RelayCommand(AssociateStigToHardware);

        private void AssociateStigToHardware()
        {
            try
            {
                BackgroundWorker backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += associateStigToHardwareBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerAsync();
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to generate background worker for AssociateStigToHardware.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void associateStigToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                Hardware hardware = SelectedHardware as Hardware;
                int hardwareId = int.Parse(hardware.Hardware_ID.ToString());
                int vulnerabilitySourceId = int.Parse(SelectedVulnerabilitySource.VulnerabilitySource_ID.ToString());
                AssociateStig associateStig = new AssociateStig();
                associateStig.ToHardware(vulnerabilitySourceId, hardwareId);
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"),
                    MessengerToken.ModelUpdated);
            }
            catch (Exception exception)
            {
                LogWriter.LogError(
                    $"Unable to associate STIG '{SelectedVulnerabilitySource.VulnerabilitySourceFileName}' to Hardware.");
                throw exception;
            }
        }

        public RelayCommand ModifyGroupCommand => new RelayCommand(ModifyGroup);

        private void ModifyGroup()
        {
            try
            {
                if (SelectedGroup == null && NewGroup == null) return;

                BackgroundWorker backgroundWorker = new BackgroundWorker();
                if (SelectedGroup != null)
                {
                    backgroundWorker.DoWork += updateGroupBackgroundWorker_DoWork;
                }
                else
                {
                    backgroundWorker.DoWork += addGroupBackgroundWorker_DoWork;
                }

                backgroundWorker.RunWorkerAsync();
                backgroundWorker.RunWorkerCompleted += groupActionBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = "Unable to insert or update the group.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void updateGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteTransaction sQLiteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["Group_ID"].Value = SelectedGroup.Group_ID;
                        sqliteCommand.Parameters["GroupName"].Value = SelectedGroup.GroupName;
                        sqliteCommand.Parameters["GroupAcronym"].Value =
                            (object) SelectedGroup.GroupAcronym ?? DBNull.Value;
                        sqliteCommand.Parameters["GroupTier"].Value = SelectedGroup.GroupTier;
                        sqliteCommand.Parameters["IsAccreditation"].Value = SelectedGroup.IsAccreditation ?? "False";
                        sqliteCommand.Parameters["Accreditation_eMASS_ID"].Value =
                            (object) SelectedGroup.Accreditation_eMASS_ID ?? DBNull.Value;
                        sqliteCommand.Parameters["IsPlatform"].Value = SelectedGroup.IsPlatform ?? "False";
                        databaseInterface.UpdateGroup(sqliteCommand);
                    }

                    sQLiteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update group '{SelectedGroup.GroupName}'.");
                throw exception;
            }
            finally
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                {
                    DatabaseBuilder.sqliteConnection.Close();
                }
            }
        }

        private void addGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["GroupName"].Value = NewGroup.GroupName;
                        sqliteCommand.Parameters["GroupAcronym"].Value = NewGroup.GroupAcronym;
                        sqliteCommand.Parameters["GroupTier"].Value = NewGroup.GroupTier;
                        sqliteCommand.Parameters["IsAccreditation"].Value = NewGroup.IsAccreditation ?? "False";
                        sqliteCommand.Parameters["Accreditation_eMASS_ID"].Value = NewGroup.Accreditation_eMASS_ID;
                        sqliteCommand.Parameters["IsPlatform"].Value = NewGroup.IsPlatform ?? "False";
                        databaseInterface.InsertGroup(sqliteCommand);

                        string storedProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";
                        sqliteCommand.Parameters.Add(new SQLiteParameter("UserName",
                            Properties.Settings.Default.ActiveUser));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Group_ID",
                            databaseInterface.SelectLastInsertRowId(sqliteCommand)));
                        List<string> reportIds = new List<string>();
                        sqliteCommand.CommandText = _ddlReader.ReadDdl(
                            storedProcedureBase + "Select.RequiredReportIds.dml",
                            assembly);
                        ;
                        using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                        {
                            if (sqliteDataReader.HasRows)
                            {
                                while (sqliteDataReader.Read())
                                {
                                    reportIds.Add(sqliteDataReader[0].ToString());
                                }
                            }
                        }

                        sqliteCommand.CommandText =
                            _ddlReader.ReadDdl(storedProcedureBase + "Insert.RequiredReportUserGroups.dml",
                                assembly);
                        foreach (string report in reportIds)
                        {
                            sqliteCommand.Parameters.Add(new SQLiteParameter("RequiredReport_ID", report));
                            sqliteCommand.ExecuteNonQuery();
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to insert group '{NewGroup.GroupName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                {
                    DatabaseBuilder.sqliteConnection.Close();
                }
            }
        }

        public RelayCommand ClearSelectedGroupCommand => new RelayCommand(ClearSelectedGroup);

        private void ClearSelectedGroup()
        {
            try
            {
                if (SelectedGroup == null) return;
                SelectedGroup = null;
                if (NewGroup != null) return;
                NewGroup = new Group();
            }
            catch (Exception exception)
            {
                string error = "Unable to clear the selected group.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand DeleteGroupCommand => new RelayCommand(DeleteGroupHandler);

        private void DeleteGroupHandler()
        {
            try
            {
                if (SelectedGroup == null && Groups.Count(x => x.IsChecked) < 1) return;
                BackgroundWorker backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += deleteGroupBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += groupActionBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync();
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                string error = $"Unable to delete group '{SelectedGroup.GroupName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void deleteGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.Equals(ConnectionState.Open))
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        if (Groups.Count(x => x.IsChecked) > 0)
                        {
                            foreach (Group group in Groups.Where(x => x.IsChecked))
                            {
                                DeleteGroup(group, sqliteCommand);
                            }
                        }
                        else if (SelectedGroup != null)
                        {
                            DeleteGroup(SelectedGroup, sqliteCommand);
                        }
                    }

                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Group deletion BackgroundWorker failed.");
                throw exception;
            }
            finally
            {
                if (!DatabaseBuilder.sqliteConnection.State.Equals(ConnectionState.Closed))
                {
                    DatabaseBuilder.sqliteConnection.Close();
                }
            }
        }

        private void DeleteGroup(Group group, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Group_ID", group.Group_ID));
                databaseInterface.DeleteGroup(sqliteCommand);
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Group deletion failed.");
                throw exception;
            }
        }

        public RelayCommand AddHardwareToGroupCommand => new RelayCommand(AddHardwareToGroup);

        private void AddHardwareToGroup()
        {
            try
            {
                if (SelectedGroup is null || SelectedHardwareForGroupMapping is null)
                {
                    return;
                }
                // Combobox controls clear the bound SelectedItem when the command fires;
                // mapping those values to an arguments class prevents a race condition
                GroupHardwareMappingDoWorkArguments doWorkArguments = new GroupHardwareMappingDoWorkArguments()
                    {GroupName = SelectedGroup.GroupName, DiscoveredHostName = SelectedHardwareForGroupMapping.DiscoveredHostName};
                BackgroundWorker backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += addHardwareToGroupBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += groupActionBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync(doWorkArguments);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug(
                    $"Unable to associate hardware asset '{SelectedHardwareForGroupMapping.DisplayedHostName}' to group '{SelectedGroup.GroupName}'.",
                    exception);
            }
        }

        private void addHardwareToGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.Equals(ConnectionState.Open))
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        GroupHardwareMappingDoWorkArguments arguments =
                            e.Argument as GroupHardwareMappingDoWorkArguments;
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["GroupName"].Value = arguments.GroupName;
                        sqliteCommand.Parameters["DiscoveredHostName"].Value = arguments.DiscoveredHostName;
                        databaseInterface.MapHardwareToGroup(sqliteCommand);
                    }

                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Hardware to Group association background worker failed.");
                throw exception;
            }
        }

        public RelayCommand AddGroupToHardwareCommand => new RelayCommand(AddGroupToHardware);

        private void AddGroupToHardware()
        {
            try
            {
                if (SelectedHardware is null || SelectedGroupForHardwareMapping is null)
                {
                    return;
                }
                // Combobox controls clear the bound SelectedItem when the command fires;
                // mapping those values to an arguments class prevents a race condition
                GroupHardwareMappingDoWorkArguments doWorkArguments = new GroupHardwareMappingDoWorkArguments()
                    {GroupName = SelectedGroupForHardwareMapping.GroupName, DiscoveredHostName = SelectedHardware.DiscoveredHostName};
                BackgroundWorker backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += addGroupToHardwareBackgroundWorker_DoWork;
                backgroundWorker.RunWorkerCompleted += groupActionBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.RunWorkerAsync(doWorkArguments);
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug(
                    $"Unable to associate group '{SelectedGroupForHardwareMapping.GroupName}' to hardware asset '{SelectedHardware.DisplayedHostName}'.",
                    exception);
            }
        }

        private void addGroupToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            Console.WriteLine("GroupToHardware DoWork");
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.Equals(ConnectionState.Open))
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        GroupHardwareMappingDoWorkArguments arguments =
                            e.Argument as GroupHardwareMappingDoWorkArguments;
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["GroupName"].Value = arguments.GroupName;
                        sqliteCommand.Parameters["DiscoveredHostName"].Value = arguments.DiscoveredHostName;
                        databaseInterface.MapHardwareToGroup(sqliteCommand);
                    }

                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Group to Hardware association background worker failed.");
                throw exception;
            }
        }

        private void groupActionBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"),
                    MessengerToken.ModelUpdated);
                NewGroup = new Group();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to run Group post-modification background worker RunWorkerCompleted tasks.");
                throw exception;
            }
        }

        private void SetEditableHardware()
        {
            try
            {
                if (SelectedHardware == null)
                {
                    EditableHardware = null;
                    return;
                }

                EditableHardware = SelectedHardware;
            }
            catch (Exception exception)
            {
                string error = "Unable to clear set editable hardware.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand ModifyHardwareCommand => new RelayCommand(ModifyHardware);

        private void ModifyHardware()
        {
            BackgroundWorker backgroundWorker = new BackgroundWorker();
            if (SelectedHardware == null)
            {
                backgroundWorker.DoWork += AddHardwareBackgroundWorker_DoWork;
            }
            else
            {
                backgroundWorker.DoWork += UpdateHardwareBackgroundWorker_DoWork;
            }
            backgroundWorker.RunWorkerAsync();
            backgroundWorker.Dispose();
        }

        private void AddHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {

            }
            catch (Exception exception)
            {
                string error = "Unable to add a new hardware to the database.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void UpdateHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {

            }
            catch (Exception exception)
            {
                string error = $"Unable to update hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        /// <summary>
        /// Holds the Group ID and Hardware ID to be associated / disassociated
        /// </summary>
        public class GroupHardwareMappingDoWorkArguments
        {
            public string GroupName { get; set; }

            public string DiscoveredHostName { get; set; }
        }
    }
}