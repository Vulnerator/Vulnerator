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
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel.ConfigurationManagement.Tabs
{
    public class Hardware : ViewModelBase
    {
        private VulnerabilitySource vulnerabilitySource;
        private string saveDirectory = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private BackgroundWorkerFactory _backgroundWorkerFactory = new BackgroundWorkerFactory();

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

        private Model.Entity.Hardware _newHardware;

        public Model.Entity.Hardware NewHardware
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
                    SetEditableHardware();
                }
            }
        }

        private Model.Entity.Hardware _editableHardware;

        public Model.Entity.Hardware EditableHardware
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

        private string _selectedIpAddress;

        public string SelectedIpAddress
        {
            get => _selectedIpAddress;
            set
            {
                if (_selectedIpAddress != value)
                {
                    _selectedIpAddress = value;
                    RaisePropertyChanged("SelectedIpAddress");
                }
            }
        }

        private string _selectedMacAddress;

        public string SelectedMacAddress
        {
            get => _selectedMacAddress;
            set
            {
                if (_selectedMacAddress != value)
                {
                    _selectedMacAddress = value;
                    RaisePropertyChanged("SelectedMacAddress");
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
                }
            }
        }

        private PortProtocolService _selectedPps;

        public PortProtocolService SelectedPps
        {
            get => _selectedPps;
            set
            {
                if (_selectedPps != value)
                {
                    _selectedPps = value;
                    RaisePropertyChanged("SelectedPps");
                }
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

        private LifecycleStatus _selectedLifecycleStatus;

        public LifecycleStatus SelectedLifecycleStatus
        {
            get => _selectedLifecycleStatus;
            set
            {
                if (_selectedLifecycleStatus != value)
                {
                    _selectedLifecycleStatus = value;
                    RaisePropertyChanged("SelectedLifecycleStatus");
                }
            }
        }

        public Hardware()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of Configuration Management view 'Hardware' tab ViewModel.");
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated,
                    (msg) => HandleModelUpdate(msg.Notification));
                LogWriter.LogStatusUpdate("Configuration Management view 'Hardware' tab ViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate Configuration Management view 'Hardware' tab ViewModel.";
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
                        .Include(h => h.SoftwareHardwares
                            .Select(s => s.Software))
                        .Include(h => h.IP_Addresses)
                        .Include(h => h.MAC_Addresses)
                        .Include(h => h.Contacts)
                        .Include(h => h.Groups)
                        .Include(h => h.HardwarePortsProtocolsServices
                            .Select(p => p.PortProtocolService))
                        .Include(h => h.LifecycleStatus)
                        .OrderBy(h => h.DisplayedHostName)
                        .AsNoTracking().ToList();
                    Softwares = databaseContext.Softwares
                        .Include(s => s.SoftwareHardwares
                            .Select(h => h.Hardware))
                        .Include("HardwareSoftwarePortsProtocolsServices.HardwareSoftwarePortsProtocolsServicesBoundaries.Boundary")
                        .Include("HardwareSoftwarePortsProtocolsServices.HardwarePortProtocolService")
                        .OrderBy(s => s.DisplayedSoftwareName)
                        .AsNoTracking().ToList();
                    PortsProtocolsServices = databaseContext.PortsProtocolsServices
                        .Include(p => p.HardwarePortsProtocolsServices
                            .Select(h => h.Hardware))
                        .AsNoTracking()
                        .ToList();
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
                    LifecycleStatuses = databaseContext.LifecycleStatuses
                        .AsNoTracking()
                        .ToList();
                    NewHardware = new Model.Entity.Hardware();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate the Configuration Management view 'Groups' tab list lists.");
                throw exception;
            }
        }

        private void HandleModelUpdate(string modelUpdated)
        {
            try
            {
                if (modelUpdated.Equals("HardwareModel") || modelUpdated.Equals("AllModels"))
                {
                    PopulateGui();
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to update the 'Hardware' tab ViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetEditableHardware()
        {
            try
            {
                if (SelectedHardware == null)
                {
                    EditableHardware = null;
                    SelectedLifecycleStatus = null;
                    SelectedIpAddress = null;
                    SelectedMacAddress = null;
                    SelectedPps = null;
                    SelectedSoftware = null;
                    SelectedGroup = null;
                    return;
                }

                EditableHardware = SelectedHardware;
                SelectedLifecycleStatus = LifecycleStatuses.FirstOrDefault(x =>
                    x.LifecycleStatus_ID.Equals(SelectedHardware.LifecycleStatus_ID));
            }
            catch (Exception exception)
            {
                string error = "Unable to clear set editable hardware.";
                LogWriter.LogErrorWithDebug(error, exception);
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
                    _backgroundWorkerFactory.Build(GenerateCklBackgroundWorker_DoWork);
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

        private void GenerateCklBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                GuiFeedback guiFeedback = new GuiFeedback();
                CklCreator cklCreator = new CklCreator();
                cklCreator.CreateCklFromHardware(SelectedHardware, vulnerabilitySource, saveDirectory);
                guiFeedback.SetFields(
                    $"{vulnerabilitySource.SourceName} CKL created for {SelectedHardware.DisplayedHostName}",
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
                _backgroundWorkerFactory.Build(AssociateStigToHardwareBackgroundWorker_DoWork);
            }
            catch (Exception exception)
            {
                string error = "Unable to generate background worker for AssociateStigToHardware.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void AssociateStigToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                int hardwareId = int.Parse(SelectedHardware.Hardware_ID.ToString());
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

        public RelayCommand AddGroupToHardwareCommand => new RelayCommand(AddGroupToHardware);

        private void AddGroupToHardware()
        {
            try
            {
                if (SelectedHardware is null || SelectedGroup is null)
                { return; }

                // Combobox controls clear the bound SelectedItem when the command fires;
                // mapping those values to an arguments class prevents a race condition
                GroupHardwareMappingDoWorkArguments doWorkArguments = new GroupHardwareMappingDoWorkArguments()
                { GroupName = SelectedGroup.GroupName, DiscoveredHostName = SelectedHardware.DiscoveredHostName };
                _backgroundWorkerFactory.Build(AddGroupToHardwareBackgroundWorker_DoWork, null, doWorkArguments);
            }
            catch (Exception exception)
            {
                string error = SelectedGroup is null ? "'SelectedGroup' has a value of 'null'." :
                    SelectedHardware is null ? "'SelectedHardware' has a value of 'null'." :
                    $"Unable to associate group '{SelectedGroup.GroupName}' to hardware asset '{SelectedHardware.DisplayedHostName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void AddGroupToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
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
                LogWriter.LogError("Group to Hardware association background worker failed.");
                throw exception;
            }
        }

        public RelayCommand ModifyHardwareCommand => new RelayCommand(ModifyHardware);

        private void ModifyHardware()
        {
            if (SelectedHardware == null)
            {
                _backgroundWorkerFactory.Build(AddHardwareBackgroundWorker_DoWork, 
                    ModifyHardwareBackgroundWorker_RunWorkerCompleted);
            }
            else
            {
                _backgroundWorkerFactory.Build(UpdateHardwareBackgroundWorker_DoWork, 
                    ModifyHardwareBackgroundWorker_RunWorkerCompleted);
            }
        }

        private void AddHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (NewHardware == null)
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
                    sqliteCommand.Parameters["DiscoveredHostName"].Value = NewHardware.DisplayedHostName;
                    sqliteCommand.Parameters["DisplayedHostName"].Value = NewHardware.DisplayedHostName;
                    sqliteCommand.Parameters["IsVirtualServer"].Value = NewHardware.IsVirtualServer;
                    sqliteCommand.Parameters["ScanIp"].Value = NewHardware.ScanIP;
                    sqliteCommand.Parameters["IP_Address"].Value = NewHardware.ScanIP;
                    sqliteCommand.Parameters["NIAP_Level"].Value = NewHardware.NIAP_Level;
                    sqliteCommand.Parameters["Manufacturer"].Value = NewHardware.Manufacturer;
                    sqliteCommand.Parameters["ModelNumber"].Value = NewHardware.ModelNumber;
                    sqliteCommand.Parameters["IsIA_Enabled"].Value = NewHardware.IsIA_Enabled;
                    sqliteCommand.Parameters["SerialNumber"].Value = NewHardware.SerialNumber;
                    sqliteCommand.Parameters["Role"].Value = NewHardware.Role;
                    sqliteCommand.Parameters["OperatingSystem"].Value = NewHardware.OperatingSystem;
                    sqliteCommand.Parameters["Found21745"].Value = "False";
                    sqliteCommand.Parameters["Found26917"].Value = "False";
                    if (SelectedLifecycleStatus != null)
                    {
                        sqliteCommand.Parameters["LifecycleStatus_ID"].Value = SelectedLifecycleStatus.LifecycleStatus_ID;
                    }
                    databaseInterface.InsertHardware(sqliteCommand);
                    databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to add a new hardware to the database.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        private void UpdateHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                    sqliteCommand.Parameters["Hardware_ID"].Value = EditableHardware.Hardware_ID;
                    sqliteCommand.Parameters["DiscoveredHostName"].Value = EditableHardware.DisplayedHostName;
                    sqliteCommand.Parameters["DisplayedHostName"].Value = EditableHardware.DisplayedHostName;
                    sqliteCommand.Parameters["IsVirtualServer"].Value = EditableHardware.IsVirtualServer;
                    sqliteCommand.Parameters["ScanIp"].Value = EditableHardware.ScanIP;
                    sqliteCommand.Parameters["NIAP_Level"].Value = EditableHardware.NIAP_Level;
                    sqliteCommand.Parameters["Manufacturer"].Value = EditableHardware.Manufacturer;
                    sqliteCommand.Parameters["ModelNumber"].Value = EditableHardware.ModelNumber;
                    sqliteCommand.Parameters["IsIA_Enabled"].Value = EditableHardware.IsIA_Enabled;
                    sqliteCommand.Parameters["SerialNumber"].Value = EditableHardware.SerialNumber;
                    sqliteCommand.Parameters["Role"].Value = EditableHardware.Role;
                    sqliteCommand.Parameters["OperatingSystem"].Value = EditableHardware.OperatingSystem;
                    if (SelectedLifecycleStatus != null)
                    {
                        sqliteCommand.Parameters["LifecycleStatus_ID"].Value = SelectedLifecycleStatus.LifecycleStatus_ID;
                    }
                    databaseInterface.UpdateHardware(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to update hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        private void ModifyHardwareBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"),
                    MessengerToken.ModelUpdated);
                SelectedHardware = null;
                NewHardware = new Model.Entity.Hardware();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to run Delete Hardware post-modification background worker RunWorkerCompleted tasks.");
                throw exception;
            }
        }
        
        public RelayCommand DeleteHardwareCommand => new RelayCommand(DeleteHardware);

        private void DeleteHardware()
        {
            _backgroundWorkerFactory.Build(DeleteHardwareBackgroundWorker_DoWork, 
                DeleteHardwareBackgroundWorker_RunWorkerCompleted);
        }

        private void DeleteHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (SelectedHardware == null)
                {
                    return;
                }

                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["Hardware_ID"].Value = SelectedHardware.Hardware_ID;
                        databaseInterface.DeleteHardwareContactsMappingByHardware(sqliteCommand);
                        databaseInterface.DeleteHardwareEnumeratedWindowsGroupsMappingByHardware(sqliteCommand);
                        databaseInterface.DeleteHardwareGroupsMappingByHardware(sqliteCommand);
                        databaseInterface.DeleteHardwareIpAddressMappingByHardware(sqliteCommand);
                        databaseInterface.DeleteHardwareMacAddressMappingByHardware(sqliteCommand);
                        databaseInterface.DeleteHardwarePortsProtocolsServicesMappingByHardware(sqliteCommand);
                        databaseInterface.DeleteHardwareLocationMappingByHardware(sqliteCommand);
                        databaseInterface.DeleteSoftwareHardwareMappingByHardware(sqliteCommand);
                        databaseInterface.DeleteScapScoresByHardware(sqliteCommand);
                        databaseInterface.DeleteUniqueFindingsByHardware(sqliteCommand);
                        databaseInterface.DeleteHardware(sqliteCommand);
                    }

                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to delete hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        private void DeleteHardwareBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"),
                    MessengerToken.ModelUpdated);
                SelectedHardware = null;
                NewHardware = new Model.Entity.Hardware();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to run Delete Hardware post-modification background worker RunWorkerCompleted tasks.");
                throw exception;
            }
        }

        public RelayCommand AssociateIpAddressToHardwareCommand => new RelayCommand(AssociateIpAddressToHardware);

        private void AssociateIpAddressToHardware()
        {
            _backgroundWorkerFactory.Build(AssociateIpAddressToHardwareBackgroundWorker_DoWork,
                ModifyHardwareBackgroundWorker_RunWorkerCompleted);
        }

        private void AssociateIpAddressToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (SelectedHardware == null || string.IsNullOrWhiteSpace(SelectedIpAddress))
                {
                    return;
                }

                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address", SelectedIpAddress));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("DiscoveredHostName", SelectedHardware.DiscoveredHostName));
                    databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error =
                    $"Unable to associate IP Address '{SelectedIpAddress}' to hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        public RelayCommand<object> RemoveIpAddressFromHardwareCommand => new RelayCommand<object>(RemoveIpAddressFromHardware);

        private void RemoveIpAddressFromHardware(object parameter)
        {
            if (SelectedHardware == null || parameter == null)
            { return; }

            int ipAddressId = int.Parse(parameter.ToString());
            _backgroundWorkerFactory.Build(RemoveIpAddressFromHardwareBackgroundWorker_DoWork,
                ModifyHardwareBackgroundWorker_RunWorkerCompleted,
                ipAddressId);
        }

        private void RemoveIpAddressFromHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address_ID", e.Argument));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", SelectedHardware.Hardware_ID));
                    databaseInterface.DeleteHardwareIpAddressMapping(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error =
                    $"Unable to remove IP Address with 'IP_Address_ID' value '{e.Argument}' from hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        public RelayCommand AssociateMacAddressToHardwareCommand => new RelayCommand(AssociateMacAddressToHardware);

        private void AssociateMacAddressToHardware()
        {
            _backgroundWorkerFactory.Build(AssociateMacAddressToHardwareBackgroundWorker_DoWork,
                ModifyHardwareBackgroundWorker_RunWorkerCompleted);
        }

        private void AssociateMacAddressToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (SelectedHardware == null || string.IsNullOrWhiteSpace(SelectedMacAddress))
                {
                    return;
                }

                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("MAC_Address", SelectedMacAddress));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("DiscoveredHostName", SelectedHardware.DiscoveredHostName));
                    databaseInterface.InsertAndMapMacAddress(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to associate MAC Address '{SelectedMacAddress}' to hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        public RelayCommand<object> RemoveMacAddressFromHardwareCommand => new RelayCommand<object>(RemoveMacAddressFromHardware);

        private void RemoveMacAddressFromHardware(object parameter)
        {
            if (SelectedHardware == null || parameter == null)
            { return; }

            int macAddressId = int.Parse(parameter.ToString());
            _backgroundWorkerFactory.Build(RemoveMacAddressFromHardwareBackgroundWorker_DoWork,
                ModifyHardwareBackgroundWorker_RunWorkerCompleted,
                macAddressId);
        }

        private void RemoveMacAddressFromHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("MAC_Address_ID", e.Argument));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", SelectedHardware.Hardware_ID));
                    databaseInterface.DeleteHardwareMacAddressMapping(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error =
                    $"Unable to remove MAC Address with 'MAC_Address_ID' value '{e.Argument}' from hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        public RelayCommand AssociateSoftwareToHardwareCommand => new RelayCommand(AssociateSoftwareToHardware);

        private void AssociateSoftwareToHardware()
        {
            _backgroundWorkerFactory.Build(AssociateSoftwareToHardwareBackgroundWorker_DoWork);
        }

        private void AssociateSoftwareToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (SelectedHardware == null || SelectedSoftware == null)
                {
                    return;
                }

                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", SelectedHardware.Hardware_ID));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Software_ID", SelectedSoftware.Software_ID));
                    databaseInterface.MapHardwareToSoftwareById(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to associate Software with 'Software_ID' value '{SelectedSoftware.Software_ID}' to hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        public RelayCommand<object> RemoveSoftwareFromHardwareCommand => new RelayCommand<object>(RemoveSoftwareFromHardware);

        private void RemoveSoftwareFromHardware(object parameter)
        {
            if (SelectedHardware == null || parameter == null)
            { return; }

            int softwareId = int.Parse(parameter.ToString());
            _backgroundWorkerFactory.Build(RemoveSoftwareFromHardwareBackgroundWorker_DoWork,
                ModifyHardwareBackgroundWorker_RunWorkerCompleted,
                softwareId);
        }

        private void RemoveSoftwareFromHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Software_ID", e.Argument));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", SelectedHardware.Hardware_ID));
                    databaseInterface.DeleteSoftwareHardwareMapping(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error =
                    $"Unable to remove Software with 'Software_ID' value '{e.Argument}' from hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        public RelayCommand AssociatePpsToHardwareCommand => new RelayCommand(AssociatePpsToHardware);

        private void AssociatePpsToHardware()
        {
            _backgroundWorkerFactory.Build(AssociatePpsToHardwareBackgroundWorker_DoWork);
        }

        private void AssociatePpsToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (SelectedHardware == null || SelectedPps == null)
                {
                    return;
                }

                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", SelectedHardware.Hardware_ID));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Port", SelectedPps.Port));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Protocol", SelectedPps.Protocol));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("DiscoveredServiceName", SelectedPps.DiscoveredServiceName));
                    databaseInterface.InsertAndMapPort(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to associate PPS with 'PortProtocolService_ID' value '{SelectedPps.PortProtocolService_ID}' to hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        public RelayCommand<object> RemovePpsFromHardwareCommand => new RelayCommand<object>(RemovePpsFromHardware);

        private void RemovePpsFromHardware(object parameter)
        {
            if (SelectedHardware == null || parameter == null)
            {
                return;
            }

            int ppsId = int.Parse(parameter.ToString());
            _backgroundWorkerFactory.Build(RemovePpsFromHardwareBackgroundWorker_DoWork,
                ModifyHardwareBackgroundWorker_RunWorkerCompleted,
                ppsId);
        }

        private void RemovePpsFromHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Closed)
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("PortProtocolService_ID", e.Argument));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", SelectedHardware.Hardware_ID));
                    databaseInterface.DeleteHardwarePortProtocolServiceMapping(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                string error =
                    $"Unable to remove PPS with 'PortProtocolService_ID' value '{e.Argument}' from hardware with 'Hardware_ID' value '{SelectedHardware.Hardware_ID}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }
    }
}
