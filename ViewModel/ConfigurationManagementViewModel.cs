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

namespace Vulnerator.ViewModel
{
    public class ConfigurationManagementViewModel : ViewModelBase
    {
        private VulnerabilitySource vulnerabilitySource;
        private string saveDirectory = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private DdlReader _ddlReader = new DdlReader();
        private BackgroundWorkerFactory _backgroundWorkerFactory = new BackgroundWorkerFactory();
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

        private string _ipAddressForHardwareMapping;

        public string IpAddressForHardwareMapping
        {
            get => _ipAddressForHardwareMapping;
            set
            {
                if (_ipAddressForHardwareMapping != value)
                {
                    _ipAddressForHardwareMapping = value;
                    RaisePropertyChanged("IpAddressForHardwareMapping");
                }
            }
        }

        private string _macAddressForHardwareMapping;

        public string MacAddressForHardwareMapping
        {
            get => _macAddressForHardwareMapping;
            set
            {
                if (_macAddressForHardwareMapping != value)
                {
                    _macAddressForHardwareMapping = value;
                    RaisePropertyChanged("MacAddressForHardwareMapping");
                }
            }
        }

        private Software _softwareForHardwareMapping;

        public Software SoftwareForHardwareMapping
        {
            get => _softwareForHardwareMapping;
            set
            {
                if (_softwareForHardwareMapping != value)
                {
                    _softwareForHardwareMapping = value;
                    RaisePropertyChanged("SoftwareForHardwareMapping");
                }
            }
        }

        private PortProtocolService _ppsForHardwareMapping;

        public PortProtocolService PpsForHardwareMapping
        {
            get => _ppsForHardwareMapping;
            set
            {
                if (_ppsForHardwareMapping != value)
                {
                    _ppsForHardwareMapping = value;
                    RaisePropertyChanged("PpsForHardwareMapping");
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
                    //Contacts = databaseContext.Contacts
                    //    .Include(c => c.Groups)
                    //    .Include(c => c.Certifications)
                    //    .Include(c => c.Groups)
                    //    .Include(c => c.Organization)
                    //    .Include(c => c.Softwares)
                    //    .AsNoTracking().ToList();
                    PortsProtocolsServices = databaseContext.PortsProtocolsServices
                        .Include(p => p.HardwarePortsProtocolsServices
                            .Select(h => h.Hardware))
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
                    LifecycleStatuses = databaseContext.LifecycleStatuses
                        .AsNoTracking()
                        .ToList();
                    NewGroup = new Group();
                    NewHardware = new Hardware();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate ConfigurationManagementView lists.");
                throw exception;
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
                string error = "Unable to clear set editable hardware.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }
    }
}