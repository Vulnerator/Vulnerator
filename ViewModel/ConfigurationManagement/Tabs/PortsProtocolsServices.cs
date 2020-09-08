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
    public class PortsProtocolsServices : ViewModelBase
    {
        private VulnerabilitySource vulnerabilitySource;
        private string saveDirectory = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private DdlReader _ddlReader = new DdlReader();
        private BackgroundWorkerFactory _backgroundWorkerFactory = new BackgroundWorkerFactory();
        private Assembly assembly = Assembly.GetExecutingAssembly();

        private List<PortProtocolService> _portsProtocolsServices;

        public List<PortProtocolService> PortsProtocolsServicesList
        {
            get => _portsProtocolsServices;
            set
            {
                if (_portsProtocolsServices != value)
                {
                    _portsProtocolsServices = value;
                    RaisePropertyChanged("PortsProtocolsServicesList");
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

        public PortsProtocolsServices()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of Configuration Management view 'PPS' tab ViewModel.");
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated,
                    (msg) => HandleModelUpdate(msg.Notification));
                LogWriter.LogStatusUpdate("Configuration Management view 'PPS' tab ViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate Configuration Management view 'PPS' tab ViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void PopulateGui()
        {
            try
            {
                using (DatabaseContext databaseContext = new DatabaseContext())
                {
                    PortsProtocolsServicesList = databaseContext.PortsProtocolsServices
                        .Include(p => p.HardwarePortsProtocolsServices
                            .Select(h => h.Hardware))
                        .AsNoTracking()
                        .ToList();
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
                if (modelUpdated.Equals("PpsModel") || modelUpdated.Equals("AllModels"))
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
