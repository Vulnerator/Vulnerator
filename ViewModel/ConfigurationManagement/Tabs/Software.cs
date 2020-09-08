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
    }
}
