using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using log4net;
using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.Entity;
using System.Data.SQLite;
using System.Linq;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.ViewModel
{
    public class ConfigurationManagementViewModel : ViewModelBase
    {
        private DatabaseContext databaseContext;
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private VulnerabilitySource vulnerabilitySource;
        private string saveDirectory = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();

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

        private List<PPS> _pps;
        public List<PPS> PPS
        {
            get => _pps;
            set
            {
                if (_pps != value)
                {
                    _pps = value;
                    RaisePropertyChanged("PPS");
                }
            }
        }

        private List<IP_Addresses> _ipAddresses;
        public List<IP_Addresses> IpAddresses
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

        private List<MAC_Addresses> _macAddresses;
        public List<MAC_Addresses> MacAddresses
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

        private object _selectedHardware;
        public object SelectedHardware
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

        private Group _selectedGroup;

        public Group SelectedGroup
        {
            get => _selectedGroup;
            set
            {
                if (_selectedGroup != value)
                {
                    NewGroup = value != null ? null : new Group();
                    _selectedGroup = value;
                    RaisePropertyChanged("SelectedGroup");
                }
            }
            
        }

        private Group _newGroup;

        public Group NewGroup
        {
            get { return _newGroup; }
            set
            {
                if (_newGroup != value)
                {
                    SelectedGroup = value != null ? null : new Group();
                    _newGroup = value;
                    RaisePropertyChanged("NewGroup");
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

        public ConfigurationManagementViewModel()
        { 
            try
            {
                log.Info("Begin instantiation of ConfigurationManagementViewModel.");
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated, (msg) => HandleModelUpdate(msg.Notification));
            }
            catch (Exception exception)
            {
                log.Error("Unable to instantiate ConfigurationManagementViewModel.");
                log.Debug("Exception details:", exception);
            }
        }

        private void HandleModelUpdate(string modelUpdated)
        {
            try
            {
                if (modelUpdated.Equals("ConfigurationManagementModel") || modelUpdated.Equals("AllModels"))
                { PopulateGui(); }
            }
            catch (Exception exception)
            {
                log.Error("Unable to update MitigationsNistViewModel.");
                log.Debug("Exception details:", exception);
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
                        .Include(h => h.Hardware_PPS.Select(p => p.PP))
                        .Include(h => h.VulnerabilitySources)
                        .OrderBy(h => h.Displayed_Host_Name)
                        .AsNoTracking().ToList();
                    Softwares = databaseContext.Softwares
                        .Include(s => s.SoftwareHardwares.Select(h => h.Hardware))
                        .OrderBy(s => s.Displayed_Software_Name)
                        .AsNoTracking().ToList();
                    Contacts = databaseContext.Contacts
                        .Include(c => c.Groups)
                        .Include(c => c.Certifications)
                        .Include(c => c.Groups)
                        .Include(c => c.Organization)
                        .Include(c => c.Softwares)
                        .Include(c => c.Title)
                        .AsNoTracking().ToList();
                    PPS = databaseContext.PPS
                        .Include(p => p.Hardware_PPS.Select(h => h.Hardware))
                        .AsNoTracking().ToList();
                    Groups = databaseContext.Groups
                        .Include(g => g.Hardwares)
                        .AsNoTracking().ToList();
                    VulnerabilitySources = databaseContext.VulnerabilitySources
                        .Where(vs => !vs.Source_Name.Contains("Nessus"))
                        .OrderBy(vs => vs.Source_Name)
                        .AsNoTracking().ToList();
                    IpAddresses = databaseContext.IP_Addresses
                        .OrderBy(i => i.IP_Address)
                        .AsNoTracking()
                        .ToList();
                    MacAddresses = databaseContext.MAC_Addresses
                        .OrderBy(m => m.MAC_Address)
                        .AsNoTracking()
                        .ToList();
                    NewGroup = new Group();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate ConfigurationManagementView");
                throw exception;
            }
        }

        public RelayCommand<object> GenerateCklCommand
        { get { return new RelayCommand<object>(p => GenerateCkl(p)); } }

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
                log.Error("Unable to create CKL file.");
                log.Debug("Exception details:", exception);
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
                    $"{vulnerabilitySource.Source_Name} CKL created for {hardware.Displayed_Host_Name}", 
                    "Collapsed", 
                    true);
                Messenger.Default.Send(guiFeedback);
                vulnerabilitySource = null;
                saveDirectory = string.Empty;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate CKL file background worker.");
                log.Debug("Exception details:", exception);
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
                log.Error("Unable to generate background worker for AssociateStigToHardware");
                log.Debug("Exception details:", exception);
            }
        }

        private void associateStigToHardwareBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        { 
            try
            {
                Hardware hardware = SelectedHardware as Hardware;
                int hardwareId = int.Parse(hardware.Hardware_ID.ToString());
                int vulnerabilitySourceId = int.Parse(SelectedVulnerabilitySource.Vulnerability_Source_ID.ToString());
                AssociateStig associateStig = new AssociateStig();
                associateStig.ToHardware(vulnerabilitySourceId, hardwareId);
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
            }
            catch (Exception exception)
            {
                log.Error("Unable to associate STIG to Hardware");
                log.Debug("Exception details:", exception);
            }
        }

        public RelayCommand ModifyGroupCommand => new RelayCommand(ModifyGroup);
        private void ModifyGroup()
        {
            try
            {
                if (SelectedGroup == null && NewGroup == null)
                { return; }

                BackgroundWorker backgroundWorker = new BackgroundWorker();
                if (SelectedGroup != null)
                { backgroundWorker.DoWork += updateGroupBackgroundWorker_DoWork; }

                if (NewGroup != null)
                { backgroundWorker.DoWork += addGroupBackgroundWorker_DoWork; }

                backgroundWorker.RunWorkerAsync();
                backgroundWorker.RunWorkerCompleted += modifyGroupBackgroundWorker_RunWorkerCompleted;
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert or update a group.");
                log.Debug($"Exception details: {exception}");
            }
        }

        private void updateGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }

                using (SQLiteTransaction sQLiteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["Group_ID"].Value = SelectedGroup.Group_ID;
                        sqliteCommand.Parameters["Name"].Value = SelectedGroup.Name;
                        sqliteCommand.Parameters["Acronym"].Value = SelectedGroup.Acronym;
                        sqliteCommand.Parameters["Group_Tier"].Value = SelectedGroup.Group_Tier;
                        sqliteCommand.Parameters["Is_Accreditation"].Value = SelectedGroup.Is_Accreditation;
                        sqliteCommand.Parameters["Accreditation_eMASS_ID"].Value = SelectedGroup.Accreditation_eMASS_ID;
                        sqliteCommand.Parameters["IsPlatform"].Value = SelectedGroup.IsPlatform;
                        databaseInterface.UpdateGroup(sqliteCommand);
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error($"Unable to insert group {NewGroup.Name}");
                log.Debug($"Exception details: {exception}");
            }
            finally
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Close(); }
            }
        }

        private void addGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }

                using (SQLiteTransaction sQLiteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Name", NewGroup.Name));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Acronym", NewGroup.Acronym));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Group_Tier", NewGroup.Group_Tier));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Accreditation", NewGroup.Is_Accreditation));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Accreditation_eMASS_ID", NewGroup.Accreditation_eMASS_ID));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("IsPlatform", NewGroup.IsPlatform));
                        databaseInterface.InsertGroup(sqliteCommand);
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error($"Unable to insert group {NewGroup.Name}");
                log.Debug($"Exception details: {exception}");
            }
            finally
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Close(); }
            }
        }

        private void modifyGroupBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {

            try
            {
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
                NewGroup = new Group();
            }
            catch (Exception exception)
            {
                log.Error("Unable to run Group post-modification background worker RunWorkerCompleted tasks.");
                throw exception;
            }
        }
    }
}
