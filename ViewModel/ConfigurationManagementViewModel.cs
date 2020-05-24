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
        private DatabaseContext databaseContext;
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

        private List<PortsProtocols> _pps;
        public List<PortsProtocols> PortsProtocols
        {
            get => _pps;
            set
            {
                if (_pps != value)
                {
                    _pps = value;
                    RaisePropertyChanged("PortsProtocols");
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
                if (_selectedGroup == value) return;
                _selectedGroup = value;
                RaisePropertyChanged("SelectedGroup");
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

        public ConfigurationManagementViewModel()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of ConfigurationManagementViewModel.");
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated, (msg) => HandleModelUpdate(msg.Notification));
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
                { PopulateGui(); }
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
                        .Include(h => h.HardwarePortsProtocols.Select(p => p.PP))
                        .Include(h => h.VulnerabilitySources)
                        .OrderBy(h => h.DisplayedHostName)
                        .AsNoTracking().ToList();
                    Softwares = databaseContext.Softwares
                        .Include(s => s.SoftwareHardwares.Select(h => h.Hardware))
                        .OrderBy(s => s.DisplayedSoftwareName)
                        .AsNoTracking().ToList();
                    Contacts = databaseContext.Contacts
                        .Include(c => c.Groups)
                        .Include(c => c.Certifications)
                        .Include(c => c.Groups)
                        .Include(c => c.Organization)
                        .Include(c => c.Softwares)
                        .AsNoTracking().ToList();
                    PortsProtocols = databaseContext.PortsProtocols
                        .Include(p => p.HardwarePortsProtocols.Select(h => h.Hardware))
                        .AsNoTracking().ToList();
                    Groups = databaseContext.Groups
                        .Include(g => g.Hardwares)
                        .AsNoTracking().ToList();
                    VulnerabilitySources = databaseContext.VulnerabilitySources
                        .Where(vs => !vs.SourceName.Contains("Nessus"))
                        .OrderBy(vs => vs.SourceName)
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
                LogWriter.LogError("Unable to populate ConfigurationManagementView lists.");
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
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to associate STIG '{SelectedVulnerabilitySource.VulnerabilitySourceFileName}' to Hardware.");
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
                { backgroundWorker.DoWork += updateGroupBackgroundWorker_DoWork; }
                else
                { backgroundWorker.DoWork += addGroupBackgroundWorker_DoWork; }

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
                { DatabaseBuilder.sqliteConnection.Open(); }

                using (SQLiteTransaction sQLiteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["Group_ID"].Value = SelectedGroup.Group_ID;
                        sqliteCommand.Parameters["GroupName"].Value = SelectedGroup.GroupName;
                        sqliteCommand.Parameters["GroupAcronym"].Value = SelectedGroup.GroupAcronym;
                        sqliteCommand.Parameters["GroupTier"].Value = SelectedGroup.GroupTier;
                        sqliteCommand.Parameters["IsAccreditation"].Value = SelectedGroup.IsAccreditation ?? "False";
                        sqliteCommand.Parameters["Accreditation_eMASS_ID"].Value = SelectedGroup.Accreditation_eMASS_ID;
                        sqliteCommand.Parameters["IsPlatform"].Value = SelectedGroup.IsPlatform ?? "False";
                        databaseInterface.UpdateGroup(sqliteCommand);
                    }

                    sQLiteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update group '{NewGroup.GroupName}'.");
                throw exception;
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
                        sqliteCommand.Parameters["Name"].Value = NewGroup.GroupName;
                        sqliteCommand.Parameters["Acronym"].Value = NewGroup.GroupAcronym;
                        sqliteCommand.Parameters["GroupTier"].Value = NewGroup.GroupTier;
                        sqliteCommand.Parameters["IsAccreditation"].Value = NewGroup.IsAccreditation ?? "False";
                        sqliteCommand.Parameters["Accreditation_eMASS_ID"].Value = NewGroup.Accreditation_eMASS_ID;
                        sqliteCommand.Parameters["IsPlatform"].Value = NewGroup.IsPlatform ?? "False";
                        databaseInterface.InsertGroup(sqliteCommand);
                    }

                    sQLiteTransaction.Commit();
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
                { DatabaseBuilder.sqliteConnection.Close(); }
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
                { DatabaseBuilder.sqliteConnection.Open(); }

                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        if (Groups.Count(x => x.IsChecked) > 0)
                        {
                            foreach (Group group in Groups.Where(x => x.IsChecked))
                            { DeleteGroup(group, sqliteCommand); }
                        }
                        else if (SelectedGroup != null)
                        { DeleteGroup(SelectedGroup, sqliteCommand); }
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
                { DatabaseBuilder.sqliteConnection.Close(); }
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

        private void groupActionBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {

            try
            {
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
                NewGroup = new Group();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to run Group post-modification background worker RunWorkerCompleted tasks.");
                throw exception;
            }
        }
    }
}
