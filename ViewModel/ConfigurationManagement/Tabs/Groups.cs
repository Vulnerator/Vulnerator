using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.Entity;
using System.Data.SQLite;
using System.Linq;
using System.Reflection;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;
using Vulnerator.Model.Object;

namespace Vulnerator.ViewModel.ConfigurationManagement.Tabs
{
    public class Groups : ViewModelBase
    {
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

        private List<Group> _groupsList;

        public List<Group> GroupsList
        {
            get => _groupsList;
            set
            {
                if (_groupsList != value)
                {
                    _groupsList = value;
                    RaisePropertyChanged("GroupsList");
                }
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

        private Group _selectedGroup;

        public Group SelectedGroup
        {
            get => _selectedGroup;
            set
            {
                if (_selectedGroup == value) return;
                _selectedGroup = value;
                RaisePropertyChanged("SelectedGroup");
                SetEditableGroup();
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

        public Groups()
        {
            try
            {
                LogWriter.LogStatusUpdate("Begin instantiation of Configuration Management view 'Groups' tab ViewModel.");
                PopulateGui();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated,
                    (msg) => HandleModelUpdate(msg.Notification));
                LogWriter.LogStatusUpdate("Configuration Management view 'Groups' tab ViewModel instantiated successfully.");
            }
            catch (Exception exception)
            {
                string error = "Unable to instantiate Configuration Management view 'Groups' tab ViewModel.";
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
                    GroupsList = databaseContext.Groups
                        .Include(g => g.Hardwares)
                        .AsNoTracking().ToList();
                    NewGroup = new Group();
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
                if (modelUpdated.Equals("GroupsModel") || modelUpdated.Equals("AllModels"))
                {
                    PopulateGui();
                }
            }
            catch (Exception exception)
            {
                string error = "Unable to update the 'Groups' tab ViewModel.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void SetEditableGroup()
        {
            try
            {
                if (SelectedGroup == null)
                {
                    EditableGroup = null;
                    SelectedHardware = null;
                    return;
                }

                EditableGroup = EditableGroup;
            }
            catch (Exception exception)
            {
                string error = "Unable to set or clear 'EditableGroup'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        public RelayCommand ModifyGroupCommand => new RelayCommand(ModifyGroup);

        private void ModifyGroup()
        {
            try
            {
                if (SelectedGroup == null && NewGroup == null) return;

                if (SelectedGroup != null)
                {
                    _backgroundWorkerFactory.Build(UpdateGroupBackgroundWorker_DoWork, GroupActionBackgroundWorker_RunWorkerCompleted);
                }
                else
                {
                    _backgroundWorkerFactory.Build(AddGroupBackgroundWorker_DoWork, GroupActionBackgroundWorker_RunWorkerCompleted);
                }
            }
            catch (Exception exception)
            {
                string error = SelectedGroup is null && NewGroup is null ? "Both 'SelectedGroup' and 'NewGroup' have 'null' values." : 
                    SelectedGroup is null ? $"Unable to add group '{NewGroup.GroupName}'" :
                    $"Unable to update group '{SelectedGroup.GroupName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void UpdateGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
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
                        sqliteCommand.Parameters["Group_ID"].Value = EditableGroup.Group_ID;
                        sqliteCommand.Parameters["GroupName"].Value = EditableGroup.GroupName;
                        sqliteCommand.Parameters["GroupAcronym"].Value =
                            (object)EditableGroup.GroupAcronym ?? DBNull.Value;
                        sqliteCommand.Parameters["GroupTier"].Value = EditableGroup.GroupTier;
                        sqliteCommand.Parameters["IsAccreditation"].Value = EditableGroup.IsAccreditation ?? "False";
                        sqliteCommand.Parameters["Accreditation_eMASS_ID"].Value =
                            (object)EditableGroup.Accreditation_eMASS_ID ?? DBNull.Value;
                        sqliteCommand.Parameters["IsPlatform"].Value = EditableGroup.IsPlatform ?? "False";
                        databaseInterface.UpdateGroup(sqliteCommand);
                    }

                    sQLiteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError(SelectedGroup is null ? "'SelectedGroup' has a 'null' value." : 
                    $"Unable to update group '{SelectedGroup.GroupName}'.");
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

        private void AddGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
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
                string error = NewGroup is null ? "'NewGroup' has a 'null' value." : 
                    $"Unable to insert group '{NewGroup.GroupName}'.";
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

        public RelayCommand DeleteGroupCommand => new RelayCommand(DeleteGroup);

        private void DeleteGroup()
        {
            try
            {
                if (SelectedGroup == null && GroupsList.Count(x => x.IsChecked) < 1) return;
                _backgroundWorkerFactory.Build(DeleteGroupBackgroundWorker_DoWork, GroupActionBackgroundWorker_RunWorkerCompleted);
            }
            catch (Exception exception)
            {
                string error = SelectedGroup is null ? "'SelectedGroup' has a 'null' value." : 
                    $"Unable to delete group '{SelectedGroup.GroupName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void DeleteGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
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
                        if (GroupsList.Count(x => x.IsChecked) > 0)
                        {
                            foreach (Group group in GroupsList.Where(x => x.IsChecked))
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
                if (SelectedGroup is null || SelectedHardware is null)
                {
                    return;
                }
                // Combobox controls clear the bound SelectedItem when the command fires;
                // mapping those values to an arguments class prevents a race condition
                GroupHardwareMappingDoWorkArguments doWorkArguments = new GroupHardwareMappingDoWorkArguments()
                { GroupName = SelectedGroup.GroupName, DiscoveredHostName = SelectedHardware.DiscoveredHostName };
                _backgroundWorkerFactory.Build(AddHardwareToGroupBackgroundWorker_DoWork, 
                    GroupActionBackgroundWorker_RunWorkerCompleted, 
                    doWorkArguments);
            }
            catch (Exception exception)
            {
                string error = SelectedHardware is null ? "'SelectedHardware' has a 'null' value." :
                    SelectedGroup is null ? "'SelectedGroup' has a 'null' value." :
                    $"Unable to associate hardware asset '{SelectedHardware.DisplayedHostName}' to group '{SelectedGroup.GroupName}'";
                LogWriter.LogErrorWithDebug(error, exception);
            }
        }

        private void AddHardwareToGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
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
                        if (e.Argument is null)
                        { return; }
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

        private void GroupActionBackgroundWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
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
    }
}
