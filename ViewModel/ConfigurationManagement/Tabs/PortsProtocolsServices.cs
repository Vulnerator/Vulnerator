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

        private List<PortProtocolService> _portsProtocolsServicesList;

        public List<PortProtocolService> PortsProtocolsServicesList
        {
            get => _portsProtocolsServicesList;
            set
            {
                if (_portsProtocolsServicesList != value)
                {
                    _portsProtocolsServicesList = value;
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
                        .Where(p => p.Port > 0)
                        .AsNoTracking()
                        .ToList()
                        .OrderBy(p => p.Port).ThenBy(p => p.Protocol).ThenBy(p => p.DiscoveredServiceName)
                        .ToList();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate the Configuration Management view 'Ports, Protocols, Services' tab list.");
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
    
        public RelayCommand SavePpsCommand => new RelayCommand(SavePps);
        public RelayCommand DeletePpsCommand => new RelayCommand(DeletePps);
        public RelayCommand ClearSelectedPpsCommand => new RelayCommand(ClearSelectedPps);

        /// <summary>Saves the service name and acronym of the selected port / protocol / service.</summary>
        private void SavePps()
        {
            if (SelectedPPS == null)
            { return; }
            long id = SelectedPPS.PortProtocolService_ID;
            try
            {
                ExecuteSql(command =>
                {
                    command.CommandText = "UPDATE PortsProtocolsServices SET DisplayedServiceName = @Name, ServiceAcronym = @Acronym " +
                                          "WHERE PortProtocolService_ID = @Id";
                    command.Parameters.AddWithValue("@Name", string.IsNullOrWhiteSpace(SelectedPPS.DisplayedServiceName) ? (object)DBNull.Value : SelectedPPS.DisplayedServiceName.Trim());
                    command.Parameters.AddWithValue("@Acronym", string.IsNullOrWhiteSpace(SelectedPPS.ServiceAcronym) ? (object)DBNull.Value : SelectedPPS.ServiceAcronym.Trim());
                    command.Parameters.AddWithValue("@Id", id);
                    command.ExecuteNonQuery();
                });
                LogWriter.LogStatusUpdate($"Saved the name of {SelectedPPS.Port}/{SelectedPPS.Protocol} {SelectedPPS.DiscoveredServiceName}.");
                PopulateGui();
                SelectedPPS = PortsProtocolsServicesList.FirstOrDefault(p => p.PortProtocolService_ID == id);
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Unable to save the port / protocol / service.", exception);
                System.Windows.MessageBox.Show("Unable to save: " + exception.Message, "Ports, Protocols, Services",
                    System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            }
        }

        /// <summary>Removes the selected port / protocol / service and its host links (a later scan adds it back if still seen).</summary>
        private void DeletePps()
        {
            if (SelectedPPS == null)
            { return; }
            string label = $"{SelectedPPS.Port}/{SelectedPPS.Protocol} {SelectedPPS.DiscoveredServiceName}";
            if (System.Windows.MessageBox.Show($"Remove {label} and its links to {SelectedPPS.HardwarePortsProtocolsServices.Count} host(s)?\n\n" +
                                               "Importing a scan that still shows it adds it back.", "Ports, Protocols, Services",
                    System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question) != System.Windows.MessageBoxResult.Yes)
            { return; }
            long id = SelectedPPS.PortProtocolService_ID;
            try
            {
                ExecuteSql(command =>
                {
                    command.Parameters.AddWithValue("@Id", id);
                    command.CommandText =
                        "DELETE FROM PortProtocolServiceEvidence WHERE HardwarePortProtocolService_ID IN " +
                        "(SELECT HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices WHERE PortProtocolService_ID = @Id); " +
                        "DELETE FROM HardwareSoftwarePortsProtocolsServices WHERE HardwarePortProtocolService_ID IN " +
                        "(SELECT HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices WHERE PortProtocolService_ID = @Id); " +
                        "DELETE FROM HardwarePortsProtocolsServices WHERE PortProtocolService_ID = @Id; " +
                        "DELETE FROM PortsProtocolsServices WHERE PortProtocolService_ID = @Id;";
                    command.ExecuteNonQuery();
                });
                LogWriter.LogStatusUpdate($"Removed {label}.");
                SelectedPPS = null;
                PopulateGui();
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to remove {label}.", exception);
                System.Windows.MessageBox.Show("Unable to remove: " + exception.Message, "Ports, Protocols, Services",
                    System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            }
        }

        /// <summary>Clears the selection and reloads the list (unsaved name / acronym edits are discarded).</summary>
        private void ClearSelectedPps()
        {
            SelectedPPS = null;
            try
            { PopulateGui(); }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Unable to reload the ports, protocols and services.", exception); }
        }

        private static void ExecuteSql(Action<SQLiteCommand> action)
        {
            bool wasOpen = DatabaseBuilder.sqliteConnection.State == ConnectionState.Open;
            if (!wasOpen)
            { DatabaseBuilder.sqliteConnection.Open(); }
            try
            {
                using (SQLiteTransaction transaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
                    { action(command); }
                    transaction.Commit();
                }
            }
            finally
            {
                if (!wasOpen)
                { DatabaseBuilder.sqliteConnection.Close(); }
            }
        }
    }
}
