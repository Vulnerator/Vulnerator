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
                    Hardwares = databaseContext.Hardwares
                        .OrderBy(h => h.DisplayedHostName)
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

        // ----- Edits (Configuration Management > Software) ---------------------------------------------------

        public RelayCommand ClearSelectedSoftwareCommand => new RelayCommand(() =>
        {
            SelectedSoftware = null;
            NewSoftware = new Model.Entity.Software();
        });

        public RelayCommand ModifySoftwareCommand => new RelayCommand(ModifySoftware);

        private void ModifySoftware()
        {
            if (SelectedSoftware == null)
            {
                Model.Entity.Software software = NewSoftware;
                RunEdit("Add software", () => AssetEditor.AddSoftware(software), null, true);
            }
            else
            {
                Model.Entity.Software software = EditableSoftware ?? SelectedSoftware;
                RunEdit("Update software", () => { AssetEditor.UpdateSoftware(software); return software.Software_ID; }, software.Software_ID);
            }
        }

        public RelayCommand DeleteSoftwareCommand => new RelayCommand(() =>
        {
            Model.Entity.Software software = SelectedSoftware;
            if (software == null) return;
            if (System.Windows.MessageBox.Show(
                    $"Delete '{software.DisplayedSoftwareName}', its host links and the findings recorded against it?",
                    "Delete Software", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes)
            { return; }
            RunEdit("Delete software", () => { AssetEditor.DeleteSoftware(software.Software_ID); return 0; }, null);
        });

        /// <summary>Splits entries that hold several programs on separate lines into one entry per program.</summary>
        public RelayCommand SplitCombinedSoftwareCommand => new RelayCommand(() =>
        {
            int combined = Softwares?.Count(s => (s.DiscoveredSoftwareName ?? string.Empty).IndexOfAny(new[] { '\r', '\n' }) >= 0) ?? 0;
            if (combined == 0)
            {
                System.Windows.MessageBox.Show("No software entries hold several programs; nothing to split.", "Split Combined Entries",
                    System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
                return;
            }
            if (System.Windows.MessageBox.Show(
                    $"Split {combined} combined software entr{(combined == 1 ? "y" : "ies")} into one entry per program? Each new entry keeps the original's details and hardware links.",
                    "Split Combined Entries", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question) != System.Windows.MessageBoxResult.Yes)
            { return; }
            RunEdit("Split combined entries", () => { AssetEditor.SplitCombinedSoftware(); return 0; }, null);
        });

        public RelayCommand AddHardwareToSoftwareCommand => new RelayCommand(() =>
        {
            long? softwareId = SelectedSoftware?.Software_ID;
            long? hardwareId = SelectedHardware?.Hardware_ID;
            if (softwareId == null || hardwareId == null) return;
            RunEdit("Add hardware", () => { AssetEditor.AddSoftwareToHardware(hardwareId.Value, softwareId.Value); return 0; }, softwareId);
        });

        public RelayCommand<object> RemoveHardwareFromSoftwareCommand => new RelayCommand<object>(parameter =>
        {
            long? softwareId = SelectedSoftware?.Software_ID;
            long hardwareId;
            if (softwareId == null || parameter == null || !long.TryParse(parameter.ToString(), out hardwareId)) return;
            RunEdit("Remove hardware", () => { AssetEditor.RemoveSoftwareFromHardware(hardwareId, softwareId.Value); return 0; }, softwareId);
        });

        /// <summary>Runs a database edit in the background, then reloads every tab and selects the given software again.</summary>
        private void RunEdit(string description, Func<long> edit, long? reselectId, bool selectResult = false)
        {
            BackgroundWorker worker = new BackgroundWorker();
            worker.DoWork += (sender, e) => e.Result = edit();
            worker.RunWorkerCompleted += (sender, e) =>
            {
                if (e.Error != null)
                {
                    LogWriter.LogErrorWithDebug($"{description} failed.", e.Error);
                    System.Windows.MessageBox.Show(e.Error.Message, description, System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    return;
                }
                long? select = selectResult && e.Result is long ? (long)e.Result : reselectId;
                Messenger.Default.Send(new NotificationMessage<string>("ModelUpdate", "AllModels"), MessengerToken.ModelUpdated);
                NewSoftware = new Model.Entity.Software();
                SelectedSoftware = select.HasValue ? Softwares?.FirstOrDefault(x => x.Software_ID == select.Value) : null;
            };
            worker.RunWorkerAsync();
        }
    }
}
