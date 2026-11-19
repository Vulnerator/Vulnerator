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
                    List<Model.Entity.Hardware> hardwares = databaseContext.Hardwares
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
                    // Last ACAS scan and last checklist / SCAP result per host, for the optional Hardware columns.
                    Dictionary<long, HardwareScanDates.Dates> scanDates = HardwareScanDates.Load();
                    Dictionary<long, HardwareIdentity.Identifiers> identifiers = HardwareIdentity.LoadAll();
                    foreach (Model.Entity.Hardware hardware in hardwares)
                    {
                        HardwareScanDates.Dates dates;
                        if (scanDates.TryGetValue(hardware.Hardware_ID, out dates))
                        {
                            hardware.LastAcasScan = dates.LastAcas;
                            hardware.LastChecklistScan = dates.LastChecklist;
                        }
                        HardwareIdentity.Identifiers ids;
                        if (identifiers.TryGetValue(hardware.Hardware_ID, out ids))
                        {
                            hardware.AlsoKnownAs = string.Join(", ", ids.Aliases.Concat(ids.RetiredNumbers));
                            hardware.Aliases = ids.Aliases.ToList();
                            hardware.MergedNumbers = ids.RetiredNumbers.ToList();
                            hardware.RegistryNumber = ids.RegistryNumber.HasValue ? DeviceRegistry.Format(ids.RegistryNumber.Value) : string.Empty;
                        }
                    }
                    Hardwares = hardwares;
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
                        .Where(p => p.Port > 0)
                        .AsNoTracking()
                        .ToList()
                        .OrderBy(p => p.Port).ThenBy(p => p.Protocol)
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

        private string cklMarking;

        private void GenerateCkl(object param)
        {
            try
            {
                cklMarking = ExportMarking.Confirm("STIG checklist (CKL)");
                if (cklMarking == null)
                { return; }
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
                CklCreator cklCreator = new CklCreator { Marking = cklMarking };
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

        // ----- Edits (Configuration Management > Hardware) ---------------------------------------------------
        // Values are captured on the UI thread (the combo boxes clear their selection when their button fires), the
        // database change runs in the background, then every tab reloads and this host stays selected.

        public RelayCommand ClearSelectedHardwareCommand => new RelayCommand(() =>
        {
            SelectedHardware = null;
            NewHardware = new Model.Entity.Hardware();
        });

        public RelayCommand ModifyHardwareCommand => new RelayCommand(ModifyHardware);

        private void ModifyHardware()
        {
            long? lifecycle = SelectedLifecycleStatus?.LifecycleStatus_ID;
            if (SelectedHardware == null)
            {
                Model.Entity.Hardware hardware = NewHardware;
                RunEdit("Add hardware", () => AssetEditor.AddHardware(hardware, lifecycle), null, true);
            }
            else
            {
                Model.Entity.Hardware hardware = EditableHardware ?? SelectedHardware;
                RunEdit("Update hardware", () => { AssetEditor.UpdateHardware(hardware, lifecycle); return hardware.Hardware_ID; }, hardware.Hardware_ID);
            }
        }

        public RelayCommand DeleteHardwareCommand => new RelayCommand(DeleteHardware);

        private void DeleteHardware()
        {
            Model.Entity.Hardware hardware = SelectedHardware;
            if (hardware == null)
            { return; }
            if (System.Windows.MessageBox.Show(
                    $"Delete '{hardware.DisplayedHostName}' and all of its findings, addresses, group, software and port links?",
                    "Delete Hardware", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning) != System.Windows.MessageBoxResult.Yes)
            { return; }
            RunEdit("Delete hardware", () => { AssetEditor.DeleteHardware(hardware.Hardware_ID); return 0; }, null);
        }

        private string _newAlias;

        /// <summary>The name typed in the side panel's "Add another name" box.</summary>
        public string NewAlias
        {
            get => _newAlias;
            set
            {
                if (_newAlias != value)
                {
                    _newAlias = value;
                    RaisePropertyChanged("NewAlias");
                }
            }
        }

        public RelayCommand AddAliasCommand => new RelayCommand(() =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            string alias = NewAlias;
            if (hardwareId == null) return;
            RunEdit("Add name", () => { AssetEditor.AddAlias(hardwareId.Value, alias); return 0; }, hardwareId);
            NewAlias = string.Empty;
        });

        public RelayCommand<object> RemoveAliasCommand => new RelayCommand<object>(parameter =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            string alias = parameter as string;
            if (hardwareId == null || string.IsNullOrEmpty(alias)) return;
            if (System.Windows.MessageBox.Show($"Forget the name '{alias}' for this device? Later imports with that name will no longer land on it.",
                    "Remove Name", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question) != System.Windows.MessageBoxResult.Yes)
            { return; }
            RunEdit("Remove name", () => { AssetEditor.RemoveAlias(hardwareId.Value, alias); return 0; }, hardwareId);
        });

        /// <summary>Merge Hardware...: the parameter is the Hardware list's selected rows (they start ticked).</summary>
        public RelayCommand<object> MergeHardwareCommand => new RelayCommand<object>(MergeHardware);

        /// <summary>
        /// Opens Merge Hardware with the whole inventory: the user ticks the records that are the same device (records
        /// ticked or selected in the Hardware list start ticked), and they are combined into one device, which keeps the
        /// oldest registry number, after an optional database backup.
        /// </summary>
        private void MergeHardware(object selectedRows)
        {
            List<Model.Entity.Hardware> inventory = Hardwares?.ToList() ?? new List<Model.Entity.Hardware>();
            if (inventory.Count < 2)
            {
                System.Windows.MessageBox.Show("There are fewer than two hardware records, so there is nothing to merge.", "Merge Hardware",
                    System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
                return;
            }
            HashSet<long> preTicked = new HashSet<long>(inventory.Where(h => h.IsChecked).Select(h => h.Hardware_ID));
            if (selectedRows is System.Collections.IEnumerable rows && !(selectedRows is string))
            {
                foreach (Model.Entity.Hardware row in rows.OfType<Model.Entity.Hardware>())
                { preTicked.Add(row.Hardware_ID); }
            }
            if (preTicked.Count < 2 && SelectedHardware != null)
            { preTicked.Add(SelectedHardware.Hardware_ID); }
            Vulnerator.View.UI.ConfigurationManagement.MergeHardwareWindow window = new Vulnerator.View.UI.ConfigurationManagement.MergeHardwareWindow(inventory, preTicked)
            {
                Owner = System.Windows.Application.Current.Windows.OfType<System.Windows.Window>().FirstOrDefault(w => w.IsActive) ?? System.Windows.Application.Current.MainWindow
            };
            if (window.ShowDialog() != true || window.SelectedIds.Count < 2)
            { return; }
            long keepId = window.KeepId;
            List<Model.Entity.Hardware> ticked = inventory.Where(h => window.SelectedIds.Contains(h.Hardware_ID)).ToList();
            List<long> mergeIds = ticked.Where(h => h.Hardware_ID != keepId).Select(h => h.Hardware_ID).ToList();
            if (window.BackUpFirst)
            {
                try
                {
                    string backup = HardwareMerger.BackUpDatabase();
                    LogWriter.LogStatusUpdate($"Database backed up before the merge: {backup}");
                }
                catch (Exception exception)
                {
                    LogWriter.LogErrorWithDebug("The database backup before a merge failed.", exception);
                    System.Windows.MessageBox.Show("The database could not be backed up, so nothing was merged: " + exception.Message, "Merge Hardware",
                        System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    return;
                }
            }
            RunEdit("Merge hardware", () =>
            {
                HardwareMerger.Result result = HardwareMerger.Merge(keepId, mergeIds);
                LogWriter.LogStatusUpdate($"Merge complete: {result.RecordsMerged + 1} records are now one device.");
                return keepId;
            }, keepId);
        }

        public RelayCommand AddGroupToHardwareCommand => new RelayCommand(() =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            long? groupId = SelectedGroup?.Group_ID;
            if (hardwareId == null || groupId == null) return;
            RunEdit("Add group", () => { AssetEditor.AddGroup(hardwareId.Value, groupId.Value); return 0; }, hardwareId);
        });

        public RelayCommand<object> RemoveGroupFromHardwareCommand => new RelayCommand<object>(parameter =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            long groupId;
            if (hardwareId == null || parameter == null || !long.TryParse(parameter.ToString(), out groupId)) return;
            RunEdit("Remove group", () => { AssetEditor.RemoveGroup(hardwareId.Value, groupId); return 0; }, hardwareId);
        });

        public RelayCommand AssociateIpAddressToHardwareCommand => new RelayCommand(() =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            string ip = SelectedIpAddress;
            if (hardwareId == null) return;
            RunEdit("Add IP address", () => { AssetEditor.AddIpAddress(hardwareId.Value, ip); return 0; }, hardwareId);
        });

        public RelayCommand<object> RemoveIpAddressFromHardwareCommand => new RelayCommand<object>(parameter =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            long ipId;
            if (hardwareId == null || parameter == null || !long.TryParse(parameter.ToString(), out ipId)) return;
            RunEdit("Remove IP address", () => { AssetEditor.RemoveIpAddress(hardwareId.Value, ipId); return 0; }, hardwareId);
        });

        public RelayCommand AssociateMacAddressToHardwareCommand => new RelayCommand(() =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            string mac = SelectedMacAddress;
            if (hardwareId == null) return;
            RunEdit("Add MAC address", () => { AssetEditor.AddMacAddress(hardwareId.Value, mac); return 0; }, hardwareId);
        });

        public RelayCommand<object> RemoveMacAddressFromHardwareCommand => new RelayCommand<object>(parameter =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            long macId;
            if (hardwareId == null || parameter == null || !long.TryParse(parameter.ToString(), out macId)) return;
            RunEdit("Remove MAC address", () => { AssetEditor.RemoveMacAddress(hardwareId.Value, macId); return 0; }, hardwareId);
        });

        public RelayCommand AssociateSoftwareToHardwareCommand => new RelayCommand(() =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            long? softwareId = SelectedSoftware?.Software_ID;
            if (hardwareId == null || softwareId == null) return;
            RunEdit("Add software", () => { AssetEditor.AddSoftwareToHardware(hardwareId.Value, softwareId.Value); return 0; }, hardwareId);
        });

        public RelayCommand<object> RemoveSoftwareFromHardwareCommand => new RelayCommand<object>(parameter =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            long softwareId;
            if (hardwareId == null || parameter == null || !long.TryParse(parameter.ToString(), out softwareId)) return;
            RunEdit("Remove software", () => { AssetEditor.RemoveSoftwareFromHardware(hardwareId.Value, softwareId); return 0; }, hardwareId);
        });

        public RelayCommand AssociatePpsToHardwareCommand => new RelayCommand(() =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            long? ppsId = SelectedPps?.PortProtocolService_ID;
            if (hardwareId == null || ppsId == null) return;
            RunEdit("Add port / protocol / service", () => { AssetEditor.AddPortProtocolService(hardwareId.Value, ppsId.Value); return 0; }, hardwareId);
        });

        public RelayCommand<object> RemovePpsFromHardwareCommand => new RelayCommand<object>(parameter =>
        {
            long? hardwareId = SelectedHardware?.Hardware_ID;
            long ppsId;
            if (hardwareId == null || parameter == null || !long.TryParse(parameter.ToString(), out ppsId)) return;
            RunEdit("Remove port / protocol / service", () => { AssetEditor.RemovePortProtocolService(hardwareId.Value, ppsId); return 0; }, hardwareId);
        });

        /// <summary>Runs a database edit in the background, then reloads every tab and selects the given host again.</summary>
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
                NewHardware = new Model.Entity.Hardware();
                SelectedHardware = select.HasValue ? Hardwares?.FirstOrDefault(h => h.Hardware_ID == select.Value) : null;
            };
            worker.RunWorkerAsync();
        }
    }
}
