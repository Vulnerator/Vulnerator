using Microsoft.Win32;
using System;
using System.Collections;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Input;
using System.Xml.Linq;
using Vulnerator.Model;

namespace Vulnerator.ViewModel
{
    public class MainWindowViewModel : BaseInpc
	{
		public static ConfigAlter configAlter;
		public static CommandParameters commandParameters = new CommandParameters();
		public static UpdateMitigationParameters updateMitigationParameters = new UpdateMitigationParameters();
		public static UpdateContactParameters updateContactParameters = new UpdateContactParameters();
		public static UpdateSystemGroupParameters updateSystemGroupParameters = new UpdateSystemGroupParameters();
		public static UpdateSystemParameters updateSystemParameters = new UpdateSystemParameters();
		public static FindingsDatabaseActions findingsDatabaseActions;
        public GitHubActions githubActions;
		public VulneratorDatabaseActions vulneratorDatabaseActions;
		public static DataSet cciDs = new DataSet();
		public string cciFileLocation = Directory.GetCurrentDirectory().ToString() + @"\U_CCI_List.xml";
		public static bool excelFailed = false;
		public static bool reportSaveError = false;
		public static Stopwatch stopWatch = new Stopwatch();
		public static Stopwatch fileStopWatch = new Stopwatch();
		private BackgroundWorker backgroundWorker;
		private SaveFileDialog saveExcelFile;
		private SaveFileDialog savePdfFile;


		#region Properties

		public string FileVersion
		{
			//get { return Assembly.GetExecutingAssembly().GetName().Version.ToString(); }
			get 
			{
				Assembly assembly = Assembly.GetExecutingAssembly();
				return FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion.ToString();
			}
		}
		
		private string _themeFlyoutIsOpen = "False";
		public string ThemeFlyoutIsOpen
		{
			get { return _themeFlyoutIsOpen; }
			set
			{
				if (_themeFlyoutIsOpen != value)
				{
					_themeFlyoutIsOpen = value;
					OnPropertyChanged("ThemeFlyoutIsOpen");
				}
			}
		}

		private string _importFlyoutIsOpen = "False";
		public string ImportFlyoutIsOpen
		{
			get { return _importFlyoutIsOpen; }
			set
			{
				if (_importFlyoutIsOpen != value)
				{
					_importFlyoutIsOpen = value;
					OnPropertyChanged("ImportFlyoutIsOpen");
				}
			}
		}

		private string _advancedFlyoutIsOpen = "False";
		public string AdvancedFlyoutIsOpen
		{
			get { return _advancedFlyoutIsOpen; }
			set
			{
				if (_advancedFlyoutIsOpen != value)
				{
					_advancedFlyoutIsOpen = value;
					OnPropertyChanged("AdvancedFlyoutIsOpen");
				}
			}
		}

		private string _aboutFlyoutIsOpen = "False";
		public string AboutFlyoutIsOpen
		{
			get { return _aboutFlyoutIsOpen; }
			set
			{
				if (_aboutFlyoutIsOpen != value)
				{
					_aboutFlyoutIsOpen = value;
					OnPropertyChanged("AboutFlyoutIsOpen");
				}
			}
		}

        private string _newsFlyoutIsOpen = "False";
        public string NewsFlyoutIsOpen
        {
            get { return _newsFlyoutIsOpen; }
            set
            {
                if (_newsFlyoutIsOpen != value)
                {
                    _newsFlyoutIsOpen = value;
                    OnPropertyChanged("NewsFlyoutIsOpen");
                }
            }
        }

        private AsyncObservableCollection<Iavm> _iavms;
		public AsyncObservableCollection<Iavm> IavmList
		{
			get { return _iavms; }
			set
			{
				if (_iavms != value)
				{
					_iavms = value;
					OnPropertyChanged("IavmList");
				}
			}
		}

		private AsyncObservableCollection<SystemGroup> _systemGroupList;
		public AsyncObservableCollection<SystemGroup> SystemGroupList
		{
			get { return _systemGroupList; }
			set
			{
				if (_systemGroupList != value)
				{
					_systemGroupList = value;
					OnPropertyChanged("MitigationGroupName");
				}
			}
		}

		private AsyncObservableCollection<Files> _fileList;
		public AsyncObservableCollection<Files> FileList
		{
			get { return _fileList; }
			set
			{
				if (_fileList != value)
				{
					_fileList = value;
					OnPropertyChanged("FileList");
				}
			}
		}

		private AsyncObservableCollection<MitigationItem> _mitList;
		public AsyncObservableCollection<MitigationItem> MitigationList
		{
			get { return _mitList; }
			set
			{
				if (_mitList != value)
				{
					_mitList = value;
					OnPropertyChanged("MitigationList");
				}
			}
		}

		private AsyncObservableCollection<StatusItem> _statusItemList;
		public AsyncObservableCollection<StatusItem> StatusItemList
		{
			get { return _statusItemList; }
			set
			{
				if (_statusItemList != value)
				{
					_statusItemList = value;
					OnPropertyChanged("StatusItemList");
				}
			}
		}

		private AsyncObservableCollection<MacLevel> _macLevelList;
		public AsyncObservableCollection<MacLevel> MacLevelList
		{
			get { return _macLevelList; }
			set
			{
				if (_macLevelList != value)
				{
					_macLevelList = value;
					OnPropertyChanged("MacLevelList");
				}
			}
		}

		private AsyncObservableCollection<Contact> _contactList;
		public AsyncObservableCollection<Contact> ContactList
		{
			get { return _contactList; }
			set
			{
				if (_contactList != value)
				{
					_contactList = value;
					OnPropertyChanged("ContactList");
				}
			}
		}

		private AsyncObservableCollection<ContactTitle> _contactTitleList;
		public AsyncObservableCollection<ContactTitle> ContactTitleList
		{
			get { return _contactTitleList; }
			set
			{
				if (_contactTitleList != value)
				{
					_contactTitleList = value;
					OnPropertyChanged("ContactTitleList");
				}
			}
		}

		private AsyncObservableCollection<MonitoredSystem> _monitoredSystemList;
		public AsyncObservableCollection<MonitoredSystem> MonitoredSystemList
		{
			get { return _monitoredSystemList; }
			set
			{
				if (_monitoredSystemList != value)
				{
					_monitoredSystemList = value;
					OnPropertyChanged("MonitoredSystemList");
				}
			}
		}

		private AsyncObservableCollection<UpdatableMonitoredSystem> _monitoredSystemListForUpdating;
		public AsyncObservableCollection<UpdatableMonitoredSystem> MonitoredSystemListForUpdating
		{
			get { return _monitoredSystemListForUpdating; }
			set
			{
				if (_monitoredSystemListForUpdating != value)
				{
					_monitoredSystemListForUpdating = value;
					OnPropertyChanged("MonitoredSystemListForUpdating");
				}
			}
		}

		private AsyncObservableCollection<UpdatableSystemGroup> _systemGroupListForUpdating;
		public AsyncObservableCollection<UpdatableSystemGroup> SystemGroupListForUpdating
		{
			get { return _systemGroupListForUpdating; }
			set
			{
				if (_systemGroupListForUpdating != value)
				{
					_systemGroupListForUpdating = value;
					OnPropertyChanged("SystemGroupListForUpdating");
				}
			}
		}

        private AsyncObservableCollection<Issue> _issueList;
        public AsyncObservableCollection<Issue> IssueList
        {
            get { return _issueList; }
            set
            {
                if (_issueList != value)
                {
                    _issueList = value;
                    OnPropertyChanged("IssueList");
                }
            }
        }

        private AsyncObservableCollection<Release> _releaseList;
        public AsyncObservableCollection<Release> ReleaseList
        {
            get { return _releaseList; }
            set
            {
                if (_releaseList != value)
                {
                    _releaseList = value;
                    OnPropertyChanged("ReleaseList");
                }
            }
        }

		private string _addMitigationId;
		public string AddMitigationId
		{
			get { return _addMitigationId; }
			set
			{
				if (_addMitigationId != value)
				{
					_addMitigationId = value;
					OnPropertyChanged("AddMitigationId");
				}
			}
		}

		private string _addMitigationStatus;
		public string AddMitigationStatus
		{
			get { return _addMitigationStatus; }
			set
			{
				if (_addMitigationStatus != value)
				{
					_addMitigationStatus = value;
					OnPropertyChanged("AddMitigationStatus");
				}
			}
		}

		private string _addMitigationMacLevel;
		public string AddMitigationMacLevel
		{
			get { return _addMitigationMacLevel; }
			set
			{
				if (_addMitigationMacLevel != value)
				{
					_addMitigationMacLevel = value;
					OnPropertyChanged("AddMitigationMacLevel");
				}
			}
		}

		private string _mitigationGroupNameToUpdate;
		public string MitigationGroupNameToUpdate
		{
			get { return _mitigationGroupNameToUpdate; }
			set
			{
				if (_mitigationGroupNameToUpdate != value)
				{
					_mitigationGroupNameToUpdate = value;
					OnPropertyChanged("MitigationGroupNameToUpdate");
				}
			}
		}

		private string _addMitigationGroupName;
		public string AddMitigationGroupName
		{
			get { return _addMitigationGroupName; }
			set
			{
				if (_addMitigationGroupName != value)
				{
					_addMitigationGroupName = value;
					OnPropertyChanged("AddMitigationGroupName");
				}
			}
		}

		private string _addMitigationText;
		public string AddMitigationText
		{
			get { return _addMitigationText; }
			set
			{
				if (_addMitigationText != value)
				{
					_addMitigationText = value;
					OnPropertyChanged("AddMitigationText");
				}
			}
		}

		private string _updateMitigationStatus;
		public string UpdateMitigationStatus
		{
			get { return _updateMitigationStatus; }
			set
			{
				if (_updateMitigationStatus != value)
				{
					_updateMitigationStatus = value;
					OnPropertyChanged("UpdateMitigationStatus");
				}
			}
		}

		private string _updateMitigationMacLevel;
		public string UpdateMitigationMacLevel
		{
			get { return _updateMitigationMacLevel; }
			set
			{
				if (_updateMitigationMacLevel != value)
				{
					_updateMitigationMacLevel = value;
					OnPropertyChanged("UpdateMitigationMacLevel");
				}
			}
		}

		private string _updateMitigationGroupName;
		public string UpdateMitigationGroupName
		{
			get { return _updateMitigationGroupName; }
			set
			{
				if (_updateMitigationGroupName != value)
				{
					_updateMitigationGroupName = value;
					OnPropertyChanged("UpdateMitigationGroupName");
				}
			}
		}

		private string _updateMitigationText;
		public string UpdateMitigationText
		{
			get { return _updateMitigationText; }
			set
			{
				if (_updateMitigationText != value)
				{
					_updateMitigationText = value;
					OnPropertyChanged("UpdateMitigationText");
				}
			}
		}

		private string _systemNameForReporting = string.Empty;
		public string SystemNameForReporting
		{
			get { return _systemNameForReporting; }
			set
			{
				if (_systemNameForReporting != value)
				{
					_systemNameForReporting = value;
					OnPropertyChanged("SystemNameForReporting");
				}
			}
		}

		private string _selectedMitigation;
		public string SelectedMitigation
		{
			get { return _selectedMitigation; }
			set
			{
				if (_selectedMitigation != value)
				{
					_selectedMitigation = value;
					OnPropertyChanged("SelectedMitigation");
				}
			}
		}

		private string _selectedMitigationForUpdating;
		public string SelectedMitigationForUpdating
		{
			get { return _selectedMitigationForUpdating; }
			set
			{
				if (_selectedMitigationForUpdating != value)
				{
					_selectedMitigationForUpdating = value;
					OnPropertyChanged("SelectedMitigationForUpdating");
				}
			}
		}

		private string _mitigationsTextFile;
		public string ImportMitigationTextFileName
		{
			get { return _mitigationsTextFile; }
			set
			{
				if (value != _mitigationsTextFile)
				{
					_mitigationsTextFile = value;
					OnPropertyChanged("ImportMitigationTextFileName");
				}
			}
		}

		private bool _isEnabled = true;
		public bool IsEnabled
		{
			get { return _isEnabled; }
			set
			{
				if (_isEnabled != value)
				{
					_isEnabled = value;
					OnPropertyChanged("IsEnabled");
				}
			}
		}

		private string _progressLabelText = "Awaiting Execution...";
		public string ProgressLabelText
		{
			get { return _progressLabelText; }
			set
			{
				if (_progressLabelText != value)
				{
					_progressLabelText = value;
					OnPropertyChanged("ProgressLabelText");
				}
			}
		}

		private string _progressRingVisibility = "Collapsed";
		public string ProgressRingVisibility
		{
			get { return _progressRingVisibility; }
			set
			{
				if (_progressRingVisibility != value)
				{
					_progressRingVisibility = value;
					OnPropertyChanged("ProgressRingVisibility");
				}
			}
		}

		private bool _mitigationsAreChecked;
		public bool MitigationsAreChecked
		{
			get { return _mitigationsAreChecked; }
			set
			{
				if (_mitigationsAreChecked != value)
				{
					_mitigationsAreChecked = value;
					OnPropertyChanged("MitigationsAreChecked");
				}
			}
		}

		private bool _iavmsAreChecked;
		public bool IavmsAreChecked
		{
			get { return _iavmsAreChecked; }
			set
			{
				if (_iavmsAreChecked != value)
				{
					_iavmsAreChecked = value;
					OnPropertyChanged("IavmsAreChecked");
				}
			}
		}

		private bool _contactsAreChecked;
		public bool ContactsAreChecked
		{
			get { return _contactsAreChecked; }
			set
			{
				if (_contactsAreChecked != value)
				{
					_contactsAreChecked = value;
					OnPropertyChanged("ContactsAreChecked");
				}
			}
		}

		private string _mitigationDatabaseLocation;
		public string MitigationDatabaseLocation
		{
			get { return _mitigationDatabaseLocation; }
			set
			{
				if (_mitigationDatabaseLocation != value)
				{
					_mitigationDatabaseLocation = value;
					OnPropertyChanged("MitigationDatabaseLocation");
				}
			}
		}

		private string _contactDatabaseLocation;
		public string ContactDatabaseLocation
		{
			get { return _contactDatabaseLocation; }
			set
			{
				if (_contactDatabaseLocation != value)
				{
					_contactDatabaseLocation = value;
					OnPropertyChanged("ContactDatabaseLocation");
				}
			}
		}

		private string _selectedSystemGroupToUpdate;
		public string SelectedSystemGroupToUpdate
		{
			get { return _selectedSystemGroupToUpdate; }
			set
			{
				if (_selectedSystemGroupToUpdate != value)
				{
					_selectedSystemGroupToUpdate = value;
					OnPropertyChanged("SelectedSystemGroupToUpdate");
				}
			}
		}

		private string _selectedContactSystemToUpdate;
		public string SelectedContactSystemToUpdate
		{
			get { return _selectedContactSystemToUpdate; }
			set
			{
				if (_selectedContactSystemToUpdate != value)
				{
					_selectedContactSystemToUpdate = value;
					OnPropertyChanged("SelectedContactSystemToUpdate");
				}
			}
		}

		private Contact _selectedContact;
		public Contact SelectedContact
		{
			get { return _selectedContact; }
			set
			{
				if (_selectedContact != value)
				{
					_selectedContact = value;
					OnPropertyChanged("SelectedContact");
				}
			}
		}

		private string _addContactName;
		public string AddContactName
		{
			get { return _addContactName; }
			set
			{
				if (_addContactName != value)
				{
					_addContactName = value;
					OnPropertyChanged("AddContactName");
				}
			}
		}

		private string _addContactTitle;
		public string AddContactTitle
		{
			get { return _addContactTitle; }
			set
			{
				if (_addContactTitle != value)
				{
					_addContactTitle = value;
					OnPropertyChanged("AddContactTitle");
				}
			}
		}

		private string _addContactEmail;
		public string AddContactEmail
		{
			get { return _addContactEmail; }
			set
			{
				if (_addContactEmail != value)
				{
					_addContactEmail = value;
					OnPropertyChanged("AddContactEmail");
				}
			}
		}

		private string _addContactGroupName;
		public string AddContactGroupName
		{
			get { return _addContactGroupName; }
			set
			{
				if (_addContactGroupName != value)
				{
					_addContactGroupName = value;
					OnPropertyChanged("AddContactGroupName");
				}
			}
		}

		private string _addContactMacLevel;
		public string AddContactMacLevel
		{
			get { return _addContactMacLevel; }
			set
			{
				if (_addContactMacLevel != value)
				{
					_addContactMacLevel = value;
					OnPropertyChanged("AddContactMacLevel");
				}
			}
		}

		private string _addContactSystemIp;
		public string AddContactSystemIp
		{
			get { return _addContactSystemIp; }
			set
			{
				if (_addContactSystemIp != value)
				{
					_addContactSystemIp = value;
					OnPropertyChanged("AddContactSystemIp");
				}
			}
		}

		private string _addContactSystemHostName;
		public string AddContactSystemHostName
		{
			get { return _addContactSystemHostName; }
			set
			{
				if (_addContactSystemHostName != value)
				{
					_addContactSystemHostName = value;
					OnPropertyChanged("AddContactSystemHostName");
				}
			}
		}

		private int _iavmFilterOne;
		public int IavmFilterOne
		{
			get { return _iavmFilterOne; }
			set
			{
				if (_iavmFilterOne != value)
				{
					_iavmFilterOne = value;
					OnPropertyChanged("IavmFilterOne");
				}
			}
		}

		private int _iavmFilterTwo;
		public int IavmFilterTwo
		{
			get { return _iavmFilterTwo; }
			set
			{
				if (_iavmFilterTwo != value)
				{
					_iavmFilterTwo = value;
					OnPropertyChanged("IavmFilterTwo");
				}
			}
		}

		private int _iavmFilterThree;
		public int IavmFilterThree
		{
			get { return _iavmFilterThree; }
			set
			{
				if (_iavmFilterThree != value)
				{
					_iavmFilterThree = value;
					OnPropertyChanged("IavmFilterThree");
				}
			}
		}

		private int _iavmFilterFour;
		public int IavmFilterFour
		{
			get { return _iavmFilterFour; }
			set
			{
				if (_iavmFilterFour != value)
				{
					_iavmFilterFour = value;
					OnPropertyChanged("IavmFilterFour");
				}
			}
		}

		#endregion

		#region MainWindowViewModel Constructor

		public MainWindowViewModel()
		{
			if (File.Exists(Environment.GetFolderPath(
				Environment.SpecialFolder.ApplicationData) + @"\Vulnerator\VulneratorV6Log.txt"))
			{
				File.Delete(Environment.GetFolderPath(
				Environment.SpecialFolder.ApplicationData) + @"\Vulnerator\VulneratorV6Log.txt");
			}
			
			configAlter = new ConfigAlter();
			configAlter.CreateConfigurationXml();
			configAlter.CreateSettingsDictionary();
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			
			MitigationDatabaseLocation = ConfigAlter.ReadSettingsFromDictionary("tbMitDbLocation");
			ContactDatabaseLocation = ConfigAlter.ReadSettingsFromDictionary("tbContactDbLocation");
			IavmFilterOne = int.Parse(ConfigAlter.ReadSettingsFromDictionary("iavmFilterOne"));
			IavmFilterTwo = int.Parse(ConfigAlter.ReadSettingsFromDictionary("iavmFilterTwo"));
			IavmFilterThree = int.Parse(ConfigAlter.ReadSettingsFromDictionary("iavmFilterThree"));
			IavmFilterFour = int.Parse(ConfigAlter.ReadSettingsFromDictionary("iavmFilterFour"));
			FileList = new AsyncObservableCollection<Files>();
			MitigationList = new AsyncObservableCollection<MitigationItem>();
			SystemGroupList = new AsyncObservableCollection<SystemGroup>();
			IavmList = new AsyncObservableCollection<Iavm>();
			ContactList = new AsyncObservableCollection<Contact>();
			ContactTitleList = new AsyncObservableCollection<ContactTitle>();
			MonitoredSystemList = new AsyncObservableCollection<MonitoredSystem>();
			MonitoredSystemListForUpdating = new AsyncObservableCollection<UpdatableMonitoredSystem>();
			SystemGroupListForUpdating = new AsyncObservableCollection<UpdatableSystemGroup>();
            IssueList = new AsyncObservableCollection<Issue>();
            ReleaseList = new AsyncObservableCollection<Release>();
			vulneratorDatabaseActions.CreateVulneratorDatabase();
			findingsDatabaseActions = new FindingsDatabaseActions();
			vulneratorDatabaseActions.PopulateGuiLists(this);
			cciDs.EnforceConstraints = false;
			if (!File.Exists(cciFileLocation))
			{
				//string cciFileContents = GetCciFile("U_CCI_List.xml");
				//File.WriteAllText(cciFileLocation, cciFileContents);
			}
			cciDs.ReadXml(cciFileLocation);

			StatusItemList = new AsyncObservableCollection<StatusItem>();
			StatusItemList.Add(new StatusItem("Ongoing"));
			StatusItemList.Add(new StatusItem("Completed"));
			StatusItemList.Add(new StatusItem("False Positive"));

			MacLevelList = new AsyncObservableCollection<MacLevel>();
			MacLevelList.Add(new MacLevel("I"));
			MacLevelList.Add(new MacLevel("II"));
			MacLevelList.Add(new MacLevel("III"));
            githubActions = new GitHubActions();
            githubActions.GetGitHubIssues(IssueList);
            githubActions.GetGitHubReleases(ReleaseList);
		}

		#endregion

		#region Findings DataTable Creator

		public static DataTable CreateFindingsDataTable()
		{
			DataTable findingsDataTable = new DataTable();
			findingsDataTable.Columns.Add("FindingType", typeof(string));
			findingsDataTable.Columns.Add("Source", typeof(string));
			findingsDataTable.Columns.Add("RuleId", typeof(string));
			findingsDataTable.Columns.Add("VulnId", typeof(string));
			findingsDataTable.Columns.Add("VulnTitle", typeof(string));
			findingsDataTable.Columns.Add("Description", typeof(string));
			findingsDataTable.Columns.Add("RiskStatement", typeof(string));
			findingsDataTable.Columns.Add("Impact", typeof(string));
			findingsDataTable.Columns.Add("RawRisk", typeof(string));
			findingsDataTable.Columns.Add("Status", typeof(string));
			findingsDataTable.Columns.Add("FixText", typeof(string));
			findingsDataTable.Columns.Add("IpAddress", typeof(string));
			findingsDataTable.Columns.Add("HostName", typeof(string));
			findingsDataTable.Columns.Add("CrossReferences", typeof(string));
			findingsDataTable.Columns.Add("Cpe", typeof(string));
			findingsDataTable.Columns.Add("IavmNumber", typeof(string));
			findingsDataTable.Columns.Add("IaControl", typeof(string));
			findingsDataTable.Columns.Add("CciRef", typeof(string));
			findingsDataTable.Columns.Add("LastObserved", typeof(string));
			findingsDataTable.Columns.Add("PluginPublicationDate", typeof(string));
			findingsDataTable.Columns.Add("PluginModificationDate", typeof(string));
			findingsDataTable.Columns.Add("PatchPublicationDate", typeof(string));
			findingsDataTable.Columns.Add("Age", typeof(string));
			findingsDataTable.Columns.Add("PluginOutput", typeof(string));
			findingsDataTable.Columns.Add("Comments", typeof(string));
			findingsDataTable.Columns.Add("FindingDetails", typeof(string));
			findingsDataTable.Columns.Add("SystemName", typeof(string));
			findingsDataTable.Columns.Add("FileName", typeof(string));
			return findingsDataTable;
		}

		#endregion

		#region MainWindowViewModel Destructor

		~MainWindowViewModel()
		{
			configAlter.WriteSettingsToConfigurationXml();
			//findingsDatabaseActions.DeleteFindingsDatabase();
		}

		#endregion

		#region GetCciFile

		private string GetCciFile(string fileName)
		{
			string result = string.Empty;

			using (Stream stream = this.GetType().Assembly.
					   GetManifestResourceStream("Vulnerator.Resources." + fileName))
			{
				using (StreamReader sr = new StreamReader(stream))
				{ result = sr.ReadToEnd(); }
			}
			return result;

		}

		#endregion

		#region UpdateDictionaryCommand

		// Command to update confDic as Checkbox controls are toggled true / false
		public ICommand UpdateDictionaryCommand
		{
			get { return new DelegateCommand(UpdateDictionary); }
		}

		private void UpdateDictionary()
		{
			if (!String.IsNullOrWhiteSpace(commandParameters.controlName))
			{
				configAlter.WriteSettingsToDictionary(commandParameters.controlName, commandParameters.controlValue);

				switch (commandParameters.controlName)
				{
					case "rbDiacap":
						{
							configAlter.WriteSettingsToDictionary("rbRmf", (!bool.Parse(commandParameters.controlValue)).ToString());
							break;
						}
					case "rbRmf":
						{
							configAlter.WriteSettingsToDictionary("rbDiacap", (!bool.Parse(commandParameters.controlValue)).ToString());
							break;
						}
					case "rbPki":
						{
							configAlter.WriteSettingsToDictionary("rbNone", (!bool.Parse(commandParameters.controlValue)).ToString()); 
							break;
						}
					case "rbNone":
						{
							configAlter.WriteSettingsToDictionary("rbPki", (!bool.Parse(commandParameters.controlValue)).ToString()); 
							break;
						}
					default:
						{
							break;
						}
				}
			}
		}

		#endregion

		#region MitigationsDotTxtBrowseDialogCommand

		public ICommand MitigationsDotTxtBrowseDialogCommand
		{
			get { return new DelegateCommand(MitigationsDotTxtBrowseDialog); }
		}
		
		private void MitigationsDotTxtBrowseDialog()
		{
			if (openDialog == null)
			{
				openDialog = new OpenFileDialog();
				openDialog.Multiselect = false;
				openDialog.CheckFileExists = true;
				openDialog.Filter = "Text Files (*.txt)|*.txt";
				openDialog.Title = "Please select Mitigations file";
				openDialog.DefaultExt = ".txt";
				openDialog.ShowDialog();
				ImportMitigationTextFileName = openDialog.FileName;
			}
			openDialog = null;
		}

		#endregion

		#region DatabaseBrowseDialogCommand

		public ICommand DatabaseBrowseDialogCommand
		{
			get { return new DelegateCommand(DatabaseBrowseDialog); }
		}

		private void DatabaseBrowseDialog()
		{
			if (openDialog == null)
			{
				openDialog = new OpenFileDialog();
				openDialog.Multiselect = false;
				openDialog.CheckFileExists = true;
				openDialog.Filter = "SDF Files (*.sdf)|*.sdf";
				openDialog.Title = "Please select Mitigations Database file";
				openDialog.DefaultExt = ".sdf";

				if (openDialog.ShowDialog() == true)
				{
					configAlter.WriteSettingsToDictionary("tbMitDbLocation", openDialog.FileName);
					configAlter.WriteSettingsToDictionary("tbContactDbLocation", openDialog.FileName);
					MitigationDatabaseLocation = ContactDatabaseLocation = openDialog.FileName;
					MitigationList.Clear();
					SystemGroupList.Clear();
					vulneratorDatabaseActions.PopulateGuiLists(this);
				}
			}

			openDialog = null;
		}

		#endregion

		#region CreateDatabaseDialogCommand

		public ICommand CreateDatabaseDialogCommand
		{
			get { return new DelegateCommand(DatabaseCreateDialog); }
		}

		private void DatabaseCreateDialog()
		{
			if (openDialog == null)
			{
				openDialog = new OpenFileDialog();
				openDialog.Multiselect = false;
				openDialog.CheckFileExists = true;
				openDialog.Filter = "SDF Files (*.sdf)|*.sdf";
				openDialog.Title = "Please select Contact Database file";
				openDialog.DefaultExt = ".sdf";

				if (openDialog.ShowDialog() == true)
				{
					configAlter.WriteSettingsToDictionary("tbMitDbLocation", openDialog.FileName);
					configAlter.WriteSettingsToDictionary("tbContactDbLocation", openDialog.FileName);
					MitigationDatabaseLocation = ContactDatabaseLocation = openDialog.FileName;
					MitigationList.Clear();
					SystemGroupList.Clear();
				}

				openDialog = null;
			}
		}

		#endregion

		#region OpenDialogCommand

		public ICommand OpenDialogCommand
		{
			get { return new DelegateCommand(OpenDialog); }
		}

		private OpenFileDialog openDialog;
		private void OpenDialog(object param)
		{
			if (openDialog == null)
			{
				openDialog = new OpenFileDialog();
				openDialog.Multiselect = true;
				openDialog.CheckFileExists = true;

				string p = param.ToString();

				if (p.Contains("ACAS"))
				{ OpenAcasFiles(); }

				else if (p.Contains("CKL"))
				{ OpenCklFiles(); }

				else if (p.Contains("WASSP"))
				{ OpenWasspFiles(); }

				else if (p.Contains("XCCDF"))
				{ OpenXccdfFiles(); }
			}
			openDialog = null;
		}

		private void OpenAcasFiles()
		{
			openDialog.Filter = "ACAS Files (*.csv;*.nessus)|*.csv;*.nessus";
			openDialog.Title = "Please select ACAS file(s)";
			openDialog.ShowDialog();
			if (openDialog.FileNames.Length > 0)
			{
				for (int i = 0; i < openDialog.FileNames.Length; i++)
				{
					string filePath = openDialog.FileNames[i];
					string fileName = Path.GetFileNameWithoutExtension(filePath);
					if (Path.GetExtension(filePath).ToLower().Equals(".nessus"))
					{
						FileList.Add(new Files(fileName, "ACAS - Nessus", "Ready", string.Empty, filePath));
					}
					else
					{
						FileList.Add(new Files(fileName, "ACAS - CSV", "Ready", string.Empty, filePath));
					}
				}
			}
		}

		private void OpenCklFiles()
		{
			openDialog.Filter = "CKL Files (*.ckl)|*.ckl";
			openDialog.Title = "Please select CKL file(s)";
			openDialog.ShowDialog();
			if (openDialog.FileNames.Length > 0)
			{
				for (int i = 0; i < openDialog.FileNames.Length; i++)
				{
					string filePath = openDialog.FileNames[i];
					string fileName = Path.GetFileNameWithoutExtension(filePath);
					FileList.Add(new Files(fileName, "Checklist", "Ready", string.Empty, filePath));
				}
			}
		}

		private void OpenWasspFiles()
		{
			openDialog.Filter = "WASSP Files (*.html)|*.html;*.xml";
			openDialog.Title = "Please select WASSP file(s)";
			openDialog.ShowDialog();
			if (openDialog.FileNames.Length > 0)
			{
				for (int i = 0; i < openDialog.FileNames.Length; i++)
				{
					string filePath = openDialog.FileNames[i];
					string fileName = Path.GetFileNameWithoutExtension(filePath);
					if (Path.GetExtension(filePath).ToLower().Equals(".html"))
					{
						FileList.Add(new Files(fileName, "WASSP - HTML", "Ready", string.Empty, filePath));
					}
					else
					{
						FileList.Add(new Files(fileName, "WASSP - XML", "Ready", string.Empty, filePath));
					}
				}
			}
		}

		private void OpenXccdfFiles()
		{
			openDialog.Filter = "XCCDF Files (*.xml)|*.xml";
			openDialog.Title = "Please select XCCDF file(s)";
			openDialog.ShowDialog();
			if (openDialog.FileNames.Length > 0)
			{
				for (int i = 0; i < openDialog.FileNames.Length; i++)
				{
					string filePath = openDialog.FileNames[i];
					string fileName = Path.GetFileNameWithoutExtension(filePath);
					FileList.Add(new Files(fileName, "SCAP Benchmark", "Ready", string.Empty, filePath));
				}
			}
		}

		#endregion

		#region ClearCollectionCommand

		public ICommand ClearCollectionCommand
		{
			get { return new DelegateCommand(ClearCollection); }
		}

		private void ClearCollection(object param)
		{
			string p = param.ToString();

			if (p.Contains("Clear Files"))
			{
				if (FileList.Count != 0)
				{
					FileList.Clear();
					IavmList.Clear();
				}
			}
		}

		#endregion

		#region DeleteButtonsCommand

		public ICommand DeleteButtonsCommand
		{
			get { return new DelegateCommand(DeleteButtons); }
		}
		
		private void DeleteButtons(object param)
		{
			string p = param.ToString();
			
			if (p.Contains("bMitDelete"))
			{
				backgroundWorker = new BackgroundWorker();
				backgroundWorker.DoWork += deleteMitigationsBackgroundWorker_DoWork;
				backgroundWorker.RunWorkerAsync();
				backgroundWorker.Dispose();
			}
			else if (p.Contains("bIavmDelete"))
			{
				backgroundWorker = new BackgroundWorker();
				backgroundWorker.DoWork += deleteIavmsBackgroundWorker_DoWork;
				backgroundWorker.RunWorkerAsync();
				backgroundWorker.Dispose();
			}
			else if (p.Contains("deleteContactsButton"))
			{
				backgroundWorker = new BackgroundWorker();
				backgroundWorker.DoWork += deleteContactsBackgroundWorker_DoWork;
				backgroundWorker.RunWorkerAsync();
				backgroundWorker.Dispose();
			}
		}

		private void deleteMitigationsBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.DeleteMitigation(MitigationList);
			MitigationsAreChecked = false;
		}

		private void deleteIavmsBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			ArrayList arrayList = new ArrayList();
			foreach (Iavm iavm in IavmList)
			{
				if (iavm.IsChecked)
				{ arrayList.Add(iavm); }
			}
			foreach (Iavm iavm in arrayList)
			{ IavmList.Remove(iavm); }
			arrayList.Clear();
			IavmsAreChecked = false;
		}

		private void deleteContactsBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.DeleteContact(ContactList);
			ContactsAreChecked = false;
		}

		#endregion

		#region SelectCheckboxCommand

		public ICommand SelectCheckboxCommand
		{
			get { return new DelegateCommand(SelectCheckbox); }
		}

		private void SelectCheckbox(object param)
		{
			string p = param.ToString();
			if (p.Contains("allMits"))
			{
				foreach (MitigationItem item in MitigationList)
				{ item.IsChecked = MitigationsAreChecked; }
			}
			else if (p.Contains("allIavms"))
			{
				foreach (Iavm item in IavmList)
				{ item.IsChecked = IavmsAreChecked; }
			}
			else if (p.Contains("selectAllContactsCheckbox"))
			{
				foreach (Contact item in ContactList)
				{ item.IsChecked = ContactsAreChecked; }
			}

		}

		#endregion

		#region UpdateAllSystemNamesCommand

		public ICommand UpdateAllSystemNamesCommand
		{
			get { return new DelegateCommand(UpdateAllSystemNames); }
		}

		private void UpdateAllSystemNames(object parameter)
		{
			foreach (Files file in FileList)
			{
				if (parameter != null)
				{ file.FileSystemName = parameter.ToString(); }
				else
				{ file.FileSystemName = string.Empty; }
			}
		}

		#endregion

		#region ClearMitigationSelectionCommand

		public ICommand ClearMitigationSelectionCommand
		{
			get { return new DelegateCommand(ClearMitigationSelection); } 
		}
		
		private void ClearMitigationSelection()
		{
			SelectedMitigation = string.Empty;
		}

		#endregion

		#region ClearContactSelectionCommand

		public ICommand ClearContactSelectionCommand
		{
			get { return new DelegateCommand(ClearContactSelection); }
		}

		private void ClearContactSelection()
		{
			SelectedContact = null;
		}

		#endregion

		#region ExecuteButtonCommand

		public ICommand ExecuteButtonCommand
		{
			get { return new DelegateCommand(ExecuteButton); }
		}

		private void ExecuteButton()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += executeButtonBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
			backgroundWorker.Dispose();
		}

		private void executeButtonBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			string excelReportStatus = string.Empty;
			string pdfReportStatus = string.Empty;

			if (FileList.Count > 0)
			{ ParseFiles(); }
			else
			{ SetGuiProperties("No files to process", "Collapsed", true, null, null); return; }

			if (ExcelReportsAreRequired())
			{
				SetGuiProperties("Getting excel report name...", "Visible", false, null, null);
				if ((bool)GetExcelReportName())
				{
					SetGuiProperties("Creating excel report(s)...", "Visible", false, saveExcelFile, null);
					excelReportStatus = CreateExcelReports();
				}
				else
				{
					SetGuiProperties(ProgressLabelText, "Visible", false, null, null);
					excelReportStatus = "Excel report cancelled by user"; 
				}
				
			}
			else
			{ excelReportStatus = "Excel report not required"; }

			if (PdfReportIsRequired())
			{
				SetGuiProperties("Getting PDF report name...", "Visible", false, null, null);
				if ((bool)GetPdfReportName())
				{
					SetGuiProperties("Creating PDF report...", "Visible", false, null, savePdfFile);
					pdfReportStatus = CreatePdfReport();
				}
				else
				{
					SetGuiProperties(ProgressLabelText, "Visible", false, null, null);
					pdfReportStatus = "PDF report cancelled by user"; 
				}
			}
			else
			{ pdfReportStatus = "PDF report not required"; }

			findingsDatabaseActions.IndexDatabase();

			stopWatch.Stop();
			WriteLog.DiagnosticsInformation(string.Empty, "Processing complete; " + excelReportStatus + "; " + pdfReportStatus, stopWatch.Elapsed.ToString());
			SetGuiProperties("Processing complete; " + excelReportStatus + "; " + pdfReportStatus, "Collapsed", true, null, null);
		}

		private void ParseFiles()
		{
			SetGuiProperties("Processing Files...", "Visible", false, null, null);
			stopWatch.Start();

            findingsDatabaseActions.RefreshFindingsDatabase();
			foreach (Files file in FileList)
			{
				fileStopWatch.Start();
				file.Status = "Processing...";
				ProgressLabelText = "Processing File " + (FileList.IndexOf(file) + 1).ToString() + "...";
				WriteLog.DiagnosticsInformation(file.FileName, "Beginning processing of", string.Empty);
				switch (file.FileType)
				{
					case "ACAS - CSV":
						{
							AcasCsvReader acasCsvReader = new AcasCsvReader();
							file.Status = acasCsvReader.ReadAcasCsvFile(file.FilePath, MitigationList, file.FileSystemName.Split(':')[0].TrimEnd());
							break;
						}
					case "ACAS - Nessus":
						{
							AcasNessusReader acasNessusReader = new AcasNessusReader();
							file.Status = acasNessusReader.ReadAcasNessusFile(file.FilePath, MitigationList, file.FileSystemName.Split(':')[0].Trim());
							acasNessusReader = null;
							break;
						}
					case "Checklist":
						{
							CklReader cklReader = new CklReader();
							file.Status = cklReader.ReadCklFile(file.FilePath, MitigationList, file.FileSystemName.Split(':')[0].TrimEnd());
							break;
						}
					case "WASSP - HTML":
						{
							WasspReader wasspReader = new WasspReader();
							file.Status = wasspReader.ReadWassp(file.FilePath, MitigationList, file.FileSystemName.Split(':')[0].TrimEnd());
							break;
						}
					case "WASSP - XML":
						{
							XmlWasspReader xmlWasspReader = new XmlWasspReader();
							file.Status = xmlWasspReader.ReadXmlWassp(file.FilePath, MitigationList, file.FileSystemName.Split(':')[0].TrimEnd());
							break;
						}
					case "SCAP Benchmark":
						{
							XccdfReader xccdfReader = new XccdfReader();
							file.Status = xccdfReader.ReadXccdfFile(file.FilePath, MitigationList, file.FileSystemName.Split(':')[0].TrimEnd());
							break;
						}
					default:
						{
							WriteLog.DiagnosticsInformation(file.FileName, "File type not recognized for", string.Empty);
							break;
						}
				}

				WriteLog.DiagnosticsInformation(file.FileName, "Finished processing of", fileStopWatch.Elapsed.ToString());
				fileStopWatch.Stop();
				fileStopWatch.Reset();
			}
		}

		private void SetGuiProperties(string progressLabelText, string progressRingVisibility, bool isEnabled, SaveFileDialog saveExcelFileDialog, SaveFileDialog savePdfFileDialog)
		{
			ProgressLabelText = progressLabelText;
			ProgressRingVisibility = progressRingVisibility;
			IsEnabled = isEnabled;
			saveExcelFile = saveExcelFileDialog;
			savePdfFile = savePdfFileDialog;
		}

		private bool ExcelReportsAreRequired()
		{
			bool PoamAndRarAreNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbPoamRar"));
			bool SummaryTabIsNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbAssetOverview"));
			bool DiscrepanciesTabIsNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbDiscrepancies"));
			bool AcasOutputTabIsNeeded = bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbAcasOutput"));
			if (PoamAndRarAreNeeded || SummaryTabIsNeeded || DiscrepanciesTabIsNeeded || AcasOutputTabIsNeeded)
			{ return true; }
			else
			{ return false; }
		}

		private bool? GetExcelReportName()
		{
			saveExcelFile = new SaveFileDialog();
			saveExcelFile.AddExtension = true;
			saveExcelFile.Filter = "Excel Files (*.xlsx)|*.xlsx";
			saveExcelFile.DefaultExt = "xlsx";
			saveExcelFile.Title = "Save Excel Report";
			saveExcelFile.OverwritePrompt = true;
			saveExcelFile.CheckPathExists = true;
			return saveExcelFile.ShowDialog();
		}
		
		private string CreateExcelReports()
		{
			WriteLog.DiagnosticsInformation(Path.GetFileName(saveExcelFile.FileName), "Creating Excel report", string.Empty);
			fileStopWatch.Start();
			OpenXmlReportCreator openXmlReportCreator = new OpenXmlReportCreator();
			if (!openXmlReportCreator.CreateExcelReport(saveExcelFile.FileName, MitigationList).Contains("successful"))
			{
				WriteLog.DiagnosticsInformation(saveExcelFile.FileName, "Excel report creation failed", fileStopWatch.Elapsed.ToString());
				fileStopWatch.Stop();
				fileStopWatch.Reset();
				return "Excel report creation error; see log for details";
			}
			else
			{
				WriteLog.DiagnosticsInformation(saveExcelFile.FileName, "Finished creating Excel report", fileStopWatch.Elapsed.ToString());
				fileStopWatch.Stop();
				fileStopWatch.Reset();
				return "Excel report created successfully";
			}
		}

		private bool PdfReportIsRequired()
		{
			if (bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbPdfSum")))
			{ return true; }
			else
			{ return false; }
		}

		private bool? GetPdfReportName()
		{
			savePdfFile = new SaveFileDialog();
			savePdfFile.AddExtension = true;
			savePdfFile.Filter = "PDF Files (*.pdf)|*.pdf";
			savePdfFile.DefaultExt = "xls";
			savePdfFile.Title = "Save PDF Report";
			savePdfFile.OverwritePrompt = true;
			savePdfFile.CheckPathExists = true;
			return savePdfFile.ShowDialog();
		}

		private string CreatePdfReport()
		{
			WriteLog.DiagnosticsInformation(Path.GetFileName(saveExcelFile.FileName), "Creating PDF report", string.Empty);
			fileStopWatch.Start();
			PdfReportCreator pdfReportCreator = new PdfReportCreator();
			if (!pdfReportCreator.PdfWriter(savePdfFile.FileName.ToString(), SystemNameForReporting).Equals("Success"))
			{
				WriteLog.DiagnosticsInformation(saveExcelFile.FileName, "PDF report creation failed", fileStopWatch.Elapsed.ToString());
				fileStopWatch.Stop();
				fileStopWatch.Reset();
				return "PDF report creation error; see log for details";
			}
			else
			{
				WriteLog.DiagnosticsInformation(saveExcelFile.FileName, "Finished creating PDF report", fileStopWatch.Elapsed.ToString());
				fileStopWatch.Stop();
				fileStopWatch.Reset();
				return "PDF summary created successfully"; 
			}
		}
		
		#endregion

		#region HandleFlyoutsCommand

		public ICommand HandleFlyoutsCommand
		{
			get { return new DelegateCommand(HandleFlyouts); }
		}
		
		private void HandleFlyouts(object param)
		{
			string p = param.ToString();

			switch (p)
			{
				case "theme":
				{ ToggleThemeFlyout(); break; }
				case "Email Options":
				{ ToggleEmailOptionsFlyout(); break; }
				case "Import Mitigation(s)":
				{ ToggleImportMitigationsFlyout(); break; }
				case "about":
				{ ToggleAboutFlyout(); break; }
                case "news":
                { ToggleNewsFlyout(); break; }
                default:
				{ break; }
			}
			
		}

		private void ToggleThemeFlyout()
		{
			if (ThemeFlyoutIsOpen == "False")
			{ ThemeFlyoutIsOpen = "True"; }
			else
			{ ThemeFlyoutIsOpen = "False"; }
			AboutFlyoutIsOpen = "False";
			AdvancedFlyoutIsOpen = "False";
			ImportFlyoutIsOpen = "False";
            NewsFlyoutIsOpen = "False";
		}

		private void ToggleEmailOptionsFlyout()
		{
			if (AdvancedFlyoutIsOpen == "False")
			{ AdvancedFlyoutIsOpen = "True"; }
			else
			{ AdvancedFlyoutIsOpen = "False"; }
			ThemeFlyoutIsOpen = "False";
			AboutFlyoutIsOpen = "False";
			ImportFlyoutIsOpen = "False";
            NewsFlyoutIsOpen = "False";
        }

		private void ToggleImportMitigationsFlyout()
		{
			if (ImportFlyoutIsOpen == "False")
			{ ImportFlyoutIsOpen = "True"; }
			else
			{ ImportFlyoutIsOpen = "False"; }
			ThemeFlyoutIsOpen = "False";
			AboutFlyoutIsOpen = "False";
			AdvancedFlyoutIsOpen = "False";
            NewsFlyoutIsOpen = "False";
        }

		private void ToggleAboutFlyout()
		{
			if (AboutFlyoutIsOpen == "False")
			{ AboutFlyoutIsOpen = "True"; }
			else
			{ AboutFlyoutIsOpen = "False"; }
			ThemeFlyoutIsOpen = "False";
			ImportFlyoutIsOpen = "False";
			AdvancedFlyoutIsOpen = "False";
            NewsFlyoutIsOpen = "False";
        }

        private void ToggleNewsFlyout()
        {
            if (NewsFlyoutIsOpen == "False")
            { NewsFlyoutIsOpen = "True"; }
            else
            { NewsFlyoutIsOpen = "False"; }
            ThemeFlyoutIsOpen = "False";
            ImportFlyoutIsOpen = "False";
            AdvancedFlyoutIsOpen = "False";
            AboutFlyoutIsOpen= "False";
        }

		#endregion

		#region AboutLinksCommand

		public ICommand AboutLinksCommand
		{
			get { return new DelegateCommand(AboutLinks); }
		}
		
		private void AboutLinks(object param)
		{
			string p = param.ToString();

			switch (p)
			{
				case "tbAlex":
					{
						EmailAlex();
						break;
					}
				case "tbJeffV":
					{
						EmailJeffV();
						break;
					}
				case "tbRick":
					{
						EmailRick();
						break;
					}
				case "tbJeffP":
					{
						EmailJeffP();
						break;
					}
				case "tbProject":
					{
                        VisitProjectPage();
						break;
					}
                case "tbWiki":
                    {
                        VisitWikiPage();
                        break;
                    }
                case "tbRepo":
                    {
                        VisitRepo();
                        break;
                    }
                case "tbKcs":
                    {
                        VisitKcs();
                        break;
                    }
                default:
					{ break; }
			}
		}

		private void EmailAlex()
		{
			string mailTo = "mailto:alex.kuchta.ctr@navy.mil";
			try
			{
				System.Diagnostics.Process.Start(mailTo);
			}
			catch (Exception exception)
			{
				WriteLog.LogWriter(exception, string.Empty);
				View.NoEmailApplication emailWarning = new View.NoEmailApplication();
				emailWarning.ShowDialog();
				return;
			}
		}

		private void EmailJeffV()
		{
			string mailTo = "mailto:Jeff.Vanerwegen@QinetiQ-NA.com";
			try
			{
				System.Diagnostics.Process.Start(mailTo);
			}
			catch (Exception exception)
			{
				WriteLog.LogWriter(exception, string.Empty);
				View.NoEmailApplication emailWarning = new View.NoEmailApplication();
				emailWarning.ShowDialog();
				return;
			}
		}

		private void EmailRick()
		{
			string mailTo = "mailto:rick.murphy@navy.mil";
			try
			{
				System.Diagnostics.Process.Start(mailTo);
			}
			catch (Exception exception)
			{
				WriteLog.LogWriter(exception, string.Empty);
				View.NoEmailApplication emailWarning = new View.NoEmailApplication();
				emailWarning.ShowDialog();
				return;
			}
		}

		private void EmailJeffP()
		{
			string mailTo = "mailto:jeffrey.a.purcell@navy.mil";
			try
			{
				System.Diagnostics.Process.Start(mailTo);
			}
			catch (Exception exception)
			{
				WriteLog.LogWriter(exception, string.Empty);
				View.NoEmailApplication emailWarning = new View.NoEmailApplication();
				emailWarning.ShowDialog();
				return;
			}
		}

		private void VisitProjectPage()
		{
			string goTo = "https://vulnerator.github.io/Vulnerator";
			try
			{
				System.Diagnostics.Process.Start(goTo);
			}
			catch (Exception exception)
			{
				WriteLog.LogWriter(exception, string.Empty);
				View.NoInternetApplication internetWarning = new View.NoInternetApplication();
				internetWarning.ShowDialog();
				return;
			}
		}

        private void VisitWikiPage()
        {
            string goTo = "https://github.com/Vulnerator/Vulnerator/wiki";
            try
            {
                System.Diagnostics.Process.Start(goTo);
            }
            catch (Exception exception)
            {
                WriteLog.LogWriter(exception, string.Empty);
                View.NoInternetApplication internetWarning = new View.NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        private void VisitRepo()
        {
            string goTo = "https://github.com/Vulnerator/Vulnerator";
            try
            {
                System.Diagnostics.Process.Start(goTo);
            }
            catch (Exception exception)
            {
                WriteLog.LogWriter(exception, string.Empty);
                View.NoInternetApplication internetWarning = new View.NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        private void VisitKcs()
        {
            string goTo = "https://kuchtacreativeservices.com";
            try
            {
                System.Diagnostics.Process.Start(goTo);
            }
            catch (Exception exception)
            {
                WriteLog.LogWriter(exception, string.Empty);
                View.NoInternetApplication internetWarning = new View.NoInternetApplication();
                internetWarning.ShowDialog();
                return;
            }
        }

        #endregion

        #region SaveMitigationsCommand

        public ICommand SaveMitigationsCommand
		{
			get { return new DelegateCommand(SaveMitigations); }
		}

		private void SaveMitigations()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += addMitigationBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}

		private void addMitigationBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			if (String.IsNullOrWhiteSpace(AddMitigationId))
			{
				ProgressLabelText = "Please enter a vulnerability or set of vulnerabilities for the new mitigation entry";
				return;
			}
			if (String.IsNullOrWhiteSpace(AddMitigationStatus))
			{
				ProgressLabelText = "Please enter a status for the new mitigation entry";
				return;
			}
			if (String.IsNullOrWhiteSpace(AddMitigationText))
			{
				ProgressLabelText = "Please enter finding text for the new mitigation entry";
				return;
			}
			if (!String.IsNullOrWhiteSpace(AddMitigationGroupName))
			{
				if (String.IsNullOrWhiteSpace(AddMitigationMacLevel) && !AddMitigationGroupName.Contains(" : MAC"))
				{
					ProgressLabelText = "Please enter a MAC Level (I, II, III) for the new group entry";
					return;
				}
				vulneratorDatabaseActions = new VulneratorDatabaseActions();
				ProgressLabelText = vulneratorDatabaseActions.AddMitigation(AddMitigationId, AddMitigationStatus, AddMitigationGroupName, AddMitigationMacLevel, AddMitigationText, this);
			}
			else
			{
				ProgressLabelText = "Please select or enter a group name for the new mitigation entry";
				return;
			}

			if (ProgressLabelText.Contains("successful"))
			{
				AddMitigationId = string.Empty;
				AddMitigationStatus = string.Empty;
				AddMitigationMacLevel = string.Empty;
				MitigationGroupNameToUpdate = string.Empty;
				AddMitigationGroupName = string.Empty;
				AddMitigationText = string.Empty;
			}
		}

		#endregion

		#region UpdateMitigationCommand

		public ICommand UpdateMitigationCommand
		{
			get { return new DelegateCommand(UpdateMitigation); }
		}

		private void UpdateMitigation()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += updateMitigationBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}

		private void updateMitigationBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			if (String.IsNullOrWhiteSpace(updateMitigationParameters.VulnerabilityId) || updateMitigationParameters.VulnerabilityId.Contains("DependencyProperty.UnsetValue"))
			{
				ProgressLabelText = "Please select a mitigation to update";
				return;
			}
			if (!String.IsNullOrWhiteSpace(UpdateMitigationGroupName))
			{
				if (String.IsNullOrWhiteSpace(UpdateMitigationMacLevel) && !UpdateMitigationGroupName.Contains(" : MAC"))
				{
					ProgressLabelText = "Please enter a MAC Level (I, II, III) for the new group entry";
					return;
				}
			}
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.UpdateMitigation(updateMitigationParameters.VulnerabilityId, UpdateMitigationStatus, updateMitigationParameters.CurrentGroupName,
				UpdateMitigationGroupName, UpdateMitigationMacLevel, UpdateMitigationText, this);

			if (ProgressLabelText.Contains("successful"))
			{
				UpdateMitigationGroupName = string.Empty;
				UpdateMitigationMacLevel = string.Empty;
				UpdateMitigationStatus = string.Empty;
				UpdateMitigationText = string.Empty;
			}
		}

		#endregion

		#region ImportMitigationsCommand

		public ICommand ImportMitigationsCommand
		{
			get { return new DelegateCommand(ImportMitigations); }
		}

		private void ImportMitigations()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += importMitigationBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}

		private void importMitigationBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			if (String.IsNullOrWhiteSpace(ImportMitigationTextFileName))
			{
				ProgressLabelText = "Please select a \"Mitigations.txt\" file to import";
				return;
			}
			if (String.IsNullOrWhiteSpace(AddMitigationStatus))
			{
				ProgressLabelText = "Please select a status for the imported mitigations";
				return;
			}
			if (!String.IsNullOrWhiteSpace(AddMitigationGroupName))
			{
				if (String.IsNullOrWhiteSpace(AddMitigationMacLevel) && !AddMitigationGroupName.Contains(" : MAC"))
				{
					ProgressLabelText = "Please enter a MAC Level (I, II, III) for the new group entry";
					return;
				}
				vulneratorDatabaseActions = new VulneratorDatabaseActions();
				ProgressLabelText = vulneratorDatabaseActions.ImportMitigations(ImportMitigationTextFileName, AddMitigationGroupName, AddMitigationMacLevel, 
					AddMitigationStatus, this);
			}
			else
			{
				ProgressLabelText = "Please enter or select a group for the imported mitigations";
				return;
			}
			if (ProgressLabelText.Contains("successful"))
			{
				AddMitigationStatus = string.Empty;
				AddMitigationMacLevel = string.Empty;
				AddMitigationGroupName = string.Empty;
				ImportMitigationTextFileName = string.Empty;
			}
		}

		#endregion

		#region AddContactCommand

		public ICommand AddContactCommand
		{
			get { return new DelegateCommand(AddContact); }
		}

		private void AddContact()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += addContactBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}

		private void addContactBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			if (String.IsNullOrWhiteSpace(AddContactName))
			{
				ProgressLabelText = "Please provide a contact name";
				return;
			}
			if (String.IsNullOrWhiteSpace(AddContactEmail))
			{
				ProgressLabelText = "Please provide an email for \"" + AddContactName + "\"";
				return;
			}
			if (String.IsNullOrWhiteSpace(AddContactTitle))
			{
				ProgressLabelText = "Please provide an title for \"" + AddContactName + "\"";
				return;
			}
			if (String.IsNullOrWhiteSpace(AddContactGroupName))
			{
				ProgressLabelText = "Please provide a group for \"" + AddContactName + "\"";
				return;
			}
			if (String.IsNullOrWhiteSpace(AddContactSystemHostName))
			{
				ProgressLabelText = "Please provide a system host name for \"" + AddContactName + "\" to be associated with";
				return;
			}
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.AddContact(AddContactName, AddContactTitle, AddContactEmail, AddContactSystemHostName, AddContactSystemIp, 
				AddContactGroupName, AddContactMacLevel, this);
			if (ProgressLabelText.Contains("successful"))
			{
				AddContactName = string.Empty;
				AddContactTitle = string.Empty;
				AddContactEmail = string.Empty;
				AddContactGroupName = string.Empty;
				AddContactMacLevel = string.Empty;
				AddContactSystemIp = string.Empty;
				AddContactSystemHostName = string.Empty;
			}
		}

		#endregion

		#region UpdateContactCommand

		public ICommand UpdateContactCommand
		{
			get { return new DelegateCommand(UpdateContact); }
		}

		private void UpdateContact()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += updateContactBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}

		private void updateContactBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			if (updateContactParameters.CurrentName.Contains("DependencyProperty.UnsetValue"))
			{
				ProgressLabelText = "Please select a contact to update";
				return;
			}
			if (String.IsNullOrWhiteSpace(updateContactParameters.NewName))
			{
				ProgressLabelText = "Please provide an updated name";
				return;
			}
			if (String.IsNullOrWhiteSpace(updateContactParameters.NewTitle))
			{
				ProgressLabelText = "Please provide an updated title";
				return;
			}
			if (String.IsNullOrWhiteSpace(updateContactParameters.NewEmail))
			{
				ProgressLabelText = "Please provide an updated email";
				return;
			}
			if (String.IsNullOrWhiteSpace(updateContactParameters.NewGroupName))
			{
				ProgressLabelText = "Please provide an updated group name";
				return;
			}
			if (String.IsNullOrWhiteSpace(updateContactParameters.NewSystemName))
			{
				ProgressLabelText = "Please provide an updated system name";
				return;
			}
			if (String.IsNullOrWhiteSpace(updateContactParameters.NewSystemIp))
			{
				ProgressLabelText = "Please provide an updated system IP";
				return;
			}

			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.UpdateContact(SelectedContact, updateContactParameters, this);
		}

		#endregion

		#region UpdateGroupCommand

		public ICommand UpdateGroupCommand
		{
			get { return new DelegateCommand(UpdateGroup); }
		}
		
		private void UpdateGroup()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += updateGroupBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}

		private void updateGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			if (String.IsNullOrWhiteSpace(SelectedSystemGroupToUpdate))
			{
				ProgressLabelText = "Please select a group to update";
				return;
			}
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.UpdateGroup(SelectedSystemGroupToUpdate, updateSystemGroupParameters.UpdatedSystemGroupName,
				updateSystemGroupParameters.UpdatedSystemGroupMacLevel, this);

			if (ProgressLabelText.Contains("successful"))
			{
				SelectedSystemGroupToUpdate = string.Empty;
			}
		}

		#endregion

		#region DeleteGroupCommand

		public ICommand DeleteGroupCommand
		{
			get { return new DelegateCommand(DeleteGroup); }
		}
		
		private void DeleteGroup()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += deleteGroupBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}

		private void deleteGroupBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.DeleteGroup(SelectedSystemGroupToUpdate, this);
			if (ProgressLabelText.Contains("successful"))
			{
				SelectedSystemGroupToUpdate = string.Empty;
			}
		}

		#endregion

		#region UpdateSystemCommand

		public ICommand UpdateSystemCommand
		{
			get { return new DelegateCommand(UpdateSystem); }
		}

		private void UpdateSystem()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += updateSystemBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}

		private void updateSystemBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			if (String.IsNullOrWhiteSpace(SelectedContactSystemToUpdate))
			{
				ProgressLabelText = "Please select the system to be updated";
				return;
			}

			if (String.IsNullOrWhiteSpace(updateSystemParameters.UpdatedSystemGroup))
			{
				ProgressLabelText = "Please select an updated system group";
				return;
			}
			if (String.IsNullOrWhiteSpace(updateSystemParameters.UpdatedSystemName))
			{
				ProgressLabelText = "Please enter an updated system name";
				return;
			}
			if (String.IsNullOrWhiteSpace(updateSystemParameters.UpdatedSystemIP))
			{
				ProgressLabelText = "Please enter an updated system IP address";
				return;
			}
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.UpdateSystem(SelectedContactSystemToUpdate, updateSystemParameters, this);
			if (ProgressLabelText.Contains("successful"))
			{
				SelectedContactSystemToUpdate = string.Empty;
				updateSystemParameters.UpdatedSystemName = string.Empty;
				updateSystemParameters.UpdatedSystemIP = string.Empty;
			}
		}

		#endregion

		#region DeleteSystemCommand

		public ICommand DeleteSystemCommand
		{
			get { return new DelegateCommand(DeleteSystem); }
		}
		
		private void DeleteSystem()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += deleteSystemBackgroundWorker_DoWork;
			backgroundWorker.RunWorkerAsync();
		}
		
		private void deleteSystemBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			vulneratorDatabaseActions = new VulneratorDatabaseActions();
			ProgressLabelText = vulneratorDatabaseActions.DeleteSystem(SelectedContactSystemToUpdate, this);
			if (ProgressLabelText.Contains("successful"))
			{ SelectedContactSystemToUpdate = string.Empty; }
		}

		#endregion

		#region EmailTestCommand

		public ICommand EmailTestCommand
		{ get { return new DelegateCommand(EmailTest); } }

		public void EmailTest()
		{
			backgroundWorker = new BackgroundWorker();
			backgroundWorker.DoWork += sendEmailBackgroundWorker_DoWork;
			//backgroundWorker.RunWorkerAsync();
			backgroundWorker.Dispose();
		}

		private void sendEmailBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
		{
			Microsoft.Exchange.WebServices.Data.ExchangeService exchangeService = new Microsoft.Exchange.WebServices.Data.ExchangeService(Microsoft.Exchange.WebServices.Data.ExchangeVersion.Exchange2010_SP2);
			exchangeService.UseDefaultCredentials = true;

			string outlookLocalAppDataDirectory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Microsoft\\Outlook";
			string[] localAppDataOutlookFileArray = Directory.GetFiles(outlookLocalAppDataDirectory);
			string autodiscoverSettingsFile = localAppDataOutlookFileArray.FirstOrDefault(x => x.Contains(" - Autodiscover"));
			if (autodiscoverSettingsFile == null)
			{
				exchangeService.AutodiscoverUrl(ConfigAlter.ReadSettingsFromDictionary("tbNotifyingEmail"));
			}
			else
			{
				XDocument autodiscoverSettingsXmlFile = XDocument.Load(autodiscoverSettingsFile);
				Uri exchangeServerUri = new Uri(autodiscoverSettingsXmlFile.Root.Descendants().FirstOrDefault(x => x.Name.LocalName.Equals("ASUrl")).Value);
				exchangeService.Url = exchangeServerUri;
			}

			Microsoft.Exchange.WebServices.Data.EmailMessage emailMessage = new Microsoft.Exchange.WebServices.Data.EmailMessage(exchangeService);
			emailMessage.ToRecipients.Add("alex.kuchta@navy.mil");
			emailMessage.Subject = "Testing some more...";
			emailMessage.Body = "This is the final test";
			emailMessage.SendAndSaveCopy();
		}

        #endregion
    }
}