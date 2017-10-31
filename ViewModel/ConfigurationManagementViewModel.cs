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
using System.Linq;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;
using Vulnerator.Model.Object;

namespace Vulnerator.ViewModel
{
    public class ConfigurationManagementViewModel : ViewModelBase
    {
        private DatabaseContext databaseContext;
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private BackgroundWorker backgroundWorker;
        private VulnerabilitySource vulnerabilitySource;
        private string saveDirectory = string.Empty;

        private List<Hardware> _hardwares;
        public List<Hardware> Hardwares
        {
            get { return _hardwares; }
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
            get { return _softwares; }
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
            get { return _contacts; }
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
            get { return _groups; }
            set
            {
                if (_groups != value)
                {
                    _groups = value;
                    RaisePropertyChanged("Groups");
                }
            }
        }

        private List<Accreditation> _accreditations;
        public List<Accreditation> Accreditations
        {
            get { return _accreditations; }
            set
            {
                if (_accreditations != value)
                {
                    _accreditations = value;
                    RaisePropertyChanged("Accreditations");
                }
            }
        }

        private List<PP> _pps;
        public List<PP> PPS
        {
            get { return _pps; }
            set
            {
                if (_pps != value)
                {
                    _pps = value;
                    RaisePropertyChanged("PPS");
                }
            }
        }

        private Hardware _selectedHardware;
        public Hardware SelectedHardware
        {
            get { return _selectedHardware; }
            set
            {
                if (_selectedHardware != value)
                {
                    _selectedHardware = value;
                    RaisePropertyChanged("SelectedHardware");
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
                log.Error(string.Format("Unable to instantiate ConfigurationManagementViewModel."));
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
                log.Error(string.Format("Unable to update MitigationsNistViewModel."));
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
                        .AsNoTracking().ToList();
                    Softwares = databaseContext.Softwares
                                        .Include(s => s.SoftwareHardwares.Select(h => h.Hardware))
                                        .AsNoTracking().ToList();
                    Contacts = databaseContext.Contacts
                                        .Include(c => c.Accreditations)
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
                    Accreditations = databaseContext.Accreditations.AsNoTracking().ToList();
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to populate ConfigurationManagementView"));
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
                    backgroundWorker = new BackgroundWorker();
                    backgroundWorker.DoWork += generateCklBackgroundWorker_DoWork;
                    backgroundWorker.RunWorkerAsync();
                    backgroundWorker.Dispose();
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to create CKL file."));
                log.Debug("Exception details:", exception);
            }
        }

        private void generateCklBackgroundWorker_DoWork(object sender, DoWorkEventArgs e)
        { 
            try
            {
                CklCreator cklCreator = new CklCreator();
                cklCreator.CreateCklFromHardware(SelectedHardware, vulnerabilitySource, saveDirectory);
                vulnerabilitySource = null;
                saveDirectory = string.Empty;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to generate CKL file background worker."));
                throw exception;
            }
        }
    }
}
