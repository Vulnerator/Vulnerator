using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using log4net;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.SQLite;
using System.Linq;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;
using Vulnerator.Model.Object;

namespace Vulnerator.ViewModel
{
    public class MitigationsNistMappingViewModel : ViewModelBase
    {
        private DatabaseContext databaseContext;
        private DatabaseInterface databaseInterface;
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        private List<MitigationsOrCondition> _projectMitigations { get; set; }
        public List<MitigationsOrCondition> ProjectMitigations
        {
            get { return _projectMitigations; }
            set
            {
                if (_projectMitigations != value)
                {
                    _projectMitigations = value;
                    RaisePropertyChanged("ProjectMitigations");
                }
            }
        }

        private List<MitigationsOrCondition> _assetMitigations { get; set; }
        public List<MitigationsOrCondition> AssetMitigations
        {
            get { return _assetMitigations; }
            set
            {
                if (_assetMitigations != value)
                {
                    _assetMitigations = value;
                    RaisePropertyChanged("AssetMitigations");
                }
            }
        }

        private List<Vulnerability> _vulnerabilities { get; set; }
        public List<Vulnerability> Vulnerabilities
        {
            get { return _vulnerabilities; }
            set
            {
                if (_vulnerabilities != value)
                {
                    _vulnerabilities = value;
                    RaisePropertyChanged("Vulnerabilities");
                }
            }
        }

        private List<NistControlsCCI> _nistControlsCcis { get; set; }
        public List<NistControlsCCI> NistControlsCcis
        {
            get { return _nistControlsCcis; }
            set
            {
                if (_nistControlsCcis != value)
                {
                    _nistControlsCcis = value;
                    RaisePropertyChanged("NistControlsCcis");
                }
            }
        }

        private Vulnerability _selectedVulnerability { get; set; }
        public Vulnerability SelectedVulnerability
        {
            get { return _selectedVulnerability; }
            set
            {
                if (_selectedVulnerability != value)
                {
                    _selectedVulnerability = value;
                    RaisePropertyChanged("SelectedVulnerability");
                }
            }
        }

        private NistControlsCCI _selectedNistControlsCci { get; set; }
        public NistControlsCCI SelectedNistControlsCci
        {
            get { return _selectedNistControlsCci; }
            set
            {
                if (_selectedNistControlsCci != value)
                {
                    _selectedNistControlsCci = value;
                    RaisePropertyChanged("SelectedNistControlsCci");
                }
            }
        }


        public MitigationsNistMappingViewModel()
        {
            try
            {
                log.Info("Begin instantiation of MitigationsNistMappingViewModel.");
                databaseInterface = new DatabaseInterface();
                PopulateGui();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate MitigationsNistMappingViewModel."));
                log.Debug("Exception details:", exception);
            }
        }

        private void PopulateGui()
        {
            using (databaseContext = new DatabaseContext())
            {
                ProjectMitigations = databaseContext.MitigationsOrConditions
                    .Where(m => m.Groups.Count > 0)
                    .Include(m => m.Groups)
                    .AsNoTracking().ToList();
                AssetMitigations = databaseContext.MitigationsOrConditions
                    .Where(m => m.Hardwares.Count > 0)
                    .Include(m => m.Groups)
                    .AsNoTracking().ToList();
                Vulnerabilities = databaseContext.Vulnerabilities
                    .Include(v => v.CCIs.Select(c => c.NistControlsCCIs))
                    .AsNoTracking().ToList();
                NistControlsCcis = databaseContext.NistControlsCCIs
                    .Include(n => n.CCI)
                    .AsNoTracking().ToList();
            }
        }

        public RelayCommand<object> ShowSelectedControlsCommand
        { get { return new RelayCommand<object>((p) => ShowSelectedControls(p)); } }

        private void ShowSelectedControls(object parameter)
        {
            try
            {
                if (parameter == null)
                { return; }
                foreach (NistControlsCCI nistControlsCci in NistControlsCcis)
                { nistControlsCci.IsChecked = false; }
                Vulnerability vulnerability = parameter as Vulnerability;
                foreach (CCI cci in vulnerability.CCIs)
                { NistControlsCcis.FirstOrDefault(n => n.CCI_ID == cci.CCI_ID).IsChecked = true; }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to show selected controls for the selected item."));
                log.Debug("Exception details:", exception);
            }
        }

        public RelayCommand<object> UpdateVulnerabilityCciMappingCommand
        { get { return new RelayCommand<object>((p) => UpdateVulnerabilityCciMapping(p)); } }

        private void UpdateVulnerabilityCciMapping(object parameter)
        { 
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Vulnerability_Identifier", SelectedVulnerability.Unique_Vulnerability_Identifier));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", SelectedNistControlsCci.CCI.CCI1));
                    
                    if (SelectedNistControlsCci.IsChecked)
                    { databaseInterface.MapVulnerabilityToCci(sqliteCommand); }
                    else
                    { databaseInterface.DeleteVulnerabilityToCciMapping(sqliteCommand); }
                }
                DatabaseBuilder.sqliteConnection.Close();
                PopulateGui();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map vulnerability to CCI"));
                log.Debug("Exception details:", exception);
            }
        }
    }
}
