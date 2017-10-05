using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using GalaSoft.MvvmLight.Messaging;
using log4net;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Data.Entity;
using System.Data.SQLite;
using System.Linq;
using Vulnerator.Helper;
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

        private ObservableCollection<MitigationsOrCondition> _projectMitigations { get; set; }
        public ObservableCollection<MitigationsOrCondition> ProjectMitigations
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

        private ObservableCollection<Vulnerability> _vulnerabilities { get; set; }
        public ObservableCollection<Vulnerability> Vulnerabilities
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

        private List<NistControlsCCI> _bulkNistControlsCcis { get; set; }
        public List<NistControlsCCI> BulkNistControlsCcis
        {
            get { return _bulkNistControlsCcis; }
            set
            {
                if (_bulkNistControlsCcis != value)
                {
                    _bulkNistControlsCcis = value;
                    RaisePropertyChanged("BulkNistControlsCcis");
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

        private bool _bulkProcessExpanded { get; set; }
        public bool BulkProcessExpanded
        {
            get { return _bulkProcessExpanded; }
            set
            {
                if (_bulkProcessExpanded != value)
                {
                    _bulkProcessExpanded = value;
                    RaisePropertyChanged("BulkProcessExpanded");
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
                ProjectMitigations.CollectionChanged += ProjectMitigations_CollectionChanged;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate MitigationsNistMappingViewModel."));
                log.Debug("Exception details:", exception);
            }
        }

        private void PopulateGui()
        {
            try
            {
                using (databaseContext = new DatabaseContext())
                {
                    ProjectMitigations = databaseContext.MitigationsOrConditions
                        .Include(m => m.Groups)
                        .Include(m => m.Vulnerability)
                        .AsNoTracking()
                        .ToObservableCollection();
                    foreach (MitigationsOrCondition mitigation in ProjectMitigations)
                    { mitigation.PropertyChanged += MitigationsOrCondition_PropertyChanged; }
                    Vulnerabilities = databaseContext.Vulnerabilities
                        .Include(v => v.CCIs.Select(c => c.NistControlsCCIs))
                        .AsNoTracking()
                        .ToObservableCollection();
                    NistControlsCcis = databaseContext.NistControlsCCIs
                        .Include(n => n.CCI)
                        .AsNoTracking().ToList();
                    BulkNistControlsCcis = databaseContext.NistControlsCCIs
                        .Include(n => n.CCI)
                        .AsNoTracking().ToList();
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to populate MitigationsNistMappingView lists."));
                throw exception;
            }
        }

        private void ProjectMitigations_CollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
        { 
            try
            {
                if (e.NewItems != null)
                {
                    foreach (MitigationsOrCondition mitigation in e.NewItems)
                    { mitigation.PropertyChanged += MitigationsOrCondition_PropertyChanged; }
                }
                if (e.OldItems != null)
                {
                    foreach (MitigationsOrCondition mitigation in e.OldItems)
                    { mitigation.PropertyChanged -= MitigationsOrCondition_PropertyChanged; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to implement CollectionChanged on Project Mitigations list"));
                log.Debug("Exception details:", exception);
            }
        }

        private void MitigationsOrCondition_PropertyChanged(object sender, PropertyChangedEventArgs e)
        { 
            try
            {
                MitigationsOrCondition mitigation = sender as MitigationsOrCondition;
                int mitigationId = (int)mitigation.MitigationOrCondition_ID;
                switch (e.PropertyName)
                {
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to handle mitigation change."));
                log.Debug("Exception details:", exception);
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
                Vulnerabilities.FirstOrDefault(v => v == SelectedVulnerability).CCIs.Add(SelectedNistControlsCci.CCI);
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map vulnerability to CCI"));
                log.Debug("Exception details:", exception);
            }
        }

        public RelayCommand BulkUpdatedVulnerabilityCciMappingCommand
        { get { return new RelayCommand(BulkUpdateVulnerabilityCciMapping); } }

        private void BulkUpdateVulnerabilityCciMapping()
        {
            try
            {
                List<NistControlsCCI> checkedNistControlList = BulkNistControlsCcis.Where(n => n.IsChecked).ToList();
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    foreach (Vulnerability vulnerability in Vulnerabilities.Where(v => v.IsChecked))
                    {
                        using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                        {
                            sqliteCommand.Parameters.Add(new SQLiteParameter("CCI"));
                            sqliteCommand.Parameters.Add(
                                new SQLiteParameter("Unique_Vulnerability_Identifier", vulnerability.Unique_Vulnerability_Identifier));
                            foreach (NistControlsCCI nistControlCci in checkedNistControlList)
                            {
                                sqliteCommand.Parameters["CCI"].Value = nistControlCci.CCI.CCI1;
                                databaseInterface.MapVulnerabilityToCci(sqliteCommand);
                                vulnerability.CCIs.Add(nistControlCci.CCI);
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
                DatabaseBuilder.sqliteConnection.Close();
                foreach (NistControlsCCI nistControlCci in BulkNistControlsCcis.Where(n => n.IsChecked))
                { nistControlCci.IsChecked = false; }
                SelectedNistControlsCci = null;
                SelectedVulnerability = null;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to bulk process vulnerability to CCI mapping."));
                log.Debug("Exception details:", exception);
            }
        }
    }
}
