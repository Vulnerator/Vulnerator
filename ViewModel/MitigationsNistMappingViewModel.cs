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
using System.Reflection;
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
        private List<Likelihood> Likehoods;
        private List<Risk> Risks;
        private bool keepConnectionAlive = true;

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

        private object _selectedMitigationsOrCondition { get; set; }

        public object SelectedMitigationsOrCondition
        {
            get { return _selectedMitigationsOrCondition; }
            set
            {
                if (_selectedMitigationsOrCondition != value)
                {
                    _selectedMitigationsOrCondition = value;
                    RaisePropertyChanged("SelectedMitigationsOrCondition");
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

        private List<string> _mitigationStatuses { get; set; }

        public List<string> MitigationStatuses
        {
            get { return _mitigationStatuses; }
            set
            {
                if (_mitigationStatuses != value)
                {
                    _mitigationStatuses = value;
                    RaisePropertyChanged("MitigationStatuses");
                }
            }
        }

        private List<string> _rmfValues { get; set; }

        public List<string> RmfValues
        {
            get { return _rmfValues; }
            set
            {
                if (_rmfValues != value)
                {
                    _rmfValues = value;
                    RaisePropertyChanged("RmfValues");
                }
            }
        }

        private List<Group> _groups { get; set; }

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

        private string _impactDescription { get; set; }

        public string ImpactDescription
        {
            get { return _impactDescription; }
            set
            {
                if (_impactDescription != value)
                {
                    _impactDescription = value;
                    RaisePropertyChanged("ImpactDescription");
                }
            }
        }

        private string _predisposingConditions { get; set; }

        public string PredisposingConditions
        {
            get { return _predisposingConditions; }
            set
            {
                if (_predisposingConditions != value)
                {
                    _predisposingConditions = value;
                    RaisePropertyChanged("PredisposingConditions");
                }
            }
        }

        private string _technicalMitigations { get; set; }

        public string TechnicalMitigations
        {
            get { return _technicalMitigations; }
            set
            {
                if (_technicalMitigations != value)
                {
                    _technicalMitigations = value;
                    RaisePropertyChanged("TechnicalMitigations");
                }
            }
        }

        private string _proposedMitigations { get; set; }

        public string ProposedMitigations
        {
            get { return _proposedMitigations; }
            set
            {
                if (_proposedMitigations != value)
                {
                    _proposedMitigations = value;
                    RaisePropertyChanged("ProposedMitigations");
                }
            }
        }

        private string _mitigatedStatus { get; set; }

        public string MitigatedStatus
        {
            get { return _mitigatedStatus; }
            set
            {
                if (_mitigatedStatus != value)
                {
                    _mitigatedStatus = value;
                    RaisePropertyChanged("MitigatedStatus");
                }
            }
        }

        private string _threatRelevance { get; set; }

        public string ThreatRelevance
        {
            get { return _threatRelevance; }
            set
            {
                if (_threatRelevance != value)
                {
                    _threatRelevance = value;
                    RaisePropertyChanged("ThreatRelevance");
                }
            }
        }

        private string _severityPervasiveness { get; set; }

        public string SeverityPervasiveness
        {
            get { return _severityPervasiveness; }
            set
            {
                if (_severityPervasiveness != value)
                {
                    _severityPervasiveness = value;
                    RaisePropertyChanged("SeverityPervasiveness");
                }
            }
        }

        private string _likelihood { get; set; }

        public string Likelihood
        {
            get { return _likelihood; }
            set
            {
                if (_likelihood != value)
                {
                    _likelihood = value;
                    RaisePropertyChanged("Likelihood");
                }
            }
        }

        private string _impact { get; set; }

        public string Impact
        {
            get { return _impact; }
            set
            {
                if (_impact != value)
                {
                    _impact = value;
                    RaisePropertyChanged("Impact");
                }
            }
        }

        private string _risk { get; set; }

        public string Risk
        {
            get { return _risk; }
            set
            {
                if (_risk != value)
                {
                    _risk = value;
                    RaisePropertyChanged("Risk");
                }
            }
        }

        private string _residualRisk { get; set; }

        public string ResidualRisk
        {
            get { return _residualRisk; }
            set
            {
                if (_residualRisk != value)
                {
                    _residualRisk = value;
                    RaisePropertyChanged("ResidualRisk");
                }
            }
        }

        private string _residualRiskAfterProposed { get; set; }

        public string ResidualRiskAfterProposed
        {
            get { return _residualRiskAfterProposed; }
            set
            {
                if (_residualRiskAfterProposed != value)
                {
                    _residualRiskAfterProposed = value;
                    RaisePropertyChanged("ResidualRiskAfterProposed");
                }
            }
        }

        private string _estimatedCompletionDate { get; set; }

        public string EstimatedCompletionDate
        {
            get { return _estimatedCompletionDate; }
            set
            {
                if (_estimatedCompletionDate != value)
                {
                    _estimatedCompletionDate = value;
                    RaisePropertyChanged("EstimatedCompletionDate");
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
                Likehoods = PopulateLikelihoodMatrix();
                Risks = PopulateRiskMatrix();
                Messenger.Default.Register<NotificationMessage<string>>(this, MessengerToken.ModelUpdated, (msg) => HandleModelUpdate(msg.Notification));
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to instantiate MitigationsNistMappingViewModel."));
                log.Debug("Exception details:", exception);
            }
        }

        private void HandleModelUpdate(string modelUpdated)
        { 
            try
            {
                if (modelUpdated.Equals("MitigationsModel") || modelUpdated.Equals("AllModels"))
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
                MitigationStatuses = new List<string>() { "Ongoing", "Completed", "Not Reviewed", "Not Applicable" };
                RmfValues = new List<string>() { "Very High", "High", "Moderate", "Low", "Very Low" };
                using (databaseContext = new DatabaseContext())
                {
                    ProjectMitigations = databaseContext.MitigationsOrConditions
                        .Include(m => m.Groups)
                        .Include(m => m.Vulnerability)
                        .AsNoTracking()
                        .ToObservableCollection();
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
                    Groups = databaseContext.Groups.AsNoTracking().ToList();
                }
                ProjectMitigations.CollectionChanged += MitigationsOrConditions_CollectionChanged;
                Vulnerabilities.CollectionChanged += Vulnerabilities_CollectionChanged;
                SetPropertyChanged();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to populate MitigationsNistMappingView lists."));
                throw exception;
            }
        }

        private List<Likelihood> PopulateLikelihoodMatrix()
        { 
            try
            {
                return new List<Likelihood>()
                {
                    new Likelihood() { Relevance = "Very High", SeverityOrPervasiveness = "Very Low", CalculatedLikelihood = "Very Low" },
                    new Likelihood() { Relevance = "Very High", SeverityOrPervasiveness = "Low", CalculatedLikelihood = "Low" },
                    new Likelihood() { Relevance = "Very High", SeverityOrPervasiveness = "Moderate", CalculatedLikelihood = "Moderate" },
                    new Likelihood() { Relevance = "Very High", SeverityOrPervasiveness = "High", CalculatedLikelihood = "High" },
                    new Likelihood() { Relevance = "Very High", SeverityOrPervasiveness = "Very High", CalculatedLikelihood = "Very High" },
                    new Likelihood() { Relevance = "High", SeverityOrPervasiveness = "Very Low", CalculatedLikelihood = "Very Low" },
                    new Likelihood() { Relevance = "High", SeverityOrPervasiveness = "Low", CalculatedLikelihood = "Low" },
                    new Likelihood() { Relevance = "High", SeverityOrPervasiveness = "Moderate", CalculatedLikelihood = "Moderate" },
                    new Likelihood() { Relevance = "High", SeverityOrPervasiveness = "High", CalculatedLikelihood = "High" },
                    new Likelihood() { Relevance = "High", SeverityOrPervasiveness = "Very High", CalculatedLikelihood = "Very High" },
                    new Likelihood() { Relevance = "Moderate", SeverityOrPervasiveness = "Very Low", CalculatedLikelihood = "Very Low" },
                    new Likelihood() { Relevance = "Moderate", SeverityOrPervasiveness = "Low", CalculatedLikelihood = "Low" },
                    new Likelihood() { Relevance = "Moderate", SeverityOrPervasiveness = "Moderate", CalculatedLikelihood = "Moderate" },
                    new Likelihood() { Relevance = "Moderate", SeverityOrPervasiveness = "High", CalculatedLikelihood = "Moderate" },
                    new Likelihood() { Relevance = "Moderate", SeverityOrPervasiveness = "Very High", CalculatedLikelihood = "High" },
                    new Likelihood() { Relevance = "Low", SeverityOrPervasiveness = "Very Low", CalculatedLikelihood = "Very Low" },
                    new Likelihood() { Relevance = "Low", SeverityOrPervasiveness = "Low", CalculatedLikelihood = "Low" },
                    new Likelihood() { Relevance = "Low", SeverityOrPervasiveness = "Moderate", CalculatedLikelihood = "Low" },
                    new Likelihood() { Relevance = "Low", SeverityOrPervasiveness = "High", CalculatedLikelihood = "Low" },
                    new Likelihood() { Relevance = "Low", SeverityOrPervasiveness = "Very High", CalculatedLikelihood = "Moderate" },
                    new Likelihood() { Relevance = "Very Low", SeverityOrPervasiveness = "Very Low", CalculatedLikelihood = "Very Low" },
                    new Likelihood() { Relevance = "Very Low", SeverityOrPervasiveness = "Low", CalculatedLikelihood = "Very Low" },
                    new Likelihood() { Relevance = "Very Low", SeverityOrPervasiveness = "Moderate", CalculatedLikelihood = "Low" },
                    new Likelihood() { Relevance = "Very Low", SeverityOrPervasiveness = "High", CalculatedLikelihood = "Low" },
                    new Likelihood() { Relevance = "Very Low", SeverityOrPervasiveness = "Very High", CalculatedLikelihood = "Low" }
                };
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to populate Likelihood Matrix."));
                throw exception;
            }
        }

        private List<Risk> PopulateRiskMatrix()
        { 
            try
            {
                return new List<Risk>()
                {
                    new Risk() { Likelihood = "Very High", Impact = "Very Low", CalculatedRisk = "Very Low" },
                    new Risk() { Likelihood = "Very High", Impact = "Low", CalculatedRisk = "Low" },
                    new Risk() { Likelihood = "Very High", Impact = "Moderate", CalculatedRisk = "Moderate" },
                    new Risk() { Likelihood = "Very High", Impact = "High", CalculatedRisk = "High" },
                    new Risk() { Likelihood = "Very High", Impact = "Very High", CalculatedRisk = "Very High" },
                    new Risk() { Likelihood = "High", Impact = "Very Low", CalculatedRisk = "Very Low" },
                    new Risk() { Likelihood = "High", Impact = "Low", CalculatedRisk = "Low" },
                    new Risk() { Likelihood = "High", Impact = "Moderate", CalculatedRisk = "Moderate" },
                    new Risk() { Likelihood = "High", Impact = "High", CalculatedRisk = "High" },
                    new Risk() { Likelihood = "High", Impact = "Very High", CalculatedRisk = "Very High" },
                    new Risk() { Likelihood = "Moderate", Impact = "Very Low", CalculatedRisk = "Very Low" },
                    new Risk() { Likelihood = "Moderate", Impact = "Low", CalculatedRisk = "Low" },
                    new Risk() { Likelihood = "Moderate", Impact = "Moderate", CalculatedRisk = "Moderate" },
                    new Risk() { Likelihood = "Moderate", Impact = "High", CalculatedRisk = "Moderate" },
                    new Risk() { Likelihood = "Moderate", Impact = "Very High", CalculatedRisk = "High" },
                    new Risk() { Likelihood = "Low", Impact = "Very Low", CalculatedRisk = "Very Low" },
                    new Risk() { Likelihood = "Low", Impact = "Low", CalculatedRisk = "Low" },
                    new Risk() { Likelihood = "Low", Impact = "Moderate", CalculatedRisk = "Low" },
                    new Risk() { Likelihood = "Low", Impact = "High", CalculatedRisk = "Low" },
                    new Risk() { Likelihood = "Low", Impact = "Very High", CalculatedRisk = "Moderate" },
                    new Risk() { Likelihood = "Very Low", Impact = "Very Low", CalculatedRisk = "Very Low" },
                    new Risk() { Likelihood = "Very Low", Impact = "Low", CalculatedRisk = "Very Low" },
                    new Risk() { Likelihood = "Very Low", Impact = "Moderate", CalculatedRisk = "Low" },
                    new Risk() { Likelihood = "Very Low", Impact = "High", CalculatedRisk = "Low" },
                    new Risk() { Likelihood = "Very Low", Impact = "Very High", CalculatedRisk = "Low" }
                };
            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                log.Debug("Exception details:", exception);
                throw exception;
            }
        }

        private void SetPropertyChanged()
        {
            try
            {
                foreach (MitigationsOrCondition mitigation in ProjectMitigations)
                { mitigation.PropertyChanged += MitigationsOrCondition_PropertyChanged; }
                foreach (Vulnerability vulnerability in Vulnerabilities)
                { vulnerability.PropertyChanged += Vulnerability_PropertyChanged; }
                foreach (NistControlsCCI nistControlsCci in NistControlsCcis)
                { nistControlsCci.PropertyChanged += NistControlsCCI_PropertyChanged; }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to set PropertyChanged for existing items in lists."));
                throw exception;
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

        public void MitigationsOrConditions_CollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
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
                log.Error(string.Format("Unable to implement CollectionChanged on Mitigations list."));
                log.Debug("Exception details:", exception);
            }
        }

        public void MitigationsOrCondition_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            try
            {
                MitigationsOrCondition mitigation = sender as MitigationsOrCondition;
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    if (e.PropertyName.Equals("IsApproved"))
                    {
                        if (mitigation.IsApproved.Equals("True"))
                        { mitigation.Approver = Properties.Settings.Default.ActiveUser; }
                        else
                        { mitigation.Approver = null; }
                    }
                    if (!string.IsNullOrWhiteSpace(mitigation.Threat_Relevance) && !string.IsNullOrWhiteSpace(mitigation.Severity_Pervasiveness))
                    {
                        mitigation.Likelihood = Likehoods.FirstOrDefault(
                            x => x.Relevance.Equals(mitigation.Threat_Relevance) && x.SeverityOrPervasiveness.Equals(mitigation.Severity_Pervasiveness))
                            .CalculatedLikelihood;
                        sqliteCommand.Parameters["Likelihood"].Value = mitigation.Likelihood;
                    }
                    if (!string.IsNullOrWhiteSpace(mitigation.Likelihood) && !string.IsNullOrWhiteSpace(mitigation.Impact))
                    {
                        mitigation.Risk = Risks.FirstOrDefault(
                            x => x.Likelihood.Equals(mitigation.Likelihood) && x.Impact.Equals(mitigation.Impact))
                            .CalculatedRisk;
                        sqliteCommand.Parameters["Risk"].Value = mitigation.Risk;
                    }
                    string[] ignorableProperties = new string[] { "Risk", "Likelihood", "MitigationOrCondition_ID", "Groups", "Approver" };
                    if (mitigation.Vulnerability == null || ignorableProperties.Contains(e.PropertyName))
                    {
                        keepConnectionAlive = false;
                        return;
                    }
                    SetInitialSqliteParameters("MitigationsOrCondition", sqliteCommand);
                    sqliteCommand.Parameters["MitigationOrCondition_ID"].Value = mitigation.MitigationOrCondition_ID;
                    sqliteCommand.Parameters["Vulnerability_ID"].Value = mitigation.Vulnerability.Vulnerability_ID;
                    sqliteCommand.Parameters["Impact_Description"].Value = mitigation.Impact_Description;
                    sqliteCommand.Parameters["Predisposing_Conditions"].Value = mitigation.Predisposing_Conditions;
                    sqliteCommand.Parameters["Technical_Mitigation"].Value = mitigation.Technical_Mitigation;
                    sqliteCommand.Parameters["Proposed_Mitigation"].Value = mitigation.Proposed_Mitigation;
                    sqliteCommand.Parameters["Threat_Relevance"].Value = mitigation.Threat_Relevance;
                    sqliteCommand.Parameters["Severity_Pervasiveness"].Value = mitigation.Severity_Pervasiveness;
                    sqliteCommand.Parameters["Impact"].Value = mitigation.Impact;
                    sqliteCommand.Parameters["Residual_Risk"].Value = mitigation.Residual_Risk;
                    sqliteCommand.Parameters["Mitigated_Status"].Value = mitigation.Mitigated_Status;
                    sqliteCommand.Parameters["Expiration_Date"].Value = mitigation.Expiration_Date;
                    sqliteCommand.Parameters["IsApproved"].Value = mitigation.IsApproved ?? "False";
                    sqliteCommand.Parameters["Approver"].Value = mitigation.Approver;
                    if (mitigation.MitigationOrCondition_ID == 0)
                    {
                        databaseInterface.InsertMitigationOrCondition(sqliteCommand);
                        mitigation.MitigationOrCondition_ID = databaseInterface.SelectLastInsertRowId(sqliteCommand);
                        return;
                    }
                    databaseInterface.UpdateMitigationOrCondition(sqliteCommand);
                }
                    
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to handle mitigation change event."));
                log.Debug("Exception details:", exception);
            }
            finally
            {
                if (!keepConnectionAlive)
                {
                    DatabaseBuilder.sqliteConnection.Close();
                    keepConnectionAlive = true;
                }
            }
        }

        public void NistControlsCCIs_CollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            try
            {
                if (e.NewItems != null)
                {
                    foreach (NistControlsCCI control in e.NewItems)
                    { control.PropertyChanged += NistControlsCCI_PropertyChanged; }
                }
                if (e.OldItems != null)
                {
                    foreach (NistControlsCCI control in e.OldItems)
                    { control.PropertyChanged -= NistControlsCCI_PropertyChanged; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                log.Debug("Exception details:", exception);
            }
        }

        public void NistControlsCCI_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            try
            {
                NistControlsCCI control = sender as NistControlsCCI;
                int cciId = (int)control.CCI_ID;
                int nistControlId = (int)control.NIST_Control_ID;
                switch (e.PropertyName)
                {
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                log.Debug("Exception details:", exception);
            }
        }

        public void Vulnerabilities_CollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            try
            {
                if (e.NewItems != null)
                {
                    foreach (Vulnerability vulnerability in e.NewItems)
                    { vulnerability.PropertyChanged += Vulnerability_PropertyChanged; }
                }
                if (e.OldItems != null)
                {
                    foreach (Vulnerability vulnerability in e.OldItems)
                    { vulnerability.PropertyChanged -= Vulnerability_PropertyChanged; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to implement CollectionChanged on Vulnerability list."));
                log.Debug("Exception details:", exception);
            }
        }

        public void Vulnerability_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            try
            {
                Vulnerability vulnerability = sender as Vulnerability;
                int vulnerabilityId = (int)vulnerability.Vulnerability_ID;
                switch (e.PropertyName)
                {
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to handle vulnerability change event."));
                log.Debug("Exception details:", exception);
            }
        }

        private void SetInitialSqliteParameters(string sendingEntity, SQLiteCommand sqliteCommand)
        { 
            try
            {
                switch (sendingEntity)
                {
                    case "MitigationsOrCondition":
                        {
                            string[] parameters = new string[]
                            {
                                "MitigationOrCondition_ID", "Vulnerability_ID", "Impact_Description", "Predisposing_Conditions", "Technical_Mitigation", "Proposed_Mitigation",
                                "Threat_Relevance", "Severity_Pervasiveness", "Likelihood", "Impact", "Risk", "Residual_Risk", "Mitigated_Status", "Expiration_Date", "IsApproved",
                                "Approver", "Residual_Risk_After_Proposed", "Estimated_Completion_Date", "Approval_Date"
                            };
                            foreach (string parameter in parameters)
                            { sqliteCommand.Parameters.Add(new SQLiteParameter(parameter, DBNull.Value)); }
                            break;
                        }
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to set initial SQLite Command Parameters."));
                throw exception;
            }
        }

        public RelayCommand CalculateLikelihoodCommand
        { get { return new RelayCommand(CalculateLikelihood); } }

        private void CalculateLikelihood()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ThreatRelevance) || string.IsNullOrWhiteSpace(SeverityPervasiveness))
                { return; }
                Likelihood = Likehoods.FirstOrDefault(x => x.Relevance.Equals(ThreatRelevance) && x.SeverityOrPervasiveness.Equals(SeverityPervasiveness)).CalculatedLikelihood;
                if (!string.IsNullOrWhiteSpace(Impact))
                { CalculateRisk(); }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to calculate likelihood."));
                log.Debug(string.Format("Exception Details: {0}", exception));
                throw exception;
            }
        }

        public RelayCommand CalculateRiskCommand
        { get { return new RelayCommand(CalculateRisk); } }

        private void CalculateRisk()
        { 
            try
            {
                if (string.IsNullOrWhiteSpace(Likelihood) || string.IsNullOrWhiteSpace(Impact))
                { return; }
                Risk = Risks.FirstOrDefault(x => x.Likelihood.Equals(Likelihood) && x.Impact.Equals(Impact)).CalculatedRisk;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to calculate risk."));
                log.Debug(string.Format("Exception Details: {0}", exception));
                throw exception;
            }
        }

        public RelayCommand AddMitigationCommand
        { get { return new RelayCommand(AddMitigation); } }

        private void AddMitigation()
        { 
            try
            {

            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                log.Debug(string.Format("Exception Details: {0}", exception));
            }
        }
    }
}