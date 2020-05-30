using System.Collections.ObjectModel;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class StepOneQuestionnaire : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public StepOneQuestionnaire()
        {
            Connectivities = new ObservableCollection<Connectivity>();
            ExternalSecurityServices = new ObservableCollection<ExternalSecurityService>();
            EncryptionTechniques = new ObservableCollection<EncryptionTechnique>();
            NetworkConnectionRules = new ObservableCollection<NetworkConnectionRule>();
            UserCategories = new ObservableCollection<UserCategory>();
            AuthorizationConditions = new ObservableCollection<AuthorizationCondition>();
            AuthorizationToConnectOrInterim_ATC_PendingItems = new ObservableCollection<AuthorizationToConnectOrInterim_ATC_PendingItem>();
            DeploymentLocations = new ObservableCollection<Location>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long StepOneQuestionnaire_ID { get; set; }
        
        [Required]
        [StringLength(25)]
        public string LogicalAccess { get; set; }
        
        [Required]
        [StringLength(25)]
        public string PhysicalAccess { get; set; }
        
        [Required]
        [StringLength(25)]
        public string AV_Scan { get; set; }
        
        [Required]
        [StringLength(25)]
        public string DODIN_ConnectionPeriodicity { get; set; }
        
        [Required]
        [StringLength(25)]
        public string RegistrationType { get; set; }
        
        [Required]
        [StringLength(100)]
        public string SystemType { get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsNationalSecuritySystem { get; set; }
        
        [Required]
        [StringLength(5)]
        public string HasPublicFacingPresence { get; set; }

        [Required]
        [StringLength(2000)]
        public string SystemDescription { get; set; }

        [Required]
        [StringLength(2000)]
        public string MissionDescription { get; set; }

        [Required]
        [StringLength(2000)]
        public string CONOPS_Statement { get; set; }

        public long? DITPR_DON_Number { get; set; }
        
        [Required]
        [StringLength(200)]
        public string DOD_IT_RegistrationNumber { get; set; }

        [StringLength(100)]
        public string DVS_Site { get; set; }

        [Required]
        [StringLength(200)]
        public string PPSM_RegistrationNumber { get; set; }
        
        [Required]
        [StringLength(2000)]
        public string SystemAuthorizationBoundary { get; set; }
        
        [Required]
        [StringLength(2000)]
        public string HardwareSoftwareFirmware { get; set; }

        [Required]
        [StringLength(2000)]
        public string SystemEnterpriseArchitecture { get; set; }
        
        [Required]
        [StringLength(2000)]
        public string InformationFlowsAndPaths { get; set; }
        
        [Required]
        [StringLength(25)]
        public string SystemLocation { get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsTypeAuthorization { get; set; }
        
        public long? BaselineLocation_ID { get; set; }
        
        public virtual Location BaselineLocation { get; set; }
        
        [Required]
        [StringLength(500)]
        public string InstallationNameOrOwningOrganization { get; set; }
        
        [Required]
        [StringLength(50)]
        public string SecurityPlanApprovalStatus { get; set; }
        
        public DateTime? SecurityPlanApprovalDate { get; set; }

        [Required]
        [StringLength(25)]
        public string AuthorizationStatus { get; set; }

        [Required]
        [StringLength(5)]
        public string HasAuthorizationDocumentation { get; set; }
        
        public DateTime? AssessmentCompletionDate { get; set; }
        
        public DateTime? AuthorizationDate { get; set; }

        public DateTime? AuthorizationTerminationDate { get; set; }

        [Required]
        [StringLength(25)]
        public string RMF_Activity { get; set; }
        
        [Required]
        [StringLength(2000)]
        public string AuthorizationTermsAndConditions { get; set; }

        [Required]
        [StringLength(5)]
        public string IsSecurityReviewCompleted{ get; set; }
        
        public DateTime? SecurityReviewDate { get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsContingencyPlanRequired{ get; set; }
        
        [StringLength(5)]
        public string IsContingencyPlanTested{ get; set; }
        
        public DateTime? ContingencyPlanTestDate { get; set; }

        [Required]
        [StringLength(5)]
        public string IsPIA_Required{ get; set; }
        
        public DateTime? PIA_Date { get; set; }

        [Required]
        [StringLength(5)]
        public string IsPrivacyActNoticeRequired{ get; set; }
        
        [Required]
        [StringLength(5)]
        public string Is_eAuthenticationRiskAssessmentRequired{ get; set; }
        
        public DateTime? eAuthenticationRiskAssessmentDate { get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsReportableToFISMA{ get; set; }
        
        [Required]
        [StringLength(5)]
        public string IsReportableToERS{ get; set; }

        [Required]
        [StringLength(25)]
        public string MissionCriticality { get; set; }
        
        [Required]
        [StringLength(25)]
        public string GoverningMissionArea { get; set; }
        
        [Required]
        [StringLength(25)]
        public string DOD_Component { get; set; }
        
        [Required]
        [StringLength(25)]
        public string ACQ_Category { get; set; }
        
        [Required]
        [StringLength(25)]
        public string ACQ_Phase { get; set; }
        
        [Required]
        [StringLength(25)]
        public string SoftwareCategory { get; set; }
        
        [Required]
        [StringLength(50)]
        public string SystemOwnershipAndControl { get; set; }
        
        [StringLength(2000)]
        public string OtherInformation { get; set; }

        [Required]
        public DateTime? AuthorizationToConnectOrInterim_ATC_GrantedDate { get; set; }
        
        [Required]
        public DateTime? AuthorizationToConnectOrInterim_ATC_ExpirationDate { get; set; }
        
        [StringLength(25)]
        public string AuthorizationToConnectOrInterim_ATC_CND_ServiceProvider { get; set; }

        [Required]
        [StringLength(50)]
        public string PrimaryNIST_ControlSet { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Connectivity> Connectivities { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ExternalSecurityService> ExternalSecurityServices { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EncryptionTechnique> EncryptionTechniques { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NetworkConnectionRule> NetworkConnectionRules { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UserCategory> UserCategories { get; set; }
        

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AuthorizationCondition> AuthorizationConditions { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AuthorizationToConnectOrInterim_ATC_PendingItem> AuthorizationToConnectOrInterim_ATC_PendingItems { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Location> DeploymentLocations { get; set; }
        
        public virtual Group Group { get; set; }
    }
}
