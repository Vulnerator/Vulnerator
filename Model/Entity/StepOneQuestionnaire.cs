using System.ComponentModel;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("StepOneQuestionnaire")]
    public partial class StepOneQuestionnaire : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public StepOneQuestionnaire()
        {
            Connectivities = new HashSet<Connectivity>();
            ExternalSecurityServices = new HashSet<ExternalSecurityService>();
            EncryptionTechniques = new HashSet<EncryptionTechnique>();
            NetworkConnectionRules = new HashSet<NetworkConnectionRule>();
            UserCategories = new HashSet<UserCategory>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long StepOneQuestionnaire_ID { get; set; }

        [Required]
        [StringLength(2000)]
        public string SystemDescription { get; set; }

        [Required]
        [StringLength(2000)]
        public string MissionDescription { get; set; }

        [Required]
        [StringLength(2000)]
        public string CONOPS_Statement { get; set; }

        [Required]
        [StringLength(5)]
        public string IsTypeAuthorization { get; set; }
        
        public long? DITPR_DON_Number { get; set; }
        
        public DateTime? AuthorizationToConnectOrInterim_ATC_GrantedDate { get; set; }
        
        public DateTime? AuthorizationToConnectOrInterim_ATC_ExpirationDate { get; set; }
        
        [StringLength(25)]
        public string AuthorizationToConnectOrInterim_ATC_CND_ServiceProvider { get; set; }
        
        [StringLength(25)]
        public string SecurityPlanApprovalStatus { get; set; }
        
        public DateTime? SecurityPlanApprovalDate { get; set; }
        
        [StringLength(25)]
        public string AuthorizationStatus { get; set; }
        
        [StringLength(5)]
        public string HasAuthorizationDocumentation { get; set; }
        
        public DateTime? AssessmentCompletionDate { get; set; }
        
        public DateTime? AuthorizationDate { get; set; }
        
        public DateTime? AuthorizationTerminationDate { get; set; }
        
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
        [StringLength(25)]
        public string RMF_Activity { get; set; }

        [Required]
        public long Accessibility_ID { get; set; }

        [Required]
        public long Overview_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string PortsProtocolsRegistrationNumber { get; set; }

        [Required]
        public long AuthorizationInformation_ID { get; set; }

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
        [StringLength(25)]
        public string RegistrationType { get; set; }
        
        [Required]
        public long InformationSystemOwner_ID { get; set; }
        
        [Required]
        [StringLength(100)]
        public string SystemType { get; set; }
        
        [StringLength(100)]
        public string DVS_Site { get; set; }
        
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
        [StringLength(2000)]
        public string SystemEnterpriseArchitecture { get; set; }

        public long? AuthorizationToConnectOrInterim_ATC_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string NIST_ControlSet { get; set; }

        public virtual Group Group { get; set; }

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
    }
}
