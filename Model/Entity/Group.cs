using JetBrains.Annotations;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class Group : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Group()
        {
            CCIs = new ObservableCollection<CCI>();
            MitigationsOrConditions = new ObservableCollection<MitigationOrCondition>();
            Contacts = new ObservableCollection<Contact>();
            Hardwares = new ObservableCollection<Hardware>();
            Waivers = new ObservableCollection<Waiver>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Group_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string GroupName { get; set; }

        [StringLength(25)]
        public string GroupAcronym { get; set; }

        [Required]
        public long GroupTier { get; set; }

        [Required]
        [StringLength(5)]
        public string IsAccreditation { get; set; }

        [StringLength(25)]
        public string Accreditation_eMASS_ID { get; set; }

        [StringLength(5)]
        public string IsPlatform { get; set; }

        public long? Organization_ID { get; set; }
        
        public virtual Organization Organization { get; set; }

        public long? ConfidentialityLevel_ID { get; set; }
        
        public virtual ConfidentialityLevel ConfidentialityLevel { get; set; }

        public long? IntegrityLevel_ID { get; set; }
        
        public virtual IntegrityLevel IntegrityLevel { get; set; }

        public long? AvailabilityLevel_ID { get; set; }
        
        public virtual AvailabilityLevel AvailabilityLevel { get; set; }

        public long? SystemCategorization_ID { get; set; }
        
        public virtual SystemCategorization SystemCategorization { get; set; }

        [StringLength(25)]
        [CanBeNull]
        public string AccreditationVersion { get; set; }

        [StringLength(1)]
        [CanBeNull]
        public string CybersafeGrade { get; set; }

        [StringLength(5)]
        [CanBeNull]
        public string FISCAM_Applies { get; set; }

        public long? ControlSelection_ID { get; set; }
        
        public virtual ControlSelection ControlSelection { get; set; }

        [StringLength(5)]
        [CanBeNull]
        public string HasForeignNationals { get; set; }

        [StringLength(25)]
        [CanBeNull]
        public string SystemType { get; set; }

        [StringLength(1)]
        [CanBeNull]
        public string RDTE_Zone { get; set; }

        [CanBeNull]
        public long? StepOneQuestionnaire_ID { get; set; }
        
        public virtual StepOneQuestionnaire StepOneQuestionnaire { get; set; }

        public long? SecurityAssessmentProcedure_ID { get; set; }
        
        public virtual SecurityAssessmentProcedure SecurityAssessmentProcedure { get; set; }

        public long? PIT_Determination_ID { get; set; }
        
        public virtual PIT_Determination PIT_Determination { get; set; }

        [NotMapped]
        public bool IsChecked { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MitigationOrCondition> MitigationsOrConditions { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CCI> CCIs { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Contact> Contacts { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ConnectedSystem> ConnectedSystems { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Connection> Connections { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IATA_Standard> IATA_Standards { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Overlay> Overlays { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Waiver> Waivers { get; set; }

    }
}
