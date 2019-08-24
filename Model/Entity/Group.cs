using JetBrains.Annotations;

namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class Group : INotifyPropertyChanged
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Group()
        {
            MitigationsOrConditions = new ObservableCollection<MitigationsOrCondition>();
            Contacts = new ObservableCollection<Contact>();
            Hardwares = new ObservableCollection<Hardware>();
        }

        public event PropertyChangedEventHandler PropertyChanged;

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Group_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string Name { get; set; }

        [StringLength(25)]
        public string Acronym { get; set; }

        [Required]
        public long Group_Tier { get; set; }

        [Required]
        [StringLength(5)]
        public string Is_Accreditation { get; set; }

        [StringLength(25)]
        public string Accreditation_eMASS_ID { get; set; }

        [StringLength(5)]
        public string IsPlatform { get; set; }

        public long? Organization_ID { get; set; }

        public long? Confidentiality_ID { get; set; }

        public long? Integrity_ID { get; set; }

        public long? Availability_ID { get; set; }

        public long? SystemCategorization_ID { get; set; }

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

        [StringLength(5)]
        [CanBeNull]
        public string HasForeignNationals { get; set; }

        [StringLength(25)]
        [CanBeNull]
        public string SystemType { get; set; }

        [StringLength(1)]
        [CanBeNull]
        public string RDTE_Zone { get; set; }

        public long? StepOneQuestionnaire_ID { get; set; }

        public long? SAP_ID { get; set; }

        public long? PIT_Determination_ID { get; set; }

        [NotMapped]
        public bool IsChecked { get; set; }

        public virtual PIT_Determination PIT_Determination { get; set; }

        public virtual SAP SAP { get; set; }

        public virtual StepOneQuestionnaire StepOneQuestionnaire { get; set; }

        public virtual ControlSelection ControlSelection { get; set; }

        public virtual SystemCategorization SystemCategorization { get; set; }

        public virtual AvailabilityLevel AvailabilityLevel { get; set; }

        public virtual IntegrityLevel IntegrityLevel { get; set; }

        public virtual ConfidentialityLevel ConfidentialityLevel { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MitigationsOrCondition> MitigationsOrConditions { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Contact> Contacts { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<GroupsCCIs> GroupsCCIs { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<GroupsWaivers> GroupsWaivers { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ConnectedSystem> ConnectedSystems { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Connection> Connections { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IATA_Standards> IATA_Standards { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Overlay> Overlays { get; set; }
    }
}
