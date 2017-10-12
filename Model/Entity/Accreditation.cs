namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class Accreditation
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Accreditation()
        {
            AccreditationsNistControls = new ObservableCollection<AccreditationsNistControl>();
            AccreditationsWaivers = new ObservableCollection<AccreditationsWaiver>();
            IATA_Standards = new ObservableCollection<IATA_Standards>();
            ConnectedSystems = new ObservableCollection<ConnectedSystem>();
            Connections = new ObservableCollection<Connection>();
            Contacts = new ObservableCollection<Contact>();
            Overlays = new ObservableCollection<Overlay>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Accreditation_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string Accreditation_Name { get; set; }

        [Required]
        [StringLength(25)]
        public string Accreditation_Acronym { get; set; }

        [Required]
        [StringLength(25)]
        public string Accreditation_eMASS_ID { get; set; }

        [StringLength(5)]
        public string IsPlatform { get; set; }

        public long Confidentiality_ID { get; set; }

        public long Integrity_ID { get; set; }

        public long Availability_ID { get; set; }

        public long SystemCategorization_ID { get; set; }

        [StringLength(25)]
        public string AccreditationVersion { get; set; }

        [StringLength(1)]
        public string CybersafeGrade { get; set; }

        [StringLength(5)]
        public string FISCAM_Applies { get; set; }

        public long? ControlSelection_ID { get; set; }

        [StringLength(5)]
        public string HasForeignNationals { get; set; }

        [StringLength(25)]
        public string SystemType { get; set; }

        [StringLength(1)]
        public string RDTE_Zone { get; set; }

        public long StepOneQuestionnaire_ID { get; set; }

        public long? SAP_ID { get; set; }

        public long? PIT_Determination_ID { get; set; }

        public virtual PIT_Determination PIT_Determination { get; set; }

        public virtual SAP SAP { get; set; }

        public virtual StepOneQuestionnaire StepOneQuestionnaire { get; set; }

        public virtual ControlSelection ControlSelection { get; set; }

        public virtual SystemCategorization SystemCategorization { get; set; }

        public virtual AvailabilityLevel AvailabilityLevel { get; set; }

        public virtual IntegrityLevel IntegrityLevel { get; set; }

        public virtual ConfidentialityLevel ConfidentialityLevel { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AccreditationsNistControl> AccreditationsNistControls { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AccreditationsWaiver> AccreditationsWaivers { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IATA_Standards> IATA_Standards { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ConnectedSystem> ConnectedSystems { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Connection> Connections { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Contact> Contacts { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Overlay> Overlays { get; set; }
    }
}
