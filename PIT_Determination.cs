namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class PIT_Determination
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public PIT_Determination()
        {
            Accreditations = new HashSet<Accreditation>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PIT_Determination_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string RecievesInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string TransmitsInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string ProcessesInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string StoresInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string DisplaysInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string EmbeddedInSpecialPurpose { get; set; }

        [Required]
        [StringLength(5)]
        public string IsDedicatedSpecialPurposeSystem { get; set; }

        [Required]
        [StringLength(5)]
        public string IsEssentialSpecialPurposeSystem { get; set; }

        [Required]
        [StringLength(5)]
        public string PerformsGeneralServices { get; set; }

        public long? WeaponsSystem_ID { get; set; }

        public long? TrainingSimulation_ID { get; set; }

        public long? DiagnosticTesting_ID { get; set; }

        public long? Calibration_ID { get; set; }

        public long? ResearchWeaponsSystem_ID { get; set; }

        public long? MedicalTechnology_ID { get; set; }

        public long? NavigationSystem_ID { get; set; }

        public long? Building_ID { get; set; }

        public long? UtilityDistribution_ID { get; set; }

        public long? CommunicationSystem_ID { get; set; }

        public long? CombatSystem_ID { get; set; }

        public long? SpecialPurposeConsole_ID { get; set; }

        public long? Sensor_ID { get; set; }

        public long? TacticalSupportDatabase_ID { get; set; }

        [StringLength(5)]
        public string IsTacticalDecisionAid { get; set; }

        [StringLength(100)]
        public string OtherSystemTypeDescription { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Accreditation> Accreditations { get; set; }

        public virtual DiagnosticTestingSystem DiagnosticTestingSystem { get; set; }

        public virtual MedicalTechnology MedicalTechnology { get; set; }

        public virtual NavigationTransportationSystem NavigationTransportationSystem { get; set; }
    }
}
