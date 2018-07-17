namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class NistControl
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public NistControl()
        {
            AccreditationsNistControls = new HashSet<AccreditationsNistControl>();
            NistControlsAvailabilityLevels = new HashSet<NistControlsAvailabilityLevel>();
            NistControlsCAAs = new HashSet<NistControlsCAA>();
            NistControlsCCIs = new HashSet<NistControlsCCI>();
            NistControlsConfidentialityLevels = new HashSet<NistControlsConfidentialityLevel>();
            NistControlsIntegrityLevels = new HashSet<NistControlsIntegrityLevel>();
            IATA_Standards = new HashSet<IATA_Standards>();
            CommonControlPackages = new HashSet<CommonControlPackage>();
            ControlSets = new HashSet<ControlSet>();
            Overlays = new HashSet<Overlay>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NIST_Control_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string Control_Family { get; set; }

        public long Control_Number { get; set; }

        public long? Enhancement { get; set; }

        [Required]
        [StringLength(50)]
        public string Control_Title { get; set; }

        [Required]
        [StringLength(500)]
        public string Control_Text { get; set; }

        [Required]
        [StringLength(500)]
        public string Supplemental_Guidance { get; set; }

        [StringLength(10)]
        public string Monitoring_Frequency { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AccreditationsNistControl> AccreditationsNistControls { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControlsAvailabilityLevel> NistControlsAvailabilityLevels { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControlsCAA> NistControlsCAAs { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControlsCCI> NistControlsCCIs { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControlsConfidentialityLevel> NistControlsConfidentialityLevels { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControlsIntegrityLevel> NistControlsIntegrityLevels { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IATA_Standards> IATA_Standards { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CommonControlPackage> CommonControlPackages { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ControlSet> ControlSets { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Overlay> Overlays { get; set; }
    }
}
