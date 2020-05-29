using System.Collections.ObjectModel;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class NIST_Control
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public NIST_Control()
        {
            IATA_Standards = new HashSet<IATA_Standards>();
            CommonControlPackages = new HashSet<CommonControlPackage>();
            ControlSets = new HashSet<ControlSet>();
            Overlays = new HashSet<Overlay>();
            AvailabilityLevels = new ObservableCollection<AvailabilityLevel>();
            CCIs = new ObservableCollection<CCI>();
            ControlApplicabilityAssessments = new ObservableCollection<ControlApplicabilityAssessment>();
            ConfidentialityLevels = new ObservableCollection<ConfidentialityLevel>();
            IntegrityLevels = new ObservableCollection<IntegrityLevel>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NIST_Control_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string ControlFamily { get; set; }

        public long ControlNumber { get; set; }

        public long? Enhancement { get; set; }

        [Required]
        [StringLength(50)]
        public string ControlTitle { get; set; }

        [Required]
        [StringLength(500)]
        public string ControlText { get; set; }

        [Required]
        [StringLength(500)]
        public string SupplementalGuidance { get; set; }

        [StringLength(10)]
        public string MonitoringFrequency { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IATA_Standards> IATA_Standards { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CommonControlPackage> CommonControlPackages { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ControlSet> ControlSets { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Overlay> Overlays { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AvailabilityLevel> AvailabilityLevels { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CCI> CCIs { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ControlApplicabilityAssessment> ControlApplicabilityAssessments { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ConfidentialityLevel> ConfidentialityLevels { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IntegrityLevel> IntegrityLevels { get; set; }
        
    }
}
