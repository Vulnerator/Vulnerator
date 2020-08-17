using System.Collections.ObjectModel;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Vulnerator.Model.Entity
{
    public class NIST_Control : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public NIST_Control()
        {
            IATA_Standards = new ObservableCollection<IATA_Standard>();
            CommonControlPackages = new ObservableCollection<CommonControlPackage>();
            ControlSets = new ObservableCollection<ControlSet>();
            Overlays = new ObservableCollection<Overlay>();
            AvailabilityLevels = new ObservableCollection<AvailabilityLevel>();
            ControlApplicabilityAssessments = new ObservableCollection<ControlApplicabilityAssessment>();
            ConfidentialityLevels = new ObservableCollection<ConfidentialityLevel>();
            IntegrityLevels = new ObservableCollection<IntegrityLevel>();
            NIST_ControlsCCIs = new ObservableCollection<NIST_ControlCCI>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NIST_Control_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string ControlFamily { get; set; }

        public long ControlNumber { get; set; }

        public long? ControlEnhancement { get; set; }

        [Required]
        [StringLength(50)]
        public string ControlTitle { get; set; }

        [Required]
        [StringLength(2000)]
        public string ControlText { get; set; }

        [Required]
        [StringLength(2000)]
        public string SupplementalGuidance { get; set; }

        [StringLength(10)]
        public string MonitoringFrequency { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IATA_Standard> IATA_Standards { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CommonControlPackage> CommonControlPackages { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ControlSet> ControlSets { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Overlay> Overlays { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<AvailabilityLevel> AvailabilityLevels { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ControlApplicabilityAssessment> ControlApplicabilityAssessments { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ConfidentialityLevel> ConfidentialityLevels { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<IntegrityLevel> IntegrityLevels { get; set; }
        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NIST_ControlCCI> NIST_ControlsCCIs { get; set; }
    }
}
