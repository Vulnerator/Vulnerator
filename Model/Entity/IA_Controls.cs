namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class IA_Controls
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public IA_Controls()
        { Vulnerabilities = new ObservableCollection<Vulnerability>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long IA_Control_ID { get; set; }

        [Required]
        [StringLength(10)]
        public string IA_ControlNumber { get; set; }

        [Required]
        [StringLength(10)]
        public string Impact { get; set; }

        [Required]
        [StringLength(50)]
        public string IA_ControlSubjectArea { get; set; }

        [Required]
        [StringLength(100)]
        public string IA_ControlName { get; set; }

        [Required]
        [StringLength(250)]
        public string IA_ControlDescription { get; set; }

        [Required]
        [StringLength(2000)]
        public string IA_ControlThreatVulnerabilityCountermeasures { get; set; }

        [Required]
        [StringLength(2000)]
        public string IA_ControlGeneralImplementationGuidance { get; set; }

        [Required]
        [StringLength(2000)]
        public string IA_ControlSystemSpecificGuidanceResources { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Vulnerability> Vulnerabilities { get; set; }
    }
}
