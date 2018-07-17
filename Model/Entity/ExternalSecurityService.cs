namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class ExternalSecurityService
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ExternalSecurityService()
        { StepOneQuestionnaires = new ObservableCollection<StepOneQuestionnaire>(); }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ExternalSecurityServices_ID { get; set; }

        [Column("ExternalSecurityService")]
        [Required]
        [StringLength(50)]
        public string ExternalSecurityService1 { get; set; }

        [Required]
        [StringLength(500)]
        public string ServiceDescription { get; set; }

        [Required]
        [StringLength(500)]
        public string SecurityRequirementsDescription { get; set; }

        [Required]
        [StringLength(100)]
        public string RiskDetermination { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
    }
}
