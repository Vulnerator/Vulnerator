namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("RelatedTesting")]
    public partial class RelatedTesting
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public RelatedTesting()
        {
            SAPs = new HashSet<SecurityAssessmentProcedure>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long RelatedTesting_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string TestTitle { get; set; }

        public DateTime DateConducted { get; set; }

        [Required]
        [StringLength(50)]
        public string RelatedSystemTested { get; set; }

        [Required]
        [StringLength(100)]
        public string ResponsibleOrganization { get; set; }

        [Required]
        [StringLength(500)]
        public string TestingImpact { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityAssessmentProcedure> SAPs { get; set; }
    }
}
