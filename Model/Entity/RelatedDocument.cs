namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class RelatedDocument
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public RelatedDocument()
        {
            SecurityAssessmentProcedures = new HashSet<SecurityAssessmentProcedure>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long RelatedDocument_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string RelatedDocumentName { get; set; }

        [Required]
        [StringLength(100)]
        public string RelationshipDescription { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
    }
}
