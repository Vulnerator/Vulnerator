namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class UniqueFindingSourceFile
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public UniqueFindingSourceFile()
        {
            UniqueFindings = new HashSet<UniqueFinding>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long FindingSourceFile_ID { get; set; }

        [Required]
        [StringLength(500)]
        public string FindingSourceFileName { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UniqueFinding> UniqueFindings { get; set; }
    }
}
