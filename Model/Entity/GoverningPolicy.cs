namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class GoverningPolicy
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public GoverningPolicy()
        {
            SystemCategorizations = new HashSet<SystemCategorization>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long GoverningPolicy_ID { get; set; }

        [StringLength(50)]
        public string GoverningPolicy_Name { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SystemCategorization> SystemCategorizations { get; set; }
    }
}
