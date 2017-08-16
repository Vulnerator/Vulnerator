namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class JointAuthorizationOrganization
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public JointAuthorizationOrganization()
        {
            SystemCategorizations = new HashSet<SystemCategorization>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long JointOrganization_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string JointOrganization_Name { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SystemCategorization> SystemCategorizations { get; set; }
    }
}
