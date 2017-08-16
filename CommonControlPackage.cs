namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class CommonControlPackage
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public CommonControlPackage()
        {
            NistControls = new HashSet<NistControl>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long CCP_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string CCAP_Name { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControl> NistControls { get; set; }
    }
}
