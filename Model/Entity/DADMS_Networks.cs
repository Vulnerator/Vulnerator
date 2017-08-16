namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class DADMS_Networks
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public DADMS_Networks()
        {
            Softwares = new HashSet<Software>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long DADMS_Network_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string DADMS_Network_Name { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Software> Softwares { get; set; }
    }
}
