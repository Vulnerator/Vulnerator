namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class MAC_Addresses
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public MAC_Addresses()
        {
            Hardwares = new HashSet<Hardware>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long MAC_Address_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string MAC_Address { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }
    }
}
