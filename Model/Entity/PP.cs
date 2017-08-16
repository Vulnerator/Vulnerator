namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("PPS")]
    public partial class PP
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public PP()
        {
            Hardware_PPS = new HashSet<Hardware_PPS>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PPS_ID { get; set; }

        public long Port { get; set; }

        [Required]
        [StringLength(25)]
        public string Protocol { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware_PPS> Hardware_PPS { get; set; }
    }
}
