namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class ControlSet
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ControlSet()
        {
            NistControls = new HashSet<NistControl>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ControlSet_ID { get; set; }

        [Column("ControlSet")]
        [Required]
        [StringLength(50)]
        public string ControlSet1 { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControl> NistControls { get; set; }
    }
}
