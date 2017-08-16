namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("LifecycleStatuses")]
    public partial class LifecycleStatus
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public LifecycleStatus()
        {
            Hardwares = new HashSet<Hardware>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long LifecycleStatus_ID { get; set; }

        [Column("LifecycleStatus")]
        [Required]
        [StringLength(25)]
        public string LifecycleStatus1 { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Hardware> Hardwares { get; set; }
    }
}
