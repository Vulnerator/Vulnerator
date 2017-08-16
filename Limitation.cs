namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class Limitation
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Limitation()
        {
            SAPs = new HashSet<SAP>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Limitation_ID { get; set; }

        [Required]
        [StringLength(100)]
        public string LimitationSummary { get; set; }

        [Required]
        [StringLength(500)]
        public string LimitationBackground { get; set; }

        [Required]
        [StringLength(500)]
        public string LimitationDetails { get; set; }

        [Required]
        [StringLength(5)]
        public string IsTestException { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SAP> SAPs { get; set; }
    }
}
