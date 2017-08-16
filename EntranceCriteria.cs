namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("EntranceCriteria")]
    public partial class EntranceCriteria
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public EntranceCriteria()
        {
            SAPs = new HashSet<SAP>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long EntranceCriteria_ID { get; set; }

        [Column("EntranceCriteria")]
        [Required]
        [StringLength(100)]
        public string EntranceCriteria1 { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SAP> SAPs { get; set; }
    }
}
