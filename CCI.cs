namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class CCI
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public CCI()
        {
            NistControlsCCIs = new HashSet<NistControlsCCI>();
            Vulnerabilities = new HashSet<Vulnerability>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long CCI_ID { get; set; }

        [Column("CCI")]
        [Required]
        [StringLength(25)]
        public string CCI1 { get; set; }

        [Required]
        [StringLength(500)]
        public string Definition { get; set; }

        [Required]
        [StringLength(25)]
        public string Type { get; set; }

        [Required]
        [StringLength(25)]
        public string CCI_Status { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<NistControlsCCI> NistControlsCCIs { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Vulnerability> Vulnerabilities { get; set; }
    }
}
