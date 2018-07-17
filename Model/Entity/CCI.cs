namespace Vulnerator.Model.Entity
{
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class CCI
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public CCI()
        {
            NistControlsCCIs = new ObservableCollection<NistControlsCCI>();
            Vulnerabilities = new ObservableCollection<Vulnerability>();
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
